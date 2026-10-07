//! Recursive-descent TypeScript type grammar.

use super::*;

// Recursive-descent type parser. Production entry points
// `parse_type_expr_emitting_refs` / `parse_return_type_emitting_refs` delegate to
// `parse_type` here.
impl<'src> Parser<'src> {
    /// Type := TypePredicate | Conditional. Parses one full type expression,
    /// emitting TypeRefs, stopping at the first token that doesn't belong to
    /// the type. A type predicate (`x is T`, `asserts x is T`, `asserts x`)
    /// is only legal in return-type position, but it's cheap and unambiguous
    /// to recognize here: the subject is a value-parameter binder (or `this`),
    /// so it is consumed WITHOUT emitting a ref, and the asserted type (after
    /// `is`) is parsed normally. This is what lets generic-argument predicate
    /// types like `x is Matcher<unknown, unknown>` parse — without it the
    /// trailing `is` desyncs the caller and the `<...>` args recover.
    pub(super) fn parse_type(&mut self) {
        // Stack-overflow guard: the recursive descent through the type grammar
        // re-enters `parse_type` once per generic argument, so capping here
        // bounds most of the subtree. The same counter is also incremented at
        // `parse_type_operator` (audit-5b round-2 review item R2-P1) — that
        // lower entry point closes the `infer X extends ...` recursion cycle
        // that does NOT pass back through `parse_type`. With both entry
        // points bumping the same counter, every recursive cycle in the type
        // grammar advances the cap monotonically. `MAX_TYPE_DEPTH = 192` is
        // conservative — legitimate library types rarely exceed depth ~30 —
        // and survives a 256 KiB stack with margin even at the post-R2
        // doubled per-level cost. See the `parser_recursion_guard` and
        // `audit5b_round2_review` tests for the adversarial inputs.
        if !self.enter_reference_recursion(ReferenceRecursionKind::Type) {
            self.skip_reference_recovery_token();
            return;
        }
        if !self.try_parse_type_predicate() {
            self.parse_conditional_type();
        }
        self.leave_reference_recursion(ReferenceRecursionKind::Type);
    }

    /// Consume one token after rejected type recursion so the surrounding
    /// grammar loop progresses. Admission and evidence stay owned by the
    /// parser-level recursion policy.
    fn skip_reference_recovery_token(&mut self) {
        // Skip one token to ensure the caller's loop makes progress; the
        // outer `parse_type_args`/`parse_union_type`/... loops drain on
        // their delimiters (`>`, `|`, `&`) and the recovery path in the
        // top-level statement loop will resync at the next statement
        // boundary if we leave the type subtree malformed.
        if !matches!(self.lexer.peek().kind, TokenKind::Eof) {
            self.lexer.next();
        }
    }

    /// Recognize and consume a type predicate. Returns `true` if one was
    /// consumed. Shapes:
    ///   `asserts Ident`              (assertion signature, no `is`)
    ///   `asserts Ident is Type`      (asserted-type assertion signature)
    ///   `Ident is Type`              (ordinary type guard)
    /// `this` is also a legal subject; it lexes as `Ident` here. The subject
    /// names a value parameter, never a type, so it is consumed silently.
    fn try_parse_type_predicate(&mut self) -> bool {
        // `asserts x` / `asserts x is T`.
        if self.peek_ident_is("asserts") {
            // Look past `asserts` for `Ident` to confirm an assertion signature
            // (rather than a stray identifier type literally named `asserts`).
            let save = self.lexer.checkpoint();
            self.lexer.next(); // `asserts`
            if Self::token_can_start_binding_identifier(self.lexer.peek().kind) {
                self.lexer.next(); // subject (value param / `this`) — no ref
                if self.peek_ident_is("is") {
                    self.lexer.next(); // `is`
                    self.parse_type(); // asserted type
                }
                return true;
            }
            // Not actually an assertion signature — rewind and fall through.
            self.lexer.restore(save);
            return false;
        }
        // `x is T` — Ident followed by the `is` contextual keyword.
        if Self::token_can_start_binding_identifier(self.lexer.peek().kind) {
            let save = self.lexer.checkpoint();
            self.lexer.next(); // subject (value param / `this`) — no ref
            if self.peek_ident_is("is") {
                self.lexer.next(); // `is`
                self.parse_type(); // guarded type
                return true;
            }
            // Not a predicate — rewind so the normal type path emits the ref.
            self.lexer.restore(save);
        }
        false
    }

    /// Union := Intersection ('|' Intersection)*   (leading `|` tolerated)
    ///
    /// F2-2b (positive whitelist): each member's parse returns `Some(event
    /// index)` IFF the member was positively identified as a bare — possibly
    /// generic, possibly qualified — type reference (exactly one head TypeRef;
    /// no `[]`/indexed postfix; no `keyof`/`readonly` prefix; not
    /// parenthesized/tuple/object/function/template/`infer`/`typeof`). Only
    /// those candidates are retagged `CompositionMember`, and only when the
    /// union has >= 2 members (a one-member leading-pipe "union" `| A` is not
    /// a composition — F2-2 review Finding 2). Anything else — including any
    /// FUTURE construct — keeps its base-context position: unknown shapes
    /// default to NOT demoted (fail-safe), the inverse of the earlier
    /// depth-sweep which demoted anything at member depth unless a bespoke
    /// escape frame protected it. Retagging after the loop (rather than
    /// pushing a context before the first member) keeps the classification
    /// order-invariant: the first member — parsed before any `|` is seen — is
    /// treated identically to later members.
    fn parse_union_type(&mut self) {
        if matches!(self.lexer.peek().kind, TokenKind::Pipe) {
            self.lexer.next();
        }
        let first = self.parse_intersection_type();
        let mut rest: Vec<Option<TypeRefRetagCandidate>> = Vec::new();
        while matches!(self.lexer.peek().kind, TokenKind::Pipe) {
            self.lexer.next();
            rest.push(self.parse_intersection_type());
        }
        if !rest.is_empty() {
            // >= 2 members: retag the recorded bare-reference candidates.
            if let Some(candidate) = first {
                self.retag_event_as_composition_member(candidate);
            }
            for candidate in rest.into_iter().flatten() {
                self.retag_event_as_composition_member(candidate);
            }
        }
    }

    /// Intersection := Operator ('&' Operator)*    (leading `&` tolerated)
    ///
    /// F2-2b: same positive-whitelist retag as `parse_union_type` for
    /// `&`-separated members. Returns the single member's candidate when this
    /// "intersection" has exactly one member (so `A` in `A | B` — which parses
    /// as a one-member intersection inside the union — bubbles its candidacy
    /// up to the union's boundary); a genuine multi-member intersection retags
    /// its own candidates and returns `None` (the compound is not a bare ref).
    fn parse_intersection_type(&mut self) -> Option<TypeRefRetagCandidate> {
        if matches!(self.lexer.peek().kind, TokenKind::Amp) {
            self.lexer.next();
        }
        let first = self.parse_type_operator();
        if !matches!(self.lexer.peek().kind, TokenKind::Amp) {
            return first;
        }
        let mut rest: Vec<Option<TypeRefRetagCandidate>> = Vec::new();
        while matches!(self.lexer.peek().kind, TokenKind::Amp) {
            self.lexer.next();
            rest.push(self.parse_type_operator());
        }
        if let Some(candidate) = first {
            self.retag_event_as_composition_member(candidate);
        }
        for candidate in rest.into_iter().flatten() {
            self.retag_event_as_composition_member(candidate);
        }
        None
    }

    /// Type reference: `Name`, qualified `Name.Member...`, optional generic args.
    /// Emits the head name only (tails are member access).
    ///
    /// F2-2b: returns the head TypeRef's event index (`None` when the head was
    /// suppressed) — the retag CANDIDATE that bubbles up through
    /// `parse_primary_type`/`parse_postfix_type`/`parse_type_operator` to the
    /// union/intersection boundary, surviving only while the member stays a
    /// bare reference. G1.5 F2-4 Part C: for a qualified `NS.Type` reference,
    /// the candidate also carries the sibling `TypeMemberAccess` event's
    /// index (emitted with the SAME `current_type_pos()` as the head — the
    /// two events describe one syntactic reference), so a union/intersection
    /// retag upgrades both together.
    fn parse_type_reference(&mut self) -> Option<TypeRefRetagCandidate> {
        let t = self.lexer.peek().clone();
        let name = self.text_of(t.span).to_string();
        self.lexer.next();
        // Structured type parser: the base position is whatever the enclosing
        // entry point pushed onto `pos_stack` (annotation / return-type /
        // constraint / composition member / value / alias-RHS => Other). A
        // union/intersection retag may later upgrade this to CompositionMember.
        let base_position = self.current_type_pos();
        let head_idx = self.emit_type_ref(name.clone(), t.span, base_position);
        let mut first_member: Option<(String, Span)> = None;
        let mut member_count = 0usize;
        while matches!(self.lexer.peek().kind, TokenKind::Dot) {
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                let member_tok = self.lexer.next();
                member_count += 1;
                if first_member.is_none() {
                    first_member =
                        Some((self.text_of(member_tok.span).to_string(), member_tok.span));
                }
            }
        }
        let member_access_idx = if member_count == 1 {
            first_member.map(|(member, member_span)| {
                self.emit_type_member_access(name, member, member_span, base_position)
            })
        } else {
            None
        };
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.parse_type_args();
        }
        head_idx.map(|head| TypeRefRetagCandidate {
            head,
            member_access: member_access_idx,
        })
    }

    /// Generic type-argument list `<A, B<C>>`. Uses `rescan_gt` so `>>` closes two levels.
    ///
    /// F2-2: a nested generic argument (the `Bar` in `x: Foo<Bar>`) is not the
    /// annotation head, a union member, etc. — the brief leaves it unspecified,
    /// so reset the base to `Other` for the argument subtree. (A union WITHIN an
    /// argument, `Foo<A | B>`, still retags A/B to `CompositionMember` via
    /// `parse_union_type`.)
    fn parse_type_args(&mut self) {
        self.lexer.next(); // `<`
        self.pos_stack.push(TypeRefPosition::Other);
        loop {
            self.lexer.rescan_gt();
            match self.lexer.peek().kind {
                TokenKind::Gt => {
                    self.lexer.next();
                    self.pos_stack.pop();
                    return;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                }
                TokenKind::Eof => {
                    self.pos_stack.pop();
                    return;
                }
                _ => self.parse_type(),
            }
        }
    }

    /// Conditional := Union ('extends' Union '?' Type ':' Type)?
    /// The check-type is a Union (not a bare Conditional) so it doesn't swallow
    /// the `?`. Branches are full Types (right-associative nesting in the false
    /// branch). `infer` binders in the check-type are scoped via the enclosing
    /// type-param scope (safe over-scoping — only avoids false refs).
    fn parse_conditional_type(&mut self) {
        self.parse_union_type();
        self.parse_conditional_tail_if_present();
    }

    /// If the next token is the `extends` contextual keyword, consume the full
    /// conditional tail: `extends CheckType ? TrueBranch : FalseBranch`.
    ///
    /// Called both from `parse_conditional_type` (after the subject union) and
    /// from `parse_tuple_type` after `finish_consumed_type_reference` — because
    /// a tuple element can be a full conditional type whose subject is a generic
    /// type reference (e.g. `Foo<A, B> extends infer X ? {...} : never`).
    /// Without the call in the tuple path, the loop's next iteration would see
    /// `extends` as a fresh ident and emit it as a bogus TypeRef.
    fn parse_conditional_tail_if_present(&mut self) {
        if self.peek_ident_is("extends") {
            self.lexer.next();
            // Push a scope that owns any `infer` binders introduced in the
            // check-type (e.g. `(k: infer R) => void`). Binders must remain
            // live through the true/false branches, so we cannot use the
            // transient scope inside `parse_type_expr_emitting_refs` — that
            // scope is popped after each param type, which is too early.
            // `conditional_check_depth > 0` tells `parse_type_expr_emitting_refs`
            // to skip its own transient scope so that `note_type_param_binder`
            // writes into THIS scope instead.
            self.push_type_param_scope();
            self.conditional_check_depth += 1;
            // F2-2: the conditional `extends` check-type is a composition
            // clause — refs directly in it (e.g. `Wrapper` in
            // `T extends Wrapper<infer U> ? …`) are `CompositionMember`.
            self.pos_stack.push(TypeRefPosition::CompositionMember);
            self.parse_union_type(); // check type (may contain `infer X`)
            self.pos_stack.pop();
            self.conditional_check_depth -= 1;
            // The conditional scope stays on the stack so `infer` binders are
            // in scope for both branches, then we pop it after the false branch.
            if matches!(self.lexer.peek().kind, TokenKind::Question) {
                self.lexer.next();
                self.parse_type(); // true branch
                if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                    self.lexer.next();
                    self.parse_type(); // false branch
                }
            }
            self.pop_type_param_scope();
        }
    }

    /// Peek: is the current token an Ident whose text equals `kw`?
    /// (`keyof`/`infer`/`readonly`/`extends`/`is`/`asserts`/`as` are
    /// contextual keywords lexed as `Ident`.)
    fn peek_ident_is(&mut self, kw: &str) -> bool {
        let t = self.lexer.peek().clone();
        t.kind == TokenKind::Ident && self.text_of(t.span) == kw
    }

    /// Operator := ('keyof'|'typeof'|'readonly')* ('infer' Binder | Postfix)
    ///
    /// The prefix-keyword loop is *iterative* on purpose: the original
    /// self-recursion drove the parser to SIGABRT on a 2 MiB stack for a
    /// `keyof keyof … keyof A` chain of ~250+ keywords, because each prefix
    /// added a `parse_type_operator` frame that the audit-5b
    /// `parse_type` depth guard didn't reach (it sits on a sibling entry
    /// point). Audit-5b review item P1. Same iterative shape as
    /// `parse_union_type` (`while peek == Pipe`), `parse_intersection_type`
    /// (`while peek == Amp`), and `parse_postfix_type` (`while peek == LBracket`).
    ///
    /// Additionally gates on `MAX_TYPE_DEPTH` (audit-5b round-2 review item
    /// R2-P1): the `infer X extends C` branch below recurses through
    /// `parse_union_type` → `parse_intersection_type` → `parse_type_operator`
    /// without re-entering `parse_type`, so the upper guard never fires for
    /// chains like `infer X extends infer X extends … A`. Counting the
    /// same `type_depth` from both entry points closes the cycle.
    /// F2-2b: returns the member's retag candidate — the postfix chain's bare
    /// head ref — but only when NO prefix operator was consumed here. A
    /// `keyof X` / `readonly X` member is the compound expression, not the
    /// bare ref `X`, so consuming a prefix kills candidacy (`X` keeps its
    /// base-context position). `typeof` and `infer` branches never produce a
    /// candidate.
    fn parse_type_operator(&mut self) -> Option<TypeRefRetagCandidate> {
        if !self.enter_reference_recursion(ReferenceRecursionKind::Type) {
            self.skip_reference_recovery_token();
            return None;
        }
        let mut consumed_type_query = false;
        let mut consumed_prefix_operator = false;
        loop {
            if matches!(self.lexer.peek().kind, TokenKind::Typeof) {
                self.lexer.next();
                self.parse_type_query_operand_emitting_value_ref();
                consumed_type_query = true;
                break;
            }
            if self.peek_ident_is("keyof") || self.peek_ident_is("readonly") {
                self.lexer.next();
                consumed_prefix_operator = true;
                continue;
            }
            // `unique symbol` (TS): `unique` is a type-prefix operator ONLY
            // immediately before `symbol`. Consume it and let the operand
            // (`symbol`, a builtin type) parse below. Anything else keeps
            // `unique` as an ordinary type name (restore + fall through).
            if self.peek_ident_is("unique") {
                let save = self.lexer.checkpoint();
                self.lexer.next(); // tentatively consume `unique`
                if self.peek_ident_is("symbol") {
                    continue;
                }
                self.lexer.restore(save);
            }
            break;
        }
        if self.peek_ident_is("infer") {
            self.lexer.next();
            // `infer X` introduces a fresh type binder — scope it so X is not a ref.
            let nt = self.lexer.peek().clone();
            if nt.kind == TokenKind::Ident {
                let name = self.text_of(nt.span).to_string();
                self.note_type_param_binder(&name);
                self.lexer.next();
                // `infer X extends C` (TS 4.7) — parse the constraint.
                if self.peek_ident_is("extends") {
                    self.lexer.next();
                    self.parse_union_type();
                }
            }
            self.leave_reference_recursion(ReferenceRecursionKind::Type);
            return None;
        }
        let candidate = if consumed_type_query {
            None
        } else {
            self.parse_postfix_type()
        };
        self.leave_reference_recursion(ReferenceRecursionKind::Type);
        if consumed_prefix_operator {
            None
        } else {
            candidate
        }
    }

    fn parse_type_query_operand_emitting_value_ref(&mut self) {
        match self.lexer.peek().kind {
            TokenKind::Ident => {
                let t = self.lexer.next();
                let name = self.text_of(t.span).to_string();
                self.emit_type_query_value_ref(name, t.span);
                self.consume_type_query_member_tail();
            }
            TokenKind::Import => {
                self.parse_import_type_reference();
            }
            _ => {
                let _ = self.parse_postfix_type();
            }
        }
    }

    fn parse_import_type_reference(&mut self) {
        let import_span = self.lexer.next().span;
        if !matches!(self.lexer.peek().kind, TokenKind::LParen) {
            return;
        }
        self.lexer.next();
        if matches!(self.lexer.peek().kind, TokenKind::Str) {
            let specifier_token = self.lexer.next();
            let (specifier, specifier_span) = self.read_str_literal(specifier_token);
            self.events.push(Event::Ref(RefEvent::Import {
                specifier,
                specifier_span,
                bindings: Vec::new(),
                is_type_only: true,
                makes_external_module: false,
            }));
        } else {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::UnsupportedConstruct {
                    construct: "import type with non-literal specifier".to_string(),
                },
                file_path: self.path.clone(),
                span: import_span,
            });
        }
        loop {
            match self.lexer.peek().kind {
                TokenKind::RParen => {
                    self.lexer.next();
                    break;
                }
                TokenKind::Eof => break,
                TokenKind::Comma => {
                    self.lexer.next();
                }
                _ => {
                    let before = self.lexer.peek().span.start();
                    self.skip_balanced_value();
                    if self.lexer.peek().span.start() == before {
                        self.lexer.next();
                    }
                }
            }
        }
        self.consume_type_query_member_tail();
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.parse_type_args();
        }
    }

    fn consume_type_query_member_tail(&mut self) {
        while matches!(
            self.lexer.peek().kind,
            TokenKind::Dot | TokenKind::QuestionDot
        ) {
            self.lexer.next();
            if Self::token_can_be_dot_property_identifier(self.lexer.peek().kind) {
                self.lexer.next();
            } else {
                break;
            }
        }
    }

    /// Postfix := Primary ('[' Type? ']')*   (`[]` = array, `[K]` = indexed access)
    ///
    /// F2-2b: returns the primary's retag candidate, but only when NO postfix
    /// was consumed — a `T[]` / `T[K]` member is the compound expression, not
    /// the bare ref `T`, so the head keeps its base-context position.
    fn parse_postfix_type(&mut self) -> Option<TypeRefRetagCandidate> {
        let head = self.parse_primary_type();
        let mut consumed_postfix = false;
        while matches!(self.lexer.peek().kind, TokenKind::LBracket) {
            // Bug E (2026-05-26): if the `[` sits on a new line after
            // the primary type, this is NOT a postfix index/array on the
            // primary — it is the start of a new member in the
            // surrounding container (an interface body's `[key: T]: V`
            // index signature, or an analogous index member in an
            // object type). Without this guard, `parse_type_expr_emitting_refs`
            // called for the value-type of a normal property
            // (`prop: number`) would greedy-eat the following line's
            // `[key:` tokens as `number[key]` indexed-access. The
            // misparse leaked a stray `]` back to the outer interface-
            // body loop, which then exited early without recording
            // `last_end`, triggering the Bug-F underflow panic in
            // `parse_interface_decl`. Found in Scout's
            // src/services/kg-debug-client.ts (`interface
            // CacheStatsResponse { hit_rate: number ... [key: string]:
            // unknown }`).
            if self.newline_between_last_token_and_peek() {
                break;
            }
            consumed_postfix = true;
            self.lexer.next(); // `[`
            if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                self.lexer.next(); // array `T[]`
            } else {
                self.parse_type(); // indexed access `T[K]` — K may be a ref
                if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                    self.lexer.next();
                }
            }
        }
        if consumed_postfix {
            None
        } else {
            head
        }
    }

    /// Returns true if the bytes between the previously-consumed token
    /// and the current `peek()` contain a `\n`. Walks backwards from
    /// `peek.span.start()` skipping ASCII whitespace; the first `\n`
    /// found in that whitespace run means an ASI boundary exists.
    /// Conservatively returns false when the immediately-preceding byte
    /// is non-whitespace (e.g. the lexer is right after the last token
    /// with no gap). Used by `parse_postfix_type` to avoid extending a
    /// type expression across a newline into a new container member.
    /// Does not handle `\n` inside block comments — a rare edge that's
    /// not worth the scan cost for v1.
    fn newline_between_last_token_and_peek(&mut self) -> bool {
        let peek_pos = self.lexer.peek().span.start() as usize;
        if peek_pos == 0 {
            return false;
        }
        let src = self.source;
        let mut i = peek_pos;
        while i > 0 {
            let b = src[i - 1];
            if b == b'\n' {
                return true;
            }
            if matches!(b, b' ' | b'\t' | b'\r') {
                i -= 1;
            } else {
                return false;
            }
        }
        false
    }

    /// Primary := reference | object/mapped | function type | parenthesized | ...
    ///
    /// F2-2b: returns the retag candidate — `Some(head event index)` ONLY for
    /// the bare type-reference branch (`parse_type_reference`, possibly
    /// generic/qualified). Every other primary shape — object/mapped,
    /// parenthesized, function/constructor type, tuple, literal, template,
    /// and any FUTURE branch added here — returns `None`, so its inner refs
    /// can never be demoted by an enclosing union/intersection retag.
    fn parse_primary_type(&mut self) -> Option<TypeRefRetagCandidate> {
        match self.lexer.peek().kind {
            TokenKind::Ident => {
                // `abstract new (...) => T` — abstract constructor type.
                // `abstract` is a modifier token, not a type name; consume it
                // and fall into the `new` constructor-type path.  If `new` does
                // NOT follow, treat `abstract` as a real type identifier and
                // restore the lexer so parse_type_reference emits the ref.
                if self.peek_ident_is("abstract") {
                    let save = self.lexer.checkpoint();
                    self.lexer.next(); // consume `abstract`
                    if matches!(self.lexer.peek().kind, TokenKind::New) {
                        self.lexer.next(); // consume `new`
                        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
                            self.push_type_param_scope();
                            self.skip_type_param_list_collecting_refs();
                            self.parse_function_type();
                            self.pop_type_param_scope();
                        } else {
                            self.parse_function_type();
                        }
                        None
                    } else {
                        // `abstract` used as a plain type name — restore and
                        // emit the ref normally.
                        self.lexer.restore(save);
                        self.parse_type_reference()
                    }
                } else {
                    self.parse_type_reference()
                }
            }
            TokenKind::Import => {
                self.parse_import_type_reference();
                None
            }
            TokenKind::LBrace => {
                self.parse_object_or_mapped_type();
                None
            }
            TokenKind::LParen => {
                let cursor = self.lexer.peek().span.start() as usize;
                if looks_like_function_type(&self.source[cursor..]) {
                    self.parse_function_type();
                } else {
                    self.lexer.next(); // `(`
                    self.parse_type();
                    if matches!(self.lexer.peek().kind, TokenKind::RParen) {
                        self.lexer.next();
                    }
                }
                None
            }
            TokenKind::Lt => {
                self.push_type_param_scope();
                self.skip_type_param_list_collecting_refs();
                self.parse_function_type();
                self.pop_type_param_scope();
                None
            }
            TokenKind::New => {
                self.lexer.next(); // `new`
                if matches!(self.lexer.peek().kind, TokenKind::Lt) {
                    self.push_type_param_scope();
                    self.skip_type_param_list_collecting_refs();
                    self.parse_function_type();
                    self.pop_type_param_scope();
                } else {
                    self.parse_function_type();
                }
                None
            }
            TokenKind::LBracket => {
                self.parse_tuple_type();
                None
            }
            // Literal types — no type reference to emit.
            TokenKind::Str | TokenKind::Number => {
                self.lexer.next();
                None
            }
            // Negative numeric literal `-1` — consume minus, then the number.
            TokenKind::Minus => {
                self.lexer.next();
                if matches!(self.lexer.peek().kind, TokenKind::Number) {
                    self.lexer.next();
                }
                None
            }
            TokenKind::TemplateStart => {
                self.parse_template_literal_type();
                None
            }
            // Closing delimiters and contextual keywords that belong to an
            // enclosing parser — never consume so the caller can see them.
            TokenKind::Gt
            | TokenKind::RBracket
            | TokenKind::RParen
            | TokenKind::As   // `as` remap clause in mapped types
            | TokenKind::Eof => None,
            _ => {
                self.lexer.next(); // tolerant: consume one token
                None
            }
        }
    }

    /// Function type tail: `(params) => ReturnType`. Any leading `<...>`
    /// type-params were already consumed/scoped by the caller. Param names
    /// suppressed; param types and the return type emit refs.
    fn parse_function_type(&mut self) {
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            self.lexer.next();
            let _ = self.parse_param_list_emitting_type_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::Arrow) {
            self.lexer.next();
            self.parse_type();
        }
    }

    /// Parse an object-literal-type MEMBER's value type (the part after
    /// `:` in `name: ValueType`), re-arming the base to
    /// `AliasMemberAnnotation` (G1.9 S2) IFF the currently inherited base
    /// is `Other`. This is the additivity constraint: `Other` is exactly
    /// the base a top-level type-alias RHS object literal pushes
    /// (`parse_type_alias_decl_body`), so this re-arm fires there (and for
    /// nested object-literal members, which inherit the pushed
    /// `AliasMemberAnnotation` from their enclosing member and therefore
    /// never re-observe `Other`) — but any OTHER inherited base (e.g.
    /// `ParamAnnotation` from a parameter's inline object type, or
    /// `ValuePosition` from a `satisfies`/`as` object type) is left
    /// completely untouched, falling through to the historical
    /// `self.parse_type()` call. Called from both `parse_object_or_mapped_type`
    /// property-value arms (the plain non-minting `Colon` arm and the
    /// minting path's non-function-shaped sub-branch); the minting path's
    /// function-shaped sub-branch is deliberately NOT routed through here
    /// (out of scope — see the S2 task brief).
    fn parse_object_member_value_type(&mut self) {
        if self.current_type_pos() == TypeRefPosition::Other {
            self.parse_type_expr_with_base(TypeRefPosition::AliasMemberAnnotation);
        } else {
            self.parse_type();
        }
    }

    /// `{ ... }` — object type, mapped type, and index signatures share one loop.
    /// No multi-token lookahead: commit to consuming `[ Ident` and branch on the
    /// following token — `in` => mapped key, `:` => index-sig param.
    fn parse_object_or_mapped_type(&mut self) {
        // G1.7 Fix 2 — consume the armed alias-RHS flag only when THIS
        // invocation's opening brace is the armed position (the alias
        // RHS's first token). Nested object types see `minting = false`.
        let brace_pos = self.lexer.peek().span.start();
        let minting = match self.alias_object_mint {
            Some((owner, pos)) if pos == brace_pos && self.current_owner() == Some(owner) => {
                self.alias_object_mint = None;
                true
            }
            _ => false,
        };
        self.lexer.next(); // `{`
        loop {
            match self.lexer.peek().kind {
                TokenKind::RBrace => {
                    self.lexer.next();
                    return;
                }
                TokenKind::Eof => return,
                TokenKind::LBracket => self.parse_bracket_member(),
                TokenKind::Colon => {
                    self.lexer.next();
                    self.parse_object_member_value_type();
                }
                TokenKind::Comma
                | TokenKind::Semi
                | TokenKind::Question
                | TokenKind::Plus
                | TokenKind::Minus => {
                    self.lexer.next();
                }
                TokenKind::New => {
                    // Construct signature `new (...): R` — behaviorally
                    // identical to the old fall-through (`new` consumed by
                    // the `_` arm, then LParen → parse_method_member), made
                    // explicit so minting mode can NEVER misread a
                    // construct signature as the `"()"` call signature.
                    self.lexer.next();
                    if matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt) {
                        self.parse_method_member();
                    }
                }
                TokenKind::LParen | TokenKind::Lt => {
                    // Anonymous call signature at member position. G1.7
                    // Fix 2: when minting, record it under the reserved
                    // name `"()"` (same rationale as the interface arm).
                    if minting {
                        let sig_span = self.lexer.peek().span;
                        let refs_start = self.events.len();
                        self.parse_method_member();
                        let refs_end = self.events.len();
                        let decl_end = self.lexer.peek().span.start();
                        self.record_type_member(
                            "()".to_string(),
                            sig_span,
                            Span::new(sig_span.start(), decl_end.saturating_sub(sig_span.start())),
                            (refs_start, refs_end),
                        );
                    } else {
                        self.parse_method_member();
                    }
                }
                TokenKind::Ident if minting => {
                    // G1.7 Fix 2 — name-aware member handling so a minted
                    // member decl carries its name. Non-minting invocations
                    // keep the historical shape (name consumed here, the
                    // NEXT iteration's LParen/Colon arms do the work).
                    let name_tok = self.lexer.peek().clone();
                    let name = self.text_of(name_tok.span).to_string();
                    self.lexer.next();
                    // Optional-member `?` may precede EITHER shape
                    // (`m?(x): R` optional method, `p?: T` optional
                    // property) — consume it before dispatching.
                    if matches!(self.lexer.peek().kind, TokenKind::Question) {
                        self.lexer.next();
                    }
                    match self.lexer.peek().kind {
                        TokenKind::LParen | TokenKind::Lt => {
                            // Method-signature member `m(x: T): R`.
                            let refs_start = self.events.len();
                            self.parse_method_member();
                            let refs_end = self.events.len();
                            let decl_end = self.lexer.peek().span.start();
                            self.record_type_member(
                                name,
                                name_tok.span,
                                Span::new(
                                    name_tok.span.start(),
                                    decl_end.saturating_sub(name_tok.span.start()),
                                ),
                                (refs_start, refs_end),
                            );
                        }
                        TokenKind::Colon => {
                            self.lexer.next();
                            // Function-typed property members mint;
                            // everything else keeps today's path.
                            if self.peek_type_is_function_shaped() {
                                let refs_start = self.events.len();
                                self.parse_type();
                                let refs_end = self.events.len();
                                let decl_end = self.lexer.peek().span.start();
                                self.record_type_member(
                                    name,
                                    name_tok.span,
                                    Span::new(
                                        name_tok.span.start(),
                                        decl_end.saturating_sub(name_tok.span.start()),
                                    ),
                                    (refs_start, refs_end),
                                );
                            } else {
                                self.parse_object_member_value_type();
                            }
                        }
                        _ => {
                            // Modifier keyword (`readonly`, …) or stray
                            // ident — consumed; next iteration continues.
                        }
                    }
                }
                TokenKind::Ident | TokenKind::Str | TokenKind::Number => {
                    self.lexer.next();
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    /// `[ ... ]` inside an object type: mapped key `[K in C (as A)?]`, index
    /// signature `[k: T]`, or computed key. Then optional `?`/`-?`/`+?` and `: ValueType`.
    pub(super) fn parse_bracket_member(&mut self) {
        // Push a fresh type-param scope so that any mapped-key binder (e.g. `K`
        // in `[K in keyof T]`) is scoped to this bracket member only.  Without
        // this, `K` would leak into sibling object members and the surrounding
        // alias, over-suppressing later refs that happen to share the name.
        self.push_type_param_scope();
        self.lexer.next(); // `[`
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let binder = self.lexer.peek().clone();
            let binder_name = self.text_of(binder.span).to_string();
            self.lexer.next();
            match self.lexer.peek().kind {
                TokenKind::In => {
                    self.note_type_param_binder(&binder_name);
                    self.lexer.next(); // `in`
                    self.parse_type(); // constraint (refs emitted)
                    if matches!(self.lexer.peek().kind, TokenKind::As) {
                        self.lexer.next(); // `as` keyword token
                        self.parse_type(); // remap type (refs emitted, e.g. `Baz`)
                    }
                }
                TokenKind::Colon => {
                    self.lexer.next(); // index sig `[k: T]` — binder_name suppressed, parse value type
                    self.parse_type();
                }
                _ => {
                    // Computed key `[ns.member]` / `[Expr]` — the head ident and any
                    // dotted tail are a member-access expression, not type refs. Consume
                    // the tail without emitting refs so tokens like `.override` or
                    // `.isVariadic` do not leak into the TypeRef stream.
                    while matches!(self.lexer.peek().kind, TokenKind::Dot) {
                        self.lexer.next(); // `.`
                        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                            self.lexer.next(); // tail segment
                        }
                    }
                }
            }
        } else {
            self.parse_type(); // other computed-key forms — tolerant
        }
        if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
            self.lexer.next();
        }
        while matches!(
            self.lexer.peek().kind,
            TokenKind::Question | TokenKind::Plus | TokenKind::Minus
        ) {
            self.lexer.next(); // `?`, `+?`, `-?`
        }
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            self.parse_type(); // value type
        }
        self.pop_type_param_scope();
    }

    /// Tuple type `[A, B, ...Rest]`, including spread and `infer` elements.
    /// Labeled elements `label: T` / `label?: T` handled via commit-and-branch.
    ///
    /// F2-2b note: the transient F2-2 `type_depth` escape frame here was
    /// removed — a tuple member returns no retag candidate under the positive
    /// whitelist (`parse_primary_type`'s LBracket arm is `None`), so its
    /// elements can never be demoted by an enclosing composition. Recursion
    /// safety is unaffected: every tuple-element cycle re-enters `parse_type`,
    /// which carries the `MAX_TYPE_DEPTH` guard.
    fn parse_tuple_type(&mut self) {
        self.lexer.next(); // `[`
        loop {
            // Copy `kind` out first so we don't hold a borrow on `self` across
            // the match guard that calls `peek_is_type_operator_kw`.
            let kind = self.lexer.peek().kind;
            match kind {
                TokenKind::RBracket => {
                    self.lexer.next();
                    return;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                }
                TokenKind::Eof => return,
                TokenKind::Spread => {
                    self.lexer.next(); // `...`
                }
                TokenKind::Ident => {
                    if self.peek_is_type_operator_kw() {
                        // `infer X`, `keyof T`, `readonly T`, `typeof T` — delegate
                        // to the full type parser which handles these operators.
                        self.parse_type();
                    } else {
                        // Bare ident: could be `label: T`, `label?: T`, or `RefType`.
                        let head = self.lexer.peek().clone();
                        self.lexer.next();
                        match self.lexer.peek().kind {
                            TokenKind::Colon => {
                                // labeled element `label: T` — head is the label, not a ref
                                self.lexer.next();
                                self.parse_type();
                            }
                            TokenKind::Question => {
                                self.lexer.next();
                                if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                                    // optional labeled element `label?: T`
                                    self.lexer.next();
                                    self.parse_type();
                                } else {
                                    // bare optional element `T?` — head is a type ref
                                    self.finish_consumed_type_reference(head);
                                }
                            }
                            _ => {
                                // bare element: head is a type reference; finish its
                                // qualified tail, type-args, and array/indexed postfix.
                                self.finish_consumed_type_reference(head);
                                // A tuple element may be a full conditional type whose
                                // subject is a generic reference, e.g.:
                                //   `Foo<A, B> extends infer X ? TrueBranch : FalseBranch`
                                // After `finish_consumed_type_reference` consumes `Foo<A,B>`,
                                // the `extends` keyword must be handled here — otherwise the
                                // next loop iteration sees it as a fresh ident and emits it
                                // as a bogus TypeRef.
                                self.parse_conditional_tail_if_present();
                            }
                        }
                    }
                }
                _ => self.parse_type(),
            }
        }
    }

    /// Finish a type reference whose head ident was already consumed (during
    /// tuple label disambiguation): emit the head, then consume its qualified
    /// `.Member` tail (head-only invariant — tails are not standalone refs),
    /// generic args, and array/indexed suffixes. Mirrors `parse_type_reference`
    /// + `parse_postfix_type` for an already-consumed head.
    fn finish_consumed_type_reference(&mut self, head: Token) {
        // Structured type parser (tuple-element head): inherit the enclosing
        // base position from `pos_stack`, same as `parse_type_reference`.
        // F2-2b: tuple elements are never union-retag candidates (the tuple
        // member itself returns `None` from `parse_primary_type`), so the
        // emitted index is deliberately unused.
        let _ = self.emit_type_ref(
            self.text_of(head.span).to_string(),
            head.span,
            self.current_type_pos(),
        );
        while matches!(self.lexer.peek().kind, TokenKind::Dot) {
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                self.lexer.next(); // qualified tail — not a standalone ref
            }
        }
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.parse_type_args();
        }
        while matches!(self.lexer.peek().kind, TokenKind::LBracket) {
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                self.lexer.next();
            } else {
                self.parse_type();
                if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                    self.lexer.next();
                }
            }
        }
    }

    /// Is the current token an `Ident` whose text is a type-operator keyword
    /// (`keyof`, `infer`, `readonly`, `typeof`)? Used so tuple element parsing
    /// does not misinterpret `infer X` or `keyof T` as a labeled element.
    fn peek_is_type_operator_kw(&mut self) -> bool {
        self.peek_ident_is("keyof")
            || self.peek_ident_is("infer")
            || self.peek_ident_is("readonly")
            || self.peek_ident_is("typeof")
    }

    /// Template-literal type `` `a-${T}-b` ``.
    ///
    /// Token stream for `` `p-${Foo}-s` ``:
    ///   `TemplateStart`  (covers `` `p-${ ``)
    ///   `Ident(Foo)`
    ///   `TemplateEnd`    (covers `}-s\``)
    ///
    /// Token stream for `` `${A}${B}` ``:
    ///   `TemplateStart`, `Ident(A)`, `TemplateMid`, `Ident(B)`, `TemplateEnd`
    ///
    /// The `}` that closes a `${…}` interpolation is consumed by the lexer's
    /// `lex_template_continuation` and never appears as `RBrace` in the stream.
    fn parse_template_literal_type(&mut self) {
        let start_tok = self.lexer.next(); // `TemplateStart`
                                           // The lexer (see `Lexer::start_template`) emits a NO-INTERPOLATION
                                           // template literal (`\`aa\``) as a SINGLE `TemplateStart` token whose
                                           // span includes the closing backtick. An INTERPOLATED template's
                                           // `TemplateStart` span ends at `${`, with a matching `TemplateMid`/
                                           // `TemplateEnd` to follow.
                                           //
                                           // If the consumed `TemplateStart` already ends at the closing
                                           // backtick, there is nothing more for this type to consume.
                                           // Returning here is critical: the loop below otherwise treats every
                                           // subsequent token (including caller-owned `]`, `,`, `}`) as
                                           // template body, looping forever — found via Scout's factory.ts
                                           // (bug #3, 2026-05-26): `const x: Record<K,string> = { a: \`aa\`,
                                           // b: \`bb\` }` chained through the body-walker mis-dispatch to
                                           // route `\`bb\`` here, which then consumed the rest of the file.
        let span = start_tok.span;
        let end = (span.start() + span.length()) as usize;
        let already_complete = end > 0 && end <= self.source.len() && self.source[end - 1] == b'`';
        if already_complete {
            return;
        }
        loop {
            match self.lexer.peek().kind {
                TokenKind::TemplateEnd => {
                    self.lexer.next();
                    return;
                }
                TokenKind::TemplateMid => {
                    self.lexer.next(); // body between two interpolations
                }
                TokenKind::Eof => return,
                _ => {
                    // Recurse into the interpolation expression as a type
                    // (emits TypeRef events for any Idents).
                    //
                    // Bug #4 (2026-05-26): `parse_type` is allowed to
                    // return WITHOUT consuming for a small set of
                    // caller-owned tokens (`RParen`, `RBracket`, `As`,
                    // `Eof` — see `parse_primary_type`). If we reach
                    // those tokens here — possible when callers up the
                    // chain mis-route a value-position template literal
                    // into the type parser, OR if the interpolation
                    // expression contains a comma-separated call-arg
                    // list whose closing `)` belongs to the *caller*
                    // (e.g. `\`${Math.max(p, 0)} bye\``: the `)` after
                    // `0` closes the call but is exactly the token
                    // `parse_primary_type` declines to consume) — this
                    // arm would loop forever. Snapshot the cursor
                    // position before/after the `parse_type` call; if
                    // nothing advanced, force a one-token consume so
                    // the outer loop always progresses.
                    let pos_before = self.lexer.peek().span.start();
                    self.parse_type();
                    let pos_after = self.lexer.peek().span.start();
                    if pos_after == pos_before {
                        // No forward progress. The caller-owned token
                        // (commonly `RParen` from an enclosing call,
                        // `RBracket` from an enclosing tuple, etc.)
                        // belongs to surrounding syntax — we don't
                        // know whose, so be conservative: consume one
                        // token to advance, then keep looking for the
                        // template's `TemplateMid`/`TemplateEnd`.
                        if matches!(self.lexer.peek().kind, TokenKind::Eof) {
                            return;
                        }
                        self.lexer.next();
                    }
                }
            }
        }
    }

    /// Method member `(args): T` or `<T>(args): T` inside an object/interface type.
    fn parse_method_member(&mut self) {
        self.push_type_param_scope();
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.skip_type_param_list_collecting_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            self.lexer.next();
            let _ = self.parse_param_list_emitting_type_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            self.parse_type();
        }
        self.pop_type_param_scope();
    }
}
