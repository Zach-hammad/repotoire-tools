use super::*;

impl<'a> Parser<'a> {
    pub(super) fn walk_balanced_braces_collecting_refs(&mut self) -> Result<u32, &'static str> {
        self.with_scope_checkpoint(|parser| {
            // This body walk participates in the shared reference-recursion
            // budget. If admission fails, consume the entire balanced body so
            // the caller still resumes at the correct grammar boundary.
            if !parser.enter_reference_recursion(ReferenceRecursionKind::Expression) {
                let mut depth: i32 = 1;
                let mut end_pos: u32 = 0;
                while depth > 0 {
                    let token = parser.lexer.next();
                    end_pos = token.span.start() + token.span.length();
                    match token.kind {
                        TokenKind::LBrace => depth += 1,
                        TokenKind::RBrace => depth -= 1,
                        TokenKind::Eof => return Err("unterminated balanced braces"),
                        _ => {}
                    }
                }
                return Ok(end_pos);
            }

            let result = parser.walk_balanced_braces_collecting_refs_inner();
            parser.leave_reference_recursion(ReferenceRecursionKind::Expression);
            result
        })
    }

    /// Run the admitted body state machine. The public entry point owns scope
    /// restoration and recursion-budget lifecycle.
    fn walk_balanced_braces_collecting_refs_inner(&mut self) -> Result<u32, &'static str> {
        self.predeclare_current_block_value_binders();
        // State machine over the previous "meaningful" token:
        //   * Just consumed `let` / `const` / `var` → next Ident is a binder.
        //     The `:` that follows that binder enters type position. Other `:`
        //     occurrences (object-literal property keys, ternary `a ? b : c`)
        //     stay in value position. Without this state, `return { value:
        //     helper() }` would mis-classify `helper` as a TypeRef.
        //   * Just consumed `.` → next Ident is a member access, not a top-level
        //     reference. Skip emission (don't pretend `obj.method` is a
        //     standalone ValueRef(method) — `method` lives on `obj` and the v0
        //     graph has no Property nodes for v1's class-bodies-opaque scope).
        //   * Otherwise → value context.
        //
        // This walker emits Call/ValueRef from value position; TypeRef only on
        // the binder-`:`-Ident path. Type annotations on parameters and return
        // types are handled by the dedicated parse_param_list_emitting_type_refs
        // and parse_return_type_emitting_refs, not by this body walker.
        let mut depth = 1;
        let mut last_end = 0u32;
        #[derive(Clone, Copy)]
        enum Mode {
            /// Plain value context.
            Value,
            /// Just saw `let`/`const`/`var`; the next Ident is a binder.
            ExpectingBinder,
            /// Just saw `let X` (or const/var). A `:` here is a type
            /// annotation, handled by delegating to the type-expression
            /// walker (not a distinct walker mode).
            AfterBinder,
            /// Just saw `.`; the next Ident is a member access — skip emission.
            AfterDot,
            /// Just saw `catch`; the next Ident (after an optional `(`) is the
            /// catch binding — record it as a value binder so later uses in the
            /// block are suppressed (else `catch (err) { ...err... }` leaks a
            /// phantom ValueRef(err)).
            ExpectingCatchBinder,
        }
        let mut mode = Mode::Value;
        // `in_decl_list`: tracks whether we're inside a `let`/`const`/`var`
        // declarator list. A comma at the body's outer level (between
        // declarators) then resets `mode` back to `ExpectingBinder` so the
        // *next* Ident is recognized as a new binder. Without this, every
        // declarator after the first in `let x = 1, y = 2;` is misread as
        // a value reference and the second binder leaks into later use
        // sites as phantom UnresolvedReference(Value).
        let mut in_decl_list = false;
        // One state slot owns every receiver spelling and chain transition.
        // A property consumes it exactly once; only a following `.`/`?.`
        // installs the next PropertyChain receiver.
        let mut member_access = MemberAccessState::default();
        // `at_object_key_position`: tracks whether the next Ident-then-`:`
        // is an object-literal property key. Set immediately after `{` and
        // after `,` at paren_depth==0 inside a brace. Reset on any other
        // token. When true and Ident-then-`:` is observed, the Ident
        // emission is suppressed so `return { value: helper() }` doesn't
        // leak `value` as a phantom ValueRef → UnresolvedReference.
        let mut at_object_key_position = false;
        let mut paren_depth: i32 = 0;
        // `prev_kind` tracks the most recently consumed token so we can tell
        // an object-literal `{` (value position) from a statement-block /
        // method-body `{`. A block/method body is the only `{` immediately
        // preceded by `)` (`if (c) {`, `run() {`, `get value() {`); an object
        // literal is never preceded by `)` (it follows `=`, `(`, `,`, `:`,
        // `return`, `=>`, …). Without this, the first statement inside a block
        // body (`{ helper(); }`) is wrongly treated as an object key and
        // suppressed.
        let mut prev_kind = TokenKind::Eof;
        let mut previous_bang_was_postfix = false;
        // v0.5 commit 3 — index of the most-recently emitted BindingEvent
        // for the in-progress declarator. The ExpectingBinder Ident arm
        // pushes a None-origin BindingEvent and stores its index here;
        // the Colon-AfterBinder + Eq-AfterBinder arms peek for
        // ExplicitType / Construction origins and call
        // `set_binding_origin(idx, ...)` to attach. Reset to None at
        // declarator terminators (Comma in decl-list, Semi, RBrace,
        // Eq-init completion) so a later iteration's Colon (e.g. an
        // object-literal `key:`) doesn't accidentally update the
        // previous declarator's origin.
        let mut pending_binding_idx: Option<usize> = None;
        let mut pending_binding_name: Option<String> = None;
        let mut pending_decl_is_const = false;
        let mut seen_new_keyword: bool = false;
        let mut pending_case_label = false;
        let mut colon_was_case_label = false;
        // v0.5 commit 2 — parallel stack of "is this LBrace a block?"
        // booleans, synchronized with `depth`'s nested LBrace tracking
        // inside this walker. The depth-1 outer `{` was consumed by
        // the caller (and its scope is owned by the caller via
        // push_value_scope), so this stack starts empty. Every nested
        // LBrace processed by THIS walker pushes a bool — true for a
        // statement-position block (the LBrace AND a new lexical
        // scope), false for an object literal `{`. The matching
        // RBrace pops the bool; a true pop pops a scope. Covers
        // block-statement `{`, for/while/if/catch body `{`, and
        // try/finally body `{` — all the control-flow-body shapes
        // the plan-doc lists for commit 2.
        let mut block_brace_stack: Vec<bool> = Vec::new();
        let mut object_literal_nonbrace_depths: Vec<Option<i32>> = Vec::new();
        loop {
            if depth == 0 {
                break;
            }
            let t = self.lexer.peek().clone();
            let cur_kind = t.kind;
            let preceding_bang_was_postfix = previous_bang_was_postfix;
            previous_bang_was_postfix = false;
            let had_lt_before = self.lexer.had_line_terminator();
            let at_statement_start = Self::body_statement_boundary(prev_kind)
                || (paren_depth == 0
                    && had_lt_before
                    && Self::token_can_end_expression_statement(prev_kind));
            if !at_object_key_position
                && matches!(mode, Mode::Value)
                && at_statement_start
                && matches!(cur_kind, TokenKind::Ident)
                && self.try_parse_namespace_like_statement(t.span.start(), false)?
            {
                mode = Mode::Value;
                in_decl_list = false;
                pending_binding_idx = None;
                pending_binding_name = None;
                pending_decl_is_const = false;
                at_object_key_position = false;
                prev_kind = TokenKind::RBrace;
                if depth > 0 {
                    last_end = self.lexer.peek().span.start();
                }
                continue;
            }
            match t.kind {
                // After `.`/`?.`, keyword tokens are property identifiers,
                // even when they also start declarations or expressions.
                // Dispatch them before keyword-specific arms so `obj.class`,
                // `obj.function`, and `obj.const` complete the member access.
                kind if kind != TokenKind::Ident
                    && matches!(mode, Mode::AfterDot)
                    && Self::token_can_be_dot_property_identifier(kind) =>
                {
                    let member_tok = self.lexer.next();
                    let member_text = self.text_of(member_tok.span).to_string();
                    let member_end = member_tok.span.start() + member_tok.span.length();
                    self.complete_member_access(&mut member_access, member_text, member_end)?;
                    mode = Mode::Value;
                    at_object_key_position = false;
                    // Consume the complete member access before postfix syntax
                    // sees the preceding dot as an expression boundary.
                    prev_kind = TokenKind::Ident;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                // Arrow function in statement position (`arr.map((x: T) => x)`,
                // `const f = items.filter((i) => i.ok)`). The byte-level
                // lookahead confirms a matching `)` followed by `=>`, so plain
                // parenthesized groups and call-arg parens fall through to the
                // LParen arm below. Recognized here so member-access calls
                // (`obj.map(...)` — whose callee Ident was dropped as AfterDot
                // and thus never routed through walk_call_args) still capture
                // the arrow's binders and type annotations correctly.
                //
                // Also covers predicate-return arrows: `(value: any): value is T
                // => …` and `(x): asserts x is T => …`. These have a return-type
                // annotation between `)` and `=>`, so `looks_like_arrow_param_list`
                // (which requires `)` immediately before `=>`) returns false.
                // `paren_list_is_arrow_with_optional_return` tolerates the `: Ret`
                // gap and confirms the `=>` after the return type.
                TokenKind::LParen
                    if looks_like_arrow_param_list(self.lexer.source_after_cursor())
                        || paren_list_is_arrow_with_optional_return(
                            self.lexer.source_after_cursor(),
                        ) =>
                {
                    self.walk_arrow_function_collecting_refs()?;
                    mode = Mode::Value;
                    at_object_key_position = false;
                }
                TokenKind::Lt
                    if looks_like_generic_arrow_head(self.lexer.source_after_cursor()) =>
                {
                    self.push_type_param_scope();
                    self.skip_type_param_list_collecting_refs();
                    if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        self.walk_arrow_function_collecting_refs()?;
                    }
                    self.pop_type_param_scope();
                    mode = Mode::Value;
                    at_object_key_position = false;
                }
                // Object destructuring binder: `const { a, b: c, ...rest } = …`.
                // Intercept before the generic LBrace arm so we harvest names
                // instead of treating the pattern as a nested block/object literal.
                TokenKind::LBrace if matches!(mode, Mode::ExpectingBinder) => {
                    self.lexer.next(); // consume `{`
                    self.harvest_binding_pattern_names(true)?;
                    pending_binding_name = None;
                    mode = Mode::AfterBinder;
                    at_object_key_position = false;
                }
                TokenKind::LBrace => {
                    depth += 1;
                    mode = Mode::Value;
                    // External review #6 P1-A: a `{` is an object literal
                    // ONLY when the previous token introduces an expression
                    // (`= { ... }`, `( { ... } )`, `, { ... }`, `: { ... }`,
                    // `return { ... }`, `[ { ... } ]`, `? { ... } : ...`,
                    // `...{ ... }`, `&& { ... }`, etc.). Otherwise it's a
                    // statement block: bare `{ ... }`, body of `try` /
                    // `finally` / `else` / `do`, arrow-function body
                    // (`=> { ... }`), block after `;` or `}`, or the very
                    // first token of the body (`prev = Eof`).
                    //
                    // Pre-fix the rule was `!= RParen` which mis-classified
                    // every other statement-block as an object literal,
                    // silently losing refs inside via the key-position
                    // suppression machinery. The ext-review #5 P1-B fix
                    // (gating `Let|Const|Var` on `!at_object_key_position`)
                    // turned that latent classification bug into an active
                    // regression for `try { const local = … }`. This
                    // restores correctness at the root.
                    let colon_opens_object =
                        matches!(prev_kind, TokenKind::Colon) && !colon_was_case_label;
                    at_object_key_position = colon_opens_object
                        || Self::token_expects_expression_rhs(prev_kind)
                        || matches!(
                            prev_kind,
                            TokenKind::LParen
                                | TokenKind::Comma
                                | TokenKind::Return
                                | TokenKind::LBracket
                                | TokenKind::Question
                                | TokenKind::Spread
                                | TokenKind::AmpAmp
                                | TokenKind::PipePipe
                                | TokenKind::QuestionQuestion
                                | TokenKind::Throw
                                | TokenKind::Yield
                                | TokenKind::Await
                                | TokenKind::Of
                                | TokenKind::In
                                | TokenKind::Instanceof
                                | TokenKind::Typeof
                                | TokenKind::Void
                                | TokenKind::Delete
                                | TokenKind::New
                                | TokenKind::Bang
                        );
                    colon_was_case_label = false;
                    // v0.5 commit 2 — push a lexical scope for any
                    // statement-position block (`{ … }`, control-flow
                    // body, try/catch/finally body). Object-literal
                    // `{` does NOT introduce a lexical scope. The
                    // parallel `block_brace_stack` records the
                    // classification so the matching RBrace can pop
                    // the right number of scopes.
                    let is_block = !at_object_key_position;
                    object_literal_nonbrace_depths
                        .push(at_object_key_position.then_some(paren_depth));
                    block_brace_stack.push(is_block);
                    if is_block {
                        self.push_scope(self.current_owner());
                    }
                    self.lexer.next();
                    if is_block {
                        self.predeclare_current_block_value_binders();
                    }
                }
                TokenKind::RBrace => {
                    depth -= 1;
                    let rt = self.lexer.next();
                    last_end = rt.span.start() + rt.span.length();
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    pending_decl_is_const = false;
                    at_object_key_position = false;
                    // v0.5 commit 2 — pop the matching entry on the
                    // block stack. The walker may exit via the
                    // depth==0 break at the top of the loop before
                    // this RBrace arm fires for the outermost `}`,
                    // but every nested LBrace pushed here is matched
                    // by a nested RBrace consumed here, so the stack
                    // balances. A defensive `if Some(true)` lets a
                    // stray closer (depth>0 underflow guards above
                    // mean we still execute this arm) pop cleanly
                    // without an unwrap panic.
                    if let Some(was_block) = block_brace_stack.pop() {
                        if was_block {
                            self.pop_scope();
                        }
                    }
                    object_literal_nonbrace_depths.pop();
                }
                // Array destructuring binder: `const [a, b] = …`.
                // Intercept before the generic LBracket arm.
                //
                // Without this explicit arm, `[` bumps paren_depth and mode stays
                // ExpectingBinder; after `]` closes, mode is never transitioned to
                // AfterBinder — so the `=` that follows hits the wrong arm and
                // walk_expression_collecting_refs is never called, silently dropping
                // all value refs inside the initializer expression. This arm is a
                // correctness fix for initializer-ref loss, not cosmetic.
                TokenKind::LBracket if matches!(mode, Mode::ExpectingBinder) => {
                    self.lexer.next(); // consume `[`
                    self.harvest_binding_pattern_names(false)?;
                    pending_binding_name = None;
                    mode = Mode::AfterBinder;
                    at_object_key_position = false;
                }
                // Computed-key method shorthand: `{ [Symbol.iterator](): Iter { … } }`
                // and computed-key property: `{ [makeKey()]: value }`. At key
                // position, the `[…]` content is a RUNTIME EXPRESSION (per
                // ECMA-262 §13.2.5 ComputedPropertyName) — must be walked
                // for refs, not balance-skipped. Pre-fix this was a silent
                // dependency-loss bug (external review P1-A): `{ [makeKey()]:
                // helper() }` lost the `makeKey` call without diagnostic.
                TokenKind::LBracket if at_object_key_position => {
                    self.lexer.next(); // consume `[`
                                       // Walk the key expression for refs. The expression walker
                                       // stops at `]` (its outer-delimiter). If it stops short
                                       // due to malformed input, the explicit RBracket consume
                                       // below moves the cursor past the bracket to keep the
                                       // outer loop progressing.
                    self.walk_expression_collecting_refs()?;
                    if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                        self.lexer.next();
                    }
                    // Now at the token after `]`. If `(` or `<`, this is a computed-key
                    // method — route through the scoped method-header parser.
                    if matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt) {
                        let _ = self.walk_object_method_shorthand_collecting_refs()?;
                        mode = Mode::Value;
                    }
                    at_object_key_position = false;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                }
                TokenKind::LParen | TokenKind::LBracket => {
                    paren_depth += 1;
                    at_object_key_position = false;
                    self.lexer.next();
                }
                TokenKind::RParen | TokenKind::RBracket => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    at_object_key_position = false;
                    self.lexer.next();
                }
                TokenKind::Async
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start
                        && self.current_token_starts_named_function_decl(true) =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    self.lexer.next(); // consume `async`; parse_function_decl starts at `function`
                    if let Err(reason) =
                        self.parse_function_decl(decl_start, false, Some(local_scope))
                    {
                        self.recover(reason, t.span);
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                // Statement-leading `export` inside a namespace / `declare`
                // body (`namespace X { … }`, `declare namespace X { … }`,
                // `declare global { … }`): consume the `export` modifier and
                // present the following declaration at statement-start so the
                // existing decl arms below dispatch it. Without this,
                // `export function`/`export interface`/`export class`/`export
                // enum` fall through to the value walk and leak phantom
                // ValueRefs (Hono adapter/deno/deno.d.ts). `export` is invalid
                // inside ordinary function bodies, so skipping it there is a
                // harmless no-op. `prev_kind = RBrace` keeps `at_statement_start`
                // true for the next iteration (re-export forms `export {…}` /
                // `export *` are walked as before).
                TokenKind::Export
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start =>
                {
                    self.lexer.next(); // consume `export`
                    if self.skip_namespace_body_named_export_statement() {
                        mode = Mode::Value;
                        in_decl_list = false;
                        at_object_key_position = false;
                        prev_kind = TokenKind::Semi;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Function
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start
                        && self.current_token_starts_named_function_decl(false) =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    if let Err(reason) =
                        self.parse_function_decl(decl_start, false, Some(local_scope))
                    {
                        self.recover(reason, t.span);
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Function if !at_object_key_position => {
                    self.walk_function_expression_collecting_refs()?;
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Ident
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start
                        && self.current_token_starts_abstract_class_decl() =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    self.lexer.next(); // consume contextual `abstract`
                    if let Err(reason) = self.parse_class_decl(decl_start, false, Some(local_scope))
                    {
                        self.recover(reason, t.span);
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Class
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start
                        && self.current_token_starts_named_class_decl() =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    if let Err(reason) = self.parse_class_decl(decl_start, false, Some(local_scope))
                    {
                        self.recover(reason, t.span);
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Class if !at_object_key_position => {
                    self.walk_class_expression_collecting_refs()?;
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Enum
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    self.parse_enum_decl(decl_start, false, Some(local_scope))?;
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Const
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start
                        && self.current_token_starts_const_enum_decl() =>
                {
                    let decl_start = t.span.start();
                    let local_scope = self.current_scope();
                    self.lexer.next(); // consume `const`; parse_enum_decl starts at `enum`
                    self.parse_enum_decl(decl_start, false, Some(local_scope))?;
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    at_object_key_position = false;
                    prev_kind = TokenKind::RBrace;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                // External review #5 P1-B: gate on `!at_object_key_position`
                // so these tokens, when appearing as object-property keys
                // (e.g. `{ const(p): R { … } }`), fall through to the
                // key-position dispatch arm below. Without the gate, the
                // decl-mode setup here fires for the key and the method
                // signature leaks signature names + drops body refs.
                TokenKind::Let | TokenKind::Const | TokenKind::Var
                    if !at_object_key_position && paren_depth == 0 =>
                {
                    if let Err(reason) = self.parse_variable_decl(t.span.start(), false) {
                        self.recover(reason, t.span);
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    pending_decl_is_const = false;
                    member_access.discard();
                    prev_kind = TokenKind::Semi;
                    last_end = self.lexer.peek().span.start();
                    continue;
                }
                TokenKind::Let | TokenKind::Const | TokenKind::Var if !at_object_key_position => {
                    pending_decl_is_const = matches!(t.kind, TokenKind::Const);
                    pending_binding_name = None;
                    mode = Mode::ExpectingBinder;
                    in_decl_list = true;
                    self.lexer.next();
                }
                TokenKind::Interface
                    if !at_object_key_position
                        && matches!(mode, Mode::Value)
                        && at_statement_start =>
                {
                    self.lexer.next(); // consume `interface`
                    let next = self.lexer.peek().clone();
                    if next.kind == TokenKind::Ident {
                        let interface_name = self.text_of(next.span).to_string();
                        self.lexer.next(); // consume interface name
                        self.local_type_names.push(interface_name);
                        self.push_type_param_scope();
                        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
                            self.skip_type_param_list_collecting_refs();
                        }
                        let extends_tok = self.lexer.peek().clone();
                        if matches!(extends_tok.kind, TokenKind::Ident)
                            && self.text_of(extends_tok.span) == "extends"
                        {
                            self.lexer.next(); // consume `extends`
                            loop {
                                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                                    let h = self.parse_heritage_ref()?;
                                    // `interface X extends Base` heritage clause.
                                    // Not a type-param constraint (that is
                                    // `<T extends X>` -> ConstraintDecl); the
                                    // brief's mapping is silent on interface
                                    // heritage, so fail-open to `Other`.
                                    let _ = self.emit_type_ref(
                                        h.name,
                                        h.ref_span,
                                        TypeRefPosition::Other,
                                    );
                                    // Heritage generic args: type position -> Other.
                                    self.skip_type_args_collecting_refs_with_base(
                                        TypeRefPosition::Other,
                                    );
                                }
                                if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                                    self.lexer.next();
                                    continue;
                                }
                                break;
                            }
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                            self.lexer.next();
                            let _ = self.parse_interface_body_emitting_refs()?;
                        }
                        self.pop_type_param_scope();
                        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                            self.lexer.next();
                        }
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Catch if !at_object_key_position => {
                    // `catch (err)` / `catch (e: Foo)` / `catch {}`. The next
                    // Ident (after the optional `(`) is the catch binding; the
                    // LParen arm doesn't reset `mode`, so this survives the `(`.
                    // R5-P1-B: gate on key-position so `{ catch(): T { … } }`
                    // routes through method-shorthand instead.
                    mode = Mode::ExpectingCatchBinder;
                    self.lexer.next();
                }
                TokenKind::Case | TokenKind::Default if !at_object_key_position => {
                    pending_case_label = true;
                    self.lexer.next();
                }
                TokenKind::Return if !at_object_key_position => {
                    self.lexer.next(); // consume `return`
                    let next_kind = self.lexer.peek().kind;
                    let had_lt = self.lexer.had_line_terminator();
                    let no_operand = matches!(
                        next_kind,
                        TokenKind::Semi | TokenKind::RBrace | TokenKind::Eof
                    );
                    let needs_expression_delegate = !had_lt
                        && !no_operand
                        && (matches!(next_kind, TokenKind::Function | TokenKind::Class)
                            || (matches!(next_kind, TokenKind::Async)
                                && next_keyword_is(self.lexer.source_after_cursor(), b"function"))
                            || (matches!(next_kind, TokenKind::Lt)
                                && looks_like_generic_arrow_head(
                                    self.lexer.source_after_cursor(),
                                )));
                    if needs_expression_delegate {
                        self.walk_expression_collecting_refs()?;
                        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                            self.lexer.next();
                        }
                    } else if (had_lt || no_operand)
                        && matches!(self.lexer.peek().kind, TokenKind::Semi)
                    {
                        self.lexer.next();
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    prev_kind = TokenKind::Return;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Break | TokenKind::Continue if !at_object_key_position => {
                    self.lexer.next(); // consume `break` / `continue`
                    let next_kind = self.lexer.peek().kind;
                    let had_lt = self.lexer.had_line_terminator();
                    if !had_lt && matches!(next_kind, TokenKind::Ident) {
                        self.lexer.next(); // optional label, not a value ref
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                        self.lexer.next();
                    }
                    mode = Mode::Value;
                    in_decl_list = false;
                    at_object_key_position = false;
                    prev_kind = TokenKind::Semi;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::QuestionDot => {
                    mode = match self.consume_optional_member_follower(&mut member_access)? {
                        OptionalMemberFollower::Complete => Mode::Value,
                        OptionalMemberFollower::PropertyIdentifier => Mode::AfterDot,
                    };
                    at_object_key_position = false;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Dot => {
                    // `.` or `?.` (optional chaining). Both signal a member
                    // access on the next Ident — suppress emission so
                    // `obj?.method()` doesn't fake a Call(method) event the
                    // resolver can't possibly map.
                    mode = Mode::AfterDot;
                    at_object_key_position = false;
                    self.lexer.next();
                }
                // v0.5 commit 4 Phase C — track `new` so the next
                // Ident's emission can be re-classified as a
                // `MemberReceiver::Constructed` receiver if `.`
                // follows the construction. The `new` is still
                // consumed here (mirrors the pre-commit-4 fall-
                // through to the catchall) so emit_ident_ref runs
                // on the class identifier in the next iteration
                // and the Call(C) event for `C(args)` fires as
                // usual.
                TokenKind::New if !at_object_key_position => {
                    seen_new_keyword = true;
                    self.lexer.next();
                }
                TokenKind::Colon if matches!(mode, Mode::AfterBinder) => {
                    // `let x: T` — enter type position. Delegate to the filtered
                    // type walker so `let x: { y: T } = ...` handles object types
                    // and key filtering correctly. The walker stops at `,`, `;`,
                    // or `=` at its own depth 0.
                    //
                    // If an `=` initializer follows immediately, KEEP
                    // `Mode::AfterBinder` so the Eq-AfterBinder arm below
                    // catches it and delegates the RHS through
                    // `walk_expression_collecting_refs`. Without this, the
                    // generic Eq fall-through arm consumes `=` silently, the
                    // body walker then walks the initializer's object literal
                    // INLINE while `in_decl_list` is still true; the next `,`
                    // is misread as a multi-declarator separator, the
                    // following property key is mis-bound, and its `:`-typed
                    // value routes through `parse_template_literal_type` —
                    // which, on a no-interpolation `\`v\`` (one
                    // `TemplateStart` token, no `TemplateEnd`), looped
                    // forever (bug #3, 2026-05-26). For `let x: T;` (no
                    // initializer) drop back to `Value` so `;`/`,`/Ident
                    // follow-ups stay on their existing paths.
                    self.lexer.next();
                    // v0.5 commit 3 — capture ExplicitType origin BEFORE
                    // delegating to the type-expression walker. A
                    // single-Ident type (`let x: Foo;` / `let x: Foo =
                    // …`) qualifies; generics, unions, intersections,
                    // and parenthesized types do not. Update the
                    // pending BindingEvent's origin so commit 5's
                    // scope-walk can resolve `x.m()` to `Foo.m`.
                    if let Some(idx) = pending_binding_idx {
                        if let Some(class_name) = self.peek_explicit_type_origin() {
                            self.set_binding_origin(
                                idx,
                                Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }),
                            );
                        }
                    }
                    self.parse_type_expr_emitting_refs();
                    if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                        mode = Mode::AfterBinder;
                        at_object_key_position = false;
                    } else {
                        mode = Mode::Value;
                        pending_binding_idx = None;
                        pending_binding_name = None;
                        at_object_key_position = false;
                        // `const x: T` with NO initializer is a complete
                        // declaration. If a new statement follows (not a `,`
                        // multi-declarator continuation, and not a `;` which the
                        // Semi arm already terminates), mark statement-end so the
                        // following declaration is recognized at statement-start
                        // (ASI). Without this, `const x: T` (no `;`) before a
                        // namespace-body `export function`/`interface`/etc. leaves
                        // prev_kind at the type annotation, the next decl is not
                        // at statement-start, and it gets value-walked (Hono
                        // adapter/deno/deno.d.ts ambient `export const`).
                        if !matches!(self.lexer.peek().kind, TokenKind::Comma | TokenKind::Semi) {
                            in_decl_list = false;
                            pending_decl_is_const = false;
                            prev_kind = TokenKind::RBrace;
                            if depth > 0 {
                                last_end = self.lexer.peek().span.start();
                            }
                            continue;
                        }
                    }
                }
                TokenKind::Colon => {
                    // Object-literal `key: value` separator, ternary `a : b`,
                    // switch-case label. After `:` we're in value-context for
                    // the entire RHS / branch; the next Ident is NOT a key.
                    self.lexer.next();
                    mode = Mode::Value;
                    at_object_key_position = false;
                    colon_was_case_label = pending_case_label;
                    pending_case_label = false;
                }
                kind if !at_object_key_position
                    && matches!(mode, Mode::ExpectingBinder | Mode::ExpectingCatchBinder)
                    && Self::token_can_start_binding_identifier(kind) =>
                {
                    let binder_tok = self.lexer.next();
                    let binder_name = self.text_of(binder_tok.span).to_string();
                    self.note_value_binder(&binder_name);
                    let idx = self.emit_binding(binder_name.clone(), binder_tok.span, None);
                    pending_binding_idx = Some(idx);
                    pending_binding_name =
                        matches!(mode, Mode::ExpectingBinder).then_some(binder_name);
                    mode = Mode::AfterBinder;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                // TS type assertion: `value as Foo` / `value as const`. Same
                // delegation as the walk_expression sibling — the RHS is a
                // type expression, not a value. R5-P1-B: gate on
                // !at_object_key_position so `{ as(p): T { … } }` routes
                // through method-shorthand instead of consuming `as` as
                // a type-assertion operator on a non-existent LHS.
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, Mode::AfterDot)
                        && matches!(
                            self.next_token_kind_after_current(),
                            TokenKind::Dot | TokenKind::QuestionDot
                        ) =>
                {
                    let as_tok = self.lexer.next();
                    self.begin_member_access(
                        &mut member_access,
                        MemberReceiverSeed::Name {
                            name: self.text_of(as_tok.span).to_string(),
                            scope: self.current_scope(),
                        },
                        as_tok.span,
                    )?;
                    mode = Mode::Value;
                    prev_kind = TokenKind::Ident;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, Mode::AfterDot)
                        && !Self::token_can_end_expression_statement(prev_kind) =>
                {
                    self.lexer.next();
                    self.emit_ident_ref(t.span, /* in_type_pos */ false)?;
                    mode = Mode::Value;
                    prev_kind = TokenKind::Ident;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, Mode::AfterDot)
                        && Self::token_can_end_expression_statement(prev_kind) =>
                {
                    self.lexer.next();
                    // `x as T` type-assertion operand -> ValuePosition (brief).
                    self.parse_type_expr_with_base(TypeRefPosition::ValuePosition);
                    mode = Mode::Value;
                    // `x as T` completes an expression; let ASI stop before
                    // the next statement instead of treating `As` as the
                    // previous token.
                    prev_kind = TokenKind::Ident;
                    continue;
                }
                // Initializer after a binder: `let x = <expr>`. Delegate to
                // walk_expression so paren/brace nesting is handled correctly
                // (in particular, `let x = (a, b), y` — the inner comma is
                // a comma operator inside parens, not a declarator separator;
                // walk_expression's internal depth tracking keeps it from
                // mis-firing our `in_decl_list` Comma arm below).
                TokenKind::Eq if matches!(mode, Mode::AfterBinder) => {
                    self.lexer.next();
                    if pending_decl_is_const {
                        if let Some(name) = pending_binding_name.clone() {
                            self.note_const_string_initializer(&name);
                        }
                    }
                    // Iteration 22: arm the dynamic-import namespace-binding
                    // capture for a simple-identifier declarator. Set
                    // unconditionally (const/let/var); `emit_dynamic_import_call`
                    // filters on the initializer shape (`await import('literal')`
                    // directly, nothing wrapping/trailing it) and on non-escape,
                    // so a non-import or wrapped initializer (`= 5`,
                    // `= wrap(import('x'))`) never binds. Cleared right after the
                    // initializer walk so it cannot leak to a sibling declarator.
                    if let Some(name) = pending_binding_name.clone() {
                        let init_start = self.lexer.peek().span.start();
                        self.pending_dynamic_import_binder = Some((name, init_start));
                    }
                    // v0.5 commit 3 — capture Construction origin BEFORE
                    // walking the initializer. Only fires if the
                    // initializer is exactly `new Ident(...)`. The
                    // ExplicitType conflict rule wins automatically:
                    // `set_binding_origin` ignores a Construction
                    // update when ExplicitType is already set.
                    //
                    // v0.6 commit 3 — also captures FactoryReturn
                    // origin when the initializer is a Call-shaped
                    // expression on a plain Ident or qualified
                    // MemberAccess receiver. Same conflict-rule
                    // precedence applies via set_binding_origin.
                    // The Construction and FactoryReturn shapes are
                    // syntactically disjoint (`new` vs Ident) so the
                    // checks compose without ordering hazards.
                    if let Some(idx) = pending_binding_idx {
                        if let Some(class_name) = self.peek_construction_origin() {
                            self.set_binding_origin(
                                idx,
                                Some(crate::ts::events::ClassOrigin::Construction { class_name }),
                            );
                        } else if let Some(factory_ref) = self.peek_factory_return_origin() {
                            self.set_binding_origin(
                                idx,
                                Some(crate::ts::events::ClassOrigin::FactoryReturn { factory_ref }),
                            );
                        }
                    }
                    let initializer_result = self.walk_expression_collecting_refs();
                    // The initializer owns this one-shot capture. Clear it
                    // before propagating either success or failure so parser
                    // recovery cannot expose it to a later `import()`.
                    self.pending_dynamic_import_binder = None;
                    initializer_result?;
                    mode = Mode::Value;
                    // The declarator's init is fully consumed; reset
                    // the pending-binding tracker so an unrelated
                    // later Colon/Eq doesn't update this binding.
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    // `walk_expression_collecting_refs` stops at `,` or `;`
                    // at its own depth 0, OR at a statement-starting keyword
                    // via the ASI break (added 2026-05-26, commit 5a5d744).
                    // If it terminated on anything OTHER than `,`, the
                    // declarator chain for THIS decl is done — reset
                    // `in_decl_list` so the body-walker's `Comma if
                    // in_decl_list` arm doesn't later fire on a property
                    // comma inside an unrelated object literal (e.g. a
                    // return-statement two `if`s away), poisoning that
                    // object's key/value classification.
                    //
                    // Bug #4 root cause (2026-05-26 — found in Scout's
                    // src/features/dealer/competitive-contracts.ts): a
                    // `const u = … as const` (no terminating `;`) left
                    // `in_decl_list = true`; the body walker then
                    // traversed `if (u === 'a') { return { u, r: \`…\` } }`
                    // and at the comma after `u` inside the return object
                    // fired the in_decl_list-comma arm, mis-bound `r` as
                    // a local, sent its `:` through Colon-AfterBinder,
                    // and routed the template-literal property value into
                    // `parse_template_literal_type` — which then looped
                    // forever on `parse_type` failing to consume the
                    // caller-owned `)` inside `${Math.max(p, 0)}`.
                    //
                    // `,` is the only legal follow-up that continues the
                    // declarator chain (multi-declarator: `let x = 1, y =
                    // 2`); everything else (`;`, EOF, or an ASI'd
                    // statement-starter) terminates the chain.
                    let continues_decl_list = matches!(self.lexer.peek().kind, TokenKind::Comma);
                    if !continues_decl_list {
                        in_decl_list = false;
                        pending_decl_is_const = false;
                    }
                    if self.current_token_starts_label_statement() {
                        prev_kind = TokenKind::Semi;
                        continue;
                    }
                    if !continues_decl_list && !matches!(self.lexer.peek().kind, TokenKind::Semi) {
                        prev_kind = TokenKind::Semi;
                        continue;
                    }
                }
                // Multi-declarator separator: at the body's outer level, a
                // `,` after a declarator's initializer re-enters
                // `ExpectingBinder` so the next Ident is a binder.
                //
                // **paren_depth <= 1 gate** (tightened 2026-06-14 via Hono
                // dogfood): statement-level decls leave `paren_depth == 0`,
                // while C-style `for (let i = 0, len = n; ...)` decls live at
                // the header's outer `paren_depth == 1`. Both need the
                // declarator-separator comma to re-enter binder mode so every
                // declarator binds. Nested commas inside initializer calls,
                // arrays, or parenthesized comma expressions are deeper and
                // still fall through.
                //
                // Original `paren_depth == 0` gate (added 2026-05-26 — found via
                // a Playwright test fixture that hung the parser
                // indefinitely on Scout):
                // a comma inside *nested* parens/brackets must NOT reset
                // mode to ExpectingBinder. Otherwise, given
                //   `for (const s of ['a', 'b']) { … }`,
                // the comma at byte 44 (inside the array literal) wrongly
                // sets `mode = ExpectingBinder` — and when the for-of
                // body's `{` arrives, the parser misdispatches via the
                // `Mode::ExpectingBinder` LBrace arm into
                // `harvest_binding_pattern_names`, swallowing the body
                // content AND mis-consuming the closing brace of the
                // surrounding arrow function (depth book-keeping goes
                // off-by-one). The outer caller then loops at the
                // unconsumed `}` and the parser hangs forever.
                //
                // `in_decl_list` is only meaningful at the declaration's
                // outer delimiter depth; anywhere deeper is some other comma
                // (array/object/call arg/type-args/etc.) and goes through the
                // catchall Comma arm below.
                TokenKind::Comma if in_decl_list && paren_depth <= 1 => {
                    mode = Mode::ExpectingBinder;
                    // v0.5 commit 3 — new declarator about to begin;
                    // clear the pending binding tracker so the next
                    // Ident's emit_binding produces a fresh index.
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    self.lexer.next();
                }
                // Statement terminator inside a decl list ends both the list
                // AND the declarator mode.
                TokenKind::Semi if in_decl_list => {
                    in_decl_list = false;
                    mode = Mode::Value;
                    at_object_key_position = false;
                    // v0.5 commit 3 — declarator chain done.
                    pending_binding_idx = None;
                    pending_binding_name = None;
                    pending_decl_is_const = false;
                    self.lexer.next();
                }
                // Comma inside an object literal at the body's brace level
                // (not inside nested parens / brackets) returns us to
                // key-position for the next entry.
                TokenKind::Comma
                    if object_literal_nonbrace_depths.last().copied().flatten()
                        == Some(paren_depth) =>
                {
                    at_object_key_position = true;
                    mode = Mode::Value;
                    self.lexer.next();
                }
                TokenKind::Eq | TokenKind::Semi | TokenKind::Comma => {
                    mode = Mode::Value;
                    at_object_key_position = false;
                    self.lexer.next();
                }
                // External review #4 P1-B: object-literal methods with
                // non-Ident keys (`"named"()`, `1()`, `delete()`) per
                // ES2015+ PropertyName. Pre-fix these fell to the catchall
                // and their signatures `(p: Param): Return { … }` were
                // walked as ordinary expressions, leaking `p`/`Param`/
                // `Return` as ValueRefs and losing the body's calls.
                // Mirrors the class-body widening from commit 3300013;
                // routes through the same `walk_object_method_shorthand`
                // path as Ident-named methods.
                // External review #5 P1-B: widened from the prior narrowed
                // list to the FULL ES2015 §13.2.5 PropertyName set including
                // `As`, `Const`, `Let`, `Var`, `Catch`. The earlier arms for
                // those tokens are now gated on `!at_object_key_position`
                // so this arm claims them when they appear as object keys.
                // (Walker 2's `Function`/`Async` arms are gated the same way.)
                // Dynamic import in expression position (`await import('x')`):
                // claim the `import` keyword when it's NOT an object key and
                // emit the import edge for a literal specifier.
                TokenKind::Import if !at_object_key_position => {
                    let import_span = t.span;
                    self.lexer.next(); // consume `import`
                    let consumed_call = if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        let end = self.emit_dynamic_import_call(import_span)?;
                        last_end = end;
                        true
                    } else {
                        false
                    };
                    mode = Mode::Value;
                    at_object_key_position = false;
                    prev_kind = if consumed_call {
                        TokenKind::RParen
                    } else {
                        TokenKind::Import
                    };
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::TemplateStart => {
                    self.walk_template_literal_expr_collecting_refs()?;
                    mode = Mode::Value;
                    at_object_key_position = false;
                    prev_kind = TokenKind::TemplateEnd;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                TokenKind::Str
                | TokenKind::Number
                | TokenKind::Import
                | TokenKind::Export
                | TokenKind::From
                | TokenKind::As
                | TokenKind::Type
                | TokenKind::Interface
                | TokenKind::Class
                | TokenKind::Enum
                | TokenKind::Const
                | TokenKind::Let
                | TokenKind::Var
                | TokenKind::If
                | TokenKind::Else
                | TokenKind::For
                | TokenKind::While
                | TokenKind::Do
                | TokenKind::Switch
                | TokenKind::Case
                | TokenKind::Default
                | TokenKind::Return
                | TokenKind::Break
                | TokenKind::Continue
                | TokenKind::Throw
                | TokenKind::Try
                | TokenKind::Catch
                | TokenKind::Finally
                | TokenKind::New
                | TokenKind::Typeof
                | TokenKind::In
                | TokenKind::Of
                | TokenKind::Instanceof
                | TokenKind::Void
                | TokenKind::Delete
                | TokenKind::Yield
                | TokenKind::Await
                    if at_object_key_position =>
                {
                    self.lexer.next(); // consume the key token
                    at_object_key_position = false;
                    if matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt) {
                        let _ = self.walk_object_method_shorthand_collecting_refs()?;
                        mode = Mode::Value;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    // Non-method key (e.g. `{ "k": v }`, `{ 1: v }`) —
                    // key consumed; the outer loop will handle the `:`
                    // and the value side.
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                    continue;
                }
                // `using x = …` / `await using x = …` (TC39 explicit resource
                // management, known-v1-gaps #12). Treat the contextual `using`
                // keyword exactly like `let`/`const`/`var`: the next Ident is a
                // binder (noted, not emitted) and the `=` initializer is walked
                // normally. Gated on a `using [no LineTerminator] Ident`
                // lookahead so value uses (`using.dispose()`, `return using`,
                // `using()`) fall through to the ordinary Ident arm below.
                TokenKind::Ident
                    if !at_object_key_position && self.text_of(t.span) == "using" && {
                        let save = self.lexer.checkpoint();
                        self.lexer.next();
                        let next_kind = self.lexer.peek().kind;
                        let ok = !self.lexer.had_line_terminator()
                            && matches!(next_kind, TokenKind::Ident);
                        self.lexer.restore(save);
                        ok
                    } =>
                {
                    // Mirror the `Let | Const | Var` arm exactly.
                    pending_decl_is_const = false;
                    pending_binding_name = None;
                    mode = Mode::ExpectingBinder;
                    in_decl_list = true;
                    self.lexer.next(); // consume `using`
                }
                TokenKind::Ident => {
                    // `satisfies` (contextual keyword): same dispatch as the
                    // expression walker — consume + delegate RHS to the
                    // filtered type walker. Without this, `x satisfies Foo`
                    // inside a function body would emit phantom
                    // ValueRef(satisfies) and ValueRef(Foo).
                    if matches!(mode, Mode::Value) && self.text_of(t.span) == "satisfies" {
                        self.lexer.next();
                        // `x satisfies T` operand -> ValuePosition (brief).
                        self.parse_type_expr_with_base(TypeRefPosition::ValuePosition);
                        mode = Mode::Value;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    // Object-literal property keys: `{ value: helper() }`,
                    // method shorthand `{ run() {} }`, generic method
                    // `{ run<T>() {} }`, accessors `{ get x() {} }` /
                    // `{ set x(v) {} }`, and async methods `{ async f() {} }`
                    // ALL place an Ident at key position that must not leak
                    // as a phantom ValueRef / Call → UnresolvedReference.
                    //
                    // Shorthand `{ x, y }` desugars to `{ x: x, y: y }`, so
                    // the Ident there IS a real reference and must fall
                    // through to normal emission. Distinguished by the
                    // *next* token: `,` / `}` → shorthand (emit); `:` / `?`
                    // / `(` / `<` → key position (suppress).
                    let was_at_key = at_object_key_position;
                    at_object_key_position = false;
                    let ident_text = self.text_of(t.span).to_string();
                    self.lexer.next();
                    let next_kind = self.lexer.peek().kind;
                    if !was_at_key
                        && matches!(mode, Mode::Value)
                        && matches!(next_kind, TokenKind::Arrow)
                    {
                        self.walk_single_param_arrow_after_binder(t)?;
                        mode = Mode::Value;
                        in_decl_list = false;
                        pending_binding_idx = None;
                        pending_binding_name = None;
                        at_object_key_position = false;
                        prev_kind = TokenKind::RBrace;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    let at_statement_boundary = Self::body_statement_boundary(prev_kind)
                        || (matches!(prev_kind, TokenKind::Colon) && colon_was_case_label);
                    let at_asi_boundary =
                        had_lt_before && Self::token_can_end_expression_statement(prev_kind);
                    if !was_at_key
                        && matches!(mode, Mode::Value)
                        && paren_depth == 0
                        && (at_statement_boundary || at_asi_boundary)
                        && matches!(next_kind, TokenKind::Colon)
                    {
                        self.lexer.next(); // label colon
                        mode = Mode::Value;
                        in_decl_list = false;
                        pending_case_label = false;
                        colon_was_case_label = false;
                        prev_kind = TokenKind::Semi;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    if was_at_key {
                        // Accessor / async contextual keywords precede the
                        // real key: `get foo()`, `set foo(v)`, `async foo()`.
                        // The current Ident is a no-op contextual keyword;
                        // keep key position true so the *next* iteration
                        // suppresses the real key. (Star `*foo()` is
                        // handled implicitly because the catch-all arm
                        // consumes Star without resetting
                        // at_object_key_position.)
                        //
                        // External review #6 P1-B: the *next* token can be
                        // any valid PropertyName start per ES2015 §13.2.5:
                        // Ident, StringLiteral, NumericLiteral,
                        // ComputedPropertyName (`[`), or a reserved-word
                        // keyword used as a method name. Pre-fix only Ident
                        // was recognized; `get delete()`, `get "named"()`,
                        // `get [computed]()`, etc. leaked the `get` ident
                        // as a phantom value-ref and lost the body.
                        if matches!(ident_text.as_str(), "get" | "set" | "async")
                            && matches!(
                                next_kind,
                                TokenKind::Ident
                                    | TokenKind::Str
                                    | TokenKind::Number
                                    | TokenKind::LBracket
                                    | TokenKind::Import
                                    | TokenKind::Export
                                    | TokenKind::From
                                    | TokenKind::As
                                    | TokenKind::Type
                                    | TokenKind::Interface
                                    | TokenKind::Class
                                    | TokenKind::Enum
                                    | TokenKind::Function
                                    | TokenKind::Const
                                    | TokenKind::Let
                                    | TokenKind::Var
                                    | TokenKind::If
                                    | TokenKind::Else
                                    | TokenKind::For
                                    | TokenKind::While
                                    | TokenKind::Do
                                    | TokenKind::Switch
                                    | TokenKind::Case
                                    | TokenKind::Default
                                    | TokenKind::Return
                                    | TokenKind::Break
                                    | TokenKind::Continue
                                    | TokenKind::Throw
                                    | TokenKind::Try
                                    | TokenKind::Catch
                                    | TokenKind::Finally
                                    | TokenKind::New
                                    | TokenKind::Typeof
                                    | TokenKind::In
                                    | TokenKind::Of
                                    | TokenKind::Instanceof
                                    | TokenKind::Void
                                    | TokenKind::Delete
                                    | TokenKind::Yield
                                    | TokenKind::Async
                                    | TokenKind::Await
                            )
                        {
                            at_object_key_position = true;
                            if depth > 0 {
                                last_end = self.lexer.peek().span.start();
                            }
                            continue;
                        }
                        // Method shorthand: `{ on<Key>(type: Key) { body } }` or
                        // `{ items() { body } }`. Route through a scoped method-header
                        // parser so the generic type-param list, param type annotations,
                        // and return type are all handled in type-context (not
                        // value-context). Without this, `<Key extends keyof Events>` is
                        // token-walked in value mode and all the type tokens leak as
                        // phantom ValueRef → UnresolvedReference.
                        if matches!(next_kind, TokenKind::LParen | TokenKind::Lt) {
                            let decl_start = t.span.start();
                            let body_span = self.walk_object_method_shorthand_collecting_refs()?;
                            let decl_end = self.lexer.peek().span.start();
                            self.record_service_member(
                                ident_text.clone(),
                                t.span,
                                Span::new(decl_start, decl_end - decl_start),
                                body_span,
                                crate::ts::events::MemberKind::Method,
                            );
                            mode = Mode::Value;
                            at_object_key_position = false;
                            if depth > 0 {
                                last_end = self.lexer.peek().span.start();
                            }
                            continue;
                        }
                        // Plain property key (`key:`, `key?`) — suppress key emission
                        // and fall back to normal value-walking for the RHS.
                        if matches!(next_kind, TokenKind::Colon | TokenKind::Question) {
                            if self.object_property_value_is_function_like() {
                                self.record_service_member(
                                    ident_text.clone(),
                                    t.span,
                                    Span::new(t.span.start(), t.span.length()),
                                    Span::new(0, 0),
                                    crate::ts::events::MemberKind::Method,
                                );
                            }
                            if depth > 0 {
                                last_end = self.lexer.peek().span.start();
                            }
                            continue;
                        }
                        // Fall through: shorthand reference, emit normally.
                    }
                    match mode {
                        Mode::AfterDot => {
                            let member_end = t.span.start() + t.span.length();
                            self.complete_member_access(
                                &mut member_access,
                                ident_text,
                                member_end,
                            )?;
                            mode = Mode::Value;
                        }
                        Mode::ExpectingBinder => {
                            // Binder name (`let x` → x is a binder). Record it
                            // in the current value scope so later uses of `x`
                            // inside the same body are suppressed at emission
                            // (else we'd emit phantom ValueRef(x)).
                            // AfterBinder is set so a following `:` enters
                            // type position.
                            let binder_name = ident_text.clone();
                            self.note_value_binder(&binder_name);
                            // v0.5 commit 3 — emit a BindingEvent for this
                            // function-body binding. Origin starts as None;
                            // the Colon-AfterBinder + Eq-AfterBinder arms
                            // attach ExplicitType / Construction when they
                            // peek a matching shape. The returned index is
                            // tracked in `pending_binding_idx` so those
                            // arms know which BindingEvent to update.
                            let idx = self.emit_binding(binder_name, t.span, None);
                            pending_binding_idx = Some(idx);
                            pending_binding_name = Some(ident_text.clone());
                            mode = Mode::AfterBinder;
                        }
                        Mode::ExpectingCatchBinder => {
                            // `catch (err)` — bind err in the current value scope.
                            // AfterBinder so an optional `: Type` annotation
                            // (`catch (e: Foo)`) enters type position.
                            let binder_name = ident_text.clone();
                            self.note_value_binder(&binder_name);
                            // v0.5 commit 3 — emit a BindingEvent for the
                            // catch param. Origin defaults to None;
                            // `catch (e: Foo)` will attach ExplicitType
                            // via the same Colon-AfterBinder path the
                            // let/const flow uses, since mode transitions
                            // to AfterBinder right below.
                            let idx = self.emit_binding(binder_name, t.span, None);
                            pending_binding_idx = Some(idx);
                            pending_binding_name = None;
                            mode = Mode::AfterBinder;
                        }
                        Mode::Value | Mode::AfterBinder => {
                            // Snapshot the events length BEFORE
                            // `emit_ident_ref` so v0.5 commit 4
                            // Phase B can detect the "suppressed
                            // local binder" case (the Ident was a
                            // value scope hit so no event was
                            // emitted). That case wants the same
                            // receiver-capture treatment as a
                            // ValueRef receiver.
                            let events_len_before = self.events.len();
                            // v0.5 commit 4 Phase C — `new C(...)`
                            // emits a Call(C) event via emit_ident_ref
                            // below. We snapshot the seen_new flag
                            // here so the post-call check can detect
                            // the `new C().member` shape even though
                            // emit_ident_ref clears no flag.
                            let was_new = seen_new_keyword;
                            seen_new_keyword = false;
                            self.emit_ident_ref(t.span, /* in_type_pos */ false)?;
                            // Receiver capture for the upcoming
                            // AfterDot iteration. We capture when:
                            //   - emit_ident_ref emitted a ValueRef
                            //     (existing behavior — undefined
                            //     idents, class names, imports), OR
                            //   - emit_ident_ref suppressed the
                            //     event because the Ident is a known
                            //     local binder (v0.5 commit 4
                            //     Phase B — `x.foo()` where `x` is
                            //     `let x = …` / a param / etc.), OR
                            //   - we just emitted a Call event AND
                            //     the receiver was the result of a
                            //     `new C(args)` construction (Phase
                            //     C — Constructed receiver).
                            // We DO NOT capture when emit_ident_ref
                            // produced a Call WITHOUT a preceding
                            // `new` (`f().method()` — property chain
                            // out of v0.5 scope per goal-doc).
                            let emitted_value_ref = matches!(
                                self.events.last(),
                                Some(Event::Ref(RefEvent::ValueRef { .. }))
                            );
                            let suppressed_local_binder = self.events.len() == events_len_before;
                            let emitted_call = matches!(
                                self.events.last(),
                                Some(Event::Ref(RefEvent::Call { .. }))
                            );
                            let constructed_receiver = was_new && emitted_call;
                            let name_receiver = emitted_value_ref || suppressed_local_binder;
                            if constructed_receiver || name_receiver {
                                let seed = if constructed_receiver {
                                    MemberReceiverSeed::Constructed {
                                        class_name: ident_text.clone(),
                                    }
                                } else {
                                    MemberReceiverSeed::Name {
                                        name: ident_text.clone(),
                                        scope: self.current_scope(),
                                    }
                                };
                                self.begin_member_access(&mut member_access, seed, t.span)?;
                            }
                            mode = Mode::Value;
                        }
                    }
                }
                // Local type alias inside a function body: `type X = …`.
                // A `type` keyword in statement-leading position (Mode::Value)
                // followed by an Ident is always a local alias declaration.
                // We record the name (so the resolver can suppress External(Unknown)
                // for references to it) WITHOUT emitting a DeclEvent (which would
                // create a graph node and shift decl-count snapshots). After
                // consuming `type Ident`, we continue the walk normally so the RHS
                // (`= expr/type;`) is walked for any refs it contains.
                TokenKind::Type if matches!(mode, Mode::Value) => {
                    self.lexer.next(); // consume `type`
                    let next = self.lexer.peek().clone();
                    if next.kind == TokenKind::Ident {
                        let alias_name = self.text_of(next.span).to_string();
                        self.lexer.next(); // consume the Ident name
                        self.local_type_names.push(alias_name);
                        // Optional generic type-param list `<T, U>` on the alias:
                        // `type Foo<T> = …`. A SINGLE scope covers both the
                        // type-param list and the RHS so binders like `T` remain
                        // in scope during `parse_type_expr_emitting_refs` and are
                        // suppressed there. This mirrors `parse_type_alias_decl_body`
                        // (parser.rs:898-903) which uses one scope for the same reason.
                        self.push_type_param_scope(); // spans both the param list and the RHS
                        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
                            self.skip_type_param_list_collecting_refs();
                        }
                        // Consume `=` and route the RHS through the filtered type
                        // walker so `| Handler<Events[keyof Events]>` emits TypeRefs
                        // (not ValueRefs). Without this, the union RHS was consumed
                        // by the generic `Eq | Semi | Comma` arm (which just drops
                        // the `=` and continues in value mode), causing Handler /
                        // Events / keyof / WildcardHandler to leak as phantom
                        // ValueRef → UnresolvedReference diagnostics.
                        if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                            self.lexer.next(); // consume `=`
                            self.parse_type_expr_emitting_refs();
                        }
                        self.pop_type_param_scope(); // end of single scope
                                                     // Consume trailing `;` if present.
                        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                            self.lexer.next();
                        }
                        mode = Mode::Value;
                        in_decl_list = false;
                        prev_kind = TokenKind::Semi;
                        if depth > 0 {
                            last_end = self.lexer.peek().span.start();
                        }
                        continue;
                    }
                    // If next is NOT an Ident (shouldn't happen in valid TS inside
                    // a body, but be safe), just consumed `type` and continue.
                }
                // JSX in value/statement position (`return <Foo/>;`,
                // `const x = <Foo>…</Foo>`): skip the element as opaque so a
                // .tsx component's tag/prop names don't leak as ValueRefs.
                // Guard excludes comparisons (`a<b`) and generic calls
                // (`Foo.make<T>()` — the `<…>(` shape) per the expression walker.
                TokenKind::Lt if looks_like_jsx_element(self.lexer.source_after_cursor()) => {
                    self.skip_jsx_element();
                    mode = Mode::Value;
                    if depth > 0 {
                        last_end = self.lexer.peek().span.start();
                    }
                }
                TokenKind::Eof => return Err("unterminated brace"),
                TokenKind::Bang => {
                    previous_bang_was_postfix =
                        self.consume_expression_bang(prev_kind, preceding_bang_was_postfix);
                }
                _ => {
                    self.lexer.next();
                }
            }
            prev_kind = cur_kind;
            if depth > 0 {
                last_end = self.lexer.peek().span.start();
            }
        }
        Ok(last_end)
    }
}
