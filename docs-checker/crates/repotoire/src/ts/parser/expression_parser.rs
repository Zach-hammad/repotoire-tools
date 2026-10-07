//! TypeScript expression and runtime-reference grammar.

use super::*;

impl<'src> Parser<'src> {
    /// Classify a single Ident token at `ident_span` and emit the appropriate
    /// event. If the next token is `(`, this is a call expression — recurse via
    /// `walk_call_args_collecting_refs` to capture nested Call/ValueRef/TypeRef
    /// events inside the argument list (so `foo(bar(), baz)` produces
    /// `Call(foo, full_span)` AND `Call(bar, bar_span)` AND `ValueRef(baz)`).
    ///
    /// `in_type_pos` short-circuits to TypeRef; the type-position heuristic is
    /// computed by the caller's mode tracking.
    pub(super) fn emit_ident_ref(
        &mut self,
        ident_span: Span,
        in_type_pos: bool,
    ) -> Result<(), &'static str> {
        let name = self.text_of(ident_span).to_string();
        if in_type_pos {
            // Reached only from the value/expression token walker's
            // type-position heuristic: `x as T`, `x satisfies T`, and
            // expression-position generic arguments (`expectType<Words<''>>()`).
            // The brief maps all of these to `ValuePosition`.
            let _ = self.emit_type_ref(name, ident_span, TypeRefPosition::ValuePosition);
            return Ok(());
        }
        // CommonJS `require('./x')`: a string-literal specifier becomes an
        // import edge (resolved like any import). `require` is overwhelmingly
        // the CJS builtin; a user value named `require` followed by `(` is a
        // rare edge we accept. Non-literal `require(expr)` → diagnostic + args
        // walked (handled in the helper).
        if name == "require" && matches!(self.lexer.peek().kind, TokenKind::LParen) {
            let _ = self.emit_dynamic_import_call(ident_span)?;
            return Ok(());
        }
        // `require.resolve('./b')` (known-v1-gaps #14): the `.resolve` member
        // means the bare `require(StringLit)` recognizer above doesn't match,
        // so the specifier was dropped. `require.resolve` is the Node/TS
        // module-path resolver — its literal argument is a real module
        // specifier. Recognize the `require . resolve (` shape and route it
        // through the same import-edge emitter. Any other member
        // (`require.cache`, `require.main`) or a paren-less `require.resolve`
        // restores and falls through to ordinary handling.
        if name == "require" && matches!(self.lexer.peek().kind, TokenKind::Dot) {
            let saved = self.lexer.checkpoint();
            self.lexer.next(); // consume `.`
            let member = self.lexer.peek().clone();
            if matches!(member.kind, TokenKind::Ident) && self.text_of(member.span) == "resolve" {
                self.lexer.next(); // consume `resolve`
                if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                    let _ = self.emit_dynamic_import_call(ident_span)?;
                    return Ok(());
                }
            }
            self.lexer.restore(saved);
        }
        // NOTE: language built-ins (`this`/`Map`/`Promise`/…) are NO LONGER
        // suppressed here — they fall through and emit a Call/ValueRef like any
        // other name (the generic-call/LParen detection below still walks their
        // args). The resolver classifies them: a built-in that resolves to no
        // local/imported decl is dropped silently (see A5). This is what lets a
        // project that declares its OWN `Promise` keep the real edge.
        // Keep the reference until all declarations in this lexical scope
        // are known. Finalization suppresses bindings without graph identity
        // (parameters, catch bindings), preserving forward local references.
        // Generic call: `foo<T, U>(args)`. The shape is Ident `<` ... `>` `(`.
        // To distinguish from a comparison `foo < bar`, peek bytes ahead and
        // confirm a matching `>` exists at the right bracket depth AND is
        // followed by `(`. Only then consume `<...>` via the type-args
        // walker (which emits TypeRefs for inner Idents under the existing
        // filter). For a plain comparison (`if (a < b)`), the lookahead
        // returns false and we leave the `<` for the surrounding walker to
        // handle as an operator. Without this guard,
        // `skip_type_args_collecting_refs` would consume through EOF
        // searching for a matching `>` that doesn't exist.
        if matches!(self.lexer.peek().kind, TokenKind::Lt)
            && looks_like_generic_call_args(self.lexer.source_after_cursor())
        {
            self.skip_type_args_collecting_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            // Reserve the outer Call's event slot BEFORE recursing into the
            // argument list. Inner calls emitted from walk_call_args will
            // land at indexes > this one, giving us pre-order events
            // (outer-then-inner) which matches the resolver's iteration order
            // and the documented test expectation `["foo", "bar"]` for
            // `foo(bar())`. The slot's call_span is patched in after we know
            // the end position.
            let call_idx = self.events.len();
            let owner = self.current_owner();
            self.events.push(Event::Ref(RefEvent::Call {
                name: name.clone(),
                call_span: ident_span, // placeholder — overwritten below
                owner,
                scope: self.current_scope(),
                argument_anchors: Vec::new(), // placeholder — overwritten below
            }));
            // G1.6 fork (a): a second, independent, purely-syntactic scan of
            // this call's argument list for interior anchors (checkpoint/
            // restore, so it cannot desync the real walk below). Runs BEFORE
            // the real walk consumes the args, from the same `(` cursor.
            let argument_anchors = self.scan_call_argument_anchors();
            let end_pos = self.walk_call_args_collecting_refs()?;
            let full_span = Span::new(ident_span.start(), end_pos - ident_span.start());
            if let Event::Ref(RefEvent::Call {
                call_span,
                argument_anchors: aa,
                ..
            }) = &mut self.events[call_idx]
            {
                *call_span = full_span;
                *aa = argument_anchors;
            }
        } else {
            let owner = self.current_owner();
            self.events.push(Event::Ref(RefEvent::ValueRef {
                name,
                ref_span: ident_span,
                owner,
                scope: self.current_scope(),
            }));
        }
        Ok(())
    }

    /// Walk balanced parens starting at the current `(` peek, collecting
    /// nested refs along the way. Returns the byte offset immediately after
    /// the closing `)`. The caller has already consumed the callee identifier
    /// and uses the return value to compute the call expression's span.
    ///
    /// Recursion: an inner `name(args)` re-enters `emit_ident_ref` which calls
    /// this function again. Each nested call emits its own Call event with its
    /// own span; the outer call's span still covers everything via the
    /// returned end-position.
    pub(super) fn walk_call_args_collecting_refs(&mut self) -> Result<u32, &'static str> {
        // Walk each comma-separated argument as a full expression. Delegating
        // to walk_expression_collecting_refs (rather than running our own
        // flat paren-balance loop) gets us:
        //   * Member-access suppression for `foo(obj.method())` — without
        //     this, `obj.method()` inside an arg list would emit a phantom
        //     `Call(method)` because the flat walker didn't track Dot.
        //   * Arrow-function recognition for `items.map((item: Item) => ...)`
        //     — handled inside walk_expression's arrow-detection lookahead,
        //     which captures the `item` binder and emits TypeRef(Item) at
        //     the right place.
        //   * Optional chaining (`?.`), template literals, ternaries — all
        //     of walk_expression's existing mode handling applies inside
        //     call args too.
        //
        // walk_expression stops without consuming when it sees `,`, `;`, or a
        // depth-0 `)`. Our loop consumes the `,` and re-enters; the final
        // `)` is consumed here and its end-byte returned for the outer
        // call_span computation.
        self.lexer.next(); // consume `(`
                           // Break out of the loop with the closing `)`'s end byte — mirrors
                           // `recover()`'s loop-as-expression so there's no dead initial value
                           // to assign (the only read is at the `)` boundary, which produces it).
        let end_pos = loop {
            match self.lexer.peek().kind {
                TokenKind::RParen => {
                    let r = self.lexer.next();
                    break r.span.start() + r.span.length();
                }
                TokenKind::Comma => {
                    self.lexer.next();
                }
                TokenKind::Eof => return Err("unterminated call"),
                _ => {
                    let before = self.lexer.peek().span.start();
                    self.walk_expression_collecting_refs()?;
                    // Forward-progress guard. `walk_expression` stops WITHOUT
                    // consuming at `,`, `;`, or a depth-0 `)`. The `,` and `)`
                    // cases are handled by the arms above; a stray `;` (or any
                    // other token `walk_expression` declines to consume) would
                    // otherwise re-enter `walk_expression` at the same offset
                    // forever. Not hypothetical: a generic call whose
                    // type-argument list is a large inline object type
                    // (`React.forwardRef<{ a?: T; b?: U }>((p) => …)`) gets the
                    // object type's `;` separators value-walked into here, which
                    // spun ~5M re-entries on one 13 KB file. If the cursor did
                    // not advance, consume one token so the loop always
                    // terminates (best-effort recovery — subsequent args still
                    // walk; the real `)`/EOF still ends the list).
                    if self.lexer.peek().span.start() == before
                        && !matches!(self.lexer.peek().kind, TokenKind::Eof)
                    {
                        self.lexer.next();
                    }
                }
            }
        };
        Ok(end_pos)
    }

    // --- G1.6 fork (a): call-argument interior-anchor scan --------------
    //
    // A SECOND, independent, purely-syntactic pass over one call's argument
    // list (`self.lexer.checkpoint()`/`restore()` bracket it so it can never
    // desync the real walk in `walk_call_args_collecting_refs`). Generic over
    // every call: no type knowledge, no chain filtering — see
    // `CallArgumentAnchor`'s doc comment. Kept deliberately separate from the
    // real expression walker (rather than threading anchor capture through
    // it) because that walker's control flow is already dense with ASI/spin-
    // guard invariants that this feature must not risk perturbing.
    //
    // Every loop and every literal descent in this scan MUST route through
    // `AnchorScanGuard` (below) — see its doc comment for the two enforced
    // fail-safe properties and the review history that made them mandatory.

    /// Scan the call argument list starting at the current `(` (same
    /// precondition as `walk_call_args_collecting_refs`) for interior
    /// anchors, then restore the lexer to exactly where it started so the
    /// real walk proceeds unaffected.
    ///
    /// The lexer checkpoint includes diagnostic latches, so this speculative
    /// scan cannot publish an error that the authoritative walk never reaches.
    pub(super) fn scan_call_argument_anchors(&mut self) -> Vec<CallArgumentAnchor> {
        let checkpoint = self.lexer.checkpoint();
        let mut anchors = Vec::new();
        let mut guard = AnchorScanGuard::new();
        self.lexer.next(); // consume `(`
        let mut arg_index: u16 = 0;
        loop {
            match self.lexer.peek().kind {
                TokenKind::RParen | TokenKind::Eof => {
                    break;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                    arg_index = arg_index.saturating_add(1);
                }
                _ => {
                    let before = self.lexer.peek().span.start();
                    self.scan_argument_value_for_anchors(
                        arg_index,
                        "",
                        0,
                        &mut guard,
                        &mut anchors,
                    );
                    // Whatever the recursive scan did or didn't recognize, land
                    // exactly on the next depth-0 `,`/`)` boundary before the
                    // outer loop re-peeks.
                    self.skip_balanced_value();
                    if guard.stalled_bail(&mut self.lexer, before) {
                        break;
                    }
                }
            }
        }
        self.lexer.restore(checkpoint);
        anchors
    }

    /// Does the token at the current cursor start a function-expression or
    /// arrow-function literal? Pure lookahead — checkpoints/restores its own
    /// probing, never net-consumes. Reuses the existing byte-level arrow
    /// lookahead helpers (`looks_like_arrow_param_list`,
    /// `paren_list_is_arrow_with_optional_return`) for the parenthesized-
    /// params case, same detection the real expression walker uses.
    fn looks_like_callback_head(&mut self) -> bool {
        match self.lexer.peek().kind {
            TokenKind::Function => true,
            TokenKind::LParen => {
                looks_like_arrow_param_list(self.lexer.source_after_cursor())
                    || paren_list_is_arrow_with_optional_return(self.lexer.source_after_cursor())
            }
            TokenKind::Ident => {
                let cp = self.lexer.checkpoint();
                self.lexer.next();
                let next_is_arrow = matches!(self.lexer.peek().kind, TokenKind::Arrow);
                self.lexer.restore(cp);
                next_is_arrow
            }
            TokenKind::Async => {
                let cp = self.lexer.checkpoint();
                self.lexer.next(); // consume `async`
                let is_callback = match self.lexer.peek().kind {
                    TokenKind::Function => true,
                    TokenKind::LParen => {
                        looks_like_arrow_param_list(self.lexer.source_after_cursor())
                            || paren_list_is_arrow_with_optional_return(
                                self.lexer.source_after_cursor(),
                            )
                    }
                    TokenKind::Ident => {
                        let cp2 = self.lexer.checkpoint();
                        self.lexer.next();
                        let next_is_arrow = matches!(self.lexer.peek().kind, TokenKind::Arrow);
                        self.lexer.restore(cp2);
                        next_is_arrow
                    }
                    _ => false,
                };
                self.lexer.restore(cp);
                is_callback
            }
            _ => false,
        }
    }

    /// If the current cursor is a plain (non-computed) property key —
    /// `Ident` or a string literal — return its display name and span
    /// (quotes stripped for string keys) WITHOUT consuming any tokens.
    /// Computed keys (`[expr]`), numeric keys, and spreads are deliberately
    /// unclassified (`None`) — the caller falls back to a generic skip.
    fn peek_plain_object_key(&mut self) -> Option<(String, Span)> {
        match self.lexer.peek().kind {
            TokenKind::Ident => {
                let t = self.lexer.peek().clone();
                Some((self.text_of(t.span).to_string(), t.span))
            }
            TokenKind::Str => {
                let t = self.lexer.peek().clone();
                Some(self.read_str_literal(t))
            }
            _ => None,
        }
    }

    /// Recursively scan one argument's (or nested value's) literal structure
    /// for `CallArgumentAnchor`s.
    ///
    /// Returns `true` iff the value at the current cursor is ITSELF a
    /// callback, "directly" in the sense that only ARRAY layers were
    /// unwrapped to reach it (an array is transparent: `[cb]` and `[[cb]]`
    /// both read as "directly a callback" to whatever key holds them). An
    /// OBJECT layer is NOT transparent — recursing into a nested object
    /// always returns `false` to ITS caller regardless of what's inside,
    /// because only the DEEPEST key immediately enclosing a callback (via
    /// zero or more array layers) gets an `ObjectKey` anchor, carrying the
    /// FULL accumulated dotted path. This is what makes the ky-hooks shape
    /// `{ hooks: { beforeRetry: [cb] } }` yield exactly ONE `ObjectKey`
    /// (`beforeRetry`, path `"hooks.beforeRetry"`) rather than one at every
    /// ancestor key — `hooks` itself never qualifies, since its immediate
    /// value is another object, not a callback or array of callbacks.
    ///
    /// On return, the lexer is positioned exactly at the end of whatever
    /// this call fully consumed (a callback literal's head + body, an array
    /// literal, or an object literal); for anything it declines to classify
    /// it returns `false` WITHOUT consuming — the caller's
    /// `skip_balanced_value` takes over.
    fn scan_argument_value_for_anchors(
        &mut self,
        arg_index: u16,
        path: &str,
        depth: u32,
        guard: &mut AnchorScanGuard,
        anchors: &mut Vec<CallArgumentAnchor>,
    ) -> bool {
        if self.looks_like_callback_head() {
            let span = self.lexer.peek().span;
            anchors.push(CallArgumentAnchor::CallbackHead { arg_index, span });
            self.skip_balanced_value();
            return true;
        }
        match self.lexer.peek().kind {
            TokenKind::LBracket => {
                if !guard.try_descend() {
                    // TOTAL descent bound reached (see AnchorScanGuard):
                    // consume the array iteratively — NO recursion — and
                    // conservatively report "no callback found".
                    self.skip_balanced_value();
                    return false;
                }
                self.lexer.next(); // consume `[`
                let mut any_element_is_callback = false;
                loop {
                    let before = self.lexer.peek().span.start();
                    match self.lexer.peek().kind {
                        TokenKind::RBracket => {
                            self.lexer.next();
                            break;
                        }
                        TokenKind::Comma => {
                            self.lexer.next();
                        }
                        TokenKind::Eof => break,
                        _ => {
                            // Same path/depth as the array itself — arrays
                            // don't introduce a path segment and don't count
                            // against the SEMANTIC object-nesting depth bound
                            // (they do count against the guard's TOTAL
                            // descent bound, claimed above).
                            let element_is_callback = self.scan_argument_value_for_anchors(
                                arg_index, path, depth, guard, anchors,
                            );
                            any_element_is_callback |= element_is_callback;
                            self.skip_balanced_value();
                            if guard.stalled_bail(&mut self.lexer, before) {
                                break;
                            }
                        }
                    }
                }
                guard.ascend();
                any_element_is_callback
            }
            TokenKind::LBrace if depth < 4 => {
                if !guard.try_descend() {
                    // Same TOTAL-descent truncation as the array arm.
                    self.skip_balanced_value();
                    return false;
                }
                self.lexer.next(); // consume `{`
                loop {
                    let before = self.lexer.peek().span.start();
                    match self.lexer.peek().kind {
                        TokenKind::RBrace => {
                            self.lexer.next();
                            break;
                        }
                        TokenKind::Comma => {
                            self.lexer.next();
                        }
                        TokenKind::Eof => break,
                        _ => {
                            if let Some((key_name, key_span)) = self.peek_plain_object_key() {
                                self.lexer.next(); // consume the key token
                                let child_path = if path.is_empty() {
                                    key_name.clone()
                                } else {
                                    format!("{path}.{key_name}")
                                };
                                let value_is_callback =
                                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                                        self.lexer.next(); // consume `:`
                                        let value_is_callback = self
                                            .scan_argument_value_for_anchors(
                                                arg_index,
                                                &child_path,
                                                depth + 1,
                                                guard,
                                                anchors,
                                            );
                                        self.skip_balanced_value();
                                        value_is_callback
                                    } else if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                                        // Method-shorthand definition (`m(x) { ... }`)
                                        // — the method itself is the callback.
                                        anchors.push(CallArgumentAnchor::CallbackHead {
                                            arg_index,
                                            span: key_span,
                                        });
                                        self.skip_balanced_value();
                                        true
                                    } else {
                                        // Shorthand `{ cb }` — the value is a bare
                                        // variable reference, never a literal
                                        // callback (no binding knowledge here).
                                        false
                                    };
                                if value_is_callback {
                                    anchors.push(CallArgumentAnchor::ObjectKey {
                                        arg_index,
                                        name: key_name,
                                        span: key_span,
                                        path: child_path,
                                    });
                                }
                            } else {
                                // Computed key, spread, or numeric key —
                                // unclassified; skip this property generically.
                                self.skip_balanced_value();
                            }
                            if guard.stalled_bail(&mut self.lexer, before) {
                                break;
                            }
                        }
                    }
                }
                guard.ascend();
                // An object literal is never ITSELF "directly a callback" —
                // see the doc comment above for why this must be `false`
                // even when a descendant key qualified.
                false
            }
            TokenKind::LBrace => {
                // SEMANTIC depth bound reached (mirrors Pattern PC's
                // chain-depth discipline): truncate WITHOUT panicking. Still
                // consume the object so the caller's cursor stays correct;
                // conservatively report "no callback found" since we
                // declined to look.
                self.skip_balanced_value();
                false
            }
            _ => false,
        }
    }

    /// Dynamic import / CommonJS require: the callee (`import` keyword or
    /// `require` ident) is already consumed and the current peek is `(`. Emit
    /// a `RefEvent::Import` for a string-literal specifier (so it flows through
    /// the same resolver path as a static import — aliases included), or a
    /// diagnostic for a non-literal specifier. Either way, walk the remaining
    /// arguments to the matching `)` and return its end byte. NO `Call` event
    /// is emitted (the import edge replaces the fake `Call(import)`/`require`).
    pub(super) fn emit_dynamic_import_call(
        &mut self,
        callee_span: Span,
    ) -> Result<u32, &'static str> {
        self.lexer.next(); // consume `(`
        let mut emitted_import = false;
        // Iteration 22: for a direct-string-literal specifier, remember the
        // emitted `Import` event index + whether the specifier is relative, so
        // that after the argument list is walked we can (conditionally) attach a
        // NAMESPACE `ImportBinding` for a non-escaping `const m = await
        // import('<relative-literal>')` declarator local. `None` for the
        // const-string-alias / template / non-literal shapes — those keep the
        // module-level reachability hedge (honest over-attribution) unchanged.
        let mut dynamic_ns_candidate: Option<(usize, bool)> = None;
        if matches!(self.lexer.peek().kind, TokenKind::Str) {
            let spec_tok = self.lexer.next();
            let (specifier, specifier_span) = self.read_str_literal(spec_tok);
            let specifier_is_relative = specifier.starts_with("./") || specifier.starts_with("../");
            let event_idx = self.events.len();
            self.events.push(Event::Ref(RefEvent::Import {
                specifier,
                specifier_span,
                bindings: Vec::new(),
                is_type_only: false,
                makes_external_module: false,
            }));
            emitted_import = true;
            dynamic_ns_candidate = Some((event_idx, specifier_is_relative));
        } else if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let ident_tok = self.lexer.peek().clone();
            let name = self.text_of(ident_tok.span).to_string();
            if let Some(specifier) = self.const_string_in_scope(&name).map(str::to_string) {
                self.lexer.next();
                self.events.push(Event::Ref(RefEvent::Import {
                    specifier,
                    specifier_span: ident_tok.span,
                    bindings: Vec::new(),
                    is_type_only: false,
                    makes_external_module: false,
                }));
                emitted_import = true;
            }
        } else if matches!(self.lexer.peek().kind, TokenKind::TemplateStart) {
            let template_tok = self.lexer.peek().clone();
            if let Some((specifier, specifier_span)) =
                self.read_static_template_import_specifier(template_tok)
            {
                self.events.push(Event::Ref(RefEvent::Import {
                    specifier,
                    specifier_span,
                    bindings: Vec::new(),
                    is_type_only: false,
                    makes_external_module: false,
                }));
                emitted_import = true;
            }
        }
        if !emitted_import {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::UnsupportedConstruct {
                    construct: "dynamic import()/require() with non-literal specifier".to_string(),
                },
                file_path: self.path.clone(),
                span: callee_span,
            });
        }
        // Walk remaining args (and, in the non-literal case, the first arg) to
        // the closing `)` — capturing any inner refs (e.g. `import(dynVar)`).
        let end_pos = loop {
            match self.lexer.peek().kind {
                TokenKind::RParen => {
                    let r = self.lexer.next();
                    break r.span.start() + r.span.length();
                }
                TokenKind::Comma => {
                    self.lexer.next();
                }
                TokenKind::Eof => return Err("unterminated call"),
                _ => {
                    let before = self.lexer.peek().span.start();
                    self.walk_expression_collecting_refs()?;
                    // Forward-progress guard. `walk_expression` stops WITHOUT
                    // consuming at `,`, `;`, or a depth-0 `)`. The `,` and `)`
                    // cases are handled by the arms above; a stray `;` (or any
                    // other token `walk_expression` declines to consume) would
                    // otherwise re-enter `walk_expression` at the same offset
                    // forever. Not hypothetical: a generic call whose
                    // type-argument list is a large inline object type
                    // (`React.forwardRef<{ a?: T; b?: U }>((p) => …)`) gets the
                    // object type's `;` separators value-walked into here, which
                    // spun ~5M re-entries on one 13 KB file. If the cursor did
                    // not advance, consume one token so the loop always
                    // terminates (best-effort recovery — subsequent args still
                    // walk; the real `)`/EOF still ends the list).
                    if self.lexer.peek().span.start() == before
                        && !matches!(self.lexer.peek().kind, TokenKind::Eof)
                    {
                        self.lexer.next();
                    }
                }
            }
        };
        // Iteration 22: decide whether this dynamic import is the direct
        // `await import('<relative-literal>')` initializer of a simple
        // `let/const/var` declarator whose local never escapes — if so, attach
        // a NAMESPACE binding so `local.<export>()` resolves to the specific
        // export exactly like `import * as ns from '…'`. `take()` unconditionally
        // consumes the pending binder (even when we decline to bind) so a nested
        // or wrapped import (`= wrap(import('x'))`) can never be bound by a later
        // sibling. The lexer now sits immediately after the closing `)`, which is
        // exactly the precondition the escape scan needs.
        if let Some((event_idx, specifier_is_relative)) = dynamic_ns_candidate {
            if let Some((local, init_start)) = self.pending_dynamic_import_binder.take() {
                // A trailing `.`/`?.`/`as`/`(`/`[` means the import result is
                // further processed (`.then(…)`, `as Foo`, …) so the local is
                // NOT the module namespace — keep the hedge in that case.
                let value_continues = matches!(
                    self.lexer.peek().kind,
                    TokenKind::Dot
                        | TokenKind::QuestionDot
                        | TokenKind::As
                        | TokenKind::LParen
                        | TokenKind::LBracket
                );
                if specifier_is_relative
                    && !value_continues
                    && self
                        .dynamic_import_initializer_prefix_is_await(init_start, callee_span.start())
                    && !self.dynamic_import_binding_escapes(&local)
                {
                    if let Some(Event::Ref(RefEvent::Import { bindings, .. })) =
                        self.events.get_mut(event_idx)
                    {
                        bindings.push(ImportBinding {
                            local: local.clone(),
                            exported: local,
                            // Only consulted for an UNRESOLVED namespace
                            // (`NamespaceImportOpaque` diagnostic); a resolvable
                            // relative target never reads it, so the import
                            // keyword span is a safe, non-panicking placeholder.
                            local_span: callee_span,
                            kind: BindingKind::Namespace,
                            is_type_only: false,
                        });
                    }
                }
            }
        }
        Ok(end_pos)
    }

    /// Iteration 22: true iff the declarator initializer between `init_start`
    /// and the `import` keyword at `callee_start` is exactly the `await`
    /// keyword (modulo whitespace) — i.e. the initializer is directly
    /// `await import(...)`, not `wrap(import(...))`, `(await import(...))`, or a
    /// ternary. Requiring `await` also excludes `const m = import('x')` whose
    /// value is a `Promise`, not the module namespace.
    fn dynamic_import_initializer_prefix_is_await(
        &self,
        init_start: u32,
        callee_start: u32,
    ) -> bool {
        if callee_start < init_start {
            return false;
        }
        let prefix = self.text_of(Span::new(init_start, callee_start - init_start));
        prefix.trim() == "await"
    }

    /// Iteration 22 escape analysis. Precondition: the lexer sits immediately
    /// after a dynamic import's closing `)`. Bounded forward scan
    /// (`checkpoint`/`restore` bracket it so it can never desync the real walk)
    /// over the remainder of the enclosing block. Returns `true` if `local` is
    /// ever referenced in ANY position other than a `local.<member>` /
    /// `local?.<member>` access (call argument, return, reassignment,
    /// destructuring RHS, index/computed access, spread, whole-object use, …).
    /// A `true` verdict is the honest fail-safe: the caller keeps the
    /// module-level reachability hedge instead of claiming a precise export.
    /// Any structural surprise (unbalanced close at scan depth 0) or the spin
    /// budget resolves to `true` — never silently to a precise (over-narrow)
    /// claim.
    fn dynamic_import_binding_escapes(&mut self, local: &str) -> bool {
        let checkpoint = self.lexer.checkpoint();
        let mut depth: i32 = 0;
        let mut prev_was_dot = false;
        let mut escaped = false;
        let mut budget: u32 = 200_000;
        loop {
            if budget == 0 {
                escaped = true;
                break;
            }
            budget -= 1;
            let tok = self.lexer.peek().clone();
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::LBrace | TokenKind::LParen | TokenKind::LBracket => {
                    depth += 1;
                    self.lexer.next();
                    prev_was_dot = false;
                }
                TokenKind::RBrace => {
                    if depth == 0 {
                        break; // closing brace of the block the binding lives in
                    }
                    depth -= 1;
                    self.lexer.next();
                    prev_was_dot = false;
                }
                TokenKind::RParen | TokenKind::RBracket => {
                    if depth == 0 {
                        // Unbalanced close at scan depth 0: the initializer was
                        // nested in a paren/call/array we did not model. Be
                        // conservative rather than claim precision.
                        escaped = true;
                        break;
                    }
                    depth -= 1;
                    self.lexer.next();
                    prev_was_dot = false;
                }
                TokenKind::Ident => {
                    let is_local = self.text_of(tok.span) == local;
                    self.lexer.next();
                    if is_local && !prev_was_dot {
                        // A primary reference to the binding. Non-escaping ONLY
                        // when it is the receiver of a member access.
                        if !matches!(
                            self.lexer.peek().kind,
                            TokenKind::Dot | TokenKind::QuestionDot
                        ) {
                            escaped = true;
                            break;
                        }
                    }
                    prev_was_dot = false;
                }
                TokenKind::Dot | TokenKind::QuestionDot => {
                    self.lexer.next();
                    prev_was_dot = true;
                }
                _ => {
                    self.lexer.next();
                    prev_was_dot = false;
                }
            }
        }
        self.lexer.restore(checkpoint);
        escaped
    }

    /// Roll back a failed member and return the current EOF source endpoint.
    fn recover_failed_class_member(
        &mut self,
        checkpoint: super::DeclarationCheckpoint,
        scope_checkpoint: super::ScopeCheckpoint,
        context: &'static str,
        span: Span,
    ) -> Result<u32, &'static str> {
        self.rollback_declaration(checkpoint);
        self.restore_scope_checkpoint(scope_checkpoint);
        if !matches!(self.lexer.peek().kind, TokenKind::Eof) {
            return Err(context);
        }
        self.diagnostics.push(Diagnostic {
            kind: DiagnosticKind::SyntaxRecovered {
                context: context.to_string(),
            },
            file_path: self.path.clone(),
            span,
        });
        Ok(self.lexer.peek().span.start())
    }

    /// Reserve named class members before walking their signatures and bodies.
    /// This gives nested declarations and runtime references stable owners. An
    /// anonymous class expression has no class node and retains its outer owner.
    pub(super) fn walk_class_body_collecting_refs(
        &mut self,
        class_decl_index: Option<u32>,
    ) -> Result<u32, &'static str> {
        let mut depth = 1;
        let mut last_end = 0u32;
        let mut decorated_member_checkpoint = None;
        loop {
            if depth == 0 {
                break;
            }
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::LBrace => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    if depth == 1 {
                        if let Some((checkpoint, scope_checkpoint)) =
                            decorated_member_checkpoint.take()
                        {
                            self.rollback_declaration(checkpoint);
                            self.restore_scope_checkpoint(scope_checkpoint);
                            self.diagnostics.push(Diagnostic {
                                kind: DiagnosticKind::SyntaxRecovered {
                                    context: "missing decorated member".to_string(),
                                },
                                file_path: self.path.clone(),
                                span: t.span,
                            });
                        }
                    }
                    depth -= 1;
                    let rt = self.lexer.next();
                    last_end = rt.span.start() + rt.span.length();
                }
                TokenKind::At if depth == 1 => {
                    // Decorator references belong to the following member and
                    // must be discarded with it if that member fails.
                    if decorated_member_checkpoint.is_none() {
                        decorated_member_checkpoint =
                            Some((self.declaration_checkpoint(), self.scope_checkpoint()));
                    }
                    // Member-level decorators share the class-level decorator
                    // prefix scanner: `@Ident(.Member)*(args)?`, stacked, with
                    // call-argument refs captured before the decorated member is
                    // parsed by the next loop iteration.
                    self.parse_decorator_prefixes_collecting_refs()?;
                    continue;
                }
                // ClassElement member dispatch.
                //
                // ECMA-262 §15.7 ClassElement allows the member name to be:
                // * Ident (the original v1 case)
                // * StringLiteral (`"name"`)
                // * NumericLiteral (`1`, `0.5`)
                // * ComputedPropertyName (`[expr]`)
                // * Any reserved-word keyword (per ES2015+ §13.2.5 — `delete`,
                //   `throw`, `return`, etc. are all valid method names)
                //
                // Pre-external-review-P1-B this arm only matched `Ident`, so
                // every other name form silently lost its body/initializer
                // refs. The widened guard below handles all five categories;
                // the kind-specific name-consume step (match below) does
                // the right thing per form.
                _ if depth == 1
                    && matches!(
                        t.kind,
                        TokenKind::Ident
                            | TokenKind::LBracket
                            | TokenKind::Str
                            | TokenKind::Number
                            // Reserved-word names valid as ClassElement members
                            // per ES2015+. (`Class`/`Enum`/`Function`/`Interface`/
                            // `Type` are special — listing them too for symmetry
                            // since TS accepts them as method names.)
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
                    ) =>
                {
                    // Earliest start position covering any modifier
                    // prefix. `decl_span` uses this so the span for
                    // `static get foo()` begins at `static`, not at
                    // `foo`. Captured BEFORE the modifier scan
                    // shadows `t` below.
                    let decl_start = t.span.start();
                    let (member_checkpoint, member_scope_checkpoint) =
                        decorated_member_checkpoint.take().unwrap_or_else(|| {
                            (self.declaration_checkpoint(), self.scope_checkpoint())
                        });

                    // === MODIFIER SCAN (v0.5 commit 1) ===
                    // Recognize modifier prefixes:
                    //   - `static` / `get` / `set` → captured as flags
                    //     (drive `is_static` and `MemberKind`).
                    //   - `readonly` / `private` / `public` / `protected`
                    //     / `abstract` / `override` → read-and-skip
                    //     (not classified in v0.5).
                    // Subsumes the static-initializer-block path:
                    // `static { … }` emits an UnsupportedConstruct
                    // diagnostic and skips the body, then routes the
                    // outer class-body loop to the next iteration.
                    //
                    // Disambiguation: an Ident like `static` is committed
                    // as a modifier only when the following token suggests
                    // a member-name continues. If the next token is
                    // `(`/`=`/`:`/`;`/`?`/`!`/`<`/`,`/`}`, this Ident IS
                    // the member name (e.g., `static() {}` is a method
                    // named `static`).
                    let mut is_static = false;
                    let mut is_getter = false;
                    let mut is_setter = false;
                    let mut static_block_handled = false;
                    // v0.6 commit 2 — declared at the outer
                    // (per-member) scope so the static-method branch
                    // can fill it and the PendingMethod-push site
                    // (after the method/field branches close) can
                    // read it. Filled inside the method branch's
                    // Colon arm via `peek_plain_ident_return_class`;
                    // remains `None` for fields and for methods with
                    // no declared return type.
                    let mut captured_member_return_class: Option<String> = None;
                    // v0.7 commit 2 — declared at the outer per-
                    // member scope, filled inside the field branch's
                    // Colon arm via `peek_plain_ident_field_type_class`.
                    // Flows through to `PendingMethod.field_type_class`
                    // at the push site (only used downstream if
                    // `kind == Field`).
                    let mut captured_member_field_type_class: Option<String> = None;
                    loop {
                        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                            break;
                        }
                        let saved = self.lexer.checkpoint();
                        let mod_tok = self.lexer.next();
                        let mod_text = self.text_of(mod_tok.span).to_string();
                        let role: Option<u8> = match mod_text.as_str() {
                            "static" => Some(0),
                            "get" => Some(1),
                            "set" => Some(2),
                            "readonly" | "private" | "public" | "protected" | "abstract"
                            | "override" => Some(3),
                            _ => None,
                        };
                        if role.is_none() {
                            self.lexer.restore(saved);
                            break;
                        }
                        // `static { … }` static-initializer block.
                        if matches!(role, Some(0))
                            && matches!(self.lexer.peek().kind, TokenKind::LBrace)
                        {
                            let static_kw_span = mod_tok.span;
                            self.diagnostics.push(Diagnostic {
                                kind: DiagnosticKind::UnsupportedConstruct {
                                    construct: "static_block".to_string(),
                                },
                                file_path: self.path.clone(),
                                span: static_kw_span,
                            });
                            // known-v1-gaps #2 (full): walk the block body for
                            // refs instead of balance-skipping it. `collect_cf_body`
                            // (peek is at `{`) pushes a fresh value scope, consumes
                            // `{`, and drives the in-body ref collector to the
                            // matching `}`, so `static { initialize(); }` now yields
                            // `initialize`. The diagnostic above is retained: the
                            // block's init-execution semantics and any declarations
                            // inside remain unmodeled (mirrors member-decorator
                            // handling, which also walks refs while flagging the
                            // unmodeled aspect).
                            self.collect_cf_body()?;
                            static_block_handled = true;
                            break;
                        }
                        // Disambiguate: is this Ident really a modifier,
                        // or is it the member name itself?
                        let next_kind = self.lexer.peek().kind;
                        let is_member_terminator = matches!(
                            next_kind,
                            TokenKind::LParen
                                | TokenKind::Eq
                                | TokenKind::Colon
                                | TokenKind::Semi
                                | TokenKind::Comma
                                | TokenKind::RBrace
                                | TokenKind::Question
                                | TokenKind::Bang
                                | TokenKind::Lt
                        );
                        if is_member_terminator {
                            self.lexer.restore(saved);
                            break;
                        }
                        match role.unwrap() {
                            0 => is_static = true,
                            1 => is_getter = true,
                            2 => is_setter = true,
                            _ => {} // visibility / abstract / override / readonly
                        }
                    }
                    if static_block_handled {
                        continue;
                    }

                    // === MEMBER-NAME TOKEN ===
                    // After the modifier scan, peek is at the actual
                    // member-name token. Shadow `t` so the rest of the
                    // arm operates on the post-modifier state.
                    let t = self.lexer.peek().clone();

                    // Eligibility tracker — only plain Ident names and
                    // constant string-literal computed names
                    // (`['foo']` / `["foo"]`) emit a PendingMethod.
                    // Non-constant computed bracket expressions and
                    // raw Str/Number/keyword names continue to walk
                    // the body for refs but do not materialize a
                    // Property node, matching the pre-v0.5 surface.
                    let member_name: String;
                    let member_name_span: Span;
                    let emit_eligible: bool;
                    if matches!(t.kind, TokenKind::LBracket) {
                        let index_sig_save = self.lexer.checkpoint();
                        // Computed name. Try to extract a single
                        // string-literal key: `['foo']` / `["foo"]`.
                        self.lexer.next(); // consume `[`
                        let inside = self.lexer.peek().clone();
                        if matches!(inside.kind, TokenKind::Ident) {
                            self.lexer.next(); // index-signature binder name
                            if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                                self.lexer.next();
                                self.parse_type_expr_emitting_refs();
                                if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                                    self.lexer.next();
                                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                                        self.lexer.next();
                                        self.parse_type_expr_emitting_refs();
                                    }
                                    if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                                        self.lexer.next();
                                    }
                                    if depth > 0 {
                                        last_end = self.lexer.peek().span.start();
                                    }
                                    continue;
                                }
                            }
                            self.lexer.restore(index_sig_save);
                            self.lexer.next(); // consume `[` again for computed-name handling below
                        }
                        let mut extracted: Option<(String, Span)> = None;
                        if matches!(inside.kind, TokenKind::Str) {
                            let saved = self.lexer.checkpoint();
                            self.lexer.next(); // tentatively consume Str
                            if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                                let raw = self.text_of(inside.span);
                                let stripped = if raw.len() >= 2
                                    && (raw.starts_with('\'') || raw.starts_with('"'))
                                {
                                    raw[1..raw.len() - 1].to_string()
                                } else {
                                    raw.to_string()
                                };
                                extracted = Some((stripped, inside.span));
                            } else {
                                self.lexer.restore(saved);
                            }
                        }
                        if let Some((n, sp)) = extracted {
                            member_name = n;
                            member_name_span = sp;
                            emit_eligible = true;
                        } else {
                            // Non-constant bracket key — walk the
                            // expression for refs (preserves the
                            // `[makeKey()]()` → ValueRef(`makeKey`)
                            // behavior from v0.4).
                            self.walk_expression_collecting_refs()?;
                            member_name = String::new();
                            member_name_span = t.span;
                            emit_eligible = false;
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                            self.lexer.next();
                        }
                    } else {
                        // Plain Ident / Str / Number / keyword name.
                        // `#foo` is lexed as a single Ident token (see
                        // lexer.rs private-name handling); its text
                        // includes the leading `#`.
                        self.lexer.next();
                        member_name = self.text_of(t.span).to_string();
                        member_name_span = t.span;
                        emit_eligible = matches!(t.kind, TokenKind::Ident);
                    }
                    let is_constructor = emit_eligible && member_name == "constructor";
                    // Reserve the member before its signature and body can
                    // emit nested declarations. Class expressions have no
                    // class declaration identity and keep their outer owner.
                    let member_slot = if emit_eligible {
                        class_decl_index.map(|class_index| {
                            let event_index = self.events.len();
                            let index = self.push_decl(DeclEvent::Method {
                                name: member_name.clone(),
                                name_span: member_name_span,
                                decl_span: Span::new(decl_start, 0),
                                body_span: Span::new(decl_start, 0),
                                owner_class_decl_index: class_index,
                                is_static,
                                kind: crate::ts::events::MemberKind::Method,
                                return_class_name: None,
                                field_type_class: None,
                            });
                            self.push_owner(index);
                            event_index
                        })
                    } else {
                        None
                    };

                    // Method generics `<T, U extends Base>` open a
                    // nested type-param scope. Popped when the member
                    // finishes parsing below.
                    let opened_method_scope = matches!(self.lexer.peek().kind, TokenKind::Lt);
                    if opened_method_scope {
                        self.push_type_param_scope();
                        self.skip_type_param_list_collecting_refs();
                    }

                    // Parameter-property fields are emitted after their constructor.
                    let mut param_property_fields: Vec<PendingMethod> = Vec::new();

                    let is_field;
                    let body_span_out;
                    let decl_end_out: u32;

                    if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        is_field = false;
                        // Method/getter/setter header.
                        self.push_value_scope();
                        self.lexer.next(); // consume `(`
                        let mut paren_depth: i32 = 1;
                        let mut expecting_binder = true;
                        let mut pending_param_property = false;
                        // v0.5 commit 3 — pending BindingEvent for the
                        // in-progress param, attached with ExplicitType
                        // origin on the Colon arm below.
                        let mut pending_param_binding_idx: Option<usize> = None;
                        // v0.9 — pending index into `param_property_fields`
                        // for the most recently pushed param-property field
                        // awaiting its type annotation. Set after the push;
                        // consumed in the Colon arm to populate
                        // field_type_class; reset on Comma / RParen if no
                        // annotation was provided (untyped param-property
                        // → field_type_class stays None).
                        let mut pending_param_property_field_idx: Option<usize> = None;
                        while paren_depth > 0 {
                            let p = self.lexer.peek().clone();
                            match p.kind {
                                TokenKind::LParen => {
                                    paren_depth += 1;
                                    self.lexer.next();
                                }
                                TokenKind::RParen => {
                                    paren_depth -= 1;
                                    pending_param_binding_idx = None;
                                    pending_param_property_field_idx = None;
                                    self.lexer.next();
                                }
                                TokenKind::Comma if paren_depth == 1 => {
                                    expecting_binder = true;
                                    pending_param_property = false;
                                    pending_param_binding_idx = None;
                                    pending_param_property_field_idx = None;
                                    self.lexer.next();
                                }
                                // v0.10 — parameter-level decorator at the
                                // start of a constructor parameter
                                // (e.g. NestJS `@InjectRepository(IdeaEntity)
                                // private repo: Repository<IdeaEntity>`).
                                // Consume `@Ident(.Member)*(args)?` and
                                // continue the loop so the modifier scan +
                                // binder recognition follow normally.
                                // Mirrors the class-level decorator skip
                                // pattern (`parse_class_level_decorators`)
                                // and the class-body member-level skip.
                                // The decorator's call-arg refs are not walked
                                // here yet; parameter decorators still use the
                                // older balance-skip path. Stacked param
                                // decorators (`@A @B private svc`) re-enter
                                // this arm on the next iteration.
                                // The `expecting_binder` and
                                // `pending_param_*` state is intentionally
                                // unchanged — decorators are syntactic
                                // prefix only; the modifier + binder +
                                // type follow normally.
                                TokenKind::At if paren_depth == 1 && expecting_binder => {
                                    self.lexer.next(); // consume `@`
                                    if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                                        self.lexer.next(); // decorator base ident
                                                           // Optional `.foo.bar` member-access chain.
                                        while matches!(self.lexer.peek().kind, TokenKind::Dot) {
                                            self.lexer.next();
                                            if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                                                break;
                                            }
                                            self.lexer.next();
                                        }
                                        // Optional balanced call args `(...)`.
                                        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                                            self.lexer.next();
                                            let mut dec_paren_depth: i32 = 1;
                                            while dec_paren_depth > 0 {
                                                let tok = self.lexer.next();
                                                match tok.kind {
                                                    TokenKind::LParen => {
                                                        dec_paren_depth += 1;
                                                    }
                                                    TokenKind::RParen => {
                                                        dec_paren_depth -= 1;
                                                    }
                                                    TokenKind::Eof => {
                                                        return self.recover_failed_class_member(
                                                            member_checkpoint,
                                                            member_scope_checkpoint,
                                                            "unterminated param decorator",
                                                            t.span,
                                                        );
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                    // Unsupported shape (computed `@[expr]`,
                                    // non-Ident base) — fall through without
                                    // additional consumption. The catchall
                                    // arm cannot fire here because the `@`
                                    // is already consumed; the surrounding
                                    // loop continues with the next token.
                                }
                                TokenKind::Colon => {
                                    self.lexer.next();
                                    // v0.5 commit 3 — typed method param
                                    // (`m(x: C) {}`). Capture ExplicitType
                                    // origin before delegating to the
                                    // type-expression walker.
                                    if let Some(idx) = pending_param_binding_idx {
                                        if let Some(class_name) = self.peek_explicit_type_origin() {
                                            self.set_binding_origin(
                                                idx,
                                                Some(
                                                    crate::ts::events::ClassOrigin::ExplicitType {
                                                        class_name,
                                                    },
                                                ),
                                            );
                                        }
                                    }
                                    // v0.9 — populate field_type_class on the
                                    // most-recently-pushed param-property field
                                    // ([[param-property-field-type-gap]]
                                    // resolution). Generics-stripped per
                                    // plain-field semantics. The peek consumes
                                    // nothing; `parse_param_type_expr_emitting_refs`
                                    // below walks the type normally and emits
                                    // its refs.
                                    if let Some(field_idx) = pending_param_property_field_idx.take()
                                    {
                                        if let Some(class_name) =
                                            self.peek_param_property_field_type_class()
                                        {
                                            param_property_fields[field_idx].field_type_class =
                                                Some(class_name);
                                        }
                                    }
                                    // G1.6 D4 — method/constructor parameter
                                    // (incl. param-property fields, which
                                    // still declare a param-list type here).
                                    self.parse_param_type_expr_emitting_refs();
                                    expecting_binder = false;
                                }
                                TokenKind::Ident if expecting_binder && paren_depth == 1 => {
                                    let binder_text = self.text_of(p.span).to_string();
                                    // Parameter-property modifier
                                    // detection (constructor only —
                                    // gated at emission time). We
                                    // recognize the Ident as a modifier
                                    // only when followed by another
                                    // Ident or `[` (i.e., a real
                                    // binder follows). Otherwise the
                                    // Ident IS the binder (e.g., a
                                    // parameter literally named
                                    // `private`).
                                    let is_param_modifier_word = matches!(
                                        binder_text.as_str(),
                                        "public"
                                            | "private"
                                            | "protected"
                                            | "readonly"
                                            | "override"
                                    );
                                    let next_after = if is_param_modifier_word {
                                        let saved = self.lexer.checkpoint();
                                        self.lexer.next();
                                        let k = self.lexer.peek().kind;
                                        self.lexer.restore(saved);
                                        k
                                    } else {
                                        TokenKind::Eof
                                    };
                                    let is_real_param_modifier = is_param_modifier_word
                                        && matches!(
                                            next_after,
                                            TokenKind::Ident | TokenKind::LBracket
                                        );
                                    if is_real_param_modifier {
                                        self.lexer.next();
                                        pending_param_property = true;
                                    } else {
                                        self.note_value_binder(&binder_text);
                                        // v0.5 commit 3 — emit a
                                        // BindingEvent for the method
                                        // param. ExplicitType origin
                                        // (if any) is attached at the
                                        // Colon arm above.
                                        let idx =
                                            self.emit_binding(binder_text.clone(), p.span, None);
                                        pending_param_binding_idx = Some(idx);
                                        self.lexer.next();
                                        if pending_param_property && is_constructor {
                                            param_property_fields.push(PendingMethod {
                                                name: binder_text.clone(),
                                                name_span: p.span,
                                                decl_span: p.span,
                                                body_span: crate::spans::Span::new(0, 0),
                                                is_static: false,
                                                kind: crate::ts::events::MemberKind::Field,
                                                // v0.6 commit 1 — fields never carry a
                                                // factory return type. Always `None`.
                                                return_class_name: None,
                                                // v0.9 — field_type_class is populated
                                                // below at the Colon arm via
                                                // `peek_param_property_field_type_class`.
                                                // Initialized to `None`; the type
                                                // annotation (if present) lands when the
                                                // colon + type-expression are walked next.
                                                // Untyped param-properties
                                                // (`constructor(private svc) {}`,
                                                // technically `any`) correctly stay
                                                // `None` — matches plain-field semantics.
                                                field_type_class: None,
                                            });
                                            pending_param_property_field_idx =
                                                Some(param_property_fields.len() - 1);
                                        }
                                        pending_param_property = false;
                                        expecting_binder = false;
                                    }
                                }
                                // Destructured method params: `m({ x }, [y]) {}`.
                                // Delegate to the shared recursive harvester so
                                // nested binders are emitted and object keys are not
                                // mistaken for params.
                                TokenKind::LBrace if expecting_binder && paren_depth == 1 => {
                                    self.lexer.next(); // consume `{`
                                    if let Err(reason) = self.harvest_binding_pattern_names(true) {
                                        return self.recover_failed_class_member(
                                            member_checkpoint,
                                            member_scope_checkpoint,
                                            reason,
                                            t.span,
                                        );
                                    }
                                    expecting_binder = false;
                                }
                                TokenKind::LBracket if expecting_binder && paren_depth == 1 => {
                                    self.lexer.next(); // consume `[`
                                    if let Err(reason) = self.harvest_binding_pattern_names(false) {
                                        return self.recover_failed_class_member(
                                            member_checkpoint,
                                            member_scope_checkpoint,
                                            reason,
                                            t.span,
                                        );
                                    }
                                    expecting_binder = false;
                                }
                                TokenKind::Eof => {
                                    return self.recover_failed_class_member(
                                        member_checkpoint,
                                        member_scope_checkpoint,
                                        "unterminated method params",
                                        t.span,
                                    );
                                }
                                _ => {
                                    self.lexer.next();
                                }
                            }
                        }
                        // v0.6 commit 2 — capture the method's
                        // declared return-class for static-method
                        // factory inference BEFORE the type-emitter
                        // consumes it. Plain-Ident only; generics
                        // stripped. Only used downstream if the
                        // member turns out to be `is_static: true`
                        // (per Q4 — instance-method factories are
                        // out of scope, paired with v0.7 property
                        // chains). `captured_member_return_class`
                        // declared at the outer per-member scope so
                        // the PendingMethod push (after this branch
                        // closes) can read it.
                        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                            self.lexer.next();
                            captured_member_return_class = self.peek_plain_ident_return_class();
                            self.parse_return_type_emitting_refs();
                        }
                        let mut method_body_span = crate::spans::Span::new(0, 0);
                        let method_decl_end: u32;
                        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                            let body_start = self.lexer.peek().span.start();
                            self.lexer.next();
                            let body_end = match self.walk_balanced_braces_collecting_refs() {
                                Ok(body_end) => body_end,
                                Err(reason) => {
                                    return self.recover_failed_class_member(
                                        member_checkpoint,
                                        member_scope_checkpoint,
                                        reason,
                                        t.span,
                                    );
                                }
                            };
                            method_body_span =
                                crate::spans::Span::new(body_start, body_end - body_start);
                            method_decl_end = body_end;
                        } else if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                            let semi_tok = self.lexer.next();
                            method_decl_end = semi_tok.span.start() + semi_tok.span.length();
                        } else {
                            // Degenerate — no body, no semicolon.
                            method_decl_end = self.lexer.peek().span.start();
                        }
                        self.pop_value_scope();
                        if opened_method_scope {
                            self.pop_type_param_scope();
                        }
                        body_span_out = method_body_span;
                        decl_end_out = method_decl_end;
                    } else {
                        // === FIELD BRANCH ===
                        is_field = true;
                        if matches!(
                            self.lexer.peek().kind,
                            TokenKind::Question | TokenKind::Bang
                        ) {
                            self.lexer.next();
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                            self.lexer.next();
                            // v0.7 commit 2 — capture the field's
                            // declared plain-Ident class type for
                            // property-chain resolution BEFORE the
                            // type-emitter consumes it. Plain-Ident
                            // only; generics stripped. Stored in
                            // captured_member_field_type_class so
                            // the PendingMethod push (after this
                            // branch closes) can populate
                            // field_type_class. Uses the field-
                            // position helper (which accepts `=`,
                            // `;`, `}`, `,`, `Ident`, `Eof` as
                            // terminators) rather than the return-
                            // position helper (which accepts `{`,
                            // `=>`, `;`, `Eof`).
                            captured_member_field_type_class =
                                self.peek_plain_ident_field_type_class();
                            self.parse_type_expr_emitting_refs();
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                            self.lexer.next();
                            // Mark the initializer walk so the ASI guard in
                            // `walk_expression_collecting_refs_inner` will
                            // break at the next class-member start instead of
                            // running across a missing semicolon into it.
                            // Save/restore (rather than set/clear) so a nested
                            // class field initializer restores the outer state.
                            let prev_field_init = self.in_class_field_init;
                            self.in_class_field_init = true;
                            let walk_result = self.walk_expression_collecting_refs();
                            self.in_class_field_init = prev_field_init;
                            if let Err(reason) = walk_result {
                                return self.recover_failed_class_member(
                                    member_checkpoint,
                                    member_scope_checkpoint,
                                    reason,
                                    t.span,
                                );
                            }
                        }
                        let field_end: u32 = if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                            let semi_tok = self.lexer.next();
                            semi_tok.span.start() + semi_tok.span.length()
                        } else {
                            self.lexer.peek().span.start()
                        };
                        if opened_method_scope {
                            self.pop_type_param_scope();
                        }
                        body_span_out = crate::spans::Span::new(0, 0);
                        decl_end_out = field_end;
                    }

                    // The class owns its type surface in the existing graph
                    // contract. Runtime references and nested declarations retain
                    // the reserved member owner; do not retarget their identities.
                    if let (Some(event_index), Some(class_index)) = (member_slot, class_decl_index)
                    {
                        let member_index = self.current_owner();
                        for event in &mut self.events[event_index + 1..] {
                            if let Event::Ref(
                                RefEvent::TypeRef { owner, .. }
                                | RefEvent::TypeQueryRef { owner, .. }
                                | RefEvent::TypeMemberAccess { owner, .. },
                            ) = event
                            {
                                if *owner == member_index {
                                    *owner = Some(class_index);
                                }
                            }
                        }
                    }

                    // === Determine MemberKind ===
                    let kind = if is_field {
                        crate::ts::events::MemberKind::Field
                    } else if is_getter {
                        crate::ts::events::MemberKind::Getter
                    } else if is_setter {
                        crate::ts::events::MemberKind::Setter
                    } else {
                        crate::ts::events::MemberKind::Method
                    };

                    // Complete the reserved member declaration.
                    if let Some(event_index) = member_slot {
                        self.events[event_index] = Event::Decl(DeclEvent::Method {
                            name: member_name,
                            name_span: member_name_span,
                            owner_class_decl_index: class_decl_index
                                .expect("reserved class member"),
                            decl_span: crate::spans::Span::new(
                                decl_start,
                                decl_end_out.saturating_sub(decl_start),
                            ),
                            body_span: body_span_out,
                            is_static,
                            kind,
                            // v0.6 commit 2 — only static methods
                            // carry a factory-relevant return class
                            // per Q4. Instance methods always emit
                            // `None` here; their factory-shaped
                            // returns are paired with v0.7 property
                            // chains (resolver path requires
                            // resolving the receiver's class first).
                            // Also gated to `kind == Method` —
                            // getters/setters/fields don't enter
                            // the factory-call resolution path.
                            return_class_name: if is_static
                                && matches!(kind, crate::ts::events::MemberKind::Method)
                            {
                                captured_member_return_class.clone()
                            } else {
                                None
                            },
                            // v0.7 commit 2 — only Field-kind
                            // members carry a property-chain-
                            // relevant field type. Non-Field kinds
                            // (Method, Getter, Setter) always emit
                            // `None` here; their declared types
                            // (return types, accessor types) don't
                            // gate property-chain walks. Captured
                            // by the field branch's Colon arm via
                            // `peek_plain_ident_field_type_class`.
                            field_type_class: if matches!(
                                kind,
                                crate::ts::events::MemberKind::Field
                            ) {
                                captured_member_field_type_class.clone()
                            } else {
                                None
                            },
                        });
                    }
                    // Constructor parameter-property fields drain
                    // AFTER the constructor's own emission so the
                    // event order is [constructor, Field, Field, …].
                    if member_slot.is_some() {
                        self.pop_owner();
                    }
                    if let Some(owner_class_decl_index) = class_decl_index {
                        for field in param_property_fields {
                            self.push_decl(DeclEvent::Method {
                                name: field.name,
                                name_span: field.name_span,
                                decl_span: field.decl_span,
                                body_span: field.body_span,
                                owner_class_decl_index,
                                is_static: field.is_static,
                                kind: field.kind,
                                return_class_name: field.return_class_name,
                                field_type_class: field.field_type_class,
                            });
                        }
                    }
                }
                TokenKind::Eof => return Err("unterminated class body"),
                _ => {
                    self.lexer.next();
                }
            }
            if depth > 0 {
                last_end = self.lexer.peek().span.start();
            }
        }
        Ok(last_end)
    }

    pub(super) fn walk_expression_collecting_refs(&mut self) -> Result<(), &'static str> {
        self.with_scope_checkpoint(|parser| parser.walk_expression_collecting_refs_guarded())
    }

    fn walk_expression_collecting_refs_guarded(&mut self) -> Result<(), &'static str> {
        // External review #4 P1-A: cap the recursive cycle
        // `walk_expression → emit_ident_ref → walk_call_args →
        //  walk_expression` to prevent SIGABRT on adversarial input
        // `const x = f(f(…f(0)…))` 5000-deep. Mirrors the type-grammar
        // depth-guard pattern (MAX_TYPE_DEPTH at `parse_type` entry).
        // Expressions, balanced bodies, and destructuring share one recursion
        // budget because each can recurse into the others while collecting
        // references.
        if !self.enter_reference_recursion(ReferenceRecursionKind::Expression) {
            // Skip one token to ensure the caller's loop progresses;
            // outer parens/brackets drain on their delimiters as usual.
            if !matches!(self.lexer.peek().kind, TokenKind::Eof) {
                self.lexer.next();
            }
            return Ok(());
        }
        let result = self.walk_expression_collecting_refs_inner();
        self.leave_reference_recursion(ReferenceRecursionKind::Expression);
        result
    }

    /// Inner body of `walk_expression_collecting_refs`. Extracted so the
    /// depth-guard wrapper can run cleanly without indenting the entire
    /// expression walker.
    fn walk_expression_collecting_refs_inner(&mut self) -> Result<(), &'static str> {
        // Walks one expression at depth 0, stopping at `,` or `;` (statement /
        // argument boundary). Inside any bracket pair (), [], {}, walks
        // balanced. Idents are classified via emit_ident_ref — which itself
        // reserves the outer Call slot before recursing into args, so
        // `foo(bar(), baz)` emits Call(foo), Call(bar), ValueRef(baz) in that
        // order.
        //
        // Mode tracks whether the next Ident is a member access (`obj.method`),
        // in which case we drop emission. Without this, expressions like
        // `obj.method()` would emit a fake `Call(method)` that the resolver
        // can't possibly map to any node.
        //
        // No in_type_pos tracking: this is value-position by definition. Any
        // TypeRefs inside `<...>` generic-call args are emitted by
        // `emit_ident_ref`'s generic-call branch (see Task 14 r8).
        #[derive(Clone, Copy)]
        enum ExprMode {
            Value,
            AfterDot,
        }
        let mut depth: i32 = 0;
        let mut mode = ExprMode::Value;
        // Object-literal key suppression: track when the *next* Ident is at
        // a key position (immediately after `{` or after a `,` at the same
        // brace nest level). When the Ident is followed by `:` (or `?`),
        // it's a property key — suppress emission. Without this, `const x =
        // { value: helper() }` would leak `value` as a phantom ValueRef →
        // UnresolvedReference and shift baseline diagnostics under AI edits.
        let mut at_object_key_position = false;
        let mut brace_depth: i32 = 0; // separate from `depth` to gate the comma reset
        let mut paren_depth_local: i32 = 0; // commas in `(a, b)` are operators, not key boundaries
        let mut object_literal_nonbrace_depths: Vec<Option<i32>> = Vec::new();
        let mut member_access = MemberAccessState::default();
        // See `walk_balanced_braces_collecting_refs`: distinguishes an
        // object-literal `{` from a method/function/block-body `{`. The body
        // `{` is the only one preceded by `)` (`{ run() { helper(); } }` — the
        // method body), so its first statement is not at a key position.
        let mut prev_kind = TokenKind::Eof;
        let mut previous_bang_was_postfix = false;
        loop {
            let t = self.lexer.peek().clone();
            let cur_kind = t.kind;
            let preceding_bang_was_postfix = previous_bang_was_postfix;
            previous_bang_was_postfix = false;
            let had_lt_before = self.lexer.had_line_terminator();
            // ASI (Automatic Semicolon Insertion) heuristic
            // (added 2026-05-26 — found while parsing Scout's
            // lookout-client.ts, where the absence of a `;` between
            // `const BASE_URL = … ?? ''` and `export class LookoutError
            // extends Error { … }` caused the expression walker to
            // consume the class as part of the const's RHS, silently
            // losing every decl after that point in the file):
            //
            // At depth 0 (no nested parens/brackets/braces), if a
            // statement-starting token appears AND the previous
            // token is one that completes an expression, treat it as
            // an implicit `;` — break without consuming. The decl-
            // parser's `decl_end = self.lexer.peek().span.start();`
            // then sees the keyword peeked here and we resume normal
            // statement parsing.
            //
            // Allowed-prev set: tokens that complete an expression
            // (Ident, Number, Str, Regex, RParen, RBracket, RBrace,
            // postfix ++/--, True, False, Null, Undefined). Anything else means the
            // expression isn't complete, so the keyword is part of an
            // expression form (e.g. `const x = class Foo {}`,
            // `const x = function foo() {}`) and we must NOT break.
            //
            // Limited to depth==0 + the three depth-style counters so
            // we don't accidentally ASI-break inside `[1, class X {}]`
            // (rare but legal) or inside `({ x: class Y {} })`.
            let asi_break = if depth == 0
                && paren_depth_local == 0
                && brace_depth == 0
                && !matches!(mode, ExprMode::AfterDot)
            {
                // `true`/`false`/`null`/`undefined` aren't distinct token
                // kinds in this lexer — they come through as TokenKind::Ident,
                // already in this predicate's set.
                let prev_completes_expr = Self::token_can_end_expression_statement(prev_kind);
                let cur_is_stmt_start = matches!(
                    cur_kind,
                    TokenKind::Const
                        | TokenKind::Let
                        | TokenKind::Var
                        | TokenKind::Export
                        | TokenKind::Import
                        | TokenKind::Function
                        | TokenKind::Class
                        | TokenKind::Interface
                        | TokenKind::Enum
                        | TokenKind::Return
                        | TokenKind::Throw
                        | TokenKind::If
                        | TokenKind::For
                        | TokenKind::While
                        | TokenKind::Do
                        | TokenKind::Switch
                        | TokenKind::Try
                        | TokenKind::Break
                        | TokenKind::Continue
                        | TokenKind::LBrace
                        // `type X = …` type-alias. `type` is its own keyword
                        // token (TokenKind::Type), effectively reserved in this
                        // parser. Without it here, a preceding no-semicolon
                        // statement's value walk runs past the newline into the
                        // alias and swallows its whole body — leaking the alias
                        // name, members, and primitive types (`string`/`number`)
                        // as unresolved value refs. This was the dominant
                        // unresolved-ref source on no-semicolon codebases
                        // (Scout: Effect-TS). Analogous to Interface/Enum above.
                        | TokenKind::Type
                );
                // Class-field-initializer extension: a semicolon-free field
                // initializer must ASI-break at the next *class member* start,
                // which the keyword-only `cur_is_stmt_start` set above misses
                // (member names are plain Idents: `y: T`, `#y = ...`, arrow
                // fields, or a modifier like `static`). Scoped to field
                // initializers via `in_class_field_init`; the break is needed
                // even in the nested concise arrow-body walk (`f = () => 1\n
                // g = ...`), so this is NOT gated on `expr_depth`. Safety comes
                // from the 1-token member-shape lookahead, which only fires on
                // unambiguous member shapes (`name:`/`name=`/`name(`/...) and so
                // leaves legal continuations (`x\n satisfies T`, `x\n as T`,
                // method chains, ternaries, call-args ending in `)`) untouched.
                // Block bodies (`=> { ... }`) and object literals never reach
                // here; they are brace-balanced separately. Hono: context.ts.
                let cur_is_class_member_start = self.in_class_field_init
                    && matches!(cur_kind, TokenKind::Ident)
                    && (class_member_punct_follows(self.lexer.source_after_cursor())
                        || ident_is_member_modifier(self.text_of(t.span)));
                let cur_is_contextual_stmt_start = had_lt_before
                    && matches!(cur_kind, TokenKind::Ident)
                    && matches!(self.text_of(t.span), "declare" | "namespace");
                let cur_is_label_start = had_lt_before
                    && matches!(cur_kind, TokenKind::Ident)
                    && self.current_token_starts_label_statement();
                let cur_is_async_function_start =
                    self.current_token_starts_named_function_decl(true);
                let cur_is_abstract_class_start = self.current_token_starts_abstract_class_decl();
                prev_completes_expr
                    && (cur_is_stmt_start
                        || cur_is_class_member_start
                        || cur_is_contextual_stmt_start
                        || cur_is_label_start
                        || cur_is_async_function_start
                        || cur_is_abstract_class_start)
            } else {
                false
            };
            if asi_break {
                return Ok(());
            }
            match t.kind {
                // Member position wins over keyword classification: reserved
                // words are valid property identifiers after `.` and `?.`.
                // Keep this ahead of function/class-expression dispatch below
                // so `obj.class()` and `obj.function()` stay member accesses.
                kind if kind != TokenKind::Ident
                    && matches!(mode, ExprMode::AfterDot)
                    && Self::token_can_be_dot_property_identifier(kind) =>
                {
                    let member_tok = self.lexer.next();
                    let member_text = self.text_of(member_tok.span).to_string();
                    let member_end = member_tok.span.start() + member_tok.span.length();
                    self.complete_member_access(&mut member_access, member_text, member_end)?;
                    mode = ExprMode::Value;
                    at_object_key_position = false;
                    prev_kind = TokenKind::Ident;
                    continue;
                }
                // Generic arrow function head: `<T, U>(params) => body` (or
                // with a return-type annotation `<T>(p: T): R => body`). The
                // type-param list opens a fresh type-param scope so the binders
                // don't leak as TypeRefs, then we dispatch to the same arrow
                // walker as the non-generic case. Distinguished from a `a < b`
                // comparison by the byte-level lookahead. Fires at any depth so
                // generic arrows nested in object/array literals are caught.
                TokenKind::Lt
                    if looks_like_generic_arrow_head(self.lexer.source_after_cursor()) =>
                {
                    self.push_type_param_scope();
                    self.skip_type_param_list_collecting_refs();
                    if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        self.walk_arrow_function_collecting_refs()?;
                    }
                    self.pop_type_param_scope();
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RParen;
                    continue;
                }
                // JSX element/fragment in expression position (`<Foo/>`,
                // `<Foo>…</Foo>`, `<>…</>`). Ordered AFTER the generic-arrow arm
                // so `<T>(x) => …` is never seen here; skipped as opaque so a
                // .tsx file's imports/exports/decls extract without JSX tag/prop
                // names leaking as phantom ValueRefs. The `!generic_call_args`
                // guard excludes a generic call/instantiation `Foo.make<W>()` /
                // `new Foo<W>()` (a `<…>(` shape) that would otherwise look like
                // a no-attribute `<W>` open tag.
                TokenKind::Lt if looks_like_jsx_element(self.lexer.source_after_cursor()) => {
                    self.skip_jsx_element();
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RBrace;
                    continue;
                }
                TokenKind::LParen
                    if looks_like_arrow_param_list(self.lexer.source_after_cursor())
                        || paren_list_is_arrow_with_optional_return(
                            self.lexer.source_after_cursor(),
                        ) =>
                {
                    // Arrow function: `(p: T, q: U) => body` or `(p: T): R =>
                    // body`. The params open a value scope so later uses of
                    // `p`/`q` inside the body don't fake ValueRef events; the
                    // type annotations after `:` go through the filtered type
                    // walker.
                    //
                    // Detection fires at ANY depth so arrows nested inside
                    // object/array literals (`{ save: (e: Event) => save(e) }`,
                    // `[ (x) => x ]`) are recognized. The byte-level lookahead
                    // checks for matching `)` followed by `=>` — that excludes
                    // plain parenthesized expressions like `(a + b)`, which
                    // fall through to the normal depth-increment LParen arm.
                    self.walk_arrow_function_collecting_refs()?;
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RParen;
                    continue;
                }
                // Function / async function / class expression. Spec §5.1
                // calls these out as treated like a variable initializer
                // shape: the parser walks param/value scopes and body refs
                // identically to the top-level decl, but emits NO new
                // DeclEvent — the surrounding variable decl (or whatever
                // context) already provides the node.
                //
                // R5-P1-B: gate on !at_object_key_position so
                // `{ function(p): R { … } }` routes through the key-position
                // method-shorthand arm instead of being parsed as a
                // function-expression initializer.
                TokenKind::Function if !at_object_key_position => {
                    self.walk_function_expression_collecting_refs()?;
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RBrace;
                    continue;
                }
                TokenKind::Class if !at_object_key_position => {
                    self.walk_class_expression_collecting_refs()?;
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RBrace;
                    continue;
                }
                TokenKind::Async
                    if !at_object_key_position
                        && !matches!(mode, ExprMode::AfterDot)
                        && next_keyword_is(self.lexer.source_after_cursor(), b"function") =>
                {
                    // `async function (...) { ... }` expression. Consume the
                    // `async` keyword and dispatch to the same helper as plain
                    // function expressions — the `async` prefix doesn't
                    // change extraction semantics for v1.
                    self.lexer.next();
                    self.walk_function_expression_collecting_refs()?;
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::RBrace;
                    continue;
                }
                // `async (x) => body` or `async x => body` arrow expressions.
                // The arrow body still pushes its own value scope; the
                // `async` prefix is just consumed.
                TokenKind::Async if !matches!(mode, ExprMode::AfterDot) => {
                    // Object-literal async method: `{ async run() {} }`. Here
                    // `async` is a method modifier preceding the real key, not
                    // the start of an async arrow/function expression. Consume
                    // it and keep key position so the next Ident (`run`) is
                    // suppressed — the `get`/`set` contextual keywords (which
                    // lex as Ident) take the analogous path in the Ident arm;
                    // `async` lexes as its own keyword token so it must be
                    // handled here. (The body walker reaches the same outcome
                    // via its catch-all, which consumes `async` without
                    // clearing `at_object_key_position`.)
                    let was_at_key = at_object_key_position;
                    self.lexer.next(); // consume `async`
                                       // R5-P1-B: `{ async(p): T { ... } }` — `async` IS the
                                       // method NAME here, not a modifier. Route to the
                                       // shared method-shorthand walker (which expects to
                                       // start at the optional `<` or `(` after the name).
                    if was_at_key
                        && matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt)
                    {
                        let _ = self.walk_object_method_shorthand_collecting_refs()?;
                        at_object_key_position = false;
                        mode = ExprMode::Value;
                        continue;
                    }
                    if was_at_key && matches!(self.lexer.peek().kind, TokenKind::Ident) {
                        at_object_key_position = true;
                        prev_kind = TokenKind::Async;
                        continue;
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::LParen)
                        && (looks_like_arrow_param_list(self.lexer.source_after_cursor())
                            || paren_list_is_arrow_with_optional_return(
                                self.lexer.source_after_cursor(),
                            ))
                    {
                        self.walk_arrow_function_collecting_refs()?;
                        prev_kind = TokenKind::RParen;
                        mode = ExprMode::Value;
                        continue;
                    } else if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                        let id_tok = self.lexer.peek().clone();
                        self.lexer.next();
                        if matches!(self.lexer.peek().kind, TokenKind::Arrow) {
                            self.lexer.next(); // consume `=>`
                            self.push_value_scope();
                            let id_name = self.text_of(id_tok.span).to_string();
                            self.note_value_binder(&id_name);
                            // v0.5 commit 3 — async single-param arrow
                            // binder (`async x => …`). Origin: None
                            // (no type annotation in this shape).
                            let _ = self.emit_binding(id_name, id_tok.span, None);
                            self.walk_arrow_body_collecting_refs()?;
                            self.pop_value_scope();
                            prev_kind = TokenKind::Ident;
                            mode = ExprMode::Value;
                            continue;
                        } else {
                            // Not an arrow — bare `async someIdent` expression
                            // (rare; could be `async + x`). Emit ValueRef for
                            // the Ident; treat `async` itself as no-op since
                            // it's a contextual keyword.
                            self.emit_ident_ref(id_tok.span, false)?;
                        }
                    }
                    // Otherwise: `async` in some bare position (e.g.,
                    // `async;`). Already consumed; loop continues.
                    mode = ExprMode::Value;
                }
                TokenKind::LBrace => {
                    depth += 1;
                    brace_depth += 1;
                    mode = ExprMode::Value;
                    // External review #6 P1-A: mirror the body walker's
                    // narrowed object-literal detection. See the body-walker
                    // arm for the full rationale; same positive-list of
                    // expression-introducing tokens.
                    //
                    // IMPORTANT asymmetry from the body walker: this
                    // walker's `Eof` prev_kind means "we're at the START
                    // of an expression to walk" — and a leading `{` in
                    // expression position is necessarily an object-literal
                    // expression (block statements aren't expressions).
                    // So `Eof` IS in this walker's positive list. The
                    // body walker's `Eof` means "first statement of a
                    // body block" where a leading `{` is a nested block,
                    // so `Eof` is NOT in that walker's list.
                    let is_object_literal = matches!(
                        prev_kind,
                        TokenKind::Eof
                            | TokenKind::LParen
                            | TokenKind::Comma
                            | TokenKind::Colon
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
                    ) || Self::token_expects_expression_rhs(prev_kind);
                    at_object_key_position = is_object_literal;
                    object_literal_nonbrace_depths
                        .push(is_object_literal.then_some(paren_depth_local));
                    self.lexer.next();
                }
                // Computed-key method shorthand: `{ [Symbol.iterator](): Iter { … } }`
                // and computed-key property: `{ [makeKey()]: value }`. Same fix
                // as the other object walker (external review P1-A): walk the
                // bracket contents as a runtime expression rather than
                // balance-skipping, so refs in the key expression surface.
                TokenKind::LBracket if at_object_key_position => {
                    self.lexer.next(); // consume `[`
                    self.walk_expression_collecting_refs()?;
                    if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                        self.lexer.next();
                    }
                    // After `]`, if `(` or `<` follows, it's a computed-key method.
                    if matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt) {
                        let _ = self.walk_object_method_shorthand_collecting_refs()?;
                        mode = ExprMode::Value;
                        prev_kind = TokenKind::RBrace;
                    }
                    at_object_key_position = false;
                    continue;
                }
                TokenKind::LParen | TokenKind::LBracket => {
                    depth += 1;
                    paren_depth_local += 1;
                    mode = ExprMode::Value;
                    at_object_key_position = false;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    if depth == 0 {
                        return Ok(());
                    }
                    depth -= 1;
                    if brace_depth > 0 {
                        brace_depth -= 1;
                    }
                    object_literal_nonbrace_depths.pop();
                    at_object_key_position = false;
                    self.lexer.next();
                }
                TokenKind::RParen | TokenKind::RBracket => {
                    if depth == 0 {
                        return Ok(());
                    }
                    depth -= 1;
                    if paren_depth_local > 0 {
                        paren_depth_local -= 1;
                    }
                    at_object_key_position = false;
                    self.lexer.next();
                }
                TokenKind::Comma | TokenKind::Semi if depth == 0 => return Ok(()),
                TokenKind::Bang => {
                    previous_bang_was_postfix =
                        self.consume_expression_bang(prev_kind, preceding_bang_was_postfix);
                }
                // Comma inside the current object literal (not inside a nested
                // call/array arg) returns us to key-position. The object may
                // itself be nested in an array/call, so compare against the
                // non-brace depth captured when that object opened.
                TokenKind::Comma
                    if object_literal_nonbrace_depths.last().copied().flatten()
                        == Some(paren_depth_local) =>
                {
                    at_object_key_position = true;
                    self.lexer.next();
                }
                // TS type assertion: `value as Foo` or `value as const`. The
                // RHS is a type expression, not a value — without this arm,
                // `Foo` would emit as ValueRef and `const` would fall through
                // silently. Delegate to the filtered type walker so primitives,
                // type-param binders, object keys, contextual keywords, and
                // `as const`'s `const` keyword are all handled correctly.
                // R5-P1-B: gate so `{ as(p): T { … } }` routes through
                // method-shorthand instead.
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, ExprMode::AfterDot)
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
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::Ident;
                    continue;
                }
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, ExprMode::AfterDot)
                        && !Self::token_can_end_expression_statement(prev_kind) =>
                {
                    self.lexer.next();
                    self.emit_ident_ref(t.span, /* in_type_pos */ false)?;
                    mode = ExprMode::Value;
                    prev_kind = TokenKind::Ident;
                    continue;
                }
                TokenKind::As
                    if !at_object_key_position
                        && !matches!(mode, ExprMode::AfterDot)
                        && Self::token_can_end_expression_statement(prev_kind) =>
                {
                    self.lexer.next();
                    // `x as T` type-assertion operand -> ValuePosition (brief).
                    self.parse_type_expr_with_base(TypeRefPosition::ValuePosition);
                    mode = ExprMode::Value;
                    // `x as T` completes an expression; let ASI stop before
                    // the next statement instead of treating `As` as the
                    // previous token.
                    prev_kind = TokenKind::Ident;
                    continue;
                }
                TokenKind::QuestionDot => {
                    mode = match self.consume_optional_member_follower(&mut member_access)? {
                        OptionalMemberFollower::Complete => ExprMode::Value,
                        OptionalMemberFollower::PropertyIdentifier => ExprMode::AfterDot,
                    };
                    at_object_key_position = false;
                    continue;
                }
                TokenKind::Dot => {
                    // `.` or `?.` optional chaining — same member-access
                    // suppression as the body walker.
                    mode = ExprMode::AfterDot;
                    at_object_key_position = false;
                    self.lexer.next();
                }
                // External review #4 P1-B (second walker): mirror the body-
                // walker fix above for non-Ident object-method keys.
                // Widened to include `As`/`Const`/`Let`/`Var`/`Catch`/
                // `Function` (R5-P1-B). `Async` is handled in its own
                // arm above (line ~3587) since it has special modifier
                // semantics (`{ async run() {} }`) that the simpler
                // consume-then-dispatch shape here doesn't capture.
                // Dynamic import in expression position: claim the `import`
                // keyword (not as an object key) and emit the import edge.
                TokenKind::Import if !at_object_key_position => {
                    let import_span = t.span;
                    self.lexer.next(); // consume `import`
                    let consumed_call = if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        let _ = self.emit_dynamic_import_call(import_span)?;
                        true
                    } else {
                        false
                    };
                    mode = ExprMode::Value;
                    at_object_key_position = false;
                    prev_kind = if consumed_call {
                        TokenKind::RParen
                    } else {
                        TokenKind::Import
                    };
                    continue;
                }
                TokenKind::TemplateMid | TokenKind::TemplateEnd if depth == 0 => return Ok(()),
                TokenKind::TemplateStart => {
                    self.walk_template_literal_expr_collecting_refs()?;
                    mode = ExprMode::Value;
                    at_object_key_position = false;
                    prev_kind = TokenKind::TemplateEnd;
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
                | TokenKind::Await
                    if at_object_key_position =>
                {
                    self.lexer.next(); // consume the key token
                    at_object_key_position = false;
                    if matches!(self.lexer.peek().kind, TokenKind::LParen | TokenKind::Lt) {
                        let _ = self.walk_object_method_shorthand_collecting_refs()?;
                        mode = ExprMode::Value;
                        continue;
                    }
                    continue;
                }
                TokenKind::Ident => {
                    // TS `satisfies` lexes as Ident (contextual keyword). When
                    // it appears in expression position (`x satisfies Foo`),
                    // consume it and delegate the RHS to the filtered type
                    // walker — same shape as the `as` arm. Without this,
                    // `satisfies` itself would emit ValueRef(satisfies) and
                    // `Foo` would emit ValueRef(Foo).
                    if matches!(mode, ExprMode::Value) && self.text_of(t.span) == "satisfies" {
                        self.lexer.next();
                        // `x satisfies T` operand -> ValuePosition (brief).
                        self.parse_type_expr_with_base(TypeRefPosition::ValuePosition);
                        mode = ExprMode::Value;
                        at_object_key_position = false;
                        continue;
                    }
                    // Object-literal property key suppression — see body
                    // walker for rationale, including method shorthand
                    // (`{ run() {} }`), generic methods (`{ run<T>() {} }`),
                    // accessors (`{ get x() {} }`), async methods, and the
                    // shorthand-reference exception (`{ x, y }` IS a real
                    // ref).
                    let was_at_key = at_object_key_position;
                    at_object_key_position = false;
                    let ident_text = self.text_of(t.span).to_string();
                    self.lexer.next();
                    if was_at_key {
                        let next_kind = self.lexer.peek().kind;
                        // External review #6 P1-B: mirror the body walker's
                        // widened PropertyName check. See body-walker arm
                        // for the full rationale.
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
                            continue;
                        }
                        // Method shorthand in an object-literal expression:
                        // `{ on<Key>(type: Key) { body } }` or `{ items() { body } }`.
                        // Route through the scoped method-header parser so generic type
                        // params, param annotations, and return types are handled in
                        // type-context rather than value-context.
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
                            mode = ExprMode::Value;
                            at_object_key_position = false;
                            prev_kind = TokenKind::RBrace; // method body ends at `}`
                            continue;
                        }
                        // Plain property key (`key:`, `key?`) — suppress key
                        // emission; value-walk the RHS normally.
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
                            continue;
                        }
                        // Fall through: shorthand reference (`{ x, y }`).
                    }
                    match mode {
                        ExprMode::AfterDot => {
                            let member_end = t.span.start() + t.span.length();
                            self.complete_member_access(
                                &mut member_access,
                                ident_text,
                                member_end,
                            )?;
                            mode = ExprMode::Value;
                        }
                        ExprMode::Value => {
                            // Single-param-no-parens arrow: `x => body`.
                            if matches!(self.lexer.peek().kind, TokenKind::Arrow) {
                                self.walk_single_param_arrow_after_binder(t)?;
                            } else {
                                let events_len_before = self.events.len();
                                self.emit_ident_ref(t.span, /* in_type_pos */ false)?;
                                let emitted_value_ref = matches!(
                                    self.events.last(),
                                    Some(Event::Ref(RefEvent::ValueRef { .. }))
                                );
                                let suppressed_local_binder =
                                    self.events.len() == events_len_before;
                                if emitted_value_ref || suppressed_local_binder {
                                    self.begin_member_access(
                                        &mut member_access,
                                        MemberReceiverSeed::Name {
                                            name: ident_text.clone(),
                                            scope: self.current_scope(),
                                        },
                                        t.span,
                                    )?;
                                }
                            }
                        }
                    }
                }
                TokenKind::Eof => return Ok(()),
                _ => {
                    self.lexer.next();
                }
            }
            prev_kind = cur_kind;
        }
    }

    /// Consume `=> body` after a single, already-consumed identifier binder.
    /// Both expression and function-body walkers route this syntax through
    /// one scope owner so the binder cannot escape or appear as a value ref.
    pub(super) fn walk_single_param_arrow_after_binder(
        &mut self,
        binder: Token,
    ) -> Result<(), &'static str> {
        self.expect(TokenKind::Arrow)?;
        self.push_value_scope();
        let arrow_binder = self.text_of(binder.span).to_string();
        self.note_value_binder(&arrow_binder);
        let _ = self.emit_binding(arrow_binder, binder.span, None);
        let result = self.walk_arrow_body_collecting_refs();
        self.pop_value_scope();
        result
    }

    /// Consume `(p1: T1, p2: T2) => body` after `walk_expression`'s LParen-
    /// arrow-lookahead has committed. The current cursor is at `(`. Captures
    /// param binders into a fresh value scope so later uses inside the body
    /// don't emit phantom ValueRef events; emits TypeRef events from `:`
    /// annotations via the filtered type walker. Falls back gracefully if
    /// the lookahead heuristic was wrong (no `=>` after `)`): the value
    /// scope is popped and we return with the params already consumed
    /// (some binder-suppression may have happened, accepted as a v1 edge).
    pub(super) fn walk_arrow_function_collecting_refs(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `(`
        self.push_value_scope();
        let mut paren_depth: i32 = 1;
        let mut expecting_binder = true;
        // v0.5 commit 3 — pending BindingEvent for the in-progress
        // arrow param (`(x: C) => …`), updated to ExplicitType on the
        // Colon arm.
        let mut pending_arrow_binding_idx: Option<usize> = None;
        while paren_depth > 0 {
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::LParen => {
                    paren_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    paren_depth -= 1;
                    pending_arrow_binding_idx = None;
                    self.lexer.next();
                }
                TokenKind::Comma if paren_depth == 1 => {
                    expecting_binder = true;
                    pending_arrow_binding_idx = None;
                    self.lexer.next();
                }
                TokenKind::Colon if paren_depth == 1 => {
                    self.lexer.next();
                    // v0.5 commit 3 — typed arrow param. Attach
                    // ExplicitType origin to the pending binding.
                    if let Some(idx) = pending_arrow_binding_idx {
                        if let Some(class_name) = self.peek_explicit_type_origin() {
                            self.set_binding_origin(
                                idx,
                                Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }),
                            );
                        }
                    }
                    // G1.6 D4 — arrow-function parameter.
                    self.parse_param_type_expr_emitting_refs();
                    expecting_binder = false;
                }
                TokenKind::Eq if paren_depth == 1 => {
                    // Default value — walk as an expression for refs inside.
                    self.lexer.next();
                    self.walk_expression_collecting_refs()?;
                    expecting_binder = false;
                }
                TokenKind::Ident if expecting_binder && paren_depth == 1 => {
                    let binder_name = self.text_of(t.span).to_string();
                    self.note_value_binder(&binder_name);
                    // v0.5 commit 3 — parenthesized arrow param
                    // binder. ExplicitType origin (if any) is
                    // attached at the Colon arm above.
                    let idx = self.emit_binding(binder_name, t.span, None);
                    pending_arrow_binding_idx = Some(idx);
                    self.lexer.next();
                    expecting_binder = false;
                }
                // Destructured arrow param: `({ x }, [y]) => …`.
                TokenKind::LBrace if expecting_binder && paren_depth == 1 => {
                    self.lexer.next(); // consume `{`
                    self.harvest_binding_pattern_names(true)?;
                    expecting_binder = false;
                }
                TokenKind::LBracket if expecting_binder && paren_depth == 1 => {
                    self.lexer.next(); // consume `[`
                    self.harvest_binding_pattern_names(false)?;
                    expecting_binder = false;
                }
                TokenKind::Eof => {
                    self.pop_value_scope();
                    return Err("unterminated arrow params");
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
        // Optional return-type annotation between `)` and `=>`
        // (`(x: T): R => …`, including type-predicate returns `(x): x is T =>`).
        // Delegate to the filtered type walker so the return type emits refs
        // and the predicate subject is suppressed.
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            self.parse_return_type_emitting_refs();
        }
        // Expect `=>`. If absent, the lookahead heuristic was wrong; pop
        // and continue (the caller's outer expression walk resumes from
        // here with whatever follows).
        if matches!(self.lexer.peek().kind, TokenKind::Arrow) {
            self.lexer.next();
            self.walk_arrow_body_collecting_refs()?;
        }
        self.pop_value_scope();
        Ok(())
    }

    /// Walk an arrow function body. Either a brace block `{ ... }` or a
    /// single expression (which stops at `,` or `;` or a depth-0 `)`).
    fn walk_arrow_body_collecting_refs(&mut self) -> Result<(), &'static str> {
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.lexer.next();
            let _ = self.walk_balanced_braces_collecting_refs()?;
            Ok(())
        } else {
            self.walk_expression_collecting_refs()
        }
    }

    /// Consume a class expression: `class { ... }`,
    /// `class Local<T> extends Base<T> { ... }`, or the same shape nested in
    /// another expression. Does NOT emit a Class DeclEvent — the surrounding
    /// expression (usually a variable initializer) owns the graph node — but it
    /// still parses heritage/body structure so class-member names, type params,
    /// and method params do not leak as generic value refs.
    pub(super) fn walk_class_expression_collecting_refs(&mut self) -> Result<(), &'static str> {
        self.expect(TokenKind::Class)?;
        self.push_type_param_scope();
        self.push_value_scope();

        let result = (|| {
            // Optional name. In `class extends Base {}`, `extends` lexes as an
            // Ident, so only consume an Ident here when it is not a heritage
            // keyword. A named class expression's name is scoped to the class
            // expression itself, mirroring named function-expression handling.
            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                let name_tok = self.lexer.peek().clone();
                let name = self.text_of(name_tok.span).to_string();
                if name != "extends" && name != "implements" {
                    self.lexer.next();
                    self.note_value_binder(&name);
                    let _ = self.emit_binding(name, name_tok.span, None);
                }
            }

            self.skip_type_param_list_collecting_refs();

            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                let ext_kw = self.lexer.peek().clone();
                if self.text_of(ext_kw.span) == "extends" {
                    self.lexer.next();
                    let h = self.parse_heritage_ref()?;
                    self.events.push(Event::Ref(RefEvent::ValueRef {
                        name: h.name,
                        ref_span: h.ref_span,
                        owner: self.current_owner(),
                        scope: self.current_scope(),
                    }));
                    self.skip_type_args_collecting_refs();
                }
            }

            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                let impl_kw = self.lexer.peek().clone();
                if self.text_of(impl_kw.span) == "implements" {
                    self.lexer.next();
                    loop {
                        let _ = self.parse_heritage_ref()?;
                        self.skip_type_args_collecting_refs();
                        if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                            self.lexer.next();
                            continue;
                        }
                        break;
                    }
                }
            }

            if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                self.lexer.next();
                let _ = self.walk_class_body_collecting_refs(None)?;
            }

            Ok(())
        })();

        self.pop_value_scope();
        self.pop_type_param_scope();
        result
    }

    /// Consume a function expression: `function (params) { body }` or the
    /// named form `function foo(params) { body }`. The cursor is at
    /// `function`. Captures param + body local bindings in a fresh value
    /// scope so `const f = function(x: T) { return x }` doesn't fake
    /// ValueRef(x). Does NOT emit a DeclEvent — the surrounding variable
    /// decl (or whatever context) already provides the node. Generic param
    /// lists `<T>` are handled identically to function declarations.
    pub(super) fn walk_function_expression_collecting_refs(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `function`
        self.push_type_param_scope();
        self.push_value_scope();
        // Optional generator marker.
        if matches!(self.lexer.peek().kind, TokenKind::Star) {
            self.lexer.next();
        }
        // Optional name (named function expression). The name is visible
        // ONLY inside the function's own body — it does not leak to the
        // surrounding scope. So we bind it AFTER pushing the value scope
        // (already done above), which makes `function inner() { inner(); }`
        // resolve the inner call to the named expression rather than
        // emitting a phantom UnresolvedReference.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let name_tok = self.lexer.next();
            let fn_name = self.text_of(name_tok.span).to_string();
            self.note_value_binder(&fn_name);
            // v0.5 commit 3 — named function expression's own name
            // (only visible inside the function body). No class
            // origin — it's a function binding.
            let _ = self.emit_binding(fn_name, name_tok.span, None);
        }
        // Generic param list `<T, U>`.
        self.skip_type_param_list_collecting_refs();
        // Params.
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            self.expect(TokenKind::LParen)?;
            self.parse_param_list_emitting_type_refs()?;
        }
        // Optional return type annotation.
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            self.parse_return_type_emitting_refs();
        }
        // Body.
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.lexer.next();
            let _ = self.walk_balanced_braces_collecting_refs()?;
        }
        self.pop_value_scope();
        self.pop_type_param_scope();
        Ok(())
    }

    /// Runtime template literal `` `a-${expr}-b` `` in value position.
    ///
    /// The lexer emits the template body chunks as TemplateStart/Mid/End and
    /// leaves only interpolation expressions for the parser to walk. Unlike
    /// template-literal *types*, interpolations here are ordinary value
    /// expressions, so binders such as arrow/function parameters must suppress
    /// local refs.
    pub(super) fn walk_template_literal_expr_collecting_refs(
        &mut self,
    ) -> Result<(), &'static str> {
        let start_tok = self.lexer.next(); // `TemplateStart`
        let span = start_tok.span;
        let end = (span.start() + span.length()) as usize;
        let already_complete = end > 0 && end <= self.source.len() && self.source[end - 1] == b'`';
        if already_complete {
            return Ok(());
        }
        loop {
            match self.lexer.peek().kind {
                TokenKind::TemplateEnd => {
                    self.lexer.next();
                    return Ok(());
                }
                TokenKind::TemplateMid => {
                    self.lexer.next();
                }
                TokenKind::Eof => return Ok(()),
                _ => {
                    let pos_before = self.lexer.peek().span.start();
                    self.walk_expression_collecting_refs()?;
                    let pos_after = self.lexer.peek().span.start();
                    if pos_after == pos_before {
                        if matches!(self.lexer.peek().kind, TokenKind::Eof) {
                            return Ok(());
                        }
                        self.lexer.next();
                    }
                }
            }
        }
    }
}
