//! Recursive-descent TypeScript parser. See spec §5.

use crate::schema::TypeRefPosition;
use crate::spans::Span;
use crate::ts::diagnostics::{Diagnostic, DiagnosticKind};
use crate::ts::environment::is_language_value_builtin;
use crate::ts::events::{
    BindingKind, CallArgumentAnchor, DeclEvent, Event, ExportEntry, HeritageRef, ImportBinding,
    LocalValueDecl, ParsedFile, RefEvent,
};
use crate::ts::lexer::{Lexer, Token, TokenKind};

pub fn parse_file(path: &str, source: &[u8]) -> ParsedFile {
    let mut p = Parser::new(path, source);
    p.parse_program();
    p.into_parsed_file()
}

/// Type-grammar recursion cap. Type traversal has lighter stack frames than
/// expression traversal, so it keeps a separate, larger budget while sharing
/// the same admission and evidence owner.
const MAX_TYPE_DEPTH: u32 = 192;

/// Expression-grammar recursion cap. The recursive cycle
/// `walk_expression_collecting_refs` → `emit_ident_ref` →
/// `walk_call_args_collecting_refs` → `walk_expression_collecting_refs`
/// adds ~3 stack frames per nested-call level; a 5000-deep
/// `f(f(…f(0)…))` SIGABRTs on a 2 MiB stack at ~level 1300 without a
/// cap (external review #4 P1-A). The cap is set well below the 256
/// KiB / 2 MiB stack budgets used by the recursion-guard tests; legit
/// real-world expression nesting (`a.b.c.d.e.f.g`, AST-builder DSLs)
/// rarely exceeds depth ~30. Keep this below MAX_TYPE_DEPTH because
/// expression walks carry heavier frames and must trip before the
/// bounded-stack adversarial object-method probe reaches the OS stack
/// guard.
const MAX_EXPR_DEPTH: u32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceRecursionKind {
    Expression,
    Type,
}

/// Byte-level lookahead ceiling for arrow-shape heuristics. This remains
/// finite for adversarial unclosed syntax, but large enough for real-world
/// multi-line generic heads and option-object parameter types.
const ARROW_SHAPE_LOOKAHEAD_BYTES: usize = 16 * 1024;

fn skip_js_comment_bytes(bytes: &[u8], i: &mut usize, max: usize) -> bool {
    if *i + 1 >= max || *i + 1 >= bytes.len() || bytes[*i] != b'/' {
        return false;
    }
    match bytes[*i + 1] {
        b'/' => {
            *i += 2;
            while *i < max && *i < bytes.len() && !matches!(bytes[*i], b'\n' | b'\r') {
                *i += 1;
            }
            true
        }
        b'*' => {
            *i += 2;
            while *i + 1 < max && *i + 1 < bytes.len() {
                if bytes[*i] == b'*' && bytes[*i + 1] == b'/' {
                    *i += 2;
                    return true;
                }
                *i += 1;
            }
            *i = max.min(bytes.len());
            true
        }
        _ => false,
    }
}

fn skip_js_string_bytes(bytes: &[u8], i: &mut usize, max: usize) -> bool {
    if *i >= max || *i >= bytes.len() || !matches!(bytes[*i], b'\'' | b'"' | b'`') {
        return false;
    }
    let quote = bytes[*i];
    *i += 1;
    while *i < max && *i < bytes.len() {
        match bytes[*i] {
            b'\\' => {
                *i += 1;
                if *i < max && *i < bytes.len() {
                    *i += 1;
                }
            }
            c if c == quote => {
                *i += 1;
                return true;
            }
            _ => *i += 1,
        }
    }
    *i = max.min(bytes.len());
    true
}

fn skip_js_comment_or_string_bytes(bytes: &[u8], i: &mut usize, max: usize) -> bool {
    skip_js_string_bytes(bytes, i, max) || skip_js_comment_bytes(bytes, i, max)
}

fn skip_ws_and_js_comments(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        let before = i;
        if !skip_js_comment_bytes(bytes, &mut i, bytes.len()) || i == before {
            return i;
        }
    }
}

/// TS built-in primitive type names. None of these correspond to user-
/// defined nodes, so emitting them as TypeRef would just produce noisy
/// `UnresolvedReference(Type)` diagnostics on every typed function in
/// the corpus. The list is the closed set per TS spec; if a v1 user
/// shadows one of these names (e.g., `type string = MyString`), the
/// shadow is silently lost from the graph — accepted limitation for v1.
fn is_ts_primitive_type(name: &str) -> bool {
    matches!(
        name,
        "string"
            | "number"
            | "boolean"
            | "void"
            | "unknown"
            | "any"
            | "never"
            | "object"
            | "symbol"
            | "bigint"
            | "undefined"
            | "null"
            // Boolean literal types — lexed as Ident, never user-defined refs.
            | "true"
            | "false"
    )
}

/// Peek-byte helper: skips ASCII whitespace, then checks whether the
/// remaining bytes begin with `keyword` followed by a non-identifier byte.
fn next_keyword_is(bytes: &[u8], keyword: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if bytes.len() - i < keyword.len() {
        return false;
    }
    if &bytes[i..i + keyword.len()] != keyword {
        return false;
    }
    let after = i + keyword.len();
    if after >= bytes.len() {
        return true;
    }
    !matches!(bytes[after], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$')
}

/// Class-field-initializer ASI helper. `bytes` is `source_after_cursor()`
/// positioned just AFTER a candidate next-member-name `Ident` (the lexer has
/// already advanced past it). Returns true iff the next significant token is
/// a class-member punctuator, i.e. the Ident is a member *declaration* start
/// (`name:` field type, `name =` init, `name(` method, `name<` generic method,
/// `name?`/`name!` optional/definite, bare `name;` / `name}`), NOT a postfix
/// expression continuation (`x satisfies T`, `x as T`, `x in y` - where the
/// Ident is followed by another identifier/type, not a punctuator).
///
/// Deliberately does NOT treat `(` or `[` reached via an *operator* as a
/// member start; this helper only fires when the preceding token already
/// completed an expression (`prev_completes_expr` at the call site) and the
/// candidate is a fresh Ident, so `:`/`=`/`(`/`<`/`?`/`!`/`;`/`}` here are
/// unambiguous member shapes. Skips whitespace and `//` / `/* */` comments.
fn class_member_punct_follows(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
            i += 1;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        break;
    }
    let Some(&c) = bytes.get(i) else {
        return false;
    };
    match c {
        // `:` field type, but not `::` (not valid TS, defensive).
        b':' => bytes.get(i + 1) != Some(&b':'),
        // `=` initializer, but not `==`/`===` (comparison) or `=>` (arrow).
        b'=' => !matches!(bytes.get(i + 1), Some(&b'=') | Some(&b'>')),
        // method `(`, generic method `<`, optional `?`, definite `!`,
        // bare-field terminator `;`, or class close `}`.
        b'(' | b'<' | b'?' | b'!' | b';' | b'}' => true,
        _ => false,
    }
}

/// Is `text` a class-member modifier keyword (which lexes as `Ident`)? Used by
/// the field-initializer ASI break so `f = 1\n static y = 2` breaks before
/// `static`. A bare modifier keyword starting a line after a completed
/// expression is never a legal expression continuation, so this is safe.
fn ident_is_member_modifier(text: &str) -> bool {
    matches!(
        text,
        "static"
            | "readonly"
            | "public"
            | "private"
            | "protected"
            | "abstract"
            | "override"
            | "declare"
            | "get"
            | "set"
    )
}

/// Bounded byte-level lookahead: does the parenthesized group starting just
/// after the current `(` look like an arrow-function parameter list?
fn looks_like_arrow_param_list(bytes: &[u8]) -> bool {
    let max = bytes.len().min(ARROW_SHAPE_LOOKAHEAD_BYTES);
    let mut paren_depth: i32 = 1;
    let mut type_delim_depth: i32 = 0;
    let mut i = 0;
    while i < max {
        if skip_js_comment_or_string_bytes(bytes, &mut i, max) {
            continue;
        }
        let c = bytes[i];
        match c {
            b'(' => paren_depth += 1,
            b'{' | b'[' | b'<' => type_delim_depth += 1,
            b'}' | b']' if type_delim_depth > 0 => type_delim_depth -= 1,
            b'>' if i > 0 && bytes[i - 1] == b'=' => {}
            b'>' if type_delim_depth > 0 => type_delim_depth -= 1,
            b')' => {
                paren_depth -= 1;
                if paren_depth == 0 {
                    let j = skip_ws_and_js_comments(bytes, i + 1);
                    return j + 1 < bytes.len() && bytes[j] == b'=' && bytes[j + 1] == b'>';
                }
            }
            b';' if paren_depth == 1 && type_delim_depth == 0 => return false,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Bounded byte-level lookahead: does the source after the current cursor
/// look like a generic-call argument list (`<T, U>(args)`) rather than a
/// less-than comparison? Returns true iff a matching `>` exists at the same
/// angle-bracket depth AND is followed by `(`.
fn looks_like_generic_call_args(bytes: &[u8]) -> bool {
    let max = bytes.len().min(2048);
    let mut angle_depth: i32 = 1;
    let mut paren_depth: i32 = 0;
    let mut i = 0;
    while i < max {
        if skip_js_comment_or_string_bytes(bytes, &mut i, max) {
            continue;
        }
        let c = bytes[i];
        match c {
            b'<' => angle_depth += 1,
            b'>' if i > 0 && bytes[i - 1] == b'=' => {}
            b'>' => {
                angle_depth -= 1;
                if angle_depth == 0 && paren_depth == 0 {
                    let mut j = i + 1;
                    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                        j += 1;
                    }
                    // A generic instantiation is `Ident<…>` followed by a call
                    // `(` OR a tagged template `` ` `` (e.g. Effect-TS typed SQL
                    // `sql<{ id: string }>`…``). Both consume the type args as
                    // a type; recognizing the backtick form keeps the object-
                    // type arg from being value-walked (which leaked its
                    // members/primitives as unresolved value refs).
                    return j < bytes.len() && matches!(bytes[j], b'(' | b'`');
                }
            }
            b'(' | b'[' | b'{' => paren_depth += 1,
            b')' | b']' | b'}' => {
                if paren_depth == 0 {
                    return false;
                }
                paren_depth -= 1;
            }
            b';' if angle_depth == 1 && paren_depth == 0 => return false,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Like `looks_like_arrow_param_list`, but tolerates a return-type annotation
/// between the closing `)` and the `=>` (`(x: T): R => …`). `bytes` starts at
/// the byte AFTER the param-list's opening `(`. After the matching `)`, an
/// optional `: ReturnType` may appear; the arrow is confirmed iff a top-level
/// `=>` follows before any statement terminator. The return-type scan tracks
/// bracket depth so a `=>` *inside* a function-typed return annotation
/// (`(): (a: number) => void => …`) doesn't false-trigger early.
fn paren_list_is_arrow_with_optional_return(bytes: &[u8]) -> bool {
    let max = bytes.len().min(ARROW_SHAPE_LOOKAHEAD_BYTES);
    let mut paren_depth: i32 = 1;
    let mut type_delim_depth: i32 = 0;
    let mut i = 0;
    // 1) Find the matching `)` of the param list.
    while i < max {
        if skip_js_comment_or_string_bytes(bytes, &mut i, max) {
            continue;
        }
        match bytes[i] {
            b'(' => paren_depth += 1,
            b'{' | b'[' | b'<' => type_delim_depth += 1,
            b'}' | b']' if type_delim_depth > 0 => type_delim_depth -= 1,
            b'>' if i > 0 && bytes[i - 1] == b'=' => {}
            b'>' if type_delim_depth > 0 => type_delim_depth -= 1,
            b')' => {
                paren_depth -= 1;
                if paren_depth == 0 {
                    break;
                }
            }
            b';' if paren_depth == 1 && type_delim_depth == 0 => return false,
            _ => {}
        }
        i += 1;
    }
    if i >= max || bytes[i] != b')' {
        return false;
    }
    // 2) Skip whitespace after `)`. Either an immediate `=>` or `: Ret =>`.
    let mut j = skip_ws_and_js_comments(bytes, i + 1);
    if j + 1 < bytes.len() && bytes[j] == b'=' && bytes[j + 1] == b'>' {
        return true;
    }
    if j >= bytes.len() || bytes[j] != b':' {
        return false;
    }
    // 3) Return-type annotation: scan to a top-level `=>` (bracket-depth 0),
    //    stopping at a statement terminator or `,` (declarator boundary).
    j += 1;
    let mut depth: i32 = 0;
    while j + 1 < bytes.len() && j < i + max {
        if skip_js_comment_or_string_bytes(bytes, &mut j, (i + max).min(bytes.len())) {
            continue;
        }
        match bytes[j] {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            // The `>` in a nested `=>` function-type arrow is not a closing
            // angle bracket. Mirrors the guard in the param-list scan above.
            b'>' if j > 0 && bytes[j - 1] == b'=' => {}
            b')' | b']' | b'}' | b'>' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            b'=' if depth == 0 && bytes[j + 1] == b'>' => return true,
            b';' if depth == 0 => return false,
            b',' if depth == 0 => return false,
            _ => {}
        }
        j += 1;
    }
    false
}

/// Bounded byte-level lookahead from just after a `<`: does this open a
/// generic *arrow function* head — i.e. a balanced `<...>` type-parameter
/// list whose closing `>` is immediately followed by `(`, and that `(...)`
/// param list is itself an arrow (its matching `)` is followed by an optional
/// `: ReturnType` and then `=>`)? Used in value (expression) position to tell
/// `const f = <T>(x: T) => x` apart from a less-than comparison `a < b`.
/// `bytes` must start at the byte AFTER the opening `<`.
fn looks_like_generic_arrow_head(bytes: &[u8]) -> bool {
    let max = bytes.len().min(ARROW_SHAPE_LOOKAHEAD_BYTES);
    let mut angle_depth: i32 = 1;
    let mut paren_depth: i32 = 0;
    let mut i = 0;
    while i < max {
        if skip_js_comment_or_string_bytes(bytes, &mut i, max) {
            continue;
        }
        match bytes[i] {
            b'<' => angle_depth += 1,
            b'>' if i > 0 && bytes[i - 1] == b'=' => {}
            b'>' => {
                angle_depth -= 1;
                if angle_depth == 0 && paren_depth == 0 {
                    // Skip whitespace; require `(` then an arrow param list.
                    let j = skip_ws_and_js_comments(bytes, i + 1);
                    if j >= bytes.len() || bytes[j] != b'(' {
                        return false;
                    }
                    return paren_list_is_arrow_with_optional_return(&bytes[j + 1..]);
                }
            }
            b'(' | b'[' | b'{' => paren_depth += 1,
            b')' | b']' | b'}' => {
                if paren_depth == 0 {
                    return false;
                }
                paren_depth -= 1;
            }
            b';' if angle_depth == 1 && paren_depth == 0 => return false,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Heuristic: do the bytes immediately AFTER a `<` look like a JSX element or
/// fragment open (`<Foo …>`, `<Foo/>`, `<Foo.Bar>`, `<>`)? Used to claim JSX in
/// expression position and skip it as opaque. MUST be checked AFTER the
/// generic-arrow head (so `<T>(x) => …` is claimed there, not here).
/// Conservative: requires NO space between `<` and the tag (real JSX has none),
/// so a spaced comparison `a < b` is rejected; an unspaced `a<b` is rejected
/// because after the operand the next significant byte isn't a JSX continuation.
fn looks_like_jsx_open(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == b'>' {
        return true; // `<>` fragment
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false; // tag must start immediately (no leading space)
    }
    let mut i = 0;
    // Tag name incl. member/namespaced (`Foo.Bar`, `svg:rect`) and `-`.
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.' | b':' | b'-'))
    {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return false;
    }
    // JSX-open continues with `>` (open), `/` (self-close), `{` (spread attr),
    // or an attribute name (ident-start). A comparison's operand is followed by
    // an operator / `)` / `;` — none of these — so it's rejected.
    matches!(bytes[i], b'>' | b'/' | b'{') || bytes[i].is_ascii_alphabetic() || bytes[i] == b'_'
}

/// Stronger JSX gate (the one the walkers actually use): the bytes after a `<`
/// look like a JSX element that *closes JSX-style* — self-closing `<Tag …/>` or
/// an open tag whose content reaches a `</`. A type-argument generic
/// (`Foo<Bar>`, `x as Array<Y>`) and a generic call (`make<W>()`) have NEITHER,
/// so they are rejected — this subsumes the comparison and generic-call cases.
/// Bounded scan; skips `>` inside attribute strings and `{ … }` expressions.
fn looks_like_jsx_element(bytes: &[u8]) -> bool {
    if !looks_like_jsx_open(bytes) {
        return false;
    }
    if bytes.first() == Some(&b'>') {
        return true; // `<>` fragment (closes with `</>`)
    }
    let max = bytes.len().min(8192);
    let mut i = 0;
    let mut brace: i32 = 0; // depth of `{ … }` attr/expr containers
    while i < max {
        match bytes[i] {
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'"' | b'\'' if brace == 0 => {
                let q = bytes[i];
                i += 1;
                while i < max && bytes[i] != q {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if brace == 0 && i + 1 < bytes.len() && bytes[i + 1] == b'>' => {
                return true; // `<Tag … />` self-close
            }
            b'>' if brace == 0 => {
                // Open tag ended — a real element has a `</` close ahead; a
                // type-generic (`Foo<Bar> = …`) does not.
                let mut j = i + 1;
                while j + 1 < max {
                    if bytes[j] == b'<' && bytes[j + 1] == b'/' {
                        return true;
                    }
                    j += 1;
                }
                return false;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Bounded byte-level lookahead: starting at a `(`, does its matching `)`
/// get followed by `=>`? If so it's a function type `(params) => T`;
/// otherwise a parenthesized type `(T)`. Mirrors `looks_like_generic_call_args`'s idiom.
fn looks_like_function_type(bytes: &[u8]) -> bool {
    // A function-type parameter list cannot start with another parenthesized
    // function type. `((r: T) => U) => { ... }` and `(<T>(r: T) => U) => { ... }`
    // in an arrow return annotation are parenthesized return types followed by
    // the arrow's own `=>`, not fresh higher-order function types.
    let mut first = 1usize;
    while first < bytes.len() && matches!(bytes[first], b' ' | b'\t' | b'\n' | b'\r') {
        first += 1;
    }
    if first < bytes.len() && matches!(bytes[first], b'(' | b'<') {
        return false;
    }

    let mut depth: i32 = 0;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    let mut j = i + 1;
                    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                        j += 1;
                    }
                    return j + 1 < bytes.len() && bytes[j] == b'=' && bytes[j + 1] == b'>';
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Depths of every live parser-context stack at one grammar boundary.
///
/// Restoring this checkpoint deliberately keeps `scopes`: emitted events may
/// already refer to those persistent scope records.
#[derive(Clone, Copy)]
struct ScopeCheckpoint {
    type_param_depth: usize,
    value_depth: usize,
    const_string_depth: usize,
    const_string_shadow_depth: usize,
    type_position_depth: usize,
    owner_depth: usize,
    lexical_depth: usize,
}

/// The single pending receiver for a member-access transition.
///
/// Older walkers kept independent name, construction, and property-chain
/// slots, then repeated priority and cleanup logic at every property syntax.
/// That allowed equivalent `obj.field` and `obj["field"]` transitions to
/// diverge. This state stores the already-classified receiver instead: every
/// property spelling consumes exactly one receiver and may retain exactly one
/// chain receiver for the following property.
#[derive(Default)]
struct MemberAccessState {
    pending_receiver: Option<(crate::ts::events::MemberReceiver, u32)>,
}

impl MemberAccessState {
    fn capture(&mut self, receiver: crate::ts::events::MemberReceiver, span: crate::spans::Span) {
        self.pending_receiver = Some((receiver, span.start()));
    }

    fn take(&mut self) -> Option<(crate::ts::events::MemberReceiver, u32)> {
        self.pending_receiver.take()
    }

    fn discard(&mut self) {
        self.pending_receiver = None;
    }

    fn retain_chain(
        &mut self,
        base: crate::ts::events::MemberReceiver,
        member: String,
        chain_start: u32,
    ) {
        self.pending_receiver = Some((
            crate::ts::events::MemberReceiver::PropertyChain {
                base: Box::new(base),
                member,
            },
            chain_start,
        ));
    }
}

enum MemberReceiverSeed {
    Name {
        name: String,
        scope: crate::ts::events::ScopeId,
    },
    Constructed {
        class_name: String,
    },
}

impl MemberReceiverSeed {
    fn into_receiver(self) -> crate::ts::events::MemberReceiver {
        match self {
            Self::Name { name, .. } if name == "this" => crate::ts::events::MemberReceiver::This,
            Self::Name { name, scope } => crate::ts::events::MemberReceiver::Name { name, scope },
            Self::Constructed { class_name } => {
                crate::ts::events::MemberReceiver::Constructed { class_name }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OptionalMemberFollower {
    Complete,
    PropertyIdentifier,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberCallFollower {
    None,
    Parenthesized,
    Generic,
    OptionalParenthesized,
    OptionalGeneric,
}

impl MemberCallFollower {
    fn is_call(self) -> bool {
        !matches!(self, Self::None)
    }

    fn is_generic(self) -> bool {
        matches!(self, Self::Generic | Self::OptionalGeneric)
    }

    fn is_optional(self) -> bool {
        matches!(self, Self::OptionalParenthesized | Self::OptionalGeneric)
    }
}

struct Parser<'src> {
    lexer: Lexer<'src>,
    source: &'src [u8],
    path: String,
    events: Vec<Event>,
    exports: Vec<ExportEntry>,
    diagnostics: Vec<Diagnostic>,
    type_param_scopes: Vec<std::collections::HashSet<String>>,
    value_scopes: Vec<std::collections::HashSet<String>>,
    predeclared_value_binders: Vec<PredeclaredValueBinder>,
    const_string_scopes: Vec<std::collections::HashMap<String, String>>,
    /// Graph-visible declarations also shadow outer constant strings even when
    /// their parser path does not register an ordinary value binder.
    const_string_decl_shadow_scopes: Vec<std::collections::HashSet<String>>,
    /// G1.5 Fix 2 (F2-2): base `TypeRefPosition` for the type expression being
    /// parsed. Entry points (annotation / return-type / constraint / alias-RHS /
    /// composition member) push their context; `emit_type_ref` at the structured
    /// type-parser call sites reads the top via `current_type_pos`. Same
    /// lightweight scope-stack idiom as `type_param_scopes`. Empty => `Other`.
    pos_stack: Vec<TypeRefPosition>,
    /// Running count of `Event::Decl`s pushed so far. The `decl_index`
    /// stamped on each decl (and used by the resolver to recover the decl a
    /// `Direct` export points at) is just the count of decls preceding it.
    /// Tracking it incrementally avoids the O(n²) `events.iter().filter(..)
    /// .count()` rescan per decl that generated/barrel files would expose.
    decl_count: u32,
    /// Stack of enclosing-declaration `decl_index`es. The current owner of a
    /// reference event is the top of this stack (`None` = top-level/module-init).
    /// Owners that can contain declarations reserve their index before walking
    /// children. Statement recovery restores the stack so a failed declaration
    /// cannot leak its owner onto later references.
    owner_stack: Vec<u32>,
    /// Iteration 22 (dynamic-import export-level precision): set by the
    /// `let/const/var <name> = …` initializer arm to `(local, local_span,
    /// initializer_start_offset)` before the initializer is walked, so a
    /// directly-nested `await import('<literal>')` can register a NAMESPACE
    /// `ImportBinding` for the local (mirroring `import * as ns from '…'`) —
    /// making `local.<export>()` resolve to that specific export instead of
    /// the module-level over-attribution hedge. `emit_dynamic_import_call`
    /// takes it, and only binds when the initializer head is exactly
    /// `await import('<relative-literal>')`, the closing `)` is a clean
    /// declarator terminator, and the local provably never ESCAPES (all uses
    /// are `local.member`). Cleared after every initializer walk so it can
    /// never leak to a sibling declarator or an unrelated later import.
    /// Carries `(local, initializer_start_offset)`.
    pending_dynamic_import_binder: Option<(String, u32)>,
    /// How many conditional-type check-type positions we are currently nested
    /// inside. When > 0, `parse_type_expr_emitting_refs` skips its transient
    /// scope push/pop so that `infer` binders noted during param-type parsing
    /// land in the conditional's own scope (pushed by `parse_conditional_type`)
    /// rather than being swallowed by the transient scope and popped away before
    /// the true branch is parsed.
    conditional_check_depth: u32,
    /// Recursive-descent depth at `parse_type`'s entry. Every recursive path
    /// through the type grammar (`parse_conditional_type` → `parse_union_type`
    /// → … → `parse_type_args` → back to `parse_type` per generic arg) ends up
    /// re-entering `parse_type`, so a single counter at that entry point caps
    /// the whole subtree. The cap (`MAX_TYPE_DEPTH`) is set well below the
    /// stack-frame-budget of small test stacks (256 KiB) and CI sandboxes so
    /// adversarial inputs like `type T = A<A<…<A>>>` 5000-deep degrade to a
    /// `SyntaxRecovered { context: "excessive type nesting" }` diagnostic
    /// instead of `SIGABRT`. The audit driver was the fuzz-tier finding G1.
    type_depth: u32,
    /// One-shot latch so a single deeply-nested type expression doesn't emit
    /// thousands of identical excessive-nesting diagnostics. Reset is implicit
    /// per-file (Parser is constructed per file in `parse_file`).
    type_depth_reported: bool,
    /// Recursive-descent depth at `walk_expression_collecting_refs` entry.
    /// Capped by `MAX_EXPR_DEPTH` — same shape as `type_depth` but for the
    /// expression grammar. Adversarial input `const x = f(f(…f(0)…))`
    /// 5000-deep previously SIGABRTed on a 2 MiB stack (external review
    /// #4 P1-A). With the cap, the deepest path degrades to a single
    /// `SyntaxRecovered { context: "excessive expression nesting" }`
    /// diagnostic and the parser exits the subtree gracefully.
    expr_depth: u32,
    /// One-shot latch mirroring `type_depth_reported`.
    expr_depth_reported: bool,
    /// True only while walking a class-field initializer expression
    /// (`field = <expr>`). Scopes the class-member ASI break in
    /// `walk_expression_collecting_refs_inner` so a semicolon-free
    /// initializer does not run across the newline into the next member.
    /// Set around the FIELD BRANCH `Eq` walk. The ASI check is deliberately
    /// not restricted to `expr_depth == 1`, because concise arrow bodies inside
    /// class fields (`field = () => expr`) recurse through the expression
    /// walker and still need to stop before the next class member.
    in_class_field_init: bool,
    /// Nesting depth of an ambient declaration body (`declare namespace`,
    /// `declare global`, `declare module Foo`, or declaration-file namespace).
    /// Bodyless function signatures inside these bodies are real ambient value
    /// declarations, unlike ordinary overload signatures in executable `.ts`.
    ambient_declaration_body_depth: usize,
    /// Nesting depth of an explicit `declare global { ... }` body. External
    /// declaration modules keep their own top-level scope, but declarations
    /// inside this block are ambient globals by TypeScript semantics.
    ambient_global_body_depth: usize,
    /// Names of `type X = …` declarations collected while walking function/method
    /// bodies. Unlike top-level type aliases (which emit `DeclEvent::TypeAlias`
    /// and get a graph node), these are function-local and must NOT create nodes —
    /// but references to them from type-annotation positions inside the same body
    /// must be suppressed rather than leaked as `External(Unknown)`.
    local_type_names: Vec<String>,
    /// Declaration names observed while `ambient_global_body_depth > 0`.
    /// Drained into `ParsedFile` so the resolver can expose only explicit
    /// `declare global` declarations from external `.d.ts` modules.
    ambient_global_decl_names: Vec<String>,
    /// v0.5 commit 2 — lexical-scope sidecar. Initialized with a single
    /// entry for `ScopeId(0)` (module top-level, parent: None,
    /// enclosing_decl: None). Function/method/arrow body opens and
    /// statement-position block opens push new entries. Drained into
    /// `ParsedFile.scopes` at parse end. Pure plumbing in commit 2 —
    /// no consumer reads these yet (commit 5's resolver scope-walk).
    scopes: Vec<crate::ts::events::ScopeInfo>,
    /// Stack of active `ScopeId`s, top is the currently-open scope.
    /// Initialized to `vec![0]` so `current_scope()` returns the
    /// module top-level when no body has been entered.
    scope_stack: Vec<crate::ts::events::ScopeId>,
    /// v0.5 commit 3 — binding-emission sidecar. Lexical-binding facts
    /// pushed alongside `note_value_binder` calls. Drained into
    /// `ParsedFile.bindings` at parse end.
    bindings: Vec<crate::ts::events::BindingEvent>,
    /// v0.6 commit 1 — function-return-type sidecar for factory-return
    /// inference (Pattern F). Populated at plain-function /
    /// const-arrow declaration sites by commit 2. Drained into
    /// `ParsedFile.function_returns` at parse end. Empty in commit 1
    /// — pure plumbing for the data-shape commit.
    function_returns: Vec<crate::ts::events::FunctionReturn>,
    /// Object-literal API members discovered while parsing the body or
    /// initializer of an enclosing declaration. Drained right after that
    /// owner's DeclEvent is pushed so resolver decl-index ordering remains
    /// stable.
    pending_service_members: Vec<PendingServiceMember>,
    /// G1.7 Fix 2 — when `Some(owner_future_idx)`, the interface body
    /// currently being parsed mints member decl nodes (ServiceMember
    /// events) for its FUNCTION-TYPED members, with their signature refs
    /// re-attributed to the member at drain time. Set exclusively by
    /// `parse_interface_decl` around its body parse; the OTHER
    /// `parse_interface_body_emitting_refs` call site (local/ambient
    /// interfaces inside bodies) leaves it `None`, so nested interfaces
    /// never mint.
    type_member_minting_owner: Option<u32>,
    /// G1.7 Fix 2 — armed by `parse_type_alias_decl_body` when the alias
    /// RHS's FIRST token is `{`: `(owner_future_idx, brace_pos)`.
    /// `parse_object_or_mapped_type` consumes it only when its own opening
    /// brace position matches, so ONLY the alias's top-level object-type
    /// literal mints member decls — never a nested object type, a
    /// type-argument object, or an annotation object literal.
    alias_object_mint: Option<(u32, u32)>,
    /// Graph-visible local value declarations keyed by lexical scope. These
    /// keep nested function declarations queryable without making them
    /// file-global during reference resolution.
    local_value_decls: Vec<LocalValueDecl>,
    lexical_value_binders: std::collections::HashSet<(crate::ts::events::ScopeId, String)>,
    pending_function_overloads: Vec<(
        String,
        crate::ts::events::ScopeId,
        Option<u32>,
        std::ops::Range<usize>,
    )>,
    declaration_undo: Vec<DeclarationUndo>,
    declaration_checkpoint_depth: usize,
}

struct PredeclaredValueBinder {
    scope: crate::ts::events::ScopeId,
    name: String,
    span: Span,
    value_scope: Option<usize>,
    const_scope: usize,
}

enum DeclarationUndo {
    ValueBinder {
        scope: crate::ts::events::ScopeId,
        name: String,
        lexical_present: bool,
        value_scope: Option<(usize, bool)>,
    },
    ConstStringBinder {
        scope: usize,
        name: String,
        previous: Option<String>,
    },
    ConstStringShadow {
        scope: usize,
        name: String,
        present: bool,
    },
}

#[derive(Clone)]
struct DeclarationCheckpoint {
    source_start: u32,
    events: usize,
    exports: usize,
    bindings: usize,
    function_returns: usize,
    local_value_decls: usize,
    pending_function_overloads: usize,
    pending_service_members: usize,
    scopes: usize,
    local_type_names: usize,
    ambient_global_decl_names: usize,
    decl_count: u32,
    pending_dynamic_import_binder: Option<(String, u32)>,
    declaration_undo: usize,
}

impl<'src> Parser<'src> {
    fn declaration_checkpoint(&mut self) -> DeclarationCheckpoint {
        DeclarationCheckpoint {
            source_start: self.lexer.peek().span.start(),
            events: self.events.len(),
            exports: self.exports.len(),
            bindings: self.bindings.len(),
            function_returns: self.function_returns.len(),
            local_value_decls: self.local_value_decls.len(),
            pending_function_overloads: self.pending_function_overloads.len(),
            pending_service_members: self.pending_service_members.len(),
            scopes: self.scopes.len(),
            local_type_names: self.local_type_names.len(),
            ambient_global_decl_names: self.ambient_global_decl_names.len(),
            decl_count: self.decl_count,
            pending_dynamic_import_binder: self.pending_dynamic_import_binder.clone(),
            declaration_undo: self.declaration_undo.len(),
        }
    }

    fn rollback_declaration(&mut self, checkpoint: DeclarationCheckpoint) {
        let source_end = self.lexer.peek().span.start();
        while self.declaration_undo.len() > checkpoint.declaration_undo {
            match self.declaration_undo.pop().expect("undo length checked") {
                DeclarationUndo::ValueBinder {
                    scope,
                    name,
                    lexical_present,
                    value_scope,
                } => {
                    if lexical_present {
                        self.lexical_value_binders.insert((scope, name.clone()));
                    } else {
                        self.lexical_value_binders.remove(&(scope, name.clone()));
                    }
                    if let Some((index, present)) = value_scope {
                        if let Some(values) = self.value_scopes.get_mut(index) {
                            if present {
                                values.insert(name);
                            } else {
                                values.remove(&name);
                            }
                        }
                    }
                }
                DeclarationUndo::ConstStringBinder {
                    scope,
                    name,
                    previous,
                } => {
                    if let Some(values) = self.const_string_scopes.get_mut(scope) {
                        if let Some(previous) = previous {
                            values.insert(name, previous);
                        } else {
                            values.remove(&name);
                        }
                    }
                }
                DeclarationUndo::ConstStringShadow {
                    scope,
                    name,
                    present,
                } => {
                    if let Some(shadows) = self.const_string_decl_shadow_scopes.get_mut(scope) {
                        if present {
                            shadows.insert(name);
                        } else {
                            shadows.remove(&name);
                        }
                    }
                }
            }
        }
        self.bindings.truncate(checkpoint.bindings);
        self.events.truncate(checkpoint.events);
        self.exports.truncate(checkpoint.exports);
        self.function_returns.truncate(checkpoint.function_returns);
        self.local_value_decls
            .truncate(checkpoint.local_value_decls);
        self.pending_function_overloads
            .truncate(checkpoint.pending_function_overloads);
        self.pending_service_members
            .truncate(checkpoint.pending_service_members);
        self.scopes.truncate(checkpoint.scopes);
        self.local_type_names.truncate(checkpoint.local_type_names);
        self.ambient_global_decl_names
            .truncate(checkpoint.ambient_global_decl_names);
        self.decl_count = checkpoint.decl_count;
        self.pending_dynamic_import_binder = checkpoint.pending_dynamic_import_binder;
        // A block scan sees future names before a declaration transaction begins.
        // Invalidate only reservations owned by the failed source range or scope;
        // same-name declarations elsewhere retain their independent reservations.
        let mut removed = Vec::new();
        self.predeclared_value_binders.retain(|binder| {
            let failed = binder.scope as usize >= checkpoint.scopes
                || (checkpoint.source_start..=source_end).contains(&binder.span.start());
            if failed {
                removed.push((
                    binder.scope,
                    binder.name.clone(),
                    binder.value_scope,
                    binder.const_scope,
                ));
            }
            !failed
        });
        for (scope, name, value_scope, const_scope) in removed {
            let retained = self.lexical_value_binders.contains(&(scope, name.clone()))
                || self
                    .bindings
                    .iter()
                    .any(|binding| binding.scope == scope && binding.name == name)
                || self
                    .local_value_decls
                    .iter()
                    .any(|decl| decl.scope == scope && decl.name == name)
                || self
                    .predeclared_value_binders
                    .iter()
                    .any(|binder| binder.scope == scope && binder.name == name);
            if !retained {
                if let Some(values) = value_scope.and_then(|index| self.value_scopes.get_mut(index))
                {
                    values.remove(&name);
                }
                if let Some(shadows) = self.const_string_decl_shadow_scopes.get_mut(const_scope) {
                    shadows.remove(&name);
                }
            }
        }
    }

    fn with_declaration_checkpoint<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let checkpoint = self.declaration_checkpoint();
        let scope_checkpoint = self.scope_checkpoint();
        self.declaration_checkpoint_depth += 1;
        let result = operation(self);
        self.declaration_checkpoint_depth -= 1;
        if result.is_err() {
            self.rollback_declaration(checkpoint);
            self.restore_scope_checkpoint(scope_checkpoint);
        } else if self.declaration_checkpoint_depth == 0 {
            self.declaration_undo.truncate(checkpoint.declaration_undo);
        }
        result
    }

    fn finish_declaration_checkpoint(&mut self, checkpoint: DeclarationCheckpoint) {
        self.declaration_checkpoint_depth -= 1;
        if self.declaration_checkpoint_depth == 0 {
            self.declaration_undo.truncate(checkpoint.declaration_undo);
        }
    }

    fn abort_declaration_checkpoint(
        &mut self,
        checkpoint: DeclarationCheckpoint,
        scope_checkpoint: ScopeCheckpoint,
    ) {
        self.rollback_declaration(checkpoint);
        self.restore_scope_checkpoint(scope_checkpoint);
        self.declaration_checkpoint_depth -= 1;
    }

    fn new(path: &str, source: &'src [u8]) -> Self {
        Self {
            lexer: Lexer::new(source),
            source,
            path: path.to_string(),
            events: Vec::new(),
            exports: Vec::new(),
            diagnostics: Vec::new(),
            type_param_scopes: Vec::new(),
            value_scopes: Vec::new(),
            predeclared_value_binders: Vec::new(),
            // Keep one file/module scope alive across top-level statements.
            // Nested value scopes are pushed and popped around functions and
            // blocks, but a top-level `const path = './x'` must remain visible
            // to a later `import(path)` in the same module.
            const_string_scopes: vec![std::collections::HashMap::new()],
            const_string_decl_shadow_scopes: vec![std::collections::HashSet::new()],
            pos_stack: Vec::new(),
            decl_count: 0,
            owner_stack: Vec::new(),
            pending_dynamic_import_binder: None,
            conditional_check_depth: 0,
            type_depth: 0,
            type_depth_reported: false,
            expr_depth: 0,
            expr_depth_reported: false,
            in_class_field_init: false,
            ambient_declaration_body_depth: 0,
            ambient_global_body_depth: 0,
            local_type_names: Vec::new(),
            ambient_global_decl_names: Vec::new(),
            // v0.5 commit 2 — initialize with the module top-level
            // scope. ScopeId(0) is always present and has no parent.
            scopes: vec![crate::ts::events::ScopeInfo {
                parent: None,
                enclosing_decl: None,
            }],
            scope_stack: vec![0],
            // v0.5 commit 3 — empty bindings stream; populated by
            // `emit_binding` co-located with `note_value_binder`.
            bindings: Vec::new(),
            // v0.6 commit 1 — empty function-returns sidecar.
            // Populated by commit 2's plain-function / const-arrow
            // return-type extraction.
            function_returns: Vec::new(),
            pending_service_members: Vec::new(),
            type_member_minting_owner: None,
            alias_object_mint: None,
            local_value_decls: Vec::new(),
            lexical_value_binders: std::collections::HashSet::new(),
            pending_function_overloads: Vec::new(),
            declaration_undo: Vec::new(),
            declaration_checkpoint_depth: 0,
        }
    }

    /// Admit one recursive reference-extraction frame.
    ///
    /// This is the single transition owner for both recursion domains.
    /// Domain-specific counters and limits preserve their different stack
    /// costs; rejected entries never mutate a counter and always leave durable
    /// evidence that the parser omitted possible references.
    fn enter_reference_recursion(&mut self, kind: ReferenceRecursionKind) -> bool {
        let current_depth = match kind {
            ReferenceRecursionKind::Expression => self.expr_depth,
            ReferenceRecursionKind::Type => self.type_depth,
        };
        let next_depth = current_depth
            .checked_add(1)
            .expect("reference recursion depth must not overflow");
        if !self.reference_depth_is_admitted(kind, next_depth) {
            return false;
        }
        match kind {
            ReferenceRecursionKind::Expression => self.expr_depth = next_depth,
            ReferenceRecursionKind::Type => self.type_depth = next_depth,
        }
        true
    }

    fn leave_reference_recursion(&mut self, kind: ReferenceRecursionKind) {
        let depth = match kind {
            ReferenceRecursionKind::Expression => &mut self.expr_depth,
            ReferenceRecursionKind::Type => &mut self.type_depth,
        };
        *depth = depth
            .checked_sub(1)
            .expect("reference recursion depth must balance every admitted entry");
    }

    /// Enforce the reference-extraction limit, including paths such as
    /// predeclaration that track their depth in an explicit argument.
    fn reference_depth_is_admitted(&mut self, kind: ReferenceRecursionKind, depth: u32) -> bool {
        let limit = match kind {
            ReferenceRecursionKind::Expression => MAX_EXPR_DEPTH,
            ReferenceRecursionKind::Type => MAX_TYPE_DEPTH,
        };
        if depth <= limit {
            return true;
        }
        self.report_reference_depth_truncation(kind);
        false
    }

    /// Record the first truncation in a recursion domain for this parsed file.
    /// One diagnostic per domain is sufficient to degrade downstream impact
    /// authority; the latches bound both memory and serialized cache growth.
    fn report_reference_depth_truncation(&mut self, kind: ReferenceRecursionKind) {
        let (reported, context) = match kind {
            ReferenceRecursionKind::Expression => (
                &mut self.expr_depth_reported,
                "excessive expression nesting",
            ),
            ReferenceRecursionKind::Type => {
                (&mut self.type_depth_reported, "excessive type nesting")
            }
        };
        if *reported {
            return;
        }
        *reported = true;
        self.diagnostics.push(Diagnostic {
            kind: DiagnosticKind::SyntaxRecovered {
                context: context.to_string(),
            },
            file_path: self.path.clone(),
            span: self.lexer.peek().span,
        });
    }

    fn current_owner(&self) -> Option<u32> {
        self.owner_stack.last().copied()
    }

    fn scope_checkpoint(&self) -> ScopeCheckpoint {
        ScopeCheckpoint {
            type_param_depth: self.type_param_scopes.len(),
            value_depth: self.value_scopes.len(),
            const_string_depth: self.const_string_scopes.len(),
            const_string_shadow_depth: self.const_string_decl_shadow_scopes.len(),
            type_position_depth: self.pos_stack.len(),
            owner_depth: self.owner_stack.len(),
            lexical_depth: self.scope_stack.len(),
        }
    }

    fn restore_scope_checkpoint(&mut self, checkpoint: ScopeCheckpoint) {
        self.type_param_scopes.truncate(checkpoint.type_param_depth);
        self.value_scopes.truncate(checkpoint.value_depth);
        self.const_string_scopes
            .truncate(checkpoint.const_string_depth);
        self.const_string_decl_shadow_scopes
            .truncate(checkpoint.const_string_shadow_depth);
        self.pos_stack.truncate(checkpoint.type_position_depth);
        self.owner_stack.truncate(checkpoint.owner_depth);
        self.scope_stack.truncate(checkpoint.lexical_depth);
    }

    /// Run one grammar operation without letting its temporary context escape.
    ///
    /// This restores live scope state on success, recovery, and ordinary
    /// `Result` errors. It does not attempt to recover from a panic.
    fn with_scope_checkpoint<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let checkpoint = self.scope_checkpoint();
        let result = operation(self);
        self.restore_scope_checkpoint(checkpoint);
        result
    }

    fn push_owner(&mut self, decl_index: u32) {
        self.owner_stack.push(decl_index);
    }

    fn token_can_start_binding_identifier(kind: TokenKind) -> bool {
        matches!(
            kind,
            TokenKind::Ident
                | TokenKind::As
                | TokenKind::Async
                | TokenKind::From
                | TokenKind::Of
                | TokenKind::Type
        )
    }

    fn token_can_be_dot_property_identifier(kind: TokenKind) -> bool {
        matches!(
            kind,
            TokenKind::Ident
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
    }

    fn next_token_kind_after_current(&mut self) -> TokenKind {
        let save = self.lexer.checkpoint();
        self.lexer.next();
        let kind = self.lexer.peek().kind;
        self.lexer.restore(save);
        kind
    }

    /// v0.5 commit 2 — `ScopeId` at the top of the scope stack. Always
    /// returns at least `0` (module top-level) because the stack is
    /// initialized with `[0]` and `pop_scope()` refuses to drop the
    /// last entry.
    fn current_scope(&self) -> crate::ts::events::ScopeId {
        self.scope_stack.last().copied().unwrap_or(0)
    }

    /// Push a new lexical scope whose parent is the currently-open
    /// scope. Returns the new `ScopeId`. `enclosing_decl` is recorded
    /// when the scope opener is a declaration boundary (function body,
    /// method body, etc.); pass `None` for plain block / control-flow
    /// body scopes that don't correspond to a declaration.
    fn push_scope(&mut self, enclosing_decl: Option<u32>) -> crate::ts::events::ScopeId {
        let parent = self.current_scope();
        let new_id: crate::ts::events::ScopeId = self.scopes.len() as u32;
        self.scopes.push(crate::ts::events::ScopeInfo {
            parent: Some(parent),
            enclosing_decl,
        });
        self.scope_stack.push(new_id);
        new_id
    }

    /// Pop the currently-open scope. Refuses to drop the module
    /// top-level scope (`ScopeId(0)`) so an over-pop bug can't
    /// corrupt the scope chain.
    fn pop_scope(&mut self) {
        if self.scope_stack.len() > 1 {
            self.scope_stack.pop();
        }
    }

    /// v0.5 commit 3 — push a BindingEvent into the per-file sidecar.
    /// Returns the index of the pushed event so callers that learn
    /// the binding's ClassOrigin later (e.g., after parsing the
    /// optional type annotation or initializer) can update it
    /// in-place via `set_binding_origin`. The scope is captured from
    /// the parser's current scope stack at the call site.
    fn emit_binding(
        &mut self,
        name: String,
        span: crate::spans::Span,
        origin: Option<crate::ts::events::ClassOrigin>,
    ) -> usize {
        let scope = self.current_scope();
        let idx = self.bindings.len();
        self.bindings.push(crate::ts::events::BindingEvent {
            name,
            scope,
            origin,
            span,
        });
        idx
    }

    /// Update the origin of a previously-emitted BindingEvent.
    /// Honors the locked conflict rule: an `ExplicitType` origin
    /// wins over a `Construction` origin (the declared type beats
    /// the initializer's class). Calls with `None` are no-ops so
    /// the caller can blindly attempt a Construction-origin update
    /// after the Eq arm without checking whether ExplicitType
    /// already won.
    fn set_binding_origin(&mut self, idx: usize, origin: Option<crate::ts::events::ClassOrigin>) {
        let Some(new_origin) = origin else {
            return;
        };
        if let Some(b) = self.bindings.get_mut(idx) {
            match (&b.origin, &new_origin) {
                // ExplicitType already set — stays per the conflict rule.
                (Some(crate::ts::events::ClassOrigin::ExplicitType { .. }), _) => {}
                _ => b.origin = Some(new_origin),
            }
        }
    }

    /// Peek-only origin detection. Caller has just consumed a `:`
    /// (start of a type annotation) and the lexer is positioned at
    /// the next token. Returns `Some(class_name)` iff the type is a
    /// single bare Ident followed by a type-annotation-end token
    /// (`,` / `;` / `=` / `)` / `}` / `]` / `=>` / EOF). Anything
    /// more complex (generics, unions, intersections, type-args,
    /// parenthesized types) returns None — v0.5 only resolves
    /// plain-Ident type origins, per the locked conflict rule's
    /// "generics out of scope" carve-out. Does NOT consume input.
    fn peek_explicit_type_origin(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        let tok = self.lexer.next();
        let class_name = self.text_of(tok.span).to_string();
        let next_kind = self.lexer.peek().kind;
        self.lexer.restore(saved);
        if matches!(
            next_kind,
            TokenKind::Comma
                | TokenKind::Semi
                | TokenKind::Eq
                | TokenKind::RParen
                | TokenKind::RBrace
                | TokenKind::RBracket
                | TokenKind::Arrow
                | TokenKind::Eof
        ) {
            Some(class_name)
        } else {
            None
        }
    }

    /// v0.5 commit 4 — emit MemberAccess event(s) for a property
    /// access. The transition owner passes the already-classified access
    /// kinds so publication cannot reinterpret optional-call syntax.
    ///
    /// Returns the pushed event's index in `self.events` when (and only
    /// when) the access classified as `AccessKind::Call` — the caller uses
    /// it to patch in `argument_anchors` once the real argument list has
    /// been scanned (G1.9 S1, mirrors the direct-call Call event's
    /// placeholder-then-patch shape in `emit_ident_ref`). `Read`/`Write`
    /// (and the compound-assign Read+Write pair) never get an index back —
    /// their events keep the `Vec::new()` placeholder permanently, since
    /// there is no argument list to scan.
    fn emit_member_access(
        &mut self,
        receiver: crate::ts::events::MemberReceiver,
        member: String,
        site_span: crate::spans::Span,
        access_kinds: &[crate::ts::events::AccessKind],
    ) -> Option<usize> {
        use crate::ts::events::AccessKind;
        let owner = self.current_owner();
        let mut call_event_idx = None;
        for access in access_kinds {
            let idx = self.events.len();
            self.events.push(Event::Ref(RefEvent::MemberAccess {
                receiver: receiver.clone(),
                member: member.clone(),
                access: *access,
                site_span,
                owner,
                // G1.9 S1 — placeholder, patched by the caller for the
                // Call case (see this fn's doc comment); stays empty for
                // Read/Write.
                argument_anchors: Vec::new(),
            }));
            if matches!(access, AccessKind::Call) {
                call_event_idx = Some(idx);
            }
        }
        call_event_idx
    }

    /// Complete one member-access transition after the member token has been
    /// consumed. This is the sole owner of access classification, chain
    /// retention, generic arguments, call anchors, and call-argument walking
    /// for both body and expression walkers.
    fn complete_member_access(
        &mut self,
        state: &mut MemberAccessState,
        member: String,
        member_end: u32,
    ) -> Result<(), &'static str> {
        let follower_kind = self.lexer.peek().kind;
        let call_follower = self.classify_member_call_follower();
        let is_compound_assign = matches!(
            follower_kind,
            TokenKind::PlusEq
                | TokenKind::MinusEq
                | TokenKind::StarEq
                | TokenKind::SlashEq
                | TokenKind::PercentEq
                | TokenKind::StarStarEq
                | TokenKind::AmpEq
                | TokenKind::PipeEq
                | TokenKind::CaretEq
                | TokenKind::AmpAmpEq
                | TokenKind::PipePipeEq
                | TokenKind::QuestionQuestionEq
                | TokenKind::ShiftLeftEq
                | TokenKind::ShiftRightEq
                | TokenKind::ShiftRightUnsignedEq
        );
        let access_kinds: &[crate::ts::events::AccessKind] = if call_follower.is_call() {
            &[crate::ts::events::AccessKind::Call]
        } else if matches!(follower_kind, TokenKind::Eq) {
            &[crate::ts::events::AccessKind::Write]
        } else if is_compound_assign {
            &[
                crate::ts::events::AccessKind::Read,
                crate::ts::events::AccessKind::Write,
            ]
        } else {
            &[crate::ts::events::AccessKind::Read]
        };
        let mut call_event_idx = None;

        if let Some((receiver, chain_start)) = state.take() {
            let site_length = member_end
                .checked_sub(chain_start)
                .ok_or("member span precedes its receiver")?;
            let site_span = crate::spans::Span::new(chain_start, site_length);
            call_event_idx =
                self.emit_member_access(receiver.clone(), member.clone(), site_span, access_kinds);
            if matches!(follower_kind, TokenKind::Dot | TokenKind::QuestionDot)
                && !call_follower.is_optional()
            {
                state.retain_chain(receiver, member, chain_start);
            }
        }

        if call_follower.is_optional() {
            self.lexer.next();
        }
        if call_follower.is_generic() {
            self.skip_type_args_collecting_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            if let Some(idx) = call_event_idx {
                let argument_anchors = self.scan_call_argument_anchors();
                if let Event::Ref(RefEvent::MemberAccess {
                    argument_anchors: anchors,
                    ..
                }) = &mut self.events[idx]
                {
                    *anchors = argument_anchors;
                }
            }
            let _ = self.walk_call_args_collecting_refs()?;
        }
        Ok(())
    }

    /// Classify every call spelling that may follow a consumed member. The
    /// bounded optional-chain lookahead is restored before returning, so the
    /// completion owner can publish the event before consuming arguments.
    fn classify_member_call_follower(&mut self) -> MemberCallFollower {
        let follower_kind = self.lexer.peek().kind;
        match follower_kind {
            TokenKind::LParen => MemberCallFollower::Parenthesized,
            TokenKind::Lt if looks_like_generic_call_args(self.lexer.source_after_cursor()) => {
                MemberCallFollower::Generic
            }
            TokenKind::QuestionDot => {
                let checkpoint = self.lexer.checkpoint();
                self.lexer.next();
                let optional_follower_kind = self.lexer.peek().kind;
                let follower = match optional_follower_kind {
                    TokenKind::LParen => MemberCallFollower::OptionalParenthesized,
                    TokenKind::Lt
                        if looks_like_generic_call_args(self.lexer.source_after_cursor()) =>
                    {
                        MemberCallFollower::OptionalGeneric
                    }
                    _ => MemberCallFollower::None,
                };
                self.lexer.restore(checkpoint);
                follower
            }
            _ => MemberCallFollower::None,
        }
    }

    /// Admit a receiver into the member-access state machine and immediately
    /// normalize a constant bracket member when present. The walkers decide
    /// only whether an identifier is an eligible receiver; this owner decides
    /// how every supported follower advances the receiver.
    fn begin_member_access(
        &mut self,
        state: &mut MemberAccessState,
        seed: MemberReceiverSeed,
        receiver_span: crate::spans::Span,
    ) -> Result<(), &'static str> {
        match self.lexer.peek().kind {
            TokenKind::Dot | TokenKind::QuestionDot => {
                state.capture(seed.into_receiver(), receiver_span);
            }
            TokenKind::LBracket => {
                if let Some((member, member_end)) = self.try_consume_constant_bracket_member() {
                    state.capture(seed.into_receiver(), receiver_span);
                    self.complete_member_access(state, member, member_end)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Consume `?.` and route its complete follower grammar before either
    /// walker selects its local mode. Named properties retain the receiver;
    /// direct calls and unsupported computed members end it; constant bracket
    /// properties normalize through the same completion owner as dot syntax.
    fn consume_optional_member_follower(
        &mut self,
        state: &mut MemberAccessState,
    ) -> Result<OptionalMemberFollower, &'static str> {
        debug_assert!(matches!(self.lexer.peek().kind, TokenKind::QuestionDot));
        self.lexer.next();

        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            state.discard();
            let _ = self.walk_call_args_collecting_refs()?;
            return Ok(OptionalMemberFollower::Complete);
        }

        if matches!(self.lexer.peek().kind, TokenKind::Lt)
            && looks_like_generic_call_args(self.lexer.source_after_cursor())
        {
            state.discard();
            self.skip_type_args_collecting_refs();
            if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                let _ = self.walk_call_args_collecting_refs()?;
            }
            return Ok(OptionalMemberFollower::Complete);
        }

        if matches!(self.lexer.peek().kind, TokenKind::LBracket) {
            if let Some((member, member_end)) = self.try_consume_constant_bracket_member() {
                self.complete_member_access(state, member, member_end)?;
            } else {
                state.discard();
            }
            return Ok(OptionalMemberFollower::Complete);
        }

        Ok(OptionalMemberFollower::PropertyIdentifier)
    }

    /// Consume `["constant"]` or `['constant']` at the current cursor.
    /// Failed speculation restores the lexer exactly to the opening bracket.
    fn try_consume_constant_bracket_member(&mut self) -> Option<(String, u32)> {
        debug_assert!(matches!(self.lexer.peek().kind, TokenKind::LBracket));
        let saved = self.lexer.checkpoint();
        self.lexer.next();
        let string_token = self.lexer.peek().clone();
        if !matches!(string_token.kind, TokenKind::Str) {
            self.lexer.restore(saved);
            return None;
        }
        self.lexer.next();
        if !matches!(self.lexer.peek().kind, TokenKind::RBracket) {
            self.lexer.restore(saved);
            return None;
        }

        let raw = self.text_of(string_token.span);
        let member = if raw.len() >= 2 && (raw.starts_with('\'') || raw.starts_with('"')) {
            raw[1..raw.len() - 1].to_string()
        } else {
            raw.to_string()
        };
        let closing_bracket = self.lexer.next();
        let member_end = closing_bracket.span.start() + closing_bracket.span.length();
        Some((member, member_end))
    }

    /// Peek-only origin detection. Caller has just consumed an `=`
    /// (start of an initializer expression) and the lexer is
    /// positioned at the next token. Returns `Some(class_name)`
    /// iff the initializer begins with exactly `new Ident(...)` or
    /// `new Ident<...>(`. Does NOT consume input.
    fn peek_construction_origin(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::New) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        self.lexer.next(); // `new`
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            self.lexer.restore(saved);
            return None;
        }
        let tok = self.lexer.next();
        let class_name = self.text_of(tok.span).to_string();
        let next_kind = self.lexer.peek().kind;
        self.lexer.restore(saved);
        if matches!(next_kind, TokenKind::LParen | TokenKind::Lt) {
            Some(class_name)
        } else {
            None
        }
    }

    /// v0.6 commit 2 — peek-only return-type detection for factory
    /// extraction. Caller has just consumed a `:` (start of a
    /// return-type annotation in function-decl, method-decl, or
    /// arrow position) and the lexer is positioned at the next
    /// token. Returns `Some(class_name)` iff the return type is a
    /// plain-Ident class name (with generics optionally stripped),
    /// followed by a terminator that ends the return-type
    /// annotation: `{` (body open), `=>` (arrow body), `;`
    /// (overload signature), or `EOF`. Does NOT consume input.
    ///
    /// Conservative: union (`C | null`), intersection (`C & D`),
    /// type-function (`() => C`), object-literal (`{ client: C }`)
    /// returns, and non-Ident returns (void / never / primitives)
    /// all produce `None`. Mirrors v0.5's plain-Ident-only
    /// ExplicitType rule (Q1 in
    /// `docs/v0.6-factory-return-inference-plan.md`).
    ///
    /// Generic stripping (Q2): `(): C<T>` returns `Some("C")` —
    /// the inner `C` is captured after a balanced `<…>` walk.
    /// Nested generics close via `rescan_gt()`, same shape as the
    /// existing `skip_type_args_collecting_refs` helper.
    fn peek_plain_ident_return_class(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        let tok = self.lexer.next();
        let class_name = self.text_of(tok.span).to_string();
        // Optional `<...>` generic args after the Ident.
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.lexer.next(); // consume `<`
            let mut depth: u32 = 1;
            loop {
                self.lexer.rescan_gt();
                match self.lexer.peek().kind {
                    TokenKind::Lt => {
                        depth += 1;
                        self.lexer.next();
                    }
                    TokenKind::Gt => {
                        depth -= 1;
                        self.lexer.next();
                        if depth == 0 {
                            break;
                        }
                    }
                    TokenKind::Eof => {
                        // Unclosed generic — conservative bail.
                        self.lexer.restore(saved);
                        return None;
                    }
                    _ => {
                        self.lexer.next();
                    }
                }
            }
        }
        let terminator_ok = matches!(
            self.lexer.peek().kind,
            TokenKind::LBrace | TokenKind::Arrow | TokenKind::Semi | TokenKind::Eof
        );
        self.lexer.restore(saved);
        if terminator_ok {
            Some(class_name)
        } else {
            None
        }
    }

    /// v0.7 commit 2 — peek-only field-type detection for
    /// property-chain resolution. Caller has just consumed a `:`
    /// (start of a field-type annotation in class-body position)
    /// and the lexer is positioned at the next token. Returns
    /// `Some(class_name)` iff the field type is a plain-Ident
    /// class name (with generics optionally stripped), followed
    /// by a terminator that ends a class-body field declaration:
    /// `=` (initializer follows), `;` (end of field), `}` (end of
    /// class body), `,` (field separator), `Ident` (next field via
    /// ASI), or `Eof`.
    ///
    /// Same plain-Ident + generic-strip rules as
    /// [`peek_plain_ident_return_class`]; only the terminator set
    /// differs (field position vs return position). Conservative:
    /// union/intersection/object-literal/function-type/non-Ident
    /// field types all produce `None`. Does NOT consume input.
    /// v0.9 — peek the type annotation of a constructor-parameter-property
    /// (`constructor(private readonly svc: Svc) {}` or
    /// `constructor(private readonly box: Box<T>) {}`). Returns the
    /// plain class name with generic args stripped, mirroring the v0.7
    /// commit-2 plain-field semantics
    /// ([[param-property-field-type-gap]] resolution). Returns `None`
    /// for non-Ident types (unions, intersections, function types,
    /// inline object types) — same conservative carve-out as
    /// `peek_plain_ident_field_type_class`. Differs from that helper in
    /// only the terminator set: param-list context terminates on
    /// `Comma | RParen | Eq | Eof` (next param / end of params /
    /// default-value start / EOF) rather than class-body context's
    /// `Eq | Semi | RBrace | Comma | Ident | Eof`. Does NOT consume input.
    fn peek_param_property_field_type_class(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        let tok = self.lexer.next();
        let class_name = self.text_of(tok.span).to_string();
        // Optional `<…>` generic args — balanced, mirrors
        // `peek_plain_ident_field_type_class`.
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.lexer.next();
            let mut depth: u32 = 1;
            loop {
                self.lexer.rescan_gt();
                match self.lexer.peek().kind {
                    TokenKind::Lt => {
                        depth += 1;
                        self.lexer.next();
                    }
                    TokenKind::Gt => {
                        depth -= 1;
                        self.lexer.next();
                        if depth == 0 {
                            break;
                        }
                    }
                    TokenKind::Eof => {
                        self.lexer.restore(saved);
                        return None;
                    }
                    _ => {
                        self.lexer.next();
                    }
                }
            }
        }
        let terminator_ok = matches!(
            self.lexer.peek().kind,
            TokenKind::Comma | TokenKind::RParen | TokenKind::Eq | TokenKind::Eof
        );
        self.lexer.restore(saved);
        if terminator_ok {
            Some(class_name)
        } else {
            None
        }
    }

    fn peek_plain_ident_field_type_class(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        let tok = self.lexer.next();
        let class_name = self.text_of(tok.span).to_string();
        // Optional `<…>` generic args after the Ident.
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.lexer.next();
            let mut depth: u32 = 1;
            loop {
                self.lexer.rescan_gt();
                match self.lexer.peek().kind {
                    TokenKind::Lt => {
                        depth += 1;
                        self.lexer.next();
                    }
                    TokenKind::Gt => {
                        depth -= 1;
                        self.lexer.next();
                        if depth == 0 {
                            break;
                        }
                    }
                    TokenKind::Eof => {
                        self.lexer.restore(saved);
                        return None;
                    }
                    _ => {
                        self.lexer.next();
                    }
                }
            }
        }
        let terminator_ok = matches!(
            self.lexer.peek().kind,
            TokenKind::Eq
                | TokenKind::Semi
                | TokenKind::RBrace
                | TokenKind::Comma
                | TokenKind::Ident
                | TokenKind::Eof
        );
        self.lexer.restore(saved);
        if terminator_ok {
            Some(class_name)
        } else {
            None
        }
    }

    /// v0.6 commit 3 — peek-only factory-call detection. Caller
    /// has just consumed the `=` of a variable initializer (`const
    /// x = …`) and the lexer is positioned at the next token.
    /// Returns `Some(FactoryRef)` iff the initializer is shaped
    /// exactly like:
    ///
    /// - `Ident(…)` or `Ident<…>(…)` — a plain function-call
    ///   factory → `FactoryRef::Plain { name }`.
    /// - `Ident.Ident(…)` or `Ident.Ident<…>(…)` — a static-method
    ///   factory call → `FactoryRef::Static { class_name,
    ///   method_name }`.
    ///
    /// Does NOT consume input. Always restores the lexer
    /// checkpoint before returning.
    ///
    /// The parser doesn't check whether the named factory actually
    /// exists in scope — that's the resolver's job in commits 4-5.
    /// Mirrors the optimistic-emit pattern of
    /// `peek_construction_origin`: capture the syntactic shape now,
    /// let the resolver return `None` if the lookup fails.
    ///
    /// Conservative: non-Ident initializers, deep chains (`a.b.c()`,
    /// `a().b()`), `new C()` (caller checks Construction first),
    /// and arrow expressions all produce `None`.
    fn peek_factory_return_origin(&mut self) -> Option<crate::ts::events::FactoryRef> {
        if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        let tok1 = self.lexer.next();
        let name1 = self.text_of(tok1.span).to_string();
        // Optional `<…>` generic args before `(`.
        let skip_generics = |this: &mut Self| -> bool {
            if !matches!(this.lexer.peek().kind, TokenKind::Lt) {
                return true; // no generics, OK
            }
            this.lexer.next(); // consume `<`
            let mut depth: u32 = 1;
            loop {
                this.lexer.rescan_gt();
                match this.lexer.peek().kind {
                    TokenKind::Lt => {
                        depth += 1;
                        this.lexer.next();
                    }
                    TokenKind::Gt => {
                        depth -= 1;
                        this.lexer.next();
                        if depth == 0 {
                            return true;
                        }
                    }
                    TokenKind::Eof => return false,
                    _ => {
                        this.lexer.next();
                    }
                }
            }
        };
        let next = self.lexer.peek().kind;
        match next {
            TokenKind::LParen => {
                // `f(…)` — plain function factory call.
                self.lexer.restore(saved);
                Some(crate::ts::events::FactoryRef::Plain { name: name1 })
            }
            TokenKind::Lt => {
                // `f<T>(…)` — generic plain factory call.
                if !skip_generics(self) {
                    self.lexer.restore(saved);
                    return None;
                }
                let after_generics = self.lexer.peek().kind;
                self.lexer.restore(saved);
                if matches!(after_generics, TokenKind::LParen) {
                    Some(crate::ts::events::FactoryRef::Plain { name: name1 })
                } else {
                    None
                }
            }
            TokenKind::Dot => {
                self.lexer.next(); // consume `.`
                if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    self.lexer.restore(saved);
                    return None;
                }
                let tok2 = self.lexer.next();
                let name2 = self.text_of(tok2.span).to_string();
                let next_after_member = self.lexer.peek().kind;
                let lparen_follows = match next_after_member {
                    TokenKind::LParen => true,
                    TokenKind::Lt => {
                        if !skip_generics(self) {
                            self.lexer.restore(saved);
                            return None;
                        }
                        matches!(self.lexer.peek().kind, TokenKind::LParen)
                    }
                    _ => false,
                };
                self.lexer.restore(saved);
                if lparen_follows {
                    Some(crate::ts::events::FactoryRef::Static {
                        class_name: name1,
                        method_name: name2,
                    })
                } else {
                    None
                }
            }
            _ => {
                self.lexer.restore(saved);
                None
            }
        }
    }

    /// v0.6 commit 2 — peek-only detection for const-arrow factory
    /// initializers. Caller has just consumed the `=` of a variable
    /// initializer (`const f = …`) and the lexer is positioned at
    /// the next token. Returns `Some(class_name)` iff the
    /// initializer is shaped exactly like `(<params>): C => …` or
    /// `(): C => …` — a parenthesized parameter list, an
    /// immediately-following `:`, a plain-Ident return type
    /// (generics optionally stripped, same rule as
    /// [`peek_plain_ident_return_class`]), and then `=>`. Does NOT
    /// consume input.
    ///
    /// The caller is expected to push a `FunctionReturn { name,
    /// class_name, decl_index }` entry into the per-file
    /// `function_returns` sidecar, where `name` is the
    /// variable-binder name and `decl_index` is the
    /// `DeclEvent::Variable` index.
    ///
    /// Conservative: any non-arrow initializer (`function`-expr,
    /// `new C()`, `f(…)`, literals, identifiers) produces `None`.
    /// Arrows without a declared return type produce `None`
    /// (matches v0.6 Q9 — body-inferred returns are out of scope).
    /// Single-param arrows without parens (`const f = x => …`)
    /// produce `None` (no parens to scan, no declared return).
    fn peek_const_arrow_factory_return_class(&mut self) -> Option<String> {
        if !matches!(self.lexer.peek().kind, TokenKind::LParen) {
            return None;
        }
        let saved = self.lexer.checkpoint();
        self.lexer.next(); // consume `(`
                           // Skip balanced `(...)`. Parens nest within params via
                           // `(a: (x: T) => U)` so depth-track LParen/RParen. We don't
                           // need to recognize nested generics here — `Lt`/`Gt` inside
                           // params is allowed (e.g., `(x: Array<T>)`) but it doesn't
                           // interact with our paren balance.
        let mut depth: u32 = 1;
        loop {
            match self.lexer.peek().kind {
                TokenKind::LParen => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    depth -= 1;
                    self.lexer.next();
                    if depth == 0 {
                        break;
                    }
                }
                TokenKind::Eof => {
                    self.lexer.restore(saved);
                    return None;
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
        // After `)`, require `:` for a declared return type.
        if !matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.restore(saved);
            return None;
        }
        self.lexer.next(); // consume `:`
                           // Reuse the plain-Ident return-type peek. It does its own
                           // save/restore — but we're already inside our outer save
                           // window, so we must always restore the outer checkpoint
                           // before returning regardless of the inner result.
        let captured = self.peek_plain_ident_return_class();
        // The inner peek_plain_ident_return_class restored its own
        // checkpoint, so the lexer is positioned at the start of
        // the return-type tokens. After `:`-consume, that position
        // is the first token of the return type. The inner peek
        // already verified that a terminator follows (one of `{`,
        // `=>`, `;`, `EOF`) — for const-arrow factories the
        // expected terminator is `=>`. Verify that here so we
        // don't capture `: C { … }` shapes that aren't arrows.
        let result = if let Some(c) = captured {
            // Walk past the return type tokens to confirm `=>`
            // follows. We can re-peek using the same generics-
            // stripping inline (don't re-call the helper because
            // it returns before checking which terminator).
            if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                self.lexer.next(); // Ident
                if matches!(self.lexer.peek().kind, TokenKind::Lt) {
                    self.lexer.next();
                    let mut d: u32 = 1;
                    loop {
                        self.lexer.rescan_gt();
                        match self.lexer.peek().kind {
                            TokenKind::Lt => {
                                d += 1;
                                self.lexer.next();
                            }
                            TokenKind::Gt => {
                                d -= 1;
                                self.lexer.next();
                                if d == 0 {
                                    break;
                                }
                            }
                            TokenKind::Eof => {
                                self.lexer.restore(saved);
                                return None;
                            }
                            _ => {
                                self.lexer.next();
                            }
                        }
                    }
                }
                if matches!(self.lexer.peek().kind, TokenKind::Arrow) {
                    Some(c)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        self.lexer.restore(saved);
        result
    }
}

/// Constructor parameter-property fields buffered until their constructor has
/// finished parsing. Classes and ordinary members reserve identity immediately.
#[derive(Debug, Clone)]
pub(crate) struct PendingMethod {
    pub(crate) name: String,
    pub(crate) name_span: crate::spans::Span,
    pub(crate) decl_span: crate::spans::Span,
    pub(crate) body_span: crate::spans::Span,
    pub(crate) is_static: bool,
    pub(crate) kind: crate::ts::events::MemberKind,
    /// v0.6 commit 1 — plain-Ident class name from the member's
    /// declared return type, populated only when the member is a
    /// `is_static: true` method with a plain-Ident return-type
    /// annotation. Always `None` in commit 1 (extraction lands in
    /// commit 2). Flows through to `DeclEvent::Method.return_class_name`
    /// at class-decl emission time.
    pub(crate) return_class_name: Option<String>,
    /// v0.7 commit 1 — plain-Ident class name from the member's
    /// declared field type, populated only when `kind ==
    /// MemberKind::Field`. Always `None` in commit 1 (extraction
    /// lands in commit 2). Flows through to
    /// `DeclEvent::Method.field_type_class` at class-decl emission
    /// time.
    pub(crate) field_type_class: Option<String>,
}

/// Buffered object-literal service/API member, drained when its enclosing
/// function or variable declaration has finished parsing.
#[derive(Debug, Clone)]
pub(crate) struct PendingServiceMember {
    pub(crate) owner_decl_index: u32,
    pub(crate) name: String,
    pub(crate) name_span: crate::spans::Span,
    pub(crate) decl_span: crate::spans::Span,
    pub(crate) body_span: crate::spans::Span,
    pub(crate) kind: crate::ts::events::MemberKind,
    /// G1.7 Fix 2 — the half-open range of `self.events` indexes holding
    /// this member's OWN signature refs (params + return type). At drain
    /// time, once the member's decl_index is known, every
    /// `TypeRef`/`TypeMemberAccess` event in the range has its `owner`
    /// rewritten to the member — moving the edge SOURCE from the enclosing
    /// container to the member node (the F1-mandated attribution lift).
    /// `None` for classic object-literal service members (no rewrite).
    pub(crate) ref_event_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone)]
struct CjsObjectExport {
    exported: String,
    local: String,
    name_span: Span,
    synthetic_decl: bool,
}

#[derive(Debug, Clone)]
struct CjsMemberLabel {
    name: String,
    span: Span,
}

/// A retag candidate bubbled up through the type-parser call chain
/// (`parse_type_reference` -> `parse_primary_type` -> `parse_postfix_type` ->
/// `parse_type_operator` -> `parse_intersection_type` -> `parse_union_type`,
/// F2-2b). `head` is the event index of the bare head `TypeRef`. G1.5 F2-4
/// Part C extends this to also carry `member_access`: the sibling
/// `TypeMemberAccess` event index for a qualified `NS.Type` reference
/// (`parse_type_reference` emits both from the same base classification
/// context), so a union/intersection retag upgrades both events together —
/// otherwise a qualified ref's `TypeMemberAccess`-backed edge would keep its
/// pre-union base position even though the head `TypeRef(NS)` got retagged.
#[derive(Debug, Clone, Copy)]
struct TypeRefRetagCandidate {
    head: usize,
    member_access: Option<usize>,
}

/// Shared fail-safe for the G1.6 call-argument interior-anchor scan
/// (`scan_call_argument_anchors` and every loop/recursion under it).
///
/// Why a mechanism and not per-loop patches: the scan's first cut shipped
/// with a forward-progress guard on the TOP-LEVEL argument loop only; review
/// reproduced infinite spins in the nested array/object loops (a stray
/// closer the literal never opened, e.g. `foo([)` / `foo({ ]`, hits BOTH
/// no-consume delegates — `scan_argument_value_for_anchors`'s `_ => false`
/// arm and `skip_balanced_value`'s depth-0 return — on every iteration) plus
/// a stack overflow on deep array nesting (`[[[[…]]]]` recursed unbounded
/// because arrays are exempt from the semantic object-`depth` bound). That
/// made it the THIRD recurrence of the call-args spin family in this parser
/// (the O(∞) call-args spin and the diag-path O(n²), both 2026-05), so per
/// the standing "fix the mechanism, not the instances" discipline the
/// default now fails safe: every scan loop routes its consumed-nothing case
/// through [`AnchorScanGuard::stalled_bail`], and every literal descent
/// through [`AnchorScanGuard::try_descend`] — a future loop or recursion
/// added to this scan takes `&mut AnchorScanGuard` and inherits both bounds,
/// rather than re-deriving its own guard (or forgetting to).
///
/// The two enforced properties:
///
/// 1. **Forward progress** (`stalled_bail`): a loop iteration that consumed
///    nothing force-consumes ONE token and bails its construct. Termination
///    proof: every iteration of every scan loop now strictly consumes ≥ 1
///    token (via its arms or via the stall path), and every loop breaks at
///    `Eof`, so the whole scan is bounded by the remaining token count.
/// 2. **Total descent bound** (`try_descend`/`ascend`): counts EVERY level
///    of literal structure — arrays AND objects alike, unlike the object-only
///    `depth` parameter (a *semantic* dotted-path bound, ≤ 4, mirroring
///    Pattern PC) — so path-transparent array nesting still cannot recurse
///    toward stack overflow. Exceeding the bound truncates (the literal is
///    consumed iteratively via `skip_balanced_value`, no anchors reported),
///    never panics or aborts.
///
/// Losing anchors on adversarial/malformed input is the accepted trade in
/// both cases: the whole scan is checkpoint/restore-bracketed, so bailing
/// early can never affect the real walk — only forgo anchor evidence that
/// malformed arguments couldn't meaningfully carry anyway.
struct AnchorScanGuard {
    /// Levels of literal structure the scan may still descend into.
    descent_remaining: u32,
}

impl AnchorScanGuard {
    /// Generous for real code (the semantic object bound already cuts at 4;
    /// more than 32 combined array/object levels inside ONE call argument is
    /// adversarial), tiny for the stack (a few frames per level).
    const TOTAL_DESCENT_BOUND: u32 = 32;

    fn new() -> Self {
        Self {
            descent_remaining: Self::TOTAL_DESCENT_BOUND,
        }
    }

    /// Claim one level of literal descent. `false` = bound exhausted: the
    /// caller must NOT recurse — consume the construct iteratively
    /// (`skip_balanced_value`) and report "no callback found".
    fn try_descend(&mut self) -> bool {
        if self.descent_remaining == 0 {
            return false;
        }
        self.descent_remaining -= 1;
        true
    }

    /// Release the level claimed by the matching `try_descend` — this is a
    /// stack-DEPTH bound, not a total-node budget, so siblings don't starve.
    fn ascend(&mut self) {
        self.descent_remaining += 1;
    }

    /// Forward-progress check for one loop iteration: `pos_before` is the
    /// peeked position captured at the top of the iteration. If the cursor
    /// has not advanced, force-consume one token (never at `Eof`) and return
    /// `true`, meaning the loop must bail its construct NOW.
    fn stalled_bail(&mut self, lexer: &mut Lexer<'_>, pos_before: u32) -> bool {
        if lexer.peek().span.start() != pos_before {
            return false;
        }
        if !matches!(lexer.peek().kind, TokenKind::Eof) {
            lexer.next();
        }
        true
    }
}

impl<'src> Parser<'src> {
    fn pop_owner(&mut self) {
        self.owner_stack.pop();
    }

    /// Push a decl event and return its `decl_index` (the number of decls
    /// that preceded it). Centralizes the `decl_count` invariant so every
    /// decl-emitting parser stays in sync.
    fn push_decl(&mut self, d: DeclEvent) -> u32 {
        if self.ambient_global_body_depth > 0
            && self.ambient_declaration_body_depth == self.ambient_global_body_depth
        {
            let name = match &d {
                DeclEvent::Function { name, .. }
                | DeclEvent::Class { name, .. }
                | DeclEvent::Interface { name, .. }
                | DeclEvent::Namespace { name, .. }
                | DeclEvent::TypeAlias { name, .. }
                | DeclEvent::Enum { name, .. }
                | DeclEvent::Variable { name, .. } => Some(name.clone()),
                DeclEvent::Method { .. } | DeclEvent::ServiceMember { .. } => None,
            };
            if let Some(name) = name {
                self.ambient_global_decl_names.push(name);
            }
        }
        let idx = self.decl_count;
        self.events.push(Event::Decl(d));
        self.decl_count += 1;
        idx
    }

    fn record_service_member(
        &mut self,
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
        kind: crate::ts::events::MemberKind,
    ) {
        let Some(owner_decl_index) = self.current_owner() else {
            return;
        };
        self.pending_service_members.push(PendingServiceMember {
            owner_decl_index,
            name,
            name_span,
            decl_span,
            body_span,
            kind,
            ref_event_range: None,
        });
    }

    /// G1.7 Fix 2 — buffer a FUNCTION-TYPED interface/alias member
    /// (`m(x: T): R`, `get: (x: T) => R`, or the anonymous call signature
    /// `(x: T): R` under the reserved name `"()"`), carrying the event
    /// range of its own signature refs for the drain-time owner rewrite.
    /// Only called when `type_member_minting_owner`/`alias_object_mint`
    /// armed the enclosing container, so classic object-literal service
    /// members and nested/anonymous object types never route here.
    fn record_type_member(
        &mut self,
        name: String,
        name_span: Span,
        decl_span: Span,
        ref_event_range: (usize, usize),
    ) {
        let Some(owner_decl_index) = self.current_owner() else {
            return;
        };
        self.pending_service_members.push(PendingServiceMember {
            owner_decl_index,
            name,
            name_span,
            decl_span,
            body_span: Span::new(0, 0),
            kind: crate::ts::events::MemberKind::Method,
            ref_event_range: Some(ref_event_range),
        });
    }

    fn drain_service_members_for_owner(&mut self, owner_decl_index: u32) {
        let mut idx = 0;
        while idx < self.pending_service_members.len() {
            if self.pending_service_members[idx].owner_decl_index != owner_decl_index {
                idx += 1;
                continue;
            }
            let member = self.pending_service_members.remove(idx);
            let member_decl_index = self.push_decl(DeclEvent::ServiceMember {
                name: member.name,
                name_span: member.name_span,
                decl_span: member.decl_span,
                body_span: member.body_span,
                owner_decl_index,
                kind: member.kind,
            });
            // G1.7 Fix 2 — re-attribute the member's own signature refs
            // (recorded while the container was the current owner, before
            // this member's decl_index existed) to the member itself, so
            // the graph's TypeRef edges originate at the member node. The
            // mutation-after-emit pattern follows the established
            // `retag_type_ref_event` precedent.
            if let Some((start, end)) = member.ref_event_range {
                for ev in &mut self.events[start..end] {
                    match ev {
                        Event::Ref(RefEvent::TypeRef { owner, .. })
                        | Event::Ref(RefEvent::TypeMemberAccess { owner, .. }) => {
                            *owner = Some(member_decl_index);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// G1.7 Fix 2 — lookahead: does the type expression starting at the
    /// cursor begin with a FUNCTION type (`(params) => R` or the generic
    /// arrow `<T>(params) => R`)? Checkpoint/restore — consumes nothing.
    /// `Lt` is decisive on its own (a property VALUE type starting with
    /// `<` can only be a generic function type). `LParen` needs the
    /// balanced-paren scan to distinguish `(x: T) => R` from a
    /// parenthesized type `(A | B)`; the token budget bails adversarial
    /// input to "not function-shaped" (no minting — fail-safe: behavior
    /// identical to today).
    fn peek_type_is_function_shaped(&mut self) -> bool {
        match self.lexer.peek().kind {
            TokenKind::Lt => true,
            TokenKind::LParen => {
                const SCAN_BUDGET: u32 = 4096;
                let saved = self.lexer.checkpoint();
                self.lexer.next(); // `(`
                let mut depth: i32 = 1;
                let mut budget = SCAN_BUDGET;
                let mut is_function = false;
                while depth > 0 && budget > 0 {
                    budget -= 1;
                    match self.lexer.next().kind {
                        TokenKind::LParen => depth += 1,
                        TokenKind::RParen => depth -= 1,
                        TokenKind::Eof => break,
                        _ => {}
                    }
                }
                if depth == 0 && matches!(self.lexer.peek().kind, TokenKind::Arrow) {
                    is_function = true;
                }
                self.lexer.restore(saved);
                is_function
            }
            _ => false,
        }
    }

    fn object_property_value_is_function_like(&mut self) -> bool {
        let saved = self.lexer.checkpoint();
        let mut ok = false;

        if matches!(self.lexer.peek().kind, TokenKind::Question) {
            self.lexer.next();
        }
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            ok = match self.lexer.peek().kind {
                TokenKind::Function => true,
                TokenKind::Async => {
                    self.lexer.next();
                    matches!(
                        self.lexer.peek().kind,
                        TokenKind::Function | TokenKind::LParen
                    )
                }
                TokenKind::LParen => {
                    looks_like_arrow_param_list(self.lexer.source_after_cursor())
                        || paren_list_is_arrow_with_optional_return(
                            self.lexer.source_after_cursor(),
                        )
                }
                _ => false,
            };
        }

        self.lexer.restore(saved);
        ok
    }

    fn push_value_scope(&mut self) {
        self.value_scopes.push(std::collections::HashSet::new());
        self.const_string_scopes
            .push(std::collections::HashMap::new());
        self.const_string_decl_shadow_scopes
            .push(std::collections::HashSet::new());
        // v0.5 commit 2 — every value-scope boundary in the parser
        // (function/method/arrow/object-shorthand bodies) is also a
        // lexical-scope boundary. Push the corresponding ScopeId so
        // the per-file scopes sidecar tracks the same nesting.
        // `enclosing_decl` defaults to the current owner_stack top,
        // which captures the enclosing declaration when one is in
        // flight (function/method/class body); arrow-function bodies
        // inside an enclosing decl correctly inherit that decl as
        // their enclosing scope opener.
        let enclosing = self.current_owner();
        self.push_scope(enclosing);
    }

    fn pop_value_scope(&mut self) {
        self.value_scopes.pop();
        self.const_string_scopes.pop();
        self.const_string_decl_shadow_scopes.pop();
        self.pop_scope();
    }

    fn record_value_binder_undo(&mut self, name: &str) {
        if self.declaration_checkpoint_depth > 0 {
            let scope = self.current_scope();
            let lexical_present = self
                .lexical_value_binders
                .contains(&(scope, name.to_string()));
            let value_scope = self
                .value_scopes
                .len()
                .checked_sub(1)
                .map(|index| (index, self.value_scopes[index].contains(name)));
            self.declaration_undo.push(DeclarationUndo::ValueBinder {
                scope,
                name: name.to_string(),
                lexical_present,
                value_scope,
            });
        }
    }

    fn note_value_binder(&mut self, name: &str) {
        self.record_value_binder_undo(name);
        self.lexical_value_binders
            .insert((self.current_scope(), name.to_string()));
        if let Some(top) = self.value_scopes.last_mut() {
            top.insert(name.to_string());
        }
    }

    fn note_predeclared_value_binder(&mut self, name: &str, span: Span) {
        self.record_value_binder_undo(name);
        let value_scope = self.value_scopes.len().checked_sub(1);
        if let Some(index) = value_scope {
            self.value_scopes[index].insert(name.to_string());
        }
        self.predeclared_value_binders.push(PredeclaredValueBinder {
            scope: self.current_scope(),
            name: name.to_string(),
            span,
            value_scope,
            const_scope: self.const_string_scopes.len() - 1,
        });
    }

    fn note_const_string_binder(&mut self, name: &str, value: String) {
        if self.declaration_checkpoint_depth > 0 {
            if let Some(scope) = self.const_string_scopes.len().checked_sub(1) {
                self.declaration_undo
                    .push(DeclarationUndo::ConstStringBinder {
                        scope,
                        name: name.to_string(),
                        previous: self.const_string_scopes[scope].get(name).cloned(),
                    });
            }
        }
        if let Some(top) = self.const_string_scopes.last_mut() {
            top.insert(name.to_string(), value);
        }
    }

    fn note_const_string_decl_shadow(&mut self, name: &str) {
        if self.declaration_checkpoint_depth > 0 {
            if let Some(scope) = self.const_string_decl_shadow_scopes.len().checked_sub(1) {
                self.declaration_undo
                    .push(DeclarationUndo::ConstStringShadow {
                        scope,
                        name: name.to_string(),
                        present: self.const_string_decl_shadow_scopes[scope].contains(name),
                    });
            }
        }
        if let Some(top) = self.const_string_decl_shadow_scopes.last_mut() {
            top.insert(name.to_string());
        }
    }

    fn const_string_in_scope(&self, name: &str) -> Option<&str> {
        for (scope_index, scope) in self.const_string_scopes.iter().enumerate().rev() {
            if let Some(value) = scope.get(name) {
                return Some(value.as_str());
            }
            if self
                .const_string_decl_shadow_scopes
                .get(scope_index)
                .is_some_and(|shadows| shadows.contains(name))
            {
                return None;
            }
            // const_string_scopes[0] is the module scope; each later entry is
            // paired with value_scopes[index - 1]. A nearer runtime-valued
            // binder shadows an outer constant even though it has no constant
            // value to store here.
            if scope_index > 0
                && self
                    .value_scopes
                    .get(scope_index - 1)
                    .is_some_and(|value_scope| value_scope.contains(name))
            {
                return None;
            }
        }
        None
    }

    /// Return whether the current one-token initializer ends at a declaration
    /// boundary. This is the fail-safe distinction between an exact atom and a
    /// larger expression such as `'./services/' + name` or `base + suffix`.
    fn current_initializer_atom_is_exact(&mut self) -> bool {
        let checkpoint = self.lexer.checkpoint();
        self.lexer.next();
        let next = self.lexer.peek().clone();
        let had_line_terminator = self.lexer.had_line_terminator();
        self.lexer.restore(checkpoint);

        let explicit_end = matches!(
            next.kind,
            TokenKind::Comma
                | TokenKind::Semi
                | TokenKind::RParen
                | TokenKind::RBrace
                | TokenKind::Eof
        );
        let asi_statement_start = had_line_terminator
            && matches!(
                next.kind,
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
                    | TokenKind::Type
                    | TokenKind::Await
            );

        explicit_end || asi_statement_start
    }

    /// Return the compile-time string value when the current initializer is
    /// exactly one string literal or one previously-known const identifier.
    /// The delimiter check lets the parser propagate immutable aliases without
    /// pretending to evaluate larger expressions.
    fn peek_exact_const_string_initializer(&mut self) -> Option<String> {
        let tok = self.lexer.peek().clone();
        let value = match tok.kind {
            TokenKind::Str => self.read_str_literal(tok).0,
            TokenKind::Ident => {
                let name = self.text_of(tok.span).to_string();
                self.const_string_in_scope(&name)?.to_string()
            }
            _ => return None,
        };

        self.current_initializer_atom_is_exact().then_some(value)
    }

    /// Capture the current initializer into the lexical constant table when
    /// it is either a string literal or an exact alias of an earlier immutable
    /// string. Callers own the `const` check; this helper is shared by module
    /// declarations and declarations inside function/block bodies.
    fn note_const_string_initializer(&mut self, binder_name: &str) {
        if let Some(value) = self.peek_exact_const_string_initializer() {
            self.note_const_string_binder(binder_name, value);
        }
    }

    fn body_statement_boundary(prev_kind: TokenKind) -> bool {
        matches!(
            prev_kind,
            TokenKind::Eof | TokenKind::Semi | TokenKind::LBrace | TokenKind::RBrace
        )
    }

    fn token_can_end_expression_statement(prev_kind: TokenKind) -> bool {
        matches!(
            prev_kind,
            TokenKind::Ident
                | TokenKind::Number
                | TokenKind::Str
                | TokenKind::Regex
                | TokenKind::TemplateStart
                | TokenKind::TemplateEnd
                | TokenKind::RParen
                | TokenKind::RBracket
                | TokenKind::RBrace
                | TokenKind::Bang
                | TokenKind::PlusPlus
                | TokenKind::MinusMinus
        )
    }

    fn token_can_precede_postfix_non_null(kind: TokenKind) -> bool {
        matches!(
            kind,
            TokenKind::Ident
                | TokenKind::Number
                | TokenKind::Str
                | TokenKind::Regex
                | TokenKind::TemplateStart
                | TokenKind::TemplateEnd
                | TokenKind::RParen
                | TokenKind::RBracket
                | TokenKind::RBrace
                | TokenKind::PlusPlus
                | TokenKind::MinusMinus
        )
    }

    /// Consume `!` and choose the next slash's lexical meaning from the
    /// expression state that precedes it. Returns whether this `!` was the
    /// postfix TypeScript non-null operator so callers can classify `!!`.
    fn consume_expression_bang(
        &mut self,
        prev_kind: TokenKind,
        previous_bang_was_postfix: bool,
    ) -> bool {
        debug_assert!(matches!(self.lexer.peek().kind, TokenKind::Bang));
        let is_postfix = Self::token_can_precede_postfix_non_null(prev_kind)
            || (matches!(prev_kind, TokenKind::Bang) && previous_bang_was_postfix);
        self.lexer.next();
        if is_postfix {
            self.lexer.deny_regex_for_next();
        }
        is_postfix
    }

    /// Consume tokens up to, but not including, the next sibling delimiter.
    /// Balanced `()`, `{}`, and `[]` groups are consumed as one value. A
    /// closer is consumed only when it matches nesting opened by this call.
    fn skip_balanced_value(&mut self) {
        let mut depth: i32 = 0;
        loop {
            match self.lexer.peek().kind {
                TokenKind::LParen | TokenKind::LBrace | TokenKind::LBracket => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen | TokenKind::RBrace | TokenKind::RBracket => {
                    if depth == 0 {
                        return;
                    }
                    depth -= 1;
                    self.lexer.next();
                }
                TokenKind::Comma if depth == 0 => return,
                TokenKind::Eof => return,
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    fn token_expects_expression_rhs(prev_kind: TokenKind) -> bool {
        matches!(
            prev_kind,
            TokenKind::Eq
                | TokenKind::PlusEq
                | TokenKind::MinusEq
                | TokenKind::StarEq
                | TokenKind::SlashEq
                | TokenKind::PercentEq
                | TokenKind::StarStarEq
                | TokenKind::AmpEq
                | TokenKind::PipeEq
                | TokenKind::CaretEq
                | TokenKind::AmpAmpEq
                | TokenKind::PipePipeEq
                | TokenKind::QuestionQuestionEq
                | TokenKind::ShiftLeftEq
                | TokenKind::ShiftRightEq
                | TokenKind::ShiftRightUnsignedEq
        )
    }

    fn current_token_starts_label_statement(&mut self) -> bool {
        let save = self.lexer.checkpoint();
        let is_label = if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            self.lexer.next();
            matches!(self.lexer.peek().kind, TokenKind::Colon)
        } else {
            false
        };
        self.lexer.restore(save);
        is_label
    }

    fn parse_labeled_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // label name
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
        }
        let next = self.lexer.peek().clone();
        if matches!(next.kind, TokenKind::Eof | TokenKind::RBrace) {
            return Ok(());
        }
        self.parse_statement(&next)
    }

    fn current_token_starts_named_function_decl(&mut self, async_prefix: bool) -> bool {
        let save = self.lexer.checkpoint();
        if async_prefix {
            if !matches!(self.lexer.peek().kind, TokenKind::Async) {
                self.lexer.restore(save);
                return false;
            }
            self.lexer.next();
        }
        if !matches!(self.lexer.peek().kind, TokenKind::Function) {
            self.lexer.restore(save);
            return false;
        }
        self.lexer.next();
        if matches!(self.lexer.peek().kind, TokenKind::Star) {
            self.lexer.next();
        }
        let ok = matches!(self.lexer.peek().kind, TokenKind::Ident);
        self.lexer.restore(save);
        ok
    }

    fn current_token_starts_named_class_decl(&mut self) -> bool {
        let save = self.lexer.checkpoint();
        let ok = if matches!(self.lexer.peek().kind, TokenKind::Class) {
            self.lexer.next();
            matches!(self.lexer.peek().kind, TokenKind::Ident)
        } else {
            false
        };
        self.lexer.restore(save);
        ok
    }

    fn current_token_starts_abstract_class_decl(&mut self) -> bool {
        let save = self.lexer.checkpoint();
        let ok = if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let abstract_tok = self.lexer.peek().clone();
            if self.text_of(abstract_tok.span) == "abstract" {
                self.lexer.next();
                if matches!(self.lexer.peek().kind, TokenKind::Class) {
                    self.lexer.next();
                    matches!(self.lexer.peek().kind, TokenKind::Ident)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        self.lexer.restore(save);
        ok
    }

    fn current_token_starts_const_enum_decl(&mut self) -> bool {
        let save = self.lexer.checkpoint();
        let ok = if matches!(self.lexer.peek().kind, TokenKind::Const) {
            self.lexer.next();
            matches!(self.lexer.peek().kind, TokenKind::Enum)
        } else {
            false
        };
        self.lexer.restore(save);
        ok
    }

    fn push_type_param_scope(&mut self) {
        self.type_param_scopes
            .push(std::collections::HashSet::new());
    }

    fn pop_type_param_scope(&mut self) {
        self.type_param_scopes.pop();
    }

    fn note_type_param_binder(&mut self, name: &str) {
        if let Some(top) = self.type_param_scopes.last_mut() {
            top.insert(name.to_string());
        }
    }

    fn is_type_param_in_scope(&self, name: &str) -> bool {
        self.type_param_scopes.iter().any(|s| s.contains(name))
    }

    /// Emit a TypeRef unless the name is an in-scope type-parameter binder
    /// or a TS built-in primitive type. `position` is the parse-time
    /// classification of the reference (G1.5 Fix 2): the structured
    /// type-parser call sites pass `self.current_type_pos()`; the token-walk
    /// call sites pass the literal context they know statically.
    ///
    /// Returns the emitted event's index (`None` when suppressed) so that
    /// `parse_type_reference` can hand the head ref up the type-parsing chain
    /// as a union/intersection retag CANDIDATE (F2-2b): only refs positively
    /// identified as bare direct members ever get retagged to
    /// `CompositionMember` — see `parse_union_type`.
    fn emit_type_ref(
        &mut self,
        name: String,
        ref_span: Span,
        position: TypeRefPosition,
    ) -> Option<usize> {
        if self.is_type_param_in_scope(&name) {
            return None;
        }
        if is_ts_primitive_type(&name) {
            return None;
        }
        // Built-in/ambient types (Promise/Array/Record/…) are NO LONGER
        // suppressed here — they emit a TypeRef and the resolver drops them
        // when they resolve to no local/imported type (see A5).
        let owner = self.current_owner();
        let scope = self.current_scope();
        let event_index = self.events.len();
        self.events.push(Event::Ref(RefEvent::TypeRef {
            name,
            ref_span,
            owner,
            scope,
            position,
        }));
        Some(event_index)
    }

    /// The base `TypeRefPosition` currently in effect for the structured type
    /// parser (top of `pos_stack`). Empty stack => `Other` (fail-open).
    fn current_type_pos(&self) -> TypeRefPosition {
        self.pos_stack
            .last()
            .copied()
            .unwrap_or(TypeRefPosition::Other)
    }

    /// Retag one previously-emitted `TypeRef` event (and its qualified-ref
    /// `TypeMemberAccess` sibling, if any — G1.5 F2-4 Part C) as
    /// `CompositionMember`. F2-2b: called by
    /// `parse_union_type`/`parse_intersection_type` ONLY for
    /// positively-identified candidates — a member that parsed as a bare
    /// (possibly generic, possibly qualified) type reference, in a composition
    /// with >= 2 members. Everything else (postfix'd, operator-prefixed,
    /// parenthesized, tuple/object/function/template members, and any FUTURE
    /// construct) keeps its base-context position: unknown shapes default to
    /// NOT demoted (fail-safe), instead of inheriting demotion from a depth
    /// heuristic.
    fn retag_event_as_composition_member(&mut self, candidate: TypeRefRetagCandidate) {
        if let Some(Event::Ref(RefEvent::TypeRef { position, .. })) =
            self.events.get_mut(candidate.head)
        {
            *position = TypeRefPosition::CompositionMember;
        }
        if let Some(member_access) = candidate.member_access {
            if let Some(Event::Ref(RefEvent::TypeMemberAccess { position, .. })) =
                self.events.get_mut(member_access)
            {
                *position = TypeRefPosition::CompositionMember;
            }
        }
    }

    /// `NS.Type` qualified reference sidecar (`emit_type_ref` above emits the
    /// root `TypeRef(NS)`). `position` is the SAME base classification
    /// context as the sibling head ref — `parse_type_reference` passes
    /// `self.current_type_pos()` for both, so a later union/intersection
    /// retag (F2-2b, extended G1.5 F2-4 Part C) can upgrade both events
    /// together via `TypeRefRetagCandidate`.
    fn emit_type_member_access(
        &mut self,
        namespace: String,
        member: String,
        ref_span: Span,
        position: TypeRefPosition,
    ) -> usize {
        let owner = self.current_owner();
        let event_index = self.events.len();
        self.events.push(Event::Ref(RefEvent::TypeMemberAccess {
            namespace,
            member,
            ref_span,
            owner,
            scope: self.current_scope(),
            position,
        }));
        event_index
    }

    fn emit_type_query_value_ref(&mut self, name: String, ref_span: Span) {
        let owner = self.current_owner();
        self.events.push(Event::Ref(RefEvent::TypeQueryRef {
            name,
            ref_span,
            owner,
            scope: self.current_scope(),
        }));
    }

    fn into_parsed_file(mut self) -> ParsedFile {
        // Overload signatures share the implementation's identity. Resolve by
        // lexical scope and name after parsing, never by a reusable future index.
        let local_scopes: std::collections::HashMap<_, _> = self
            .local_value_decls
            .iter()
            .map(|decl| (decl.decl_index, decl.scope))
            .collect();
        let implementations: std::collections::HashMap<_, _> = self
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Decl(decl) => Some(decl),
                _ => None,
            })
            .enumerate()
            .filter_map(|(index, decl)| match decl {
                DeclEvent::Function {
                    name, body_span, ..
                } if body_span.length() > 0 => Some((
                    (
                        local_scopes.get(&(index as u32)).copied().unwrap_or(0),
                        name.clone(),
                    ),
                    index as u32,
                )),
                _ => None,
            })
            .collect();
        for (name, scope, parent, range) in &self.pending_function_overloads {
            let owner = implementations
                .get(&(*scope, name.clone()))
                .copied()
                .or(*parent);
            for event in &mut self.events[range.clone()] {
                if let Event::Ref(reference) = event {
                    match reference {
                        RefEvent::TypeRef { owner: current, .. }
                        | RefEvent::TypeQueryRef { owner: current, .. }
                        | RefEvent::TypeMemberAccess { owner: current, .. } => *current = owner,
                        _ => {}
                    }
                }
            }
        }
        // Resolve suppression against the completed lexical binding table,
        // not the order in which declarations happened to be parsed. A nearer
        // non-graph binding must also block an outer declaration with the
        // same name. Module bindings remain the resolver's responsibility.
        let mut lexical = std::collections::HashMap::new();
        for (scope, name) in &self.lexical_value_binders {
            lexical.insert((*scope, name.as_str()), false);
        }
        // Hoisted scan entries become evidence only when their exact source
        // binding survives parsing. Scope/name alone cannot distinguish a
        // failed declaration from an earlier or later declaration of that name.
        let completed_bindings: std::collections::HashSet<_> = self
            .bindings
            .iter()
            .map(|binding| (binding.span.start(), binding.name.as_str()))
            .collect();
        for binder in &self.predeclared_value_binders {
            if binder.value_scope.is_some()
                && completed_bindings.contains(&(binder.span.start(), binder.name.as_str()))
            {
                lexical.insert((binder.scope, binder.name.as_str()), false);
            }
        }
        for binding in &self.bindings {
            lexical.insert((binding.scope, binding.name.as_str()), false);
        }
        for decl in &self.local_value_decls {
            lexical.insert((decl.scope, decl.name.as_str()), true);
        }
        self.events.retain(|event| {
            let Event::Ref(
                RefEvent::Call { name, scope, .. }
                | RefEvent::ValueRef { name, scope, .. }
                | RefEvent::TypeQueryRef { name, scope, .. },
            ) = event
            else {
                return true;
            };
            let mut current = Some(*scope);
            while let Some(scope) = current {
                if scope == 0 {
                    break;
                }
                if let Some(graph_visible) = lexical.get(&(scope, name.as_str())) {
                    return *graph_visible;
                }
                current = self.scopes[scope as usize].parent;
            }
            true
        });
        ParsedFile {
            path: self.path,
            events: self.events,
            exports: self.exports,
            diagnostics: self.diagnostics,
            local_type_names: self.local_type_names,
            ambient_global_decl_names: self.ambient_global_decl_names,
            scopes: self.scopes,
            bindings: self.bindings,
            local_value_decls: self.local_value_decls,
            // v0.6 commit 1 — empty until commit 2's parser extraction.
            function_returns: self.function_returns,
        }
    }

    fn parse_program(&mut self) {
        // known-v1-gaps #17: leading triple-slash reference directives
        // (`/// <reference path|types="…" />`) become synthetic type-only
        // Import events before any statement is parsed. The scanner reads only
        // the leading trivia run, so directives after the first token are left
        // as ordinary comments (matches tsc).
        for d in crate::ts::directives::scan_leading_triple_slash_directives(self.source) {
            self.events.push(Event::Ref(RefEvent::Import {
                specifier: d.specifier,
                specifier_span: d.specifier_span,
                bindings: Vec::new(),
                is_type_only: d.is_type_only,
                makes_external_module: false,
            }));
        }
        loop {
            let t = self.lexer.peek().clone();
            if t.kind == TokenKind::Eof {
                break;
            }
            if let Err(reason) = self.parse_statement(&t) {
                self.recover(reason, t.span);
            }
        }
        // known-v1-gaps #22: a `/* … */` block comment that ran to EOF without
        // its closing `*/` is a trivia-level error the parser can't see while
        // tokenizing (comments are skipped). Surface the lexer's recorded span
        // as a SyntaxRecovered diagnostic.
        if let Some(span) = self.lexer.unterminated_block_comment() {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::SyntaxRecovered {
                    context: "unterminated block comment".to_string(),
                },
                file_path: self.path.clone(),
                span,
            });
        }
    }

    // Returns Err to trigger recovery; OK on successful statement parse.
    fn parse_statement(&mut self, t: &Token) -> Result<(), &'static str> {
        self.with_scope_checkpoint(|parser| parser.parse_statement_inner(t))
    }

    fn parse_statement_inner(&mut self, t: &Token) -> Result<(), &'static str> {
        // Punted constructs — explicit diagnostic + skip-to-next-statement.
        // `declare` / `namespace` are contextual (lex as Ident). Compute the
        // `construct` &'static str BEFORE the diagnostics.push: `text` borrows
        // all of `self` (text_of returns a &str with the &self lifetime), so it
        // must not be live across the `&mut self` push — materialize the literal
        // first so `text`'s borrow ends.
        // Materialize the keyword checks as owned bools so the `&str` borrow of
        // `self` ends before the mutable lexer manipulation below.
        let (is_declare_kw, is_namespace_kw) = {
            let text = self.text_of(t.span);
            (text == "declare", text == "namespace")
        };
        // Module augmentation (known-v1-gaps #18): `declare module '<spec>' { … }`
        // augments an external module — a type-level dependency. Recognize the
        // STRING form (not `declare module Foo {}`, which is an ambient namespace
        // and stays punted), emit a type-only Import edge to the specifier, and
        // balance-skip the body (walking ambient declarations is the separate
        // ambient-declarations milestone). Detected via lookahead so non-module
        // `declare` (var/fn/class) falls through to the punt below.
        if is_declare_kw {
            let saved = self.lexer.checkpoint();
            self.lexer.next(); // consume `declare`
            let next_is_module = {
                let p = self.lexer.peek();
                (p.kind, p.span)
            };
            if matches!(next_is_module.0, TokenKind::Type) {
                return self.parse_type_alias_decl(t.span.start(), false);
            }
            if matches!(next_is_module.0, TokenKind::Interface) {
                return self.parse_interface_decl(t.span.start(), false);
            }
            if matches!(next_is_module.0, TokenKind::Function) {
                return self.parse_ambient_function_decl(t.span.start());
            }
            if matches!(
                next_is_module.0,
                TokenKind::Const | TokenKind::Let | TokenKind::Var
            ) {
                return self.parse_variable_decl(t.span.start(), false);
            }
            if matches!(next_is_module.0, TokenKind::Class)
                || (matches!(next_is_module.0, TokenKind::Ident)
                    && self.text_of(next_is_module.1) == "abstract")
            {
                return self.parse_declaration(t.span.start(), false);
            }
            if matches!(next_is_module.0, TokenKind::Ident)
                && self.text_of(next_is_module.1) == "module"
            {
                self.lexer.next(); // consume `module`
                if matches!(self.lexer.peek().kind, TokenKind::Str) {
                    let spec_tok = self.lexer.next();
                    let (specifier, specifier_span) = self.read_str_literal(spec_tok);
                    self.events.push(Event::Ref(RefEvent::Import {
                        specifier,
                        specifier_span,
                        bindings: Vec::new(),
                        is_type_only: true,
                        makes_external_module: false,
                    }));
                    if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                        self.lexer.next(); // consume `{`
                        let mut depth = 1usize;
                        while depth > 0 {
                            match self.lexer.next().kind {
                                TokenKind::LBrace => depth += 1,
                                TokenKind::RBrace => depth -= 1,
                                TokenKind::Eof => break, // malformed; edge already captured
                                _ => {}
                            }
                        }
                    } else if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                        self.lexer.next();
                    }
                    return Ok(());
                }
            }
            self.lexer.restore(saved); // not a string-module augmentation → punt
        }
        // Namespace / ambient-namespace bodies (known-v1-gaps #11): `namespace
        // Foo { … }`, `declare namespace Foo { … }`, `declare global { … }`, and
        // `declare module Foo { … }` (identifier form = ambient namespace). Walk
        // the body for refs via `collect_cf_body` instead of punting it to
        // `recover()`, so refs inside aren't lost. (Registering the nested decls
        // as graph nodes remains the ambient-declarations milestone — out of
        // scope here.) Gated on an actual `{` body so `namespace.foo()` /
        // `namespace;` / `module.exports` are NOT misparsed.
        if (is_declare_kw || is_namespace_kw)
            && self.try_parse_namespace_like_statement(t.span.start(), true)?
        {
            return Ok(());
        }
        // #12: `using x = …` / `await using x = …` resource declarations at
        // statement position.
        if self.try_using_declaration(t)? {
            return Ok(());
        }
        let punted = if is_declare_kw {
            Some("declare")
        } else if is_namespace_kw {
            Some("namespace")
        } else {
            None
        };
        if let Some(construct) = punted {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::UnsupportedConstruct {
                    construct: construct.to_string(),
                },
                file_path: self.path.clone(),
                span: t.span,
            });
            return Err("punted");
        }
        if matches!(t.kind, TokenKind::Ident) && self.current_token_starts_label_statement() {
            return self.parse_labeled_statement();
        }
        // (The `@` decorator case is handled by the `TokenKind::At` match arm
        // below — `@` lexes as its own token after Step 3, never as an Ident.)
        match t.kind {
            TokenKind::Import
                if matches!(self.next_token_kind_after_current(), TokenKind::LParen) =>
            {
                self.walk_expression_collecting_refs()?;
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            TokenKind::Import => self.parse_import_statement(),
            TokenKind::Export => self.parse_export_statement(),
            // `async function f()` — consume `async`, then dispatch to the
            // function decl parser with the original `async` span as the
            // decl-start so the decl_span covers the `async` prefix. If the
            // next token isn't `function`, treat as an expression statement
            // (`async x => ...`, or a value-position `async` ident reference).
            TokenKind::Async => {
                let async_start = t.span.start();
                self.lexer.next(); // consume `async`
                if matches!(self.lexer.peek().kind, TokenKind::Function) {
                    return self.parse_function_decl(async_start, false, None);
                }
                // Not `async function`: rewind isn't possible; treat the rest
                // of the statement as an expression. `async x => ...` is
                // detected in walk_expression's arrow-detection.
                self.walk_expression_collecting_refs()?;
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            TokenKind::Function => self.parse_function_decl(t.span.start(), false, None),
            TokenKind::Class => self.parse_class_decl(t.span.start(), false, None),
            TokenKind::Ident if self.current_token_starts_abstract_class_decl() => {
                self.lexer.next(); // consume contextual `abstract`
                self.parse_class_decl(t.span.start(), false, None)
            }
            TokenKind::Interface => self.parse_interface_decl(t.span.start(), false),
            TokenKind::Type => self.parse_type_alias_decl(t.span.start(), false),
            TokenKind::Enum => self.parse_enum_decl(t.span.start(), false, None),
            TokenKind::Const | TokenKind::Let | TokenKind::Var => {
                // `const enum` is syntactically `const`-prefixed `enum` per
                // TS Handbook §6.4. Peek one ahead via the existing
                // checkpoint API to dispatch correctly; on miss, restore so
                // parse_variable_decl sees the original `const` token.
                if matches!(t.kind, TokenKind::Const) {
                    let save = self.lexer.checkpoint();
                    self.lexer.next(); // tentatively consume `const`
                    if matches!(self.lexer.peek().kind, TokenKind::Enum) {
                        return self.parse_enum_decl(t.span.start(), false, None);
                    }
                    self.lexer.restore(save);
                }
                self.parse_variable_decl(t.span.start(), false)
            }
            TokenKind::At => self.parse_class_level_decorators(t.span),
            TokenKind::Lt => {
                self.diagnostics.push(Diagnostic {
                    kind: DiagnosticKind::SyntaxRecovered {
                        context: "jsx".to_string(),
                    },
                    file_path: self.path.clone(),
                    span: t.span,
                });
                Err("punted")
            }
            // ---- ThrowStatement (ECMA-262 §14.14) ----
            // `throw [no LineTerminator] Expression ;`. Top-level `throw new
            // MyError(...)` is common in module initialization; without this
            // arm the operand expression — and any value-refs / call edges
            // inside it — were lost to the unknown-statement recovery span
            // (audit-5 round-3 finding). Consume `throw`, then walk the
            // operand via the same helper used for other expression-position
            // refs so `MyError` surfaces as a normal ValueRef.
            //
            // Audit-5b review item P2: `throw` is a *restricted production*
            // (§11.9.1) — a LineTerminator between `throw` and the operand
            // triggers ASI on a bare `throw`, which is itself a syntax
            // error since the operand is mandatory. We peek the post-`throw`
            // token to update the lexer's had_line_terminator flag, then
            // gate the walker on both (a) no LineTerminator and (b) the
            // next token actually starts an expression. Without the gate,
            // `throw\nnew MyError(...)` silently absorbs the next-line
            // expression as the operand and emits a phantom `MyError` ref.
            // ---- BreakStatement / ContinueStatement (ECMA-262 §14.8 / §14.9) ----
            // `break [no LineTerminator] LabelIdentifier? ;`
            // `continue [no LineTerminator] LabelIdentifier? ;`
            //
            // R6 audit gap: pre-fix these fell through to the unrecognized
            // recovery, which emitted a `SyntaxRecovered{"unrecognized"}`
            // diagnostic. They contribute ZERO refs to the IR (the optional
            // label is a label-namespace identifier, not a value or type),
            // so the arm just consumes the keyword, optionally the same-line
            // label ident, optionally the `;`, and returns clean. Mirrors
            // Return/Throw for the restricted-production handling (the label
            // must NOT cross a LineTerminator per §11.9.1).
            TokenKind::Break | TokenKind::Continue => {
                self.lexer.next(); // consume `break` / `continue`
                let next_kind = self.lexer.peek().kind;
                let had_lt = self.lexer.had_line_terminator();
                // Optional label — only consume if on the same line AND
                // it's an Ident token (the LabelIdentifier production).
                if !had_lt && matches!(next_kind, TokenKind::Ident) {
                    self.lexer.next();
                }
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            // ---- ReturnStatement (ECMA-262 §14.10) ----
            // `return [no LineTerminator] Expression? ;`. Unlike throw,
            // the operand is OPTIONAL — `return;` and `return\nfoo()` (ASI
            // → bare `return;`) are both legal. The R6 audit pinned that
            // top-level `return helper();` was silently losing the
            // `helper` ref because no Return arm existed; the dispatcher
            // fell through to the unknown-statement recovery and swept
            // the operand. Mirror the Throw arm's restricted-production
            // gate; bare-return is handled as the no-op success path
            // (no diagnostic — `return;` is valid).
            TokenKind::Return => {
                self.lexer.next(); // consume `return`
                let next_kind = self.lexer.peek().kind;
                let had_lt = self.lexer.had_line_terminator();
                let no_operand = matches!(
                    next_kind,
                    TokenKind::Semi | TokenKind::RBrace | TokenKind::Eof
                );
                if had_lt || no_operand {
                    // ASI inserts a semicolon after `return` (or the
                    // operand is genuinely absent). Bare `return;` is
                    // legal — no diagnostic, just consume the semi.
                    if matches!(next_kind, TokenKind::Semi) {
                        self.lexer.next();
                    }
                    return Ok(());
                }
                self.walk_expression_collecting_refs()?;
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            TokenKind::Throw => {
                let throw_tok = self.lexer.next(); // consume `throw`
                                                   // peek() forces skip_trivia for the post-`throw` trivia,
                                                   // which is the trivia had_line_terminator() reflects.
                let next_kind = self.lexer.peek().kind;
                let had_lt = self.lexer.had_line_terminator();
                let no_operand = matches!(
                    next_kind,
                    TokenKind::Semi | TokenKind::RBrace | TokenKind::Eof
                );
                if had_lt || no_operand {
                    self.diagnostics.push(Diagnostic {
                        kind: DiagnosticKind::SyntaxRecovered {
                            context: "throw operand".to_string(),
                        },
                        file_path: self.path.clone(),
                        span: throw_tok.span,
                    });
                    if matches!(next_kind, TokenKind::Semi) {
                        self.lexer.next(); // consume the inserted/explicit `;`
                    }
                    return Ok(());
                }
                self.walk_expression_collecting_refs()?;
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            // ---- Top-level expression statement ----
            // Any statement that starts with an expression: a bare call
            // `helper();`, an identifier reference `someValue;`, or operators
            // like `new`, `typeof`, `void`, `delete`, `await`, `yield`. Without
            // this branch the previous plan silently recovered every
            // `helper();`-style line — including Leg B's `__nonexistent__();`
            // synthetic edit — and the gate produced no Call events at file
            // scope. Walk the expression via the same helper used for variable
            // initializers and class-property RHS so nested Call / ValueRef /
            // TypeRef extraction works identically.
            TokenKind::Ident
            | TokenKind::New
            | TokenKind::Typeof
            | TokenKind::Void
            | TokenKind::Delete
            | TokenKind::Await
            | TokenKind::Yield
            | TokenKind::LParen
            | TokenKind::LBracket => {
                // CommonJS export assignment at statement position:
                // `module.exports = …`, `exports.foo = …`, etc. Detected via
                // checkpoint/restore — a non-match restores and falls through
                // to the normal expression walk, so this is bounded-risk.
                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    let sp = self.lexer.peek().span;
                    let is_cjs_lead = {
                        let lead = self.text_of(sp);
                        lead == "module" || lead == "exports"
                    };
                    if is_cjs_lead && self.try_parse_cjs_export()? {
                        return Ok(());
                    }
                }
                self.walk_expression_collecting_refs()?;
                // Optional trailing `;` — ASI may already have terminated the
                // expression at a newline; consume if present.
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            TokenKind::Str => {
                let save = self.lexer.checkpoint();
                self.lexer.next(); // consume the string literal
                let next_kind = self.lexer.peek().kind;
                let had_lt = self.lexer.had_line_terminator();
                if matches!(next_kind, TokenKind::Semi) {
                    self.lexer.next();
                    return Ok(());
                }
                if had_lt || matches!(next_kind, TokenKind::Eof | TokenKind::RBrace) {
                    return Ok(());
                }
                self.lexer.restore(save);
                self.walk_expression_collecting_refs()?;
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                Ok(())
            }
            TokenKind::LBrace => self.parse_block_statement(),
            TokenKind::Semi => {
                self.lexer.next();
                Ok(())
            }
            TokenKind::If => self.parse_if_statement(),
            TokenKind::While => self.parse_while_statement(),
            TokenKind::Do => self.parse_do_statement(),
            TokenKind::For => self.parse_for_statement(),
            TokenKind::Switch => self.parse_switch_statement(),
            TokenKind::Try => self.parse_try_statement(),
            _ => {
                self.lexer.next();
                Err("unrecognized")
            }
        }
    }

    /// Parse a statement-position block and own its complete lexical lifetime.
    ///
    /// The caller is positioned at `{`. The opening delimiter creates one
    /// value/lexical scope, the body walker consumes the matching `}`, and the
    /// scope is closed on both success and error. A missing `}` is returned to
    /// the program-level recovery owner as an explicit bounded diagnostic.
    fn parse_block_statement(&mut self) -> Result<(), &'static str> {
        self.expect(TokenKind::LBrace)?;
        self.push_value_scope();
        let result = self.walk_balanced_braces_collecting_refs();
        self.pop_value_scope();
        result.map(|_| ())
    }

    /// Walk a parenthesized control-flow header `( EXPR )`, collecting value
    /// refs, consuming through the matching `)`. Caller is positioned at `(`.
    /// Loops over comma-separated sub-expressions so `if (a, b)` is handled.
    fn collect_paren_header(&mut self) -> Result<(), &'static str> {
        if !matches!(self.lexer.peek().kind, TokenKind::LParen) {
            return Err("control-flow header");
        }
        self.lexer.next(); // consume `(`
        loop {
            match self.lexer.peek().kind {
                TokenKind::RParen => {
                    self.lexer.next(); // consume `)`
                    return Ok(());
                }
                TokenKind::Eof => return Err("control-flow header"),
                // `walk_expression_collecting_refs` stops (without consuming)
                // at the depth-0 `,`/`;`; skip those separators ourselves.
                TokenKind::Comma | TokenKind::Semi => {
                    self.lexer.next();
                }
                _ => self.walk_expression_collecting_refs()?,
            }
        }
    }

    /// Parse one control-flow body statement through the statement owner.
    /// Blocks, empty statements, nested control flow, and expression statements
    /// therefore share one dispatch and lifecycle contract.
    fn collect_cf_body(&mut self) -> Result<(), &'static str> {
        let t = self.lexer.peek().clone();
        if matches!(t.kind, TokenKind::Eof) {
            return Err("control-flow body");
        }
        // Mirror the expression-depth guard so adversarial chains such as
        // `if(a)if(b)if(c)…` cannot exhaust the process stack.
        if !self.enter_reference_recursion(ReferenceRecursionKind::Expression) {
            return Ok(()); // pathological nesting; leave the rest to recover()
        }
        let r = self.parse_statement(&t);
        self.leave_reference_recursion(ReferenceRecursionKind::Expression);
        r
    }

    fn collect_ambient_global_body(&mut self) -> Result<(), &'static str> {
        if !matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            return Err("ambient global body");
        }
        self.lexer.next(); // consume `{`
        loop {
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::RBrace => {
                    self.lexer.next();
                    return Ok(());
                }
                TokenKind::Eof => return Err("unterminated ambient global body"),
                _ => {
                    if let Err(reason) = self.parse_statement(&t) {
                        self.recover(reason, t.span);
                    }
                }
            }
        }
    }

    fn try_parse_namespace_like_statement(
        &mut self,
        decl_start: u32,
        register_head: bool,
    ) -> Result<bool, &'static str> {
        let save = self.lexer.checkpoint();
        let first = self.lexer.peek().clone();
        if !matches!(first.kind, TokenKind::Ident) {
            return Ok(false);
        }
        let first_text = self.text_of(first.span).to_string();
        let is_declare = first_text == "declare";
        let mut keyword = first_text.clone();
        if is_declare {
            self.lexer.next(); // consume `declare`
            let kw_tok = self.lexer.peek().clone();
            if !matches!(kw_tok.kind, TokenKind::Ident) {
                self.lexer.restore(save);
                return Ok(false);
            }
            keyword = self.text_of(kw_tok.span).to_string();
            if !matches!(keyword.as_str(), "namespace" | "global" | "module") {
                self.lexer.restore(save);
                return Ok(false);
            }
            self.lexer.next(); // consume namespace/global/module
        } else if keyword == "namespace" {
            self.lexer.next(); // consume `namespace`
        } else {
            return Ok(false);
        }

        let mut name_and_span: Option<(String, Span)> = None;
        if keyword != "global" {
            let name_tok = self.lexer.peek().clone();
            if !matches!(name_tok.kind, TokenKind::Ident) {
                self.lexer.restore(save);
                return Ok(false);
            }
            let name = self.text_of(name_tok.span).to_string();
            let name_span = name_tok.span;
            self.lexer.next(); // consume first namespace segment
            while matches!(self.lexer.peek().kind, TokenKind::Dot) {
                self.lexer.next();
                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    self.lexer.next();
                } else {
                    break;
                }
            }
            name_and_span = Some((name, name_span));
        }

        if !matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.lexer.restore(save);
            return Ok(false);
        }
        let body_start = self.lexer.peek().span.start();
        let ambient_body = is_declare || self.is_declaration_file();
        let ambient_global_body = is_declare && keyword == "global";
        if ambient_body {
            self.ambient_declaration_body_depth += 1;
        }
        if ambient_global_body {
            self.ambient_global_body_depth += 1;
        }
        let body_result = if ambient_global_body {
            self.collect_ambient_global_body()
        } else {
            self.collect_cf_body()
        };
        if ambient_global_body {
            self.ambient_global_body_depth = self.ambient_global_body_depth.saturating_sub(1);
        }
        if ambient_body {
            self.ambient_declaration_body_depth =
                self.ambient_declaration_body_depth.saturating_sub(1);
        }
        body_result?;
        let decl_end = self.lexer.peek().span.start();
        if register_head {
            if let Some((name, name_span)) = name_and_span {
                self.push_decl(DeclEvent::Namespace {
                    name,
                    name_span,
                    decl_span: Span::new(decl_start, decl_end.saturating_sub(decl_start)),
                    body_span: Span::new(body_start, decl_end.saturating_sub(body_start)),
                });
            }
        }
        Ok(true)
    }

    fn skip_namespace_body_named_export_statement(&mut self) -> bool {
        if !matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            return false;
        }
        self.lexer.next(); // consume `{`
        let mut depth = 1usize;
        while depth > 0 {
            match self.lexer.next().kind {
                TokenKind::LBrace => depth += 1,
                TokenKind::RBrace => depth -= 1,
                TokenKind::Eof => return true,
                _ => {}
            }
        }
        if matches!(self.lexer.peek().kind, TokenKind::From) {
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::Str) {
                self.lexer.next();
            }
        }
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        true
    }

    /// `if ( EXPR ) STMT [ else STMT ]` (ECMA-262 §14.6). The alternate may be
    /// another `if` (`else if`), handled by the brace-less recursion in
    /// `collect_cf_body` → `parse_statement` → this arm.
    fn parse_if_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `if`
        self.collect_paren_header()?;
        self.collect_cf_body()?; // consequent
        if matches!(self.lexer.peek().kind, TokenKind::Else) {
            self.lexer.next(); // consume `else`
            self.collect_cf_body()?; // alternate
        }
        Ok(())
    }

    /// `while ( EXPR ) STMT` (ECMA-262 §14.7.2).
    fn parse_while_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `while`
        self.collect_paren_header()?;
        self.collect_cf_body()
    }

    /// `do STMT while ( EXPR ) ;` (ECMA-262 §14.7.1). The body precedes the
    /// condition; the trailing `;` is consumed so the next statement parses.
    fn parse_do_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `do`
        self.collect_cf_body()?;
        if !matches!(self.lexer.peek().kind, TokenKind::While) {
            return Err("do-while");
        }
        self.lexer.next(); // consume `while`
        self.collect_paren_header()?;
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        Ok(())
    }

    /// `for ( … ) STMT`, covering c-style (`;;`), `for-in`, and `for-of`
    /// (ECMA-262 §14.7.4/5). The header and body share one value scope so the
    /// loop binder (`for (const x …)`) is suppressed in the body. Binder
    /// idents are noted while in `binder_mode` (entered on `const/let/var`,
    /// exited on `of`/`in`/`=`/`;`); everything else is walked as a value
    /// expression. `for await (… of …)` is accepted (the `await` is skipped).
    fn parse_for_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `for`
        if matches!(self.lexer.peek().kind, TokenKind::Await) {
            self.lexer.next(); // `for await`
        }
        if !matches!(self.lexer.peek().kind, TokenKind::LParen) {
            return Err("for header");
        }
        self.push_value_scope(); // binder + body share this scope
        self.lexer.next(); // consume `(`
        let mut pdepth: i32 = 1;
        let mut binder_mode = false;
        let mut in_decl_init = false;
        let header: Result<(), &'static str> = loop {
            match self.lexer.peek().kind {
                TokenKind::LParen => {
                    pdepth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    pdepth -= 1;
                    self.lexer.next();
                    if pdepth == 0 {
                        break Ok(());
                    }
                }
                TokenKind::Const | TokenKind::Let | TokenKind::Var => {
                    binder_mode = true;
                    in_decl_init = true;
                    self.lexer.next();
                }
                TokenKind::Of | TokenKind::In | TokenKind::Semi => {
                    binder_mode = false;
                    in_decl_init = false;
                    self.lexer.next();
                }
                TokenKind::Eq => {
                    binder_mode = false;
                    self.lexer.next();
                }
                TokenKind::Comma if in_decl_init && pdepth == 1 => {
                    binder_mode = true;
                    self.lexer.next();
                }
                TokenKind::Ident if binder_mode => {
                    let span = self.lexer.peek().span;
                    let name = self.text_of(span).to_string();
                    self.note_value_binder(&name);
                    self.lexer.next();
                }
                TokenKind::Eof => break Err("for header"),
                // Destructuring pattern punctuation (`[ ] { } ,`) during a
                // binder — pass through so inner Idents hit the binder arm.
                _ if binder_mode => {
                    self.lexer.next();
                }
                // Value position (iterable / condition / update).
                _ => {
                    if let Err(e) = self.walk_expression_collecting_refs() {
                        break Err(e);
                    }
                }
            }
        };
        if let Err(e) = header {
            self.pop_value_scope();
            return Err(e);
        }
        let body = self.collect_cf_body();
        self.pop_value_scope();
        body
    }

    /// `switch ( EXPR ) { … }` (ECMA-262 §14.12). The case block is walked
    /// opaquely by `collect_cf_body` — `case`/`default` labels and their
    /// statements are ordinary tokens the brace-balanced collector handles,
    /// exactly as it already does for switch inside function bodies.
    fn parse_switch_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `switch`
        self.collect_paren_header()?;
        self.collect_cf_body()
    }

    /// `try { … } [ catch [ ( BINDING ) ] { … } ] [ finally { … } ]`
    /// (ECMA-262 §14.15). The catch binding is noted in a value scope that
    /// also covers the catch block so the bound name is suppressed there.
    /// At least one of catch/finally is required.
    ///
    /// Known minor gap (parity follow-up): a typed catch binding
    /// `catch (e: SomeError)` does not emit `SomeError` as a TypeRef — the
    /// annotation tokens are skipped. Value-ref recovery (the gap's purpose)
    /// is unaffected.
    fn parse_try_statement(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `try`
        self.collect_cf_body()?; // try block
        let mut had_handler = false;
        if matches!(self.lexer.peek().kind, TokenKind::Catch) {
            had_handler = true;
            self.lexer.next(); // consume `catch`
            self.push_value_scope(); // catch binding + block scope
            if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                self.lexer.next(); // consume `(`
                loop {
                    match self.lexer.peek().kind {
                        TokenKind::RParen => {
                            self.lexer.next();
                            break;
                        }
                        TokenKind::Eof => break,
                        TokenKind::Ident => {
                            let span = self.lexer.peek().span;
                            let name = self.text_of(span).to_string();
                            self.note_value_binder(&name);
                            self.lexer.next();
                        }
                        // `:`, type tokens, destructuring punctuation.
                        _ => {
                            self.lexer.next();
                        }
                    }
                }
            }
            let r = self.collect_cf_body(); // catch block
            self.pop_value_scope();
            r?;
        }
        if matches!(self.lexer.peek().kind, TokenKind::Finally) {
            had_handler = true;
            self.lexer.next(); // consume `finally`
            self.collect_cf_body()?; // finally block
        }
        if !had_handler {
            return Err("try without catch/finally");
        }
        Ok(())
    }

    /// v0.8 — class-level decorator extraction.
    ///
    /// Pre-v0.8 the top-level `TokenKind::At` arm emitted
    /// `UnsupportedConstruct{decorator}` + `Err("punted")`, which
    /// caused statement-recovery to swallow the entire decorator +
    /// class + body. Every modern OO TS framework (NestJS, Angular,
    /// TypeORM, type-graphql) was structurally invisible to repotoire
    /// as a result — the v0.6-arc Phase 5 cats-app probe surfaced
    /// only 1 of 10 classes because 9 carried class-level decorators.
    ///
    /// v0.8 scans past one or more stacked decorators of the
    /// supported shapes — `@Ident`, `@Ident(args)`,
    /// `@Ident.Member...`, `@Ident.Member(args)` — then re-dispatches
    /// `parse_statement` on the decorated declaration (normally
    /// `class`, `export class`, `function`, or `async function`).
    ///
    /// The decorator expression's own refs are walked for supported call
    /// shapes, so `@UseGuards(RolesGuard)` captures `RolesGuard` while
    /// still parsing the decorated declaration that follows.
    ///
    /// Unsupported shapes (computed `@[expr]`, unterminated call
    /// args, decorator on a non-class/non-function statement) still
    /// emit `UnsupportedConstruct{decorator}` and bubble Err so
    /// `recover()` clears the region. The downstream signal that
    /// "decorators are present, contents not in IR" is therefore
    /// preserved exactly when it matters — when extraction *fails*.
    /// Try to parse a `using x = …` / `await using x = …` resource declaration
    /// (known-v1-gaps #12) at statement position. Returns `Ok(true)` if `t`
    /// introduced one (fully consumed); `Ok(false)` otherwise, leaving the lexer
    /// untouched. Strict `using [no LineTerminator] Ident =` shape so `using` as
    /// a variable / value use is unaffected. The keyword and binder names are
    /// consumed without emitting refs; the binder is noted; the initializer
    /// expression is walked so its refs (and any comma-list initializers) are
    /// captured.
    fn try_using_declaration(&mut self, t: &Token) -> Result<bool, &'static str> {
        let is_await = matches!(t.kind, TokenKind::Await);
        if !(is_await || (matches!(t.kind, TokenKind::Ident) && self.text_of(t.span) == "using")) {
            return Ok(false);
        }
        let save = self.lexer.checkpoint();
        if is_await {
            self.lexer.next(); // consume `await`
            let (k, s) = {
                let p = self.lexer.peek();
                (p.kind, p.span)
            };
            if !(matches!(k, TokenKind::Ident) && self.text_of(s) == "using") {
                self.lexer.restore(save);
                return Ok(false);
            }
        }
        self.lexer.next(); // consume `using`
                           // `using` is a restricted production: a LineTerminator before the
                           // binding triggers ASI, so it's a value use, not a declaration.
        let (b_kind, b_span, has_line_terminator) = {
            let p = self.lexer.peek();
            (p.kind, p.span, self.lexer.had_line_terminator())
        };
        if has_line_terminator {
            self.lexer.restore(save);
            return Ok(false);
        }
        if !matches!(b_kind, TokenKind::Ident) {
            self.lexer.restore(save);
            return Ok(false);
        }
        let binder = self.text_of(b_span).to_string();
        self.lexer.next(); // consume binder
        if !matches!(self.lexer.peek().kind, TokenKind::Eq) {
            // `using x` with no initializer is not a valid using-declaration;
            // treat the whole thing as a value use.
            self.lexer.restore(save);
            return Ok(false);
        }
        // Confirmed. Note the binder, walk the initializer + any comma-list.
        self.note_value_binder(&binder);
        self.lexer.next(); // `=`
        self.walk_expression_collecting_refs()?;
        while matches!(self.lexer.peek().kind, TokenKind::Comma) {
            self.lexer.next();
            let (n_kind, n_span) = {
                let p = self.lexer.peek();
                (p.kind, p.span)
            };
            if !matches!(n_kind, TokenKind::Ident) {
                break;
            }
            let n = self.text_of(n_span).to_string();
            self.note_value_binder(&n);
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                self.lexer.next();
                self.walk_expression_collecting_refs()?;
            }
        }
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        Ok(true)
    }

    fn emit_unsupported_decorator(&mut self, span: Span) {
        self.diagnostics.push(Diagnostic {
            kind: DiagnosticKind::UnsupportedConstruct {
                construct: "decorator".to_string(),
            },
            file_path: self.path.clone(),
            span,
        });
    }

    fn parse_decorator_prefixes_collecting_refs(&mut self) -> Result<(), &'static str> {
        loop {
            // Consume `@`. Loop invariant: the current token is `At`.
            let at_tok = self.lexer.next();
            // Decorator base must be an Ident. `@[expr]` (computed)
            // is unsupported.
            if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                self.emit_unsupported_decorator(at_tok.span);
                return Err("punted");
            }
            // Decorator base ident is a value reference (#10): `@Component`
            // depends on `Component`. Emit a ValueRef so the edge is captured
            // (pre-fix the base was consumed silently). The `.foo` chain below
            // is member access on that base — only the base is the ref.
            let base_tok = self.lexer.next();
            let base_name = self.text_of(base_tok.span).to_string();
            let owner = self.current_owner();
            self.events.push(Event::Ref(RefEvent::ValueRef {
                name: base_name,
                ref_span: base_tok.span,
                owner,
                scope: self.current_scope(),
            }));
            // Optional `.foo.bar` member-access chain (e.g. `@inject.foo()`).
            while matches!(self.lexer.peek().kind, TokenKind::Dot) {
                self.lexer.next();
                if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    self.emit_unsupported_decorator(at_tok.span);
                    return Err("punted");
                }
                self.lexer.next();
            }
            // Optional call args `(...)` — walk them for refs (#10) instead of
            // blindly balance-skipping, so `@Component({ providers: [Svc] })`
            // captures `Svc`. `walk_call_args_collecting_refs` consumes from the
            // `(` through the matching `)` and emits inner refs. On an
            // unterminated arg list it errors; preserve the decorator-specific
            // diagnostic (and Err) in that case, matching the pre-#10 behavior.
            if matches!(self.lexer.peek().kind, TokenKind::LParen)
                && self.walk_call_args_collecting_refs().is_err()
            {
                self.emit_unsupported_decorator(at_tok.span);
                return Err("unterminated decorator call");
            }
            // Stacked decorators (`@A @B @C class X`).
            if !matches!(self.lexer.peek().kind, TokenKind::At) {
                break;
            }
        }
        Ok(())
    }

    fn parse_class_level_decorators(&mut self, first_at_span: Span) -> Result<(), &'static str> {
        self.parse_decorator_prefixes_collecting_refs()?;
        // Re-dispatch on the decorated declaration. ECMA + TS
        // legal targets: class, export class, export default class,
        // function, async function. `abstract class` (contextual
        // `abstract` Ident keyword) is a separate gap — parse_statement
        // doesn't have an `abstract` arm today, so we fall through to
        // the unsupported case below. The cats-app fixture does not
        // exercise `abstract class`.
        let next = self.lexer.peek().clone();
        match next.kind {
            TokenKind::Class | TokenKind::Export | TokenKind::Function | TokenKind::Async => {
                self.parse_statement(&next)
            }
            _ => {
                self.emit_unsupported_decorator(first_at_span);
                Err("punted")
            }
        }
    }

    fn parse_export_statement(&mut self) -> Result<(), &'static str> {
        let export_tok = self.lexer.next(); // consume `export`
        let export_start = export_tok.span.start();
        // TS export-equals (known-v1-gaps #15): `export = expr` (CJS-style export
        // assignment). Walk the RHS expression so its refs are captured, then
        // consume an optional `;`. No export-name is registered (importers use
        // `import x = require(...)`, not a named binding).
        if matches!(self.lexer.peek().kind, TokenKind::Eq) {
            self.lexer.next(); // consume `=`
            if !matches!(self.lexer.peek().kind, TokenKind::Semi | TokenKind::Eof) {
                self.walk_expression_collecting_refs()?;
            }
            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                self.lexer.next();
            }
            return Ok(());
        }
        // `export * ...` deferred to Task 8 (parse_export_star doesn't exist yet;
        // calling it here would not compile). Task 8 flips this to the real call.
        if matches!(self.lexer.peek().kind, TokenKind::Star) {
            return self.parse_export_star();
        }
        if matches!(self.lexer.peek().kind, TokenKind::Default) {
            let default_tok = self.lexer.next();
            // Use `export_start` (captured at the top of parse_export_statement)
            // rather than the `default` keyword's position for decl-span start —
            // the source-spans contract reports source truth, same as every
            // other exported decl. The `default_tok.span` is still used as the
            // name_span for the anonymous-default synthetic Variable below.
            let decl_start = export_start;
            // Recognize `export default async function ...` by consuming `async`
            // first if present, then falling through to the Function-or-Class
            // dispatch below.
            if matches!(self.lexer.peek().kind, TokenKind::Async) {
                self.lexer.next(); // consume `async` (the function/class decl
                                   // parsers don't read `async`; it's implicit
                                   // in the decl-span starting at export_start).
            }
            match self.lexer.peek().kind {
                TokenKind::Function | TokenKind::Class | TokenKind::Interface => {
                    // Parse the decl WITHOUT registering its own Direct export
                    // (its decl-name-keyed export would be wrong here — importers
                    // resolve `default`, not the decl name). Then synthesize a
                    // Direct entry keyed by "default" pointing at the exported
                    // decl. Function/class parsers may emit nested declarations
                    // before or after the exported declaration, so recover the
                    // target from the declarations emitted by this parse,
                    // anchored by the `export` declaration span.
                    let decl_count_before_default = self.decl_count;
                    let event_count_before_default = self.events.len();
                    let default_decl_kind = self.lexer.peek().kind;
                    match default_decl_kind {
                        TokenKind::Function => {
                            let save = self.lexer.checkpoint();
                            self.lexer.next(); // `function`
                            if matches!(self.lexer.peek().kind, TokenKind::Star) {
                                self.lexer.next();
                            }
                            let is_anonymous = matches!(self.lexer.peek().kind, TokenKind::LParen);
                            self.lexer.restore(save);
                            if is_anonymous {
                                self.parse_function_decl_inner(
                                    decl_start,
                                    false,
                                    None,
                                    Some(("default".to_string(), default_tok.span)),
                                    false,
                                )?;
                            } else {
                                self.parse_function_decl(decl_start, false, None)?;
                            }
                        }
                        TokenKind::Class => self.parse_class_decl(decl_start, false, None)?,
                        TokenKind::Interface => self.parse_interface_decl(decl_start, false)?,
                        _ => unreachable!("default decl arm is gated by peeked token kind"),
                    }
                    let decl_index = self
                        .default_decl_index_from_new_events(
                            event_count_before_default,
                            decl_count_before_default,
                            decl_start,
                            default_decl_kind,
                        )
                        .unwrap_or_else(|| {
                            // Bodyless default function declarations in `.d.ts` files
                            // carry no executable body for the function parser to model,
                            // but default imports still need a concrete export target.
                            // Mirror anonymous default expressions with an opaque value
                            // node keyed by `default`.
                            let decl_end = self.lexer.peek().span.start();
                            self.push_decl(DeclEvent::Variable {
                                name: "default".to_string(),
                                name_span: default_tok.span,
                                decl_span: Span::new(
                                    decl_start,
                                    decl_end.saturating_sub(decl_start),
                                ),
                            })
                        });
                    self.exports.push(ExportEntry::Direct {
                        decl_index,
                        exported: "default".to_string(),
                    });
                    return Ok(());
                }
                _ => {
                    // G1.6 B1 mechanism (a): a BARE-IDENTIFIER default export
                    // (`export default greet;` — ky's actual shape,
                    // `const ky = createInstance(); export default ky;`)
                    // re-exports an existing local declaration under the name
                    // `default`. Route it through `ExportEntry::Named` — the
                    // exact entry `export { greet as default }` produces, and
                    // the ESM twin of the CJS `module.exports = ident` arm in
                    // `emit_cjs_whole_module_export` — so importers resolve to
                    // the REAL decl node instead of a detached synthetic
                    // Variable("default") the type-closure walk can't join.
                    //
                    // Only `Ident ;` / `Ident EOF` qualifies. Deliberate
                    // residuals that STILL take the synthesis path below (see
                    // the B1 design note follow-ups; each pinned by a
                    // residual-guard test):
                    //   * `export default someFn();` / `export default {...};`
                    //     — fresh expressions with no prior name to unify with;
                    //   * `export default greet satisfies Handler;` — the
                    //     trailing token is not `;`/EOF, so it restores and
                    //     synthesizes.
                    // Resolution order is a non-issue: `ExportEntry::Named` is
                    // resolved against the whole file's decl tables in Pass
                    // 2.5, so `export default greet;` above `function greet`
                    // still unifies.
                    if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                        let save = self.lexer.checkpoint();
                        let ident_tok = self.lexer.next();
                        let local = self.text_of(ident_tok.span).to_string();
                        // Builtin guard: `undefined`/`null`/`true`/`false`/
                        // `Promise`/… lex as Ident but have no local decl to
                        // unify with — routing them through Named would turn
                        // `export default null;` (a real stub-module shape)
                        // into a false DeadExport. They keep the synthesis
                        // path. (A local decl SHADOWING a builtin name loses
                        // unification here — accepted fail-safe: never worse
                        // than the pre-B1 behavior, which always synthesized.)
                        if matches!(self.lexer.peek().kind, TokenKind::Semi | TokenKind::Eof)
                            && !is_language_value_builtin(&local)
                        {
                            self.exports.push(ExportEntry::Named {
                                local,
                                exported: "default".to_string(),
                                ref_span: ident_tok.span,
                                is_type_only: false,
                            });
                            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                                self.lexer.next();
                            }
                            return Ok(());
                        }
                        self.lexer.restore(save);
                    }
                    // Anonymous default expression — `export default 42;`,
                    // `export default someExpr();`, etc. There's no prior decl
                    // name to unify with, so the export still needs a real node
                    // to point at for importers writing `import x from './a'`
                    // to resolve to something other than a synthetic phantom.
                    // Synthesize a Variable decl named "default":
                    //   - Pass 2 will register it into per_file_value_decls AND
                    //     per_file_all_decls (Variable is value-namespace).
                    //   - Pass 2.5 seed for Direct keys exports_map by "default",
                    //     finds the Variable node, no DeadExport diagnostic.
                    //   - Pass 3 emits an Exports edge from the file to the
                    //     Variable("default") node.
                    //
                    // decl_span covers from the `default` keyword through the
                    // expression (we capture the post-expression position via
                    // walk_expression_collecting_refs's stop point — Lexer::peek
                    // returns the next-token position, which is the start of `;`
                    // or whatever terminates the expression).
                    let body_start_of_expr = self.lexer.peek().span.start();
                    let _ = body_start_of_expr; // available if we want a body_span later
                    self.walk_expression_collecting_refs()?;
                    let decl_end = self.lexer.peek().span.start();
                    let decl_index = self.push_decl(DeclEvent::Variable {
                        name: "default".to_string(),
                        // name_span is the `default` keyword (closest thing to a
                        // name an anonymous default has). decl_span covers the
                        // entire `export default <expr>` so it matches what
                        // exported function/class defaults produce.
                        name_span: default_tok.span,
                        decl_span: Span::new(export_start, decl_end - export_start),
                    });
                    self.exports.push(ExportEntry::Direct {
                        decl_index,
                        exported: "default".to_string(),
                    });
                    if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                        self.lexer.next();
                    }
                    return Ok(());
                }
            }
        }
        // `export declare const URI: unique symbol` and friends: `declare`
        // is contextual (lexes as Ident), and the real declaration starts
        // after it. Reuse the normal declaration parser so exported ambient
        // const/type/interface/class shapes get the same bindings and Direct
        // export entries as non-ambient exports.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let save = self.lexer.checkpoint();
            let declare_tok = self.lexer.next();
            if self.text_of(declare_tok.span) == "declare" {
                let (next_kind, next_span) = {
                    let p = self.lexer.peek();
                    (p.kind, p.span)
                };
                if matches!(next_kind, TokenKind::Ident) && self.text_of(next_span) == "namespace" {
                    self.lexer.restore(save);
                } else {
                    return self.parse_declaration(export_start, true);
                }
            } else {
                self.lexer.restore(save);
            }
        }
        // `export namespace Foo { ... }` is the non-ambient counterpart of the
        // namespace body path in parse_statement. For now, keep exported
        // namespace internals opaque: registering nested namespace members as
        // graph declarations remains the broader ambient/namespaces milestone.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let save = self.lexer.checkpoint();
            let kw = self.lexer.next();
            let is_namespace = if self.text_of(kw.span) == "declare" {
                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    let next = self.lexer.next();
                    self.text_of(next.span) == "namespace"
                } else {
                    false
                }
            } else {
                self.text_of(kw.span) == "namespace"
            };
            if is_namespace {
                let name_tok = self.expect(TokenKind::Ident)?;
                let name = self.text_of(name_tok.span).to_string();
                while matches!(self.lexer.peek().kind, TokenKind::Dot) {
                    self.lexer.next();
                    if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                        self.lexer.next();
                    } else {
                        break;
                    }
                }
                if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                    let body_start = self.lexer.peek().span.start();
                    self.lexer.next();
                    let mut depth = 1usize;
                    let mut body_end = body_start + 1;
                    while depth > 0 {
                        let t = self.lexer.next();
                        match t.kind {
                            TokenKind::LBrace => depth += 1,
                            TokenKind::RBrace => {
                                depth -= 1;
                                body_end = t.span.start() + t.span.length();
                            }
                            TokenKind::Eof => break,
                            _ => {}
                        }
                    }
                    let decl_index = self.push_decl(DeclEvent::Namespace {
                        name: name.clone(),
                        name_span: name_tok.span,
                        decl_span: Span::new(export_start, body_end - export_start),
                        body_span: Span::new(body_start, body_end - body_start),
                    });
                    self.exports.push(ExportEntry::Direct {
                        decl_index,
                        exported: name,
                    });
                    return Ok(());
                }
            }
            self.lexer.restore(save);
        }
        // `export type { ... }`, `export type * from ...`, or
        // `export type Foo = ...`: consume `type`, then peek.
        let mut list_is_type_only = false;
        if matches!(self.lexer.peek().kind, TokenKind::Type) {
            self.lexer.next();
            if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
                list_is_type_only = true;
            } else if matches!(self.lexer.peek().kind, TokenKind::Star) {
                return self.parse_export_star();
            } else {
                return self.parse_type_alias_decl_body(export_start, true);
            }
        }
        // `export { ... }` or `export { ... } from '...'`
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.lexer.next();
            // (local, exported, ref_span, is_type_only)
            let mut pairs: Vec<(String, String, Span, bool)> = Vec::new();
            loop {
                if matches!(self.lexer.peek().kind, TokenKind::RBrace) {
                    self.lexer.next();
                    break;
                }
                // Per-specifier `type` modifier: `export { type X }`. Consume
                // `type`, then peek — a following binding name means modifier;
                // otherwise `type` is the exported name itself.
                let mut spec_is_type_only = false;
                let local_tok = if matches!(self.lexer.peek().kind, TokenKind::Type) {
                    let type_tok = self.lexer.next();
                    if matches!(
                        self.lexer.peek().kind,
                        TokenKind::Ident | TokenKind::Default
                    ) {
                        spec_is_type_only = true;
                        self.expect_binding_name()?
                    } else {
                        type_tok
                    }
                } else {
                    self.expect_binding_name()?
                };
                let local = self.text_of(local_tok.span).to_string();
                let exported = if matches!(self.lexer.peek().kind, TokenKind::As) {
                    self.lexer.next();
                    let t = self.expect_binding_name()?;
                    self.text_of(t.span).to_string()
                } else {
                    local.clone()
                };
                pairs.push((
                    local,
                    exported,
                    local_tok.span,
                    list_is_type_only || spec_is_type_only,
                ));
                if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                    self.lexer.next();
                }
            }
            if matches!(self.lexer.peek().kind, TokenKind::From) {
                self.lexer.next();
                let spec_tok = self.expect(TokenKind::Str)?;
                let (from, from_span) = self.read_str_literal(spec_tok);
                for (local, exported, ref_span, is_type_only) in pairs {
                    self.exports.push(ExportEntry::NamedFrom {
                        local,
                        exported,
                        from: from.clone(),
                        ref_span,
                        from_span,
                        is_type_only,
                    });
                }
            } else {
                for (local, exported, ref_span, is_type_only) in pairs {
                    self.exports.push(ExportEntry::Named {
                        local,
                        exported,
                        ref_span,
                        is_type_only,
                    });
                }
            }
            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                self.lexer.next();
            }
            return Ok(());
        }
        // `export function foo`, `export class C`, `export const x`, etc.
        self.parse_declaration(export_start, true)
    }

    fn default_decl_index_from_new_events(
        &self,
        event_start: usize,
        decl_index_start: u32,
        decl_start: u32,
        kind: TokenKind,
    ) -> Option<u32> {
        let mut decl_index = decl_index_start;
        for event in &self.events[event_start..] {
            let Event::Decl(decl) = event else {
                continue;
            };
            let (kind_matches, span_start) = match decl {
                DeclEvent::Function { decl_span, .. } => {
                    (matches!(kind, TokenKind::Function), decl_span.start())
                }
                DeclEvent::Class { decl_span, .. } => {
                    (matches!(kind, TokenKind::Class), decl_span.start())
                }
                DeclEvent::Interface { decl_span, .. } => {
                    (matches!(kind, TokenKind::Interface), decl_span.start())
                }
                _ => (false, 0),
            };
            if kind_matches && span_start == decl_start {
                return Some(decl_index);
            }
            decl_index += 1;
        }
        None
    }

    /// Shared declaration dispatcher used by both `parse_statement` (is_export=false)
    /// and the export-decl fallthrough in `parse_export_statement` (is_export=true).
    fn parse_declaration(&mut self, decl_start: u32, is_export: bool) -> Result<(), &'static str> {
        match self.lexer.peek().kind {
            TokenKind::Function => self.parse_function_decl(decl_start, is_export, None),
            TokenKind::Class => self.parse_class_decl(decl_start, is_export, None),
            TokenKind::Interface => self.parse_interface_decl(decl_start, is_export),
            TokenKind::Type => self.parse_type_alias_decl(decl_start, is_export),
            TokenKind::Enum => self.parse_enum_decl(decl_start, is_export, None),
            TokenKind::Const | TokenKind::Let | TokenKind::Var => {
                // `const enum` (with or without `export`) — mirror the
                // dispatch logic in parse_statement; see comment there.
                if matches!(self.lexer.peek().kind, TokenKind::Const) {
                    let save = self.lexer.checkpoint();
                    self.lexer.next(); // tentatively consume `const`
                    if matches!(self.lexer.peek().kind, TokenKind::Enum) {
                        return self.parse_enum_decl(decl_start, is_export, None);
                    }
                    self.lexer.restore(save);
                }
                self.parse_variable_decl(decl_start, is_export)
            }
            TokenKind::Async => {
                self.lexer.next(); // consume `async`
                if matches!(self.lexer.peek().kind, TokenKind::Function) {
                    self.parse_function_decl(decl_start, is_export, None)
                } else {
                    Err("`async` must be followed by `function` at decl position")
                }
            }
            TokenKind::Ident => {
                let is_abstract = {
                    let t = self.lexer.peek().clone();
                    self.text_of(t.span) == "abstract"
                };
                if is_abstract {
                    self.lexer.next(); // consume contextual `abstract`
                    if matches!(self.lexer.peek().kind, TokenKind::Class) {
                        self.parse_class_decl(decl_start, is_export, None)
                    } else {
                        Err("`abstract` must be followed by `class` at decl position")
                    }
                } else {
                    self.lexer.next();
                    Err("decl shape not supported")
                }
            }
            _ => {
                self.lexer.next();
                Err("decl shape not supported")
            }
        }
    }

    fn parse_type_alias_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
    ) -> Result<(), &'static str> {
        self.expect(TokenKind::Type)?;
        self.parse_type_alias_decl_body(decl_start, is_export)
    }

    /// The body of a type alias after the `type` keyword has been consumed.
    /// Split out so `parse_export_statement` can consume `type` first (to
    /// distinguish `export type { X }` from `export type Foo = ...`) and then
    /// delegate the alias case here.
    fn parse_type_alias_decl_body(
        &mut self,
        decl_start: u32,
        is_export: bool,
    ) -> Result<(), &'static str> {
        let name_tok = self.expect(TokenKind::Ident)?;
        let name = self.text_of(name_tok.span).to_string();
        self.push_type_param_scope(); // popped at end of fn
        self.push_owner(self.decl_count); // this alias owns its RHS type refs
                                          // `type T<U extends Base> = ...` — type-PARAMETER list.
        self.skip_type_param_list_collecting_refs();
        self.expect(TokenKind::Eq)?;
        // G1.7 Fix 2 — arm top-level object-literal member minting ONLY
        // when the alias RHS's first token is `{`. The brace-position
        // match in `parse_object_or_mapped_type` guarantees a nested
        // object type (inside a union member's generics, a property value,
        // a type argument, …) never consumes the armed flag.
        let minting_owner = self.current_owner();
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.alias_object_mint = minting_owner.map(|o| (o, self.lexer.peek().span.start()));
        }
        // Type-alias RHS: the brief is explicit that a top-level single ref
        // here is NOT under pressure at this site (the pressure lands at the
        // alias's USE sites), so the base is `Other`, not `Annotation`. A
        // union/intersection/conditional inside still retags its members.
        self.parse_type_expr_with_base(TypeRefPosition::Other);
        // Disarm if never consumed (RHS turned out not to route through
        // parse_object_or_mapped_type at that position).
        self.alias_object_mint = None;
        let mut decl_end = name_tok.span.start() + name_tok.span.length();
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            let t = self.lexer.next();
            decl_end = t.span.start() + t.span.length();
        }
        // decl_index = number of decls before this one (push_decl tracks it).
        let decl_index = self.push_decl(DeclEvent::TypeAlias {
            name: name.clone(),
            name_span: name_tok.span,
            decl_span: Span::new(decl_start, decl_end - decl_start),
        });
        debug_assert_eq!(
            minting_owner,
            Some(decl_index),
            "buffered type members must not shift the alias's own decl_index"
        );
        self.drain_service_members_for_owner(decl_index);
        if is_export {
            self.exports.push(ExportEntry::Direct {
                decl_index,
                exported: name,
            });
        }
        self.pop_owner();
        self.pop_type_param_scope();
        Ok(())
    }

    fn parse_enum_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
    ) -> Result<(), &'static str> {
        self.expect(TokenKind::Enum)?;
        let name_tok = self.expect(TokenKind::Ident)?;
        let name = self.text_of(name_tok.span).to_string();
        let local_owner_decl_index = local_scope.and_then(|_| self.current_owner());
        let body_start = self.lexer.peek().span.start();
        self.expect(TokenKind::LBrace)?;
        // Enum bodies are opaque (spec: "members opaque"). Balance-skip the
        // body WITHOUT ref-walking it: enum members (`First`, `Second`, …)
        // are constant declarations accessed as `E.First`, not references to
        // outer values. Ref-walking via walk_balanced_braces_collecting_refs
        // would emit a phantom ValueRef per member, which the resolver turns
        // into UnresolvedReference(Value). (Member initializers like
        // `A = compute()` therefore don't contribute Call edges in v1 — an
        // accepted opacity trade-off, same as the rest of the enum body.)
        let body_end = {
            let mut depth = 1;
            let mut end = self.lexer.peek().span.start();
            while depth > 0 {
                let t = self.lexer.next();
                end = t.span.start() + t.span.length();
                match t.kind {
                    TokenKind::LBrace => depth += 1,
                    TokenKind::RBrace => depth -= 1,
                    TokenKind::Eof => return Err("unterminated enum body"),
                    _ => {}
                }
            }
            end
        };
        // decl_index = number of decls before this one (push_decl tracks it).
        let decl_index = self.push_decl(DeclEvent::Enum {
            name: name.clone(),
            name_span: name_tok.span,
            decl_span: Span::new(decl_start, body_end - decl_start),
            body_span: Span::new(body_start, body_end - body_start),
        });
        if let Some(scope) = local_scope {
            self.local_value_decls.push(LocalValueDecl {
                name: name.clone(),
                scope,
                decl_index,
                owner_decl_index: local_owner_decl_index,
            });
        }
        if is_export {
            self.exports.push(ExportEntry::Direct {
                decl_index,
                exported: name,
            });
        }
        Ok(())
    }

    /// Reserve identity before walking annotations, defaults or initializers.
    /// Child declarations must never take their parent's index.
    fn begin_variable_decl(
        &mut self,
        name: String,
        name_span: Span,
        decl_start: u32,
        owner_decl_index: Option<u32>,
    ) -> u32 {
        let decl_index = self.push_decl(DeclEvent::Variable {
            name: name.clone(),
            name_span,
            decl_span: Span::new(decl_start, 0),
        });
        let scope = self.current_scope();
        if scope != 0 {
            self.local_value_decls.push(LocalValueDecl {
                name,
                scope,
                decl_index,
                owner_decl_index,
            });
        }
        decl_index
    }

    fn collect_variable_binding(
        &mut self,
        name: String,
        span: Span,
        out: &mut Vec<(String, u32, usize)>,
        decl_start: u32,
        parent_owner: Option<u32>,
    ) {
        self.note_value_binder(&name);
        self.emit_binding(name.clone(), span, None);
        let event_index = self.events.len();
        let decl_index = self.begin_variable_decl(name.clone(), span, decl_start, parent_owner);
        if out.is_empty() {
            self.push_owner(decl_index);
        }
        out.push((name, decl_index, event_index));
    }

    fn parse_variable_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
    ) -> Result<(), &'static str> {
        let declaration_is_const = matches!(self.lexer.peek().kind, TokenKind::Const);
        self.lexer.next(); // const/let/var
                           // The statement prefix belongs to its first module declarator only.
                           // Local declarations and later siblings start at their own binding.
        let mut declarator_start = (self.current_scope() == 0).then_some(decl_start);
        loop {
            let declarator_checkpoint = self.declaration_checkpoint();
            let declarator_scope_checkpoint = self.scope_checkpoint();
            self.declaration_checkpoint_depth += 1;
            let pattern_start = self.lexer.peek().span.start();
            let decl_start = declarator_start.take().unwrap_or(pattern_start);
            let initializer_owner = match self.lexer.peek().kind {
                kind if Self::token_can_start_binding_identifier(kind) => {
                    let name_tok = self.lexer.next();
                    let name = self.text_of(name_tok.span).to_string();
                    // Register the lexical binding before its initializer. The
                    // completed binding table distinguishes queryable declarations
                    // from parameter, catch and loop bindings during finalization.
                    self.note_value_binder(&name);
                    // v0.5 commit 3 — top-level let/const emit BOTH a
                    // DeclEvent::Variable (graph node, below) AND a
                    // BindingEvent (lexical fact). The BindingEvent
                    // captures the class-typed receiver origin so
                    // commit 5's scope-walk can resolve module-level
                    // `let x: C` / `const x = new C()` references.
                    let binding_idx = self.emit_binding(name.clone(), name_tok.span, None);
                    let decl_event_idx = self.events.len();
                    let decl_index = self.begin_variable_decl(
                        name.clone(),
                        name_tok.span,
                        decl_start,
                        self.current_owner(),
                    );
                    self.push_owner(decl_index);
                    // Optional type annotation
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        // v0.5 commit 3 — capture ExplicitType origin
                        // BEFORE parsing the type. Plain-Ident types
                        // only (per the locked conflict rule's
                        // generics-out-of-scope carve-out).
                        if let Some(class_name) = self.peek_explicit_type_origin() {
                            self.set_binding_origin(
                                binding_idx,
                                Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }),
                            );
                        }
                        self.parse_type_expr_emitting_refs();
                    }
                    // Optional initializer.
                    // v0.6 commit 2 — captured here for const-arrow
                    // factory inference (`const f = (): C => …`).
                    // The factory's own binding (`f`) keeps its
                    // origin as None (it's a function binding); the
                    // FunctionReturn { name: f, class_name: C,
                    // decl_index } entry below makes `f` queryable
                    // as a factory at resolve time.
                    let mut captured_arrow_factory_class: Option<String> = None;
                    if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                        self.lexer.next();
                        if declaration_is_const {
                            self.note_const_string_initializer(&name);
                        }
                        // v0.5 commit 3 — capture Construction origin
                        // (only takes effect if ExplicitType didn't
                        // already win — set_binding_origin enforces
                        // the conflict rule).
                        if let Some(class_name) = self.peek_construction_origin() {
                            self.set_binding_origin(
                                binding_idx,
                                Some(crate::ts::events::ClassOrigin::Construction { class_name }),
                            );
                        } else if let Some(factory_ref) = self.peek_factory_return_origin() {
                            // v0.6 commit 3 — capture FactoryReturn
                            // origin when the initializer is a Call-
                            // shaped expression on a plain Ident or
                            // qualified MemberAccess receiver. Same
                            // conflict-rule precedence: set_binding_origin
                            // ignores this update if ExplicitType
                            // already won. Construction was checked
                            // first above; the two shapes are
                            // syntactically disjoint, so this
                            // short-circuit cannot mis-fire. The
                            // resolver doesn't yet consume FactoryReturn
                            // (commit 4-5 add the arms); commit 3 just
                            // emits the data so the resolver work has
                            // a stable substrate.
                            self.set_binding_origin(
                                binding_idx,
                                Some(crate::ts::events::ClassOrigin::FactoryReturn { factory_ref }),
                            );
                        } else {
                            // Only check arrow-factory shape when
                            // neither Construction nor FactoryReturn
                            // matched. The arrow shape is distinct
                            // from both (starts with `(`).
                            captured_arrow_factory_class =
                                self.peek_const_arrow_factory_return_class();
                        }
                        if self.current_scope() != 0 {
                            self.pending_dynamic_import_binder =
                                Some((name.clone(), self.lexer.peek().span.start()));
                        }
                        let result = self.walk_expression_collecting_refs();
                        self.pending_dynamic_import_binder = None;
                        if let Err(reason) = result {
                            self.abort_declaration_checkpoint(
                                declarator_checkpoint,
                                declarator_scope_checkpoint,
                            );
                            return Err(reason);
                        }
                    }
                    // Compute decl_end as the byte after whatever just terminated the
                    // declarator (a peek of `,`, `;`, or EOF).
                    let decl_end = self.lexer.peek().span.start();
                    if let Event::Decl(DeclEvent::Variable { decl_span, .. }) =
                        &mut self.events[decl_event_idx]
                    {
                        *decl_span = Span::new(decl_start, decl_end - decl_start);
                    }
                    // v0.6 commit 2 — push the FunctionReturn entry
                    // for const-arrow factories now that decl_index
                    // is known. Consumed by commit 4's
                    // FactoryRef::Plain resolver lookup. Same
                    // sidecar as plain-function factories — the
                    // resolver doesn't distinguish where the entry
                    // came from.
                    if let Some(class_name) = captured_arrow_factory_class {
                        self.function_returns
                            .push(crate::ts::events::FunctionReturn {
                                name: name.clone(),
                                class_name,
                                decl_index,
                            });
                    }
                    if is_export {
                        self.exports.push(ExportEntry::Direct {
                            decl_index,
                            exported: name,
                        });
                    }
                    Some(decl_index)
                }
                TokenKind::LBrace | TokenKind::LBracket => {
                    // Destructuring pattern: `const { a, b } = src` or `const [x, y] = src`.
                    // Harvest all bound names; each becomes its own DeclEvent::Variable
                    // (and Direct export entry when this is an exported statement).
                    //
                    // v1 limitation: per-name spans are not tracked for destructuring
                    // patterns — each harvested name reuses the overall pattern span as
                    // its name_span. This is sufficient for the contains-edge to the file
                    // node and for downstream consumers that care about decl existence, not
                    // exact per-binding byte ranges.
                    let is_object = matches!(self.lexer.peek().kind, TokenKind::LBrace);
                    self.lexer.next(); // consume `{` or `[`

                    let mut names = Vec::new();
                    let parent_owner = self.current_owner();
                    if let Err(reason) = self.harvest_binding_pattern_names_collect(
                        is_object,
                        &mut names,
                        decl_start,
                        parent_owner,
                    ) {
                        self.abort_declaration_checkpoint(
                            declarator_checkpoint,
                            declarator_scope_checkpoint,
                        );
                        return Err(reason);
                    }
                    let pattern_end = self.lexer.peek().span.start();
                    let pattern_span = Span::new(pattern_start, pattern_end - pattern_start);

                    // Optional type annotation on the whole pattern, e.g.
                    // `const { a }: Foo = src;`
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        self.parse_type_expr_emitting_refs();
                    }
                    // Optional initializer.
                    if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                        self.lexer.next();
                        if let Err(reason) = self.walk_expression_collecting_refs() {
                            self.abort_declaration_checkpoint(
                                declarator_checkpoint,
                                declarator_scope_checkpoint,
                            );
                            return Err(reason);
                        }
                    }

                    let decl_end = self.lexer.peek().span.start();
                    let decl_span = Span::new(decl_start, decl_end - decl_start);

                    for (name, decl_index, event_index) in &names {
                        if let Event::Decl(DeclEvent::Variable {
                            name_span,
                            decl_span: span,
                            ..
                        }) = &mut self.events[*event_index]
                        {
                            *name_span = pattern_span;
                            *span = decl_span;
                        }
                        if is_export {
                            self.exports.push(ExportEntry::Direct {
                                decl_index: *decl_index,
                                exported: name.clone(),
                            });
                        }
                    }
                    names.first().map(|(_, decl_index, _)| *decl_index)
                }
                _ => {
                    self.abort_declaration_checkpoint(
                        declarator_checkpoint,
                        declarator_scope_checkpoint,
                    );
                    return Err("expected identifier or destructuring pattern in variable decl");
                }
            };
            // Every declarator finalizes its buffered members before releasing
            // its owner. For patterns, the first actual binding owns defaults
            // and the initializer; empty patterns never allocate an owner.
            if let Some(owner) = initializer_owner {
                self.drain_service_members_for_owner(owner);
                self.pop_owner();
            }
            self.finish_declaration_checkpoint(declarator_checkpoint);
            // Another declarator follows?
            if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                self.lexer.next();
                continue;
            }
            break;
        }
        // Trailing `;` (single optional consume per statement).
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        Ok(())
    }

    fn parse_export_star(&mut self) -> Result<(), &'static str> {
        self.lexer.next(); // consume `*`
        if matches!(self.lexer.peek().kind, TokenKind::As) {
            self.lexer.next();
            let local_tok = self.expect(TokenKind::Ident)?;
            let local = self.text_of(local_tok.span).to_string();
            self.expect(TokenKind::From)?;
            let spec_tok = self.expect(TokenKind::Str)?;
            let (from, from_span) = self.read_str_literal(spec_tok);
            self.exports.push(ExportEntry::NamespaceAs {
                local,
                from,
                local_span: local_tok.span,
                from_span,
            });
            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                self.lexer.next();
            }
            return Ok(());
        }
        self.expect(TokenKind::From)?;
        let spec_tok = self.expect(TokenKind::Str)?;
        let (from, from_span) = self.read_str_literal(spec_tok);
        self.exports
            .push(ExportEntry::Namespace { from, from_span });
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        Ok(())
    }

    fn parse_import_statement(&mut self) -> Result<(), &'static str> {
        let start = self.lexer.next().span; // consume `import`
                                            // TS import-equals (known-v1-gaps #15): `import x = require('m')` (CJS
                                            // interop — the literal specifier is a module edge) or `import N = A.B`
                                            // (namespace alias — no edge). Detected via an `Ident =` lookahead so the
                                            // ordinary `import x from …` default-binding path below is untouched.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let saved = self.lexer.checkpoint();
            self.lexer.next(); // tentative alias name
            if matches!(self.lexer.peek().kind, TokenKind::Eq) {
                self.lexer.next(); // consume `=`
                let (pk, psp) = {
                    let p = self.lexer.peek();
                    (p.kind, p.span)
                };
                if matches!(pk, TokenKind::Ident) && self.text_of(psp) == "require" {
                    let req_span = self.lexer.next().span; // consume `require`
                    if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                        let _ = self.emit_dynamic_import_call(req_span)?;
                    }
                } else {
                    // Namespace alias `A.B.C` — consume the qualified name; no edge.
                    while matches!(self.lexer.peek().kind, TokenKind::Ident) {
                        self.lexer.next();
                        if matches!(self.lexer.peek().kind, TokenKind::Dot) {
                            self.lexer.next();
                        } else {
                            break;
                        }
                    }
                }
                if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                    self.lexer.next();
                }
                return Ok(());
            }
            self.lexer.restore(saved);
        }
        let mut is_type_only = false;
        // Optional `type`
        if matches!(self.lexer.peek().kind, TokenKind::Type) {
            is_type_only = true;
            self.lexer.next();
        }
        let mut bindings = Vec::new();
        // Bare side-effect import: `import './x';`
        if matches!(self.lexer.peek().kind, TokenKind::Str) {
            let spec_tok = self.lexer.next();
            let (specifier, specifier_span) = self.read_str_literal(spec_tok);
            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                self.lexer.next();
            }
            self.events.push(Event::Ref(RefEvent::Import {
                specifier,
                specifier_span,
                bindings,
                is_type_only,
                makes_external_module: true,
            }));
            return Ok(());
        }
        // Default binding
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let t = self.lexer.next();
            let name = self.text_of(t.span).to_string();
            bindings.push(ImportBinding {
                local: name,
                exported: "default".to_string(),
                local_span: t.span,
                kind: BindingKind::Default,
                is_type_only,
            });
            // Optional `, { ... }` continuation
            if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                self.lexer.next();
            }
        }
        // Namespace `* as ns`
        if matches!(self.lexer.peek().kind, TokenKind::Star) {
            self.lexer.next();
            self.expect(TokenKind::As)?;
            let t = self.expect(TokenKind::Ident)?;
            let name = self.text_of(t.span).to_string();
            bindings.push(ImportBinding {
                local: name.clone(),
                exported: name,
                local_span: t.span,
                kind: BindingKind::Namespace,
                is_type_only,
            });
        }
        // Named bindings `{ a, b as c }`
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            self.lexer.next();
            loop {
                if matches!(self.lexer.peek().kind, TokenKind::RBrace) {
                    self.lexer.next();
                    break;
                }
                // Inline `type` modifier: `import { type Foo, bar }`. Consume
                // `type`, then peek — if a binding name follows, `type` was the
                // modifier; otherwise `type` IS the binding name (`{ type }`,
                // `{ type as X }`, `{ type, x }`). Avoids a 2-token lookahead.
                let mut binding_is_type_only = false;
                let exported_tok = if matches!(self.lexer.peek().kind, TokenKind::Type) {
                    let type_tok = self.lexer.next();
                    if matches!(
                        self.lexer.peek().kind,
                        TokenKind::Ident | TokenKind::Default
                    ) {
                        binding_is_type_only = true;
                        self.expect_binding_name()?
                    } else {
                        type_tok // `type` is the imported name itself
                    }
                } else {
                    // `default` is reserved by the lexer but legal in import binding
                    // position: `import { default as Foo } from './x'`.
                    self.expect_binding_name()?
                };
                let exported = self.text_of(exported_tok.span).to_string();
                let (local, local_span) = if matches!(self.lexer.peek().kind, TokenKind::As) {
                    self.lexer.next();
                    let lt = self.expect_binding_name()?;
                    (self.text_of(lt.span).to_string(), lt.span)
                } else {
                    (exported.clone(), exported_tok.span)
                };
                bindings.push(ImportBinding {
                    local,
                    exported,
                    local_span,
                    kind: BindingKind::Named,
                    is_type_only: is_type_only || binding_is_type_only,
                });
                if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                    self.lexer.next();
                }
            }
        }
        self.expect(TokenKind::From)?;
        let spec_tok = self.expect(TokenKind::Str)?;
        let (specifier, specifier_span) = self.read_str_literal(spec_tok);
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        self.events.push(Event::Ref(RefEvent::Import {
            specifier,
            specifier_span,
            bindings,
            is_type_only,
            makes_external_module: true,
        }));
        let _ = start; // mark used; or use for diagnostic context
        Ok(())
    }

    fn expect(&mut self, kind: TokenKind) -> Result<Token, &'static str> {
        if self.lexer.peek().kind != kind {
            // Keep the unexpected token available to recovery. Consuming a
            // semicolon here makes recovery start at the next declaration
            // and can swallow that complete sibling.
            return Err("expected token");
        }
        Ok(self.lexer.next())
    }

    /// Accepts IdentifierName tokens used in import/export specifier lists.
    /// Module specifier names may be reserved words (`default`, `void`,
    /// `enum`, ...), so recover the source text from `t.span` rather than
    /// relying on `TokenKind::Ident` alone.
    fn expect_binding_name(&mut self) -> Result<Token, &'static str> {
        let t = self.lexer.next();
        match t.kind {
            TokenKind::Ident
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
            | TokenKind::Await => Ok(t),
            _ => Err("expected binding name"),
        }
    }

    fn text_of(&self, span: Span) -> &str {
        // MUST NOT panic. Although `extract_project` pre-validates the whole
        // file as UTF-8, callers pass spans of *any* token — including 1-byte
        // `Error` tokens the lexer emits for non-ASCII bytes (a `π` or a BOM
        // splits into single-byte Error tokens mid-codepoint). A sub-slice
        // that bisects a multibyte char is not valid UTF-8, so `from_utf8`
        // would fail. `parse_statement` calls `text_of` on the first token
        // before classifying it, so this is reachable on valid input. Return
        // `""` on a non-UTF-8 boundary: it won't match any keyword/identifier
        // (correct — non-ASCII identifiers are a v1 known gap) and never
        // panics. Identifier/string tokens always lie on char boundaries, so
        // real names are unaffected.
        std::str::from_utf8(
            &self.source[span.start() as usize..(span.start() + span.length()) as usize],
        )
        .unwrap_or("")
    }

    fn is_declaration_file(&self) -> bool {
        self.path.ends_with(".d.ts")
            || self.path.ends_with(".d.mts")
            || self.path.ends_with(".d.cts")
    }

    /// Skip JSX markup while walking JavaScript expression containers.
    /// Called with the opening `<` as the current peek. Balances nested JSX
    /// elements. Prop names remain opaque; a component tag's base identifier
    /// emits a controlled component-usage `ValueRef` (#23) so use-site line
    /// attribution works — a tag is a component when its base is capitalized
    /// (`<Foo/>`) OR it is a member/namespaced tag (`<motion.div/>`), while a
    /// simple lowercase intrinsic tag (`<div/>`) stays opaque. `{ ... }`
    /// containers are real JavaScript expression positions and are walked for
    /// refs.
    fn skip_jsx_element(&mut self) {
        self.lexer.next(); // consume opening `<`
        self.skip_jsx_after_open();
    }

    /// The opening `<` is already consumed. Consume the tag name + attributes,
    /// and — if not self-closing — the children up to the matching `</…>`.
    fn skip_jsx_after_open(&mut self) {
        // Tag name (absent for a `<>` fragment); incl. member/namespaced chains.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            // Base identifier is a controlled component-usage ref (#23): a
            // component tag (`<Foo/>`) names a user symbol whose props
            // changing breaks a tsc check at THIS JSX line, not just the
            // import line — the compiler-verified break-detector matches
            // diagnostics to dependents by (file,line), so it needs a ref
            // anchored here.
            //
            // Component-vs-intrinsic discriminator, per JSX/React rules:
            //   * a SIMPLE tag is a component iff its name is capitalized —
            //     lowercase simple tags (`<div/>`, `<span/>`) are HTML/DOM
            //     intrinsics and stay opaque (no ref, ever);
            //   * a MEMBER/NAMESPACED tag (`<motion.div/>`, `<styles.Wrapper>`,
            //     `<ns:Thing>`) is ALWAYS a component regardless of base case —
            //     the base is an object/value reference either way, so emitting
            //     it adds no false positive.
            // Hence: emit iff `base_is_uppercase || member_chain_follows`. The
            // `member_chain_follows` peek is non-consuming (same peek the
            // member-chain-skip loop below relies on), so the lexer position is
            // undisturbed.
            //
            // Mirrors the decorator-base pattern in
            // `parse_decorator_prefixes_collecting_refs`: only the base is
            // the ref, the `.Bar`/`:Tag` member/namespace suffix chain below
            // (and all attribute/prop names) remain opaque forever.
            let base_tok = self.lexer.next();
            let base_name = self.text_of(base_tok.span).to_string();
            let base_is_uppercase = base_name.chars().next().is_some_and(|c| c.is_uppercase());
            let member_chain_follows =
                matches!(self.lexer.peek().kind, TokenKind::Dot | TokenKind::Colon);
            if base_is_uppercase || member_chain_follows {
                let owner = self.current_owner();
                self.events.push(Event::Ref(RefEvent::ValueRef {
                    name: base_name,
                    ref_span: base_tok.span,
                    owner,
                    scope: self.current_scope(),
                }));
            }
            while matches!(self.lexer.peek().kind, TokenKind::Dot | TokenKind::Colon) {
                self.lexer.next();
                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    self.lexer.next();
                }
            }
        }
        // Attributes until `>` (open) or `/>` (self-close).
        loop {
            if self.lexer.source_after_cursor().starts_with(b"/") {
                self.lexer.deny_regex_for_next();
            }
            match self.lexer.peek().kind {
                TokenKind::Gt => {
                    self.lexer.next();
                    break;
                }
                TokenKind::Slash => {
                    self.lexer.next();
                    if matches!(self.lexer.peek().kind, TokenKind::Gt) {
                        self.lexer.next();
                    }
                    return; // self-closed — no children
                }
                TokenKind::LBrace => self.skip_jsx_braces(),
                TokenKind::Eof => return,
                _ => {
                    self.lexer.next(); // attr name / `=` / string value
                }
            }
        }
        // Children until the closing `</…>`.
        loop {
            if self.lexer.source_after_cursor().starts_with(b"/") {
                self.lexer.deny_regex_for_next();
            }
            match self.lexer.peek().kind {
                TokenKind::Lt => {
                    // Consume `<`.
                    self.lexer.next();
                    // After `<` (a `Lt` operator) the lexer is in regex
                    // context. A closing tag's `/` (`</tag>`) would otherwise
                    // lex as an unterminated regex literal running to the line
                    // terminator — swallowing the rest of the line including
                    // the enclosing block's `}` and desyncing the brace walker
                    // (dropped ~51% of real `.tsx` component decls). Force the
                    // `/` to lex as `Slash` so the closing-tag arm below fires.
                    self.lexer.deny_regex_for_next();
                    if matches!(self.lexer.peek().kind, TokenKind::Slash) {
                        // Closing tag `</tag>` — consume through its `>`.
                        self.lexer.next(); // `/`
                        while !matches!(self.lexer.peek().kind, TokenKind::Gt | TokenKind::Eof) {
                            self.lexer.next();
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::Gt) {
                            self.lexer.next();
                        }
                        return;
                    }
                    // Nested element (its `<` already consumed).
                    self.skip_jsx_after_open();
                }
                TokenKind::LBrace => self.skip_jsx_braces(),
                TokenKind::Eof => return,
                _ => {
                    self.lexer.skip_raw_jsx_text_until_boundary();
                }
            }
        }
    }

    /// Consume a JSX expression container / spread attr. Peek is `{`. The
    /// container's delimiters are JSX syntax, but the contents are JavaScript
    /// expression position, so walk them for refs while still handling nested
    /// JSX through the regex-safe JSX skipper.
    fn skip_jsx_braces(&mut self) {
        self.lexer.next(); // `{`
        loop {
            let kind = self.lexer.peek().kind;
            match kind {
                TokenKind::RBrace => {
                    self.lexer.next();
                    return;
                }
                // Nested JSX inside the expression container, e.g.
                // `{items.map((i) => <li>{i}</li>)}`. Delegate to the JSX
                // skipper so the nested element's closing tag (`</li>`) is
                // consumed via the regex-safe path; byte-balancing it here
                // would let `</li>`'s `/` lex as a regex and eat our `}`.
                TokenKind::Lt if looks_like_jsx_element(self.lexer.source_after_cursor()) => {
                    self.skip_jsx_element();
                }
                TokenKind::Eof => return,
                _ => {
                    let before = self.lexer.peek().span.start();
                    let walked_expression = self.walk_expression_collecting_refs().is_ok();
                    if !walked_expression || self.lexer.peek().span.start() == before {
                        self.lexer.next();
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::Comma | TokenKind::Semi) {
                        self.lexer.next();
                    }
                }
            }
        }
    }

    /// CommonJS export assignment at statement position (spec §6). Current peek
    /// is a `module`/`exports` ident. Returns Ok(true) if a CJS export form
    /// matched (statement consumed, ExportEntry + refs emitted); Ok(false) after
    /// restoring the lexer otherwise (caller falls back to the expression walk).
    fn try_parse_cjs_export(&mut self) -> Result<bool, &'static str> {
        let cp = self.lexer.checkpoint();
        let lead_span = self.lexer.peek().span;
        let lead = self.text_of(lead_span).to_string();
        self.lexer.next(); // consume `module` or `exports`

        let label: Option<CjsMemberLabel> = if lead == "module" {
            if !matches!(self.lexer.peek().kind, TokenKind::Dot) {
                self.lexer.restore(cp);
                return Ok(false);
            }
            self.lexer.next(); // `.`
            let k = self.lexer.peek().kind;
            let sp = self.lexer.peek().span;
            if !(matches!(k, TokenKind::Ident) && self.text_of(sp) == "exports") {
                self.lexer.restore(cp);
                return Ok(false);
            }
            self.lexer.next(); // `exports`
            self.read_cjs_member_label()
        } else {
            self.read_cjs_member_label()
        };

        if !matches!(self.lexer.peek().kind, TokenKind::Eq) {
            self.lexer.restore(cp);
            return Ok(false);
        }
        self.lexer.next(); // `=`

        match label {
            Some(name) => {
                if let Some(local) = self.peek_cjs_assignment_rhs_simple_ident() {
                    self.exports.push(ExportEntry::Named {
                        local,
                        exported: name.name,
                        ref_span: name.span,
                        is_type_only: false,
                    });
                } else {
                    let decl_index = self.push_decl(DeclEvent::Variable {
                        name: name.name.clone(),
                        name_span: name.span,
                        decl_span: name.span,
                    });
                    self.exports.push(ExportEntry::Direct {
                        decl_index,
                        exported: name.name,
                    });
                }
            }
            None => self.emit_cjs_whole_module_export(lead_span),
        }
        // Walk the RHS for nested refs, then consume the terminator.
        self.walk_expression_collecting_refs()?;
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        Ok(true)
    }

    /// Read a static export label after `module.exports` / `exports`: `.foo`
    /// or `["foo"]`. Returns Some(label) (consuming it), or None — restoring
    /// the lexer — for the whole-module form (`= …`) or a computed key.
    fn read_cjs_member_label(&mut self) -> Option<CjsMemberLabel> {
        let cp = self.lexer.checkpoint();
        match self.lexer.peek().kind {
            TokenKind::Dot => {
                self.lexer.next(); // `.`
                if matches!(self.lexer.peek().kind, TokenKind::Ident) {
                    let sp = self.lexer.peek().span;
                    let name = self.text_of(sp).to_string();
                    self.lexer.next();
                    return Some(CjsMemberLabel { name, span: sp });
                }
                self.lexer.restore(cp);
                None
            }
            TokenKind::LBracket => {
                self.lexer.next(); // `[`
                if matches!(self.lexer.peek().kind, TokenKind::Str) {
                    let st = self.lexer.peek().clone();
                    let (label, span) = self.read_str_literal(st);
                    self.lexer.next(); // string
                    if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                        self.lexer.next(); // `]`
                        return Some(CjsMemberLabel { name: label, span });
                    }
                }
                self.lexer.restore(cp); // computed key — not a static label
                None
            }
            _ => None,
        }
    }

    /// Peek whether a CommonJS member assignment RHS is exactly one local
    /// identifier (`exports.foo = bar;`). Builtin/literal identifiers such as
    /// `true`, `false`, and `JSON` are not local aliases. The lexer is restored
    /// so the ordinary expression walk still records RHS references once.
    fn peek_cjs_assignment_rhs_simple_ident(&mut self) -> Option<String> {
        let cp = self.lexer.checkpoint();
        let mut simple_ident: Option<String> = None;
        let mut token_count = 0usize;
        let mut braces = 0usize;
        let mut brackets = 0usize;
        let mut parens = 0usize;
        loop {
            let tok = self.lexer.peek().clone();
            if braces == 0
                && brackets == 0
                && parens == 0
                && matches!(tok.kind, TokenKind::Semi | TokenKind::Eof)
            {
                break;
            }
            match tok.kind {
                TokenKind::Ident if token_count == 0 => {
                    let name = self.text_of(tok.span).to_string();
                    if !is_language_value_builtin(&name) {
                        simple_ident = Some(name);
                    }
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LBrace => {
                    braces += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    braces = braces.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    brackets += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RBracket => {
                    brackets = brackets.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LParen => {
                    parens += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    parens = parens.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::Eof => break,
                _ => {
                    token_count += 1;
                    self.lexer.next();
                }
            }
        }
        self.lexer.restore(cp);
        if token_count == 1 {
            simple_ident
        } else {
            None
        }
    }

    /// Emit exports for `module.exports = <rhs>` (whole-module). PEEKS the RHS
    /// to classify it, emits the matching ExportEntry, and restores the lexer
    /// so the caller's expression walk re-walks the RHS for refs:
    ///   require('./x') → Namespace re-export; `{ a, b: c }` → Named per key;
    ///   a bare identifier → Named { exported: "default" }.
    fn emit_cjs_whole_module_export(&mut self, lhs_span: Span) {
        let cp = self.lexer.checkpoint();
        let kind = self.lexer.peek().kind;
        let sp = self.lexer.peek().span;
        let txt = self.text_of(sp).to_string();
        match kind {
            TokenKind::Ident if txt == "require" => {
                self.lexer.next(); // require
                if matches!(self.lexer.peek().kind, TokenKind::LParen) {
                    self.lexer.next(); // `(`
                    if matches!(self.lexer.peek().kind, TokenKind::Str) {
                        let st = self.lexer.peek().clone();
                        let (from, from_span) = self.read_str_literal(st);
                        self.lexer.next(); // string
                        if matches!(self.lexer.peek().kind, TokenKind::RParen) {
                            self.exports
                                .push(ExportEntry::Namespace { from, from_span });
                        }
                    }
                }
                self.lexer.restore(cp);
            }
            TokenKind::LBrace => {
                let exports = self.scan_cjs_object_literal_exports();
                for export in exports {
                    if export.synthetic_decl {
                        let decl_index = self.push_decl(DeclEvent::Variable {
                            name: export.exported.clone(),
                            name_span: export.name_span,
                            decl_span: export.name_span,
                        });
                        self.exports.push(ExportEntry::Direct {
                            decl_index,
                            exported: export.exported,
                        });
                    } else {
                        self.exports.push(ExportEntry::Named {
                            local: export.local,
                            exported: export.exported,
                            ref_span: lhs_span,
                            is_type_only: false,
                        });
                    }
                }
                self.lexer.restore(cp);
            }
            TokenKind::Ident => {
                self.exports.push(ExportEntry::Named {
                    local: txt,
                    exported: "default".to_string(),
                    ref_span: lhs_span,
                    is_type_only: false,
                });
                // no consume → no restore needed
            }
            _ => {}
        }
    }

    /// Collect the top-level export facts of a CommonJS object literal at the
    /// current `{` peek. Shorthand properties (`{ a }`) and exact identifier
    /// aliases (`{ b: c }`) export existing locals. Inline values
    /// (`{ b: function () {}, c: {} }`) are materialized as synthetic direct
    /// exports so they do not become false DeadExport diagnostics.
    fn scan_cjs_object_literal_exports(&mut self) -> Vec<CjsObjectExport> {
        let mut exports = Vec::new();
        self.lexer.next(); // consume `{`
        let mut depth = 1usize; // object-brace depth
        let mut other = 0usize; // []/() depth — keys only collected at obj depth 1, other==0
        let mut at_key = true; // next name is a key (after `{` or `,`)
        loop {
            let tok = self.lexer.peek().clone();
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::LBrace => {
                    depth += 1;
                    at_key = false;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    depth -= 1;
                    self.lexer.next();
                    if depth == 0 {
                        break;
                    }
                }
                TokenKind::LParen | TokenKind::LBracket => {
                    other += 1;
                    at_key = false;
                    self.lexer.next();
                }
                TokenKind::RParen | TokenKind::RBracket => {
                    other = other.saturating_sub(1);
                    self.lexer.next();
                }
                TokenKind::Comma if depth == 1 && other == 0 => {
                    at_key = true;
                    self.lexer.next();
                }
                TokenKind::Ident | TokenKind::Str if at_key && depth == 1 && other == 0 => {
                    let raw = self.text_of(tok.span);
                    let (name, name_span) = if matches!(tok.kind, TokenKind::Str) && raw.len() >= 2
                    {
                        let inner_start = tok.span.start().saturating_add(1);
                        let inner_len = tok.span.length().saturating_sub(2);
                        (
                            raw[1..raw.len() - 1].to_string(),
                            Span::new(inner_start, inner_len),
                        )
                    } else {
                        (raw.to_string(), tok.span)
                    };
                    self.lexer.next();
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        let local = self.scan_cjs_property_value_simple_ident();
                        let synthetic_decl = local.is_none();
                        exports.push(CjsObjectExport {
                            exported: name.clone(),
                            local: local.unwrap_or_else(|| name.clone()),
                            name_span,
                            synthetic_decl,
                        });
                    } else {
                        let synthetic_decl = matches!(self.lexer.peek().kind, TokenKind::LParen);
                        exports.push(CjsObjectExport {
                            exported: name.clone(),
                            local: name,
                            name_span,
                            synthetic_decl,
                        });
                    }
                    at_key = false;
                }
                _ => {
                    at_key = false;
                    self.lexer.next();
                }
            }
        }
        exports
    }

    /// Consume one object-property value and return its local identifier only
    /// when the value is exactly a single identifier (`b: c`). The lexer stops
    /// before the top-level comma/closing brace so the outer object scanner can
    /// keep its delimiter handling in one place.
    fn scan_cjs_property_value_simple_ident(&mut self) -> Option<String> {
        let mut simple_ident: Option<String> = None;
        let mut token_count = 0usize;
        let mut braces = 0usize;
        let mut brackets = 0usize;
        let mut parens = 0usize;
        loop {
            let tok = self.lexer.peek().clone();
            if braces == 0
                && brackets == 0
                && parens == 0
                && matches!(tok.kind, TokenKind::Comma | TokenKind::RBrace)
            {
                break;
            }
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Ident if token_count == 0 => {
                    let name = self.text_of(tok.span).to_string();
                    if !is_language_value_builtin(&name) {
                        simple_ident = Some(name);
                    }
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LBrace => {
                    braces += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    braces = braces.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    brackets += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RBracket => {
                    brackets = brackets.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::LParen => {
                    parens += 1;
                    token_count += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    parens = parens.saturating_sub(1);
                    token_count += 1;
                    self.lexer.next();
                }
                _ => {
                    token_count += 1;
                    self.lexer.next();
                }
            }
        }
        if token_count == 1 {
            simple_ident
        } else {
            None
        }
    }

    fn read_str_literal(&self, tok: Token) -> (String, Span) {
        // tok.span covers including quotes. specifier_span excludes the quotes.
        let s = tok.span.start() as usize;
        let e = (tok.span.start() + tok.span.length()) as usize;
        let inner_start = s + 1;
        let inner_end = e - 1;
        let bytes = &self.source[inner_start..inner_end];
        (
            String::from_utf8_lossy(bytes).into_owned(),
            Span::new(inner_start as u32, (inner_end - inner_start) as u32),
        )
    }

    fn read_static_template_import_specifier(&self, tok: Token) -> Option<(String, Span)> {
        let s = tok.span.start() as usize;
        let e = (tok.span.start() + tok.span.length()) as usize;
        if e <= s + 1 || e > self.source.len() || self.source.get(s) != Some(&b'`') {
            return None;
        }
        let inner_start = s + 1;
        if self.source[e - 1] == b'`' {
            let inner_end = e - 1;
            if inner_end <= inner_start {
                return None;
            }
            let specifier =
                String::from_utf8_lossy(&self.source[inner_start..inner_end]).into_owned();
            return Some((
                specifier,
                Span::new(inner_start as u32, (inner_end - inner_start) as u32),
            ));
        }
        if e < 2 || &self.source[e - 2..e] != b"${" {
            return None;
        }
        let prefix_end = e - 2;
        if prefix_end <= inner_start {
            return None;
        }
        let prefix = &self.source[inner_start..prefix_end];
        let query_start = prefix.iter().position(|b| matches!(*b, b'?' | b'#'))?;
        if query_start == 0 {
            return None;
        }
        let specifier = String::from_utf8_lossy(&prefix[..query_start]).into_owned();
        Some((specifier, Span::new(inner_start as u32, query_start as u32)))
    }

    fn parse_function_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
    ) -> Result<(), &'static str> {
        self.parse_function_decl_inner(
            decl_start,
            is_export,
            local_scope,
            None,
            self.ambient_declaration_body_depth > 0,
        )
    }

    fn parse_ambient_function_decl(&mut self, decl_start: u32) -> Result<(), &'static str> {
        self.parse_function_decl_inner(decl_start, false, None, None, true)
    }

    fn parse_function_decl_inner(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
        synthetic_name: Option<(String, Span)>,
        emit_bodyless_decl: bool,
    ) -> Result<(), &'static str> {
        self.with_declaration_checkpoint(|parser| {
            parser.parse_function_decl_inner_unchecked(
                decl_start,
                is_export,
                local_scope,
                synthetic_name,
                emit_bodyless_decl,
            )
        })
    }

    fn parse_function_decl_inner_unchecked(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
        synthetic_name: Option<(String, Span)>,
        emit_bodyless_decl: bool,
    ) -> Result<(), &'static str> {
        let kw = self.expect(TokenKind::Function)?;
        let _ = kw;
        if matches!(self.lexer.peek().kind, TokenKind::Star) {
            self.lexer.next();
        }
        let (name, name_span) = if Self::token_can_start_binding_identifier(self.lexer.peek().kind)
        {
            let name_tok = self.lexer.next();
            (self.text_of(name_tok.span).to_string(), name_tok.span)
        } else if let Some((name, name_span)) = synthetic_name {
            (name, name_span)
        } else {
            return Err("expected binding identifier");
        };
        let local_owner_decl_index = local_scope.and_then(|_| self.current_owner());
        self.push_type_param_scope();
        self.push_value_scope();
        let decl_event_idx = self.events.len();
        let pending_decl_index = self.push_decl(DeclEvent::Function {
            name: name.clone(),
            name_span,
            decl_span: Span::new(decl_start, 0),
            body_span: Span::new(decl_start, 0),
        });
        self.push_owner(pending_decl_index); // this fn owns its param/return/body refs
        self.skip_type_param_list_collecting_refs();
        self.expect(TokenKind::LParen)?;
        self.parse_param_list_emitting_type_refs()?;
        // v0.6 commit 2 — capture the function's declared return-
        // class for factory-return inference BEFORE the type-emitter
        // consumes it. Plain-Ident only; generics stripped. `None`
        // for union / intersection / object-literal / void / missing
        // return-type annotations. Captured here, pushed to the
        // function_returns sidecar AFTER push_decl below so the
        // FunctionReturn carries the correct decl_index.
        let mut captured_return_class: Option<String> = None;
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            captured_return_class = self.peek_plain_ident_return_class();
            self.parse_return_type_emitting_refs();
        }
        // Bodyless declaration — no `{` body follows the signature:
        //   * an overload signature (`f(): T;`), OR
        //   * an ambient/`declare`-context function with no body
        //     (`declare function f(): void`, and `declare namespace N { export
        //     function f(): void }` — no trailing `;` in `.d.ts` style).
        // Ordinary overloads release their reserved slot when it has no children;
        // finalization binds their type references to the implementation by scope
        // and name. Ambient declarations retain a zero-body node. If malformed
        // input emitted nested declarations, retain the slot to preserve identity.
        if !matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            if matches!(self.lexer.peek().kind, TokenKind::Semi) {
                self.lexer.next();
            }
            let should_emit_bodyless_decl = emit_bodyless_decl
                || (is_export && self.is_declaration_file())
                || self.decl_count != pending_decl_index + 1;
            if should_emit_bodyless_decl {
                let decl_end = self.lexer.peek().span.start();
                let decl_index = pending_decl_index;
                self.events[decl_event_idx] = Event::Decl(DeclEvent::Function {
                    name: name.clone(),
                    name_span,
                    decl_span: Span::new(decl_start, decl_end.saturating_sub(decl_start)),
                    body_span: Span::new(decl_end, 0),
                });
                if let Some(scope) = local_scope {
                    self.local_value_decls.push(LocalValueDecl {
                        name: name.clone(),
                        scope,
                        decl_index,
                        owner_decl_index: local_owner_decl_index,
                    });
                }
                if is_export {
                    self.exports.push(ExportEntry::Direct {
                        decl_index,
                        exported: name.clone(),
                    });
                }
            }
            if !should_emit_bodyless_decl {
                self.events.remove(decl_event_idx);
                self.decl_count -= 1;
                self.pending_function_overloads.push((
                    name,
                    local_scope.unwrap_or(0),
                    self.owner_stack.iter().rev().nth(1).copied(),
                    decl_event_idx..self.events.len(),
                ));
            }
            self.pop_owner();
            self.pop_value_scope();
            self.pop_type_param_scope();
            return Ok(());
        }
        let body_start = self.lexer.peek().span.start();
        self.expect(TokenKind::LBrace)?;
        let decl_index = pending_decl_index;
        if let Some(scope) = local_scope {
            self.local_value_decls.push(LocalValueDecl {
                name: name.clone(),
                scope,
                decl_index,
                owner_decl_index: local_owner_decl_index,
            });
        }
        let (body_end, recovered_context) = match self.walk_balanced_braces_collecting_refs() {
            Ok(body_end) => (body_end, None),
            Err(context) => {
                let fallback_end = self.lexer.peek().span.start().max(body_start + 1);
                (fallback_end, Some(context))
            }
        };
        let decl_end = body_end;
        if let Some(Event::Decl(DeclEvent::Function {
            decl_span,
            body_span,
            ..
        })) = self.events.get_mut(decl_event_idx)
        {
            *decl_span = Span::new(decl_start, decl_end.saturating_sub(decl_start));
            *body_span = Span::new(body_start, body_end.saturating_sub(body_start));
        }
        if let Some(context) = recovered_context {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::SyntaxRecovered {
                    context: context.to_string(),
                },
                file_path: self.path.clone(),
                span: Span::new(decl_start, decl_end.saturating_sub(decl_start)),
            });
        }
        self.drain_service_members_for_owner(decl_index);
        // v0.6 commit 2 — push to per-file function_returns sidecar
        // now that decl_index is known. Consumed by commit 4's
        // FactoryRef::Plain resolver lookup.
        if let Some(class_name) = captured_return_class {
            self.function_returns
                .push(crate::ts::events::FunctionReturn {
                    name: name.clone(),
                    class_name,
                    decl_index,
                });
        }
        if is_export {
            self.exports.push(ExportEntry::Direct {
                decl_index,
                exported: name,
            });
        }
        if matches!(self.lexer.peek().kind, TokenKind::Semi) {
            self.lexer.next();
        }
        self.pop_owner();
        self.pop_value_scope();
        self.pop_type_param_scope();
        Ok(())
    }

    fn parse_class_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
    ) -> Result<(), &'static str> {
        self.with_declaration_checkpoint(|parser| {
            parser.parse_class_decl_unchecked(decl_start, is_export, local_scope)
        })
    }

    fn parse_class_decl_unchecked(
        &mut self,
        decl_start: u32,
        is_export: bool,
        local_scope: Option<crate::ts::events::ScopeId>,
    ) -> Result<(), &'static str> {
        self.expect(TokenKind::Class)?;
        let name_tok = self.expect(TokenKind::Ident)?;
        let name = self.text_of(name_tok.span).to_string();
        let local_owner_decl_index = local_scope.and_then(|_| self.current_owner());
        self.push_type_param_scope(); // popped at end of fn
        let decl_event_idx = self.events.len();
        let decl_index = self.push_decl(DeclEvent::Class {
            name: name.clone(),
            name_span: name_tok.span,
            decl_span: Span::new(decl_start, 0),
            body_span: Span::new(decl_start, 0),
            extends: Vec::new(),
            implements: Vec::new(),
        });
        self.push_owner(decl_index); // this class owns its heritage + body refs
                                     // `class C<T extends Base>` — binders record into the scope just opened.
        self.skip_type_param_list_collecting_refs();
        let mut extends = Vec::new();
        let mut implements = Vec::new();
        // `extends X` (at most one for classes). Use `parse_heritage_ref` so
        // qualified names like `extends React.Component<Props>` consume the
        // whole `React.Component` chain before the `<Props>` type-args walk
        // — without it, the parser stops at `React`, fails to recognize
        // `.Component` as part of the heritage name, and crashes when it
        // expects the body `{`.
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let ext_kw = self.lexer.peek().clone();
            if self.text_of(ext_kw.span) == "extends" {
                self.lexer.next();
                let h = self.parse_heritage_ref()?;
                extends.push(h);
                self.skip_class_heritage_expression_tail()?;
            }
        }
        // `implements I, J, K`
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let impl_kw = self.lexer.peek().clone();
            if self.text_of(impl_kw.span) == "implements" {
                self.lexer.next();
                loop {
                    let h = self.parse_heritage_ref()?;
                    implements.push(h);
                    // Heritage generic args (`implements I<A>`): type position,
                    // not expression position — fail-open to `Other`.
                    self.skip_type_args_collecting_refs_with_base(TypeRefPosition::Other);
                    if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                        self.lexer.next();
                        continue;
                    }
                    break;
                }
            }
        }
        let body_start = self.lexer.peek().span.start();
        self.expect(TokenKind::LBrace)?;
        let body_end = self.walk_class_body_collecting_refs(Some(decl_index))?;
        self.events[decl_event_idx] = Event::Decl(DeclEvent::Class {
            name: name.clone(),
            name_span: name_tok.span,
            decl_span: Span::new(decl_start, body_end - decl_start),
            body_span: Span::new(body_start, body_end - body_start),
            extends,
            implements,
        });
        if let Some(scope) = local_scope {
            self.local_value_decls.push(LocalValueDecl {
                name: name.clone(),
                scope,
                decl_index,
                owner_decl_index: local_owner_decl_index,
            });
        }
        if is_export {
            self.exports.push(ExportEntry::Direct {
                decl_index,
                exported: name,
            });
        }
        self.pop_owner();
        self.pop_type_param_scope();
        Ok(())
    }

    fn skip_class_heritage_expression_tail(&mut self) -> Result<(), &'static str> {
        loop {
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::LBrace | TokenKind::Eof => return Ok(()),
                TokenKind::Ident if self.text_of(t.span) == "implements" => return Ok(()),
                // Class `extends Base<A>` heritage args: type position -> Other.
                TokenKind::Lt => {
                    self.skip_type_args_collecting_refs_with_base(TypeRefPosition::Other)
                }
                TokenKind::LParen => {
                    let _ = self.walk_call_args_collecting_refs()?;
                }
                TokenKind::Dot | TokenKind::QuestionDot => {
                    self.lexer.next();
                    if Self::token_can_be_dot_property_identifier(self.lexer.peek().kind) {
                        self.lexer.next();
                    }
                }
                TokenKind::LBracket => {
                    self.lexer.next();
                    self.walk_expression_collecting_refs()?;
                    if matches!(self.lexer.peek().kind, TokenKind::RBracket) {
                        self.lexer.next();
                    }
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    /// Collect refs from a generic-argument list `<A, B<C>>` in EXPRESSION
    /// position (a generic call `foo<A>()` / `x.m<A>()` / an instantiation
    /// expression). F2-2: those args are `ValuePosition` (per the brief:
    /// "`satisfies` / `as` / expression-position generic arguments"). Heritage
    /// generic args (`class C extends Base<A>`, `implements I<A>`) are a
    /// different position and call `skip_type_args_collecting_refs_with_base`
    /// with `Other`.
    fn skip_type_args_collecting_refs(&mut self) {
        self.skip_type_args_collecting_refs_with_base(TypeRefPosition::ValuePosition);
    }

    fn skip_type_args_collecting_refs_with_base(&mut self, base: TypeRefPosition) {
        if !matches!(self.lexer.peek().kind, TokenKind::Lt) {
            return;
        }
        self.lexer.next();
        loop {
            self.lexer.rescan_gt(); // split `>>`/`>>>` so nested generics close
            match self.lexer.peek().kind {
                TokenKind::Gt => {
                    self.lexer.next();
                    return;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                    continue;
                }
                TokenKind::Eof => return,
                _ => {
                    let before = self.lexer.peek().span.start();
                    self.parse_type_expr_with_base(base);
                    // The generic-call shape check is deliberately bounded and
                    // best-effort. On malformed input (or a comparison that the
                    // lookahead mistook for `foo<T>()`), the type parser may stop
                    // without consuming the current token. Always advance during
                    // recovery so this loop cannot spin forever at that offset.
                    if self.lexer.peek().span.start() == before
                        && !matches!(self.lexer.peek().kind, TokenKind::Eof)
                    {
                        self.lexer.next();
                    }
                }
            }
        }
    }

    fn skip_type_param_list_collecting_refs(&mut self) {
        if !matches!(self.lexer.peek().kind, TokenKind::Lt) {
            return;
        }
        self.lexer.next();
        let mut depth = 1;
        let mut seen_binder_in_entry = false;
        while depth > 0 {
            self.lexer.rescan_gt(); // split `>>`/`>>>` so nested generics close
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::Lt => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::Gt => {
                    depth -= 1;
                    self.lexer.next();
                }
                TokenKind::Comma if depth == 1 => {
                    self.lexer.next();
                    seen_binder_in_entry = false;
                }
                TokenKind::Const if depth == 1 && !seen_binder_in_entry => {
                    self.lexer.next();
                }
                TokenKind::In if depth == 1 && !seen_binder_in_entry => {
                    self.lexer.next(); // variance `in` modifier; next Ident is the binder
                }
                TokenKind::Ident => {
                    let text = self.text_of(t.span).to_string();
                    if !seen_binder_in_entry {
                        // `out` variance modifier (contextual keyword): in `<out T>`
                        // it precedes the real binder. Only treat it as a modifier
                        // when an identifier binder follows; `<out>` / `<out extends
                        // C>` / `<out = D>` mean a type param literally named `out`.
                        // (The `in` variance modifier is the `In` token arm above.)
                        if text == "out" {
                            self.lexer.next(); // consume `out`
                            let next = self.lexer.peek().clone();
                            let next_is_binder = next.kind == TokenKind::Ident
                                && self.text_of(next.span) != "extends";
                            if next_is_binder {
                                // `out` was a variance modifier; leave the flag
                                // unset so the following ident is noted as binder.
                                continue;
                            }
                            // `out` is itself the binder name.
                            self.note_type_param_binder("out");
                            seen_binder_in_entry = true;
                            continue;
                        }
                        self.note_type_param_binder(&text);
                        self.lexer.next();
                        seen_binder_in_entry = true;
                    } else if text == "extends" {
                        self.lexer.next();
                        // `<T extends X>` — declaration-site type-parameter
                        // constraint: ConstraintDecl (a demoting bucket, so only
                        // set for the genuine constraint clause).
                        self.parse_type_expr_with_base(TypeRefPosition::ConstraintDecl);
                    } else {
                        self.lexer.next();
                    }
                }
                TokenKind::Eq => {
                    self.lexer.next();
                    // `<T = Default>` — type-parameter default. Not a constraint
                    // and only weakly under pressure; fail-open to `Other`.
                    self.parse_type_expr_with_base(TypeRefPosition::Other);
                }
                TokenKind::Eof => break,
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    /// Consume a destructuring binding pattern and register every bound name
    /// as a value binder in the current scope.
    ///
    /// The caller has **already consumed** the opening delimiter (`{` for
    /// object patterns, `[` for array patterns). `is_object` distinguishes
    /// the two forms.
    ///
    /// Object pattern rules:
    ///   `{ a }` → binds `a` (shorthand)
    ///   `{ a: b }` → binds `b` (renamed; `a` is the key, not a binder)
    ///   `{ a = expr }` → binds `a`; `expr` is walked for value refs
    ///   `{ a: b = expr }` → binds `b`; `expr` is walked
    ///   `{ ...rest }` → binds `rest`
    ///   `{ a: { b } }` → recurse (binds `b`)
    ///   `{ a: [b] }` → recurse (binds `b`)
    ///   Computed keys `[expr]: binder` → skip `expr`, bind `binder`
    ///
    /// Array pattern rules:
    ///   `[a, , b]` → binds `a`, `b` (holes skipped)
    ///   `[...rest]` → binds `rest`
    ///   `[[a], {b}]` → recurse
    ///
    /// Default-value expressions (`= expr`) are walked via
    /// `walk_expression_collecting_refs` so refs inside them are captured,
    /// but the expression itself does not produce additional binders.
    fn harvest_binding_pattern_names(&mut self, is_object: bool) -> Result<(), &'static str> {
        // R8-B: destructuring patterns recurse mutually via the two
        // nested-pattern arms below (parser.rs:1850 `LBrace`, :1856
        // `LBracket`). Adversarial input `const {a:{a:{a:…}}} = obj;` or
        // `const [[[…]]] = arr;` 5000-deep SIGABRTed on a 2 MiB stack
        // at ~level 130. Same DoS defect class as type/expression/
        // brace-walker recursion fixed in audit-5/ext-#4/ext-#5.
        //
        // Reuse `expr_depth` rather than introducing a third counter:
        // destructuring is in the expression-grammar family (let/const
        // declarators, arrow params, function params, catch binders),
        // and nesting a 100-deep destructure inside a 100-deep expression
        // legitimately IS 200 deep — sharing the counter keeps the
        // invariant tight without proliferating state.
        if !self.enter_reference_recursion(ReferenceRecursionKind::Expression) {
            // Drain to matching close brace/bracket without recursing.
            let close_kind = if is_object {
                TokenKind::RBrace
            } else {
                TokenKind::RBracket
            };
            let open_kind = if is_object {
                TokenKind::LBrace
            } else {
                TokenKind::LBracket
            };
            let mut depth: i32 = 1;
            while depth > 0 {
                let t = self.lexer.next();
                if t.kind == open_kind {
                    depth += 1;
                } else if t.kind == close_kind {
                    depth -= 1;
                } else if matches!(t.kind, TokenKind::Eof) {
                    return Err("unterminated binding pattern");
                }
            }
            return Ok(());
        }
        let result = self.harvest_binding_pattern_names_inner(is_object);
        self.leave_reference_recursion(ReferenceRecursionKind::Expression);
        result
    }

    /// Inner body of `harvest_binding_pattern_names`. Extracted so the
    /// depth-guard wrapper above stays a clean check-bump-bail shape.
    fn harvest_binding_pattern_names_inner(&mut self, is_object: bool) -> Result<(), &'static str> {
        let close = if is_object {
            TokenKind::RBrace
        } else {
            TokenKind::RBracket
        };
        // For object patterns we track whether the next ident is in key
        // position (before `:`) or in binder position (after `:`).
        // For array patterns every non-hole ident is a binder.
        //
        // `expect_binder`: true when the next Ident (or `{`/`[`) is a binder
        // rather than a key.  In object patterns this starts false (first
        // ident is a key); after `:` it flips to true.  In array patterns it
        // starts true and stays true.
        let mut expect_binder = !is_object;
        loop {
            let t = self.lexer.peek().clone();
            match t.kind {
                // Finished the pattern.
                k if k == close => {
                    self.lexer.next();
                    break;
                }
                TokenKind::Eof => return Err("unterminated binding pattern"),
                // Rest element / rest property: `...rest`.
                TokenKind::Spread => {
                    self.lexer.next();
                    // The next token is the rest binder (an ident, or a
                    // nested pattern for destructured rest — uncommon but
                    // valid).  Treat it as a binder position.
                    let rest = self.lexer.peek().clone();
                    match rest.kind {
                        TokenKind::Ident => {
                            let name = self.text_of(rest.span).to_string();
                            self.note_value_binder(&name);
                            // v0.5 commit 3 — destructuring rest binder.
                            // Origin: None (rest-spread doesn't carry
                            // a single-class type).
                            let _ = self.emit_binding(name, rest.span, None);
                            self.lexer.next();
                        }
                        TokenKind::LBrace => {
                            self.lexer.next();
                            self.harvest_binding_pattern_names(true)?;
                        }
                        TokenKind::LBracket => {
                            self.lexer.next();
                            self.harvest_binding_pattern_names(false)?;
                        }
                        _ => {
                            self.lexer.next();
                        }
                    }
                    // After a rest element the pattern must close immediately
                    // (a trailing comma before `}` is technically invalid but
                    // tolerated by parsers). Skip to the close.
                    if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                        self.lexer.next();
                    }
                }
                // Computed object key `[expr]: binder` — skip the key
                // expression and treat whatever follows `:` as the binder.
                // R8-D: gate the computed-key arm on `!expect_binder` so it
                // ONLY fires for `[` at key position (`{ [key]: binder }`).
                // Pre-fix the guard `if is_object` was too broad: it also
                // matched when `expect_binder` was true (after a `key:` —
                // i.e., `{ a: [x, y] }` where `[` starts a NESTED ARRAY
                // PATTERN, not a computed key). The over-broad arm balance-
                // skipped the bracket contents, silently dropping the
                // nested-array binders. Same fix applied to both
                // harvest_binding_pattern_names_inner (line 1878) and
                // harvest_binding_pattern_names_collect_inner (line 2096).
                // Mirror of the strict-subset spec-implementation defect
                // pattern external reviewers have caught at every layer.
                TokenKind::LBracket if is_object && !expect_binder => {
                    self.lexer.next(); // consume `[`
                                       // Skip until matching `]`.
                    let mut depth: u32 = 1;
                    loop {
                        match self.lexer.peek().kind {
                            TokenKind::LBracket => {
                                depth += 1;
                                self.lexer.next();
                            }
                            TokenKind::RBracket => {
                                depth -= 1;
                                self.lexer.next();
                                if depth == 0 {
                                    break;
                                }
                            }
                            TokenKind::Eof => {
                                return Err("unterminated computed key");
                            }
                            _ => {
                                self.lexer.next();
                            }
                        }
                    }
                    // Expect `:` then treat the RHS as a binder.
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        expect_binder = true;
                    }
                }
                // Nested object pattern.
                TokenKind::LBrace if expect_binder => {
                    self.lexer.next();
                    self.harvest_binding_pattern_names(true)?;
                    expect_binder = !is_object; // reset for next element
                }
                // Nested array pattern.
                TokenKind::LBracket if expect_binder => {
                    self.lexer.next();
                    self.harvest_binding_pattern_names(false)?;
                    expect_binder = !is_object;
                }
                // Default value after a binder `= expr`.  Walk the expression
                // so refs inside are collected, then reset to key position.
                TokenKind::Eq => {
                    self.lexer.next();
                    self.walk_expression_collecting_refs()?;
                    expect_binder = !is_object;
                }
                // Key–value separator in object pattern: `{ key: binder }`.
                TokenKind::Colon if is_object => {
                    self.lexer.next();
                    expect_binder = true;
                }
                // Comma separates elements.
                TokenKind::Comma => {
                    self.lexer.next();
                    expect_binder = !is_object; // array: next is binder; object: next is key
                }
                // An identifier in binder position.
                TokenKind::Ident if expect_binder => {
                    let name = self.text_of(t.span).to_string();
                    self.note_value_binder(&name);
                    // v0.5 commit 3 — destructured binder. Origin
                    // None: destructuring doesn't preserve class
                    // typing through the pattern in v0.5 scope.
                    let _ = self.emit_binding(name, t.span, None);
                    self.lexer.next();
                    expect_binder = false; // now expecting `:`, `,`, `=`, or close
                }
                // An identifier in key position (object pattern shorthand or
                // renamed key).  Don't bind yet — wait to see if `:` follows.
                // If `:` follows, the *value* side is the binder.
                // If `,` / `}` follows, this is shorthand → bind it now.
                TokenKind::Ident => {
                    // object pattern, key position
                    let name = self.text_of(t.span).to_string();
                    self.lexer.next();
                    match self.lexer.peek().kind {
                        TokenKind::Colon => {
                            // renamed: `{ key: binder }` — skip `:`; on next
                            // iteration expect_binder = true will bind the RHS.
                            self.lexer.next();
                            expect_binder = true;
                        }
                        _ => {
                            // Shorthand `{ key }` or `{ key = default }` —
                            // the key is also the binder.
                            self.note_value_binder(&name);
                            let _ = self.emit_binding(name, t.span, None);
                            // If `= default` follows, walk it next iteration.
                        }
                    }
                }
                // Skip question marks (`{ a? }` — technically not valid in
                // a binding pattern but appears in some TS-isms; treat key
                // as seen, wait for `:` or `,`).
                TokenKind::Question => {
                    self.lexer.next();
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
        Ok(())
    }

    /// Like [`harvest_binding_pattern_names`] but also appends each harvested
    /// binder name to `out` so the caller can emit `DeclEvent::Variable` for
    /// each one. The `{` / `[` opening token must already have been consumed
    /// by the caller.
    ///
    /// This is used by `parse_variable_decl` for top-level destructuring:
    /// ```text
    /// const { a, b } = src;   // harvests ["a", "b"]
    /// const [x, y]   = src;   // harvests ["x", "y"]
    /// ```
    fn harvest_binding_pattern_names_collect(
        &mut self,
        is_object: bool,
        out: &mut Vec<(String, u32, usize)>,
        decl_start: u32,
        parent_owner: Option<u32>,
    ) -> Result<(), &'static str> {
        // R8-B: same DoS surface as `harvest_binding_pattern_names`
        // but reached through `parse_variable_decl` instead of the
        // expression/arrow-param paths. Without the guard here,
        // `const { a: { a: { … } } } = obj;` 5000-deep bypasses the
        // sibling guard entirely and SIGABRTs. Enter the shared reference
        // recursion budget before descending into the collecting variant.
        if !self.enter_reference_recursion(ReferenceRecursionKind::Expression) {
            let close_kind = if is_object {
                TokenKind::RBrace
            } else {
                TokenKind::RBracket
            };
            let open_kind = if is_object {
                TokenKind::LBrace
            } else {
                TokenKind::LBracket
            };
            let mut depth: i32 = 1;
            while depth > 0 {
                let t = self.lexer.next();
                if t.kind == open_kind {
                    depth += 1;
                } else if t.kind == close_kind {
                    depth -= 1;
                } else if matches!(t.kind, TokenKind::Eof) {
                    return Err("unterminated binding pattern");
                }
            }
            return Ok(());
        }
        let result = self.harvest_binding_pattern_names_collect_inner(
            is_object,
            out,
            decl_start,
            parent_owner,
        );
        self.leave_reference_recursion(ReferenceRecursionKind::Expression);
        result
    }

    /// Inner body of `harvest_binding_pattern_names_collect`. Extracted
    /// so the depth-guard wrapper above stays a clean check-bump-bail
    /// shape (mirrors the same factoring on `harvest_binding_pattern_names`).
    fn harvest_binding_pattern_names_collect_inner(
        &mut self,
        is_object: bool,
        out: &mut Vec<(String, u32, usize)>,
        decl_start: u32,
        parent_owner: Option<u32>,
    ) -> Result<(), &'static str> {
        let close = if is_object {
            TokenKind::RBrace
        } else {
            TokenKind::RBracket
        };
        let mut expect_binder = !is_object;
        loop {
            let t = self.lexer.peek().clone();
            match t.kind {
                k if k == close => {
                    self.lexer.next();
                    break;
                }
                TokenKind::Eof => return Err("unterminated binding pattern"),
                TokenKind::Spread => {
                    self.lexer.next();
                    let rest = self.lexer.peek().clone();
                    match rest.kind {
                        TokenKind::Ident => {
                            let name = self.text_of(rest.span).to_string();
                            self.collect_variable_binding(
                                name,
                                rest.span,
                                out,
                                decl_start,
                                parent_owner,
                            );
                            self.lexer.next();
                        }
                        TokenKind::LBrace => {
                            self.lexer.next();
                            self.harvest_binding_pattern_names_collect(
                                true,
                                out,
                                decl_start,
                                parent_owner,
                            )?;
                        }
                        TokenKind::LBracket => {
                            self.lexer.next();
                            self.harvest_binding_pattern_names_collect(
                                false,
                                out,
                                decl_start,
                                parent_owner,
                            )?;
                        }
                        _ => {
                            self.lexer.next();
                        }
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                        self.lexer.next();
                    }
                }
                // Computed object key `[expr]: binder` — skip the key then
                // treat the RHS as a binder.
                // R8-D: gate the computed-key arm on `!expect_binder` so it
                // ONLY fires for `[` at key position (`{ [key]: binder }`).
                // Pre-fix the guard `if is_object` was too broad: it also
                // matched when `expect_binder` was true (after a `key:` —
                // i.e., `{ a: [x, y] }` where `[` starts a NESTED ARRAY
                // PATTERN, not a computed key). The over-broad arm balance-
                // skipped the bracket contents, silently dropping the
                // nested-array binders. Same fix applied to both
                // harvest_binding_pattern_names_inner (line 1878) and
                // harvest_binding_pattern_names_collect_inner (line 2096).
                // Mirror of the strict-subset spec-implementation defect
                // pattern external reviewers have caught at every layer.
                TokenKind::LBracket if is_object && !expect_binder => {
                    self.lexer.next();
                    let mut depth: u32 = 1;
                    loop {
                        match self.lexer.peek().kind {
                            TokenKind::LBracket => {
                                depth += 1;
                                self.lexer.next();
                            }
                            TokenKind::RBracket => {
                                depth -= 1;
                                self.lexer.next();
                                if depth == 0 {
                                    break;
                                }
                            }
                            TokenKind::Eof => return Err("unterminated computed key"),
                            _ => {
                                self.lexer.next();
                            }
                        }
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        expect_binder = true;
                    }
                }
                // Nested object pattern.
                TokenKind::LBrace if expect_binder => {
                    self.lexer.next();
                    self.harvest_binding_pattern_names_collect(
                        true,
                        out,
                        decl_start,
                        parent_owner,
                    )?;
                    expect_binder = !is_object;
                }
                // Nested array pattern.
                TokenKind::LBracket if expect_binder => {
                    self.lexer.next();
                    self.harvest_binding_pattern_names_collect(
                        false,
                        out,
                        decl_start,
                        parent_owner,
                    )?;
                    expect_binder = !is_object;
                }
                TokenKind::Eq => {
                    self.lexer.next();
                    self.walk_expression_collecting_refs()?;
                    expect_binder = !is_object;
                }
                TokenKind::Colon if is_object => {
                    self.lexer.next();
                    expect_binder = true;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                    expect_binder = !is_object;
                }
                TokenKind::Ident if expect_binder => {
                    let name = self.text_of(t.span).to_string();
                    self.collect_variable_binding(name, t.span, out, decl_start, parent_owner);
                    self.lexer.next();
                    expect_binder = false;
                }
                TokenKind::Ident => {
                    // object pattern, key position
                    let name = self.text_of(t.span).to_string();
                    self.lexer.next();
                    match self.lexer.peek().kind {
                        TokenKind::Colon => {
                            self.lexer.next();
                            expect_binder = true;
                        }
                        _ => {
                            // Shorthand `{ key }` — key is also the binder.
                            self.collect_variable_binding(
                                name,
                                t.span,
                                out,
                                decl_start,
                                parent_owner,
                            );
                        }
                    }
                }
                TokenKind::Question => {
                    self.lexer.next();
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
        Ok(())
    }

    fn parse_param_list_emitting_type_refs(&mut self) -> Result<(), &'static str> {
        let mut depth = 1;
        let mut expecting_binder = true;
        // v0.5 commit 3 — index of the most-recently emitted
        // BindingEvent for the in-progress parameter, so the Colon
        // arm can attach an ExplicitType origin. Cleared on Comma
        // (next param) and RParen (end of list).
        let mut pending_binding_idx: Option<usize> = None;
        while depth > 0 {
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::LParen => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    depth -= 1;
                    pending_binding_idx = None;
                    self.lexer.next();
                }
                TokenKind::Comma if depth == 1 => {
                    expecting_binder = true;
                    pending_binding_idx = None;
                    self.lexer.next();
                }
                TokenKind::Colon => {
                    self.lexer.next();
                    // v0.5 commit 3 — capture ExplicitType origin on
                    // typed parameters (`function f(x: C)`) so
                    // commit 5 can resolve Pattern P (`x.m()` inside
                    // `f`'s body) to `C.m`.
                    if let Some(idx) = pending_binding_idx {
                        if let Some(class_name) = self.peek_explicit_type_origin() {
                            self.set_binding_origin(
                                idx,
                                Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }),
                            );
                        }
                    }
                    // G1.6 D4 — this is the shared parameter-list parser
                    // (function decls/expressions, object-method shorthand,
                    // function-type tails, object/interface-type method
                    // members); every param type routes through here, so
                    // ParamAnnotation (not Annotation) is unconditionally
                    // correct regardless of which caller reached this loop.
                    self.parse_param_type_expr_emitting_refs();
                    expecting_binder = false;
                }
                TokenKind::Eq if depth == 1 => {
                    self.lexer.next();
                    self.walk_expression_collecting_refs()?;
                    expecting_binder = false;
                }
                kind if expecting_binder
                    && depth == 1
                    && Self::token_can_start_binding_identifier(kind) =>
                {
                    let binder_name = self.text_of(t.span).to_string();
                    self.note_value_binder(&binder_name);
                    // v0.5 commit 3 — emit a BindingEvent for the
                    // parameter. Origin starts None; the Colon arm
                    // upgrades it to ExplicitType when the param
                    // carries a single-Ident type annotation.
                    let idx = self.emit_binding(binder_name, t.span, None);
                    pending_binding_idx = Some(idx);
                    self.lexer.next();
                    expecting_binder = false;
                }
                // Destructured param: `function f({ a: b }, [c])`.
                // Harvest all bound names from the pattern without emitting
                // phantom ValueRef events for them.
                TokenKind::LBrace if expecting_binder && depth == 1 => {
                    self.lexer.next(); // consume `{`
                    self.harvest_binding_pattern_names(true)?;
                    expecting_binder = false;
                }
                TokenKind::LBracket if expecting_binder && depth == 1 => {
                    self.lexer.next(); // consume `[`
                    self.harvest_binding_pattern_names(false)?;
                    expecting_binder = false;
                }
                TokenKind::Semi | TokenKind::RBrace if depth == 1 => {
                    return Err("unterminated parameter list");
                }
                TokenKind::Eof => return Err("unterminated parameter list"),
                _ => {
                    self.lexer.next();
                }
            }
        }
        Ok(())
    }

    fn parse_interface_decl(
        &mut self,
        decl_start: u32,
        is_export: bool,
    ) -> Result<(), &'static str> {
        self.expect(TokenKind::Interface)?;
        let name_tok = self.expect(TokenKind::Ident)?;
        let name = self.text_of(name_tok.span).to_string();
        self.push_type_param_scope(); // popped at end of fn
        self.push_owner(self.decl_count); // this interface owns its member type refs
                                          // `interface I<T>` — type-PARAMETER list.
        self.skip_type_param_list_collecting_refs();
        let mut extends = Vec::new();
        if matches!(self.lexer.peek().kind, TokenKind::Ident) {
            let ext_kw = self.lexer.peek().clone();
            if self.text_of(ext_kw.span) == "extends" {
                self.lexer.next();
                loop {
                    let h = self.parse_heritage_ref()?;
                    extends.push(h);
                    // Heritage generic args (`extends Base<A>`): type position -> Other.
                    self.skip_type_args_collecting_refs_with_base(TypeRefPosition::Other);
                    if matches!(self.lexer.peek().kind, TokenKind::Comma) {
                        self.lexer.next();
                        continue;
                    }
                    break;
                }
            }
        }
        let body_start = self.lexer.peek().span.start();
        self.expect(TokenKind::LBrace)?;
        // Walk the interface body emitting TypeRef events for type-position
        // identifiers in each member declaration. Member names (the part
        // before `:` / `?:` / `(` / `<`) are suppressed via the same
        // object-type-key heuristic the type-expression walker uses.
        // Treats the body like a giant object-type literal: every member is
        // `name [?] [: TYPE | (params): TYPE]; ...`.
        //
        // G1.7 Fix 2 — arm member minting for THIS body only (the other
        // call site, local/ambient interfaces inside bodies, stays
        // unarmed). `current_owner()` here is the interface's future
        // decl_index, which stays correct through the body because minted
        // members are BUFFERED (pending_service_members), never pushed
        // mid-body.
        let minting_owner = self.current_owner();
        let prev_minting = self.type_member_minting_owner.take();
        self.type_member_minting_owner = minting_owner;
        let body_end_result = self.parse_interface_body_emitting_refs();
        self.type_member_minting_owner = prev_minting;
        let body_end = body_end_result?;
        // decl_index = number of decls before this one (push_decl tracks it).
        let decl_index = self.push_decl(DeclEvent::Interface {
            name: name.clone(),
            name_span: name_tok.span,
            decl_span: Span::new(decl_start, body_end - decl_start),
            body_span: Span::new(body_start, body_end - body_start),
            extends,
        });
        debug_assert_eq!(
            minting_owner,
            Some(decl_index),
            "buffered type members must not shift the interface's own decl_index"
        );
        self.drain_service_members_for_owner(decl_index);
        if is_export {
            self.exports.push(ExportEntry::Direct {
                decl_index,
                exported: name,
            });
        }
        self.pop_owner();
        self.pop_type_param_scope();
        Ok(())
    }

    fn parse_heritage_ref(&mut self) -> Result<HeritageRef, &'static str> {
        let first = self.expect(TokenKind::Ident)?;
        let start = first.span.start();
        let name = self.text_of(first.span).to_string();
        let mut end = first.span.start() + first.span.length();
        while matches!(self.lexer.peek().kind, TokenKind::Dot) {
            self.lexer.next();
            if !matches!(self.lexer.peek().kind, TokenKind::Ident) {
                break;
            }
            let seg = self.lexer.next();
            end = seg.span.start() + seg.span.length();
        }
        Ok(HeritageRef {
            name,
            ref_span: Span::new(start, end - start),
        })
    }

    /// Parse a type expression in an ANNOTATION position (property or
    /// body-local-variable annotation head) — the overwhelmingly common
    /// non-parameter case. Callers whose position is NOT an annotation
    /// (type-alias RHS, a type-parameter constraint or default) go through
    /// `parse_type_expr_with_base` directly. Callers parsing a parameter's
    /// own type inside a "(params)" list use `parse_param_type_expr_emitting_refs`
    /// instead (G1.6 D4) so the two positions stay distinguishable.
    fn parse_type_expr_emitting_refs(&mut self) {
        self.parse_type_expr_with_base(TypeRefPosition::Annotation);
    }

    /// Parse a type expression in a PARAMETER-annotation position (G1.6 D4):
    /// the type of one parameter inside a callable's own parameter list —
    /// function declarations/expressions/arrows, class methods (incl. object-
    /// method shorthand and interface method signatures), constructors (incl.
    /// param-property fields), and the parameter list of a function-TYPE
    /// expression (`type H = (s: State) => R`, and any nested function-type
    /// wherever one appears). Every "(params)" parameter-list parser in this
    /// file routes its Colon arm through this method instead of
    /// `parse_type_expr_emitting_refs` so a param's type ref is
    /// distinguishable from a body-local/property annotation — both
    /// previously shared discriminant 0 (`Annotation`), which M0-B found the
    /// walk side cannot disambiguate from `owner` alone.
    fn parse_param_type_expr_emitting_refs(&mut self) {
        self.parse_type_expr_with_base(TypeRefPosition::ParamAnnotation);
    }

    /// Parse a type expression whose enclosing base position is `base`. `base`
    /// is pushed onto `pos_stack` for the duration so the structured type
    /// parser's `emit_type_ref` sites classify against it (a union/intersection
    /// inside still retags its direct members to `CompositionMember`).
    fn parse_type_expr_with_base(&mut self, base: TypeRefPosition) {
        self.pos_stack.push(base);
        // Transient type-param scope so binders the type itself introduces
        // (`infer X`, and any future top-level binder) are scoped to this type
        // expression even when the caller has no decl scope of its own (e.g. a
        // top-level variable annotation). Without it, `note_type_param_binder`
        // no-ops on an empty scope stack and the binder leaks as a false ref.
        // Harmless when nested under a decl scope: `is_type_param_in_scope`
        // checks every scope and the binder's lifetime is exactly this type.
        //
        // Exception: when we are parsing inside a conditional check-type
        // (`conditional_check_depth > 0`), `parse_conditional_type` has already
        // pushed a scope that must stay live through both conditional branches.
        // Pushing another transient scope here would intercept `infer` binders
        // (via `note_type_param_binder`, which writes to the *top* scope), then
        // pop them away before the true branch is parsed — the bug. Skip the
        // transient push/pop so binders land in the conditional's scope instead.
        if self.conditional_check_depth > 0 {
            self.parse_type();
        } else {
            self.push_type_param_scope();
            self.parse_type();
            self.pop_type_param_scope();
        }
        self.pos_stack.pop();
    }

    fn parse_interface_body_emitting_refs(&mut self) -> Result<u32, &'static str> {
        let mut depth: i32 = 1;
        let mut brace_in_type: i32 = 1;
        let mut last_end = 0u32;
        while depth > 0 {
            let t = self.lexer.peek().clone();
            match t.kind {
                TokenKind::LBrace => {
                    depth += 1;
                    brace_in_type += 1;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    let rt = self.lexer.next();
                    last_end = rt.span.start() + rt.span.length();
                    depth -= 1;
                    brace_in_type -= 1;
                }
                TokenKind::LBracket if brace_in_type == 1 => {
                    // Mapped member `[K in C]: V`, index signature `[k: T]: V`, or
                    // computed key `[ns.member]: V` — delegate to the shared bracket-
                    // member parser so the mapped binder is properly scoped, dotted
                    // computed-key tails are not emitted as TypeRefs, and the value
                    // type is recursed rather than token-walked.  parse_bracket_member
                    // consumes the leading `[` itself and exits after the value type.
                    self.parse_bracket_member();
                }
                TokenKind::Lt | TokenKind::LParen if brace_in_type == 1 => {
                    // Anonymous call signature `<T>(...)` or `(...)` at member
                    // position.  Delegate to the method-signature sub-parser so
                    // the leading type-param list `<T extends Constraint, ...>` is
                    // properly scoped (binders suppressed, constraint refs emitted)
                    // and the param/return types are recursed.  The cursor is
                    // already positioned at `<` or `(` — exactly what
                    // parse_interface_method_signature_emitting_refs expects.
                    //
                    // G1.7 Fix 2 — when armed, the call signature mints a
                    // member decl under the reserved name `"()"`: it pins
                    // itself for the guard's admission pass (blocking the
                    // C-4 blanket fallback on hybrid containers) and is the
                    // substrate Fix 1's call-signature-only projection reads.
                    let minting = self.type_member_minting_owner.is_some()
                        && self.type_member_minting_owner == self.current_owner();
                    if minting {
                        let sig_span = t.span;
                        let refs_start = self.events.len();
                        let _ = self.parse_interface_method_signature_emitting_refs();
                        let refs_end = self.events.len();
                        let decl_end = self.lexer.peek().span.start();
                        self.record_type_member(
                            "()".to_string(),
                            sig_span,
                            Span::new(sig_span.start(), decl_end.saturating_sub(sig_span.start())),
                            (refs_start, refs_end),
                        );
                    } else {
                        let _ = self.parse_interface_method_signature_emitting_refs();
                    }
                }
                TokenKind::New if brace_in_type == 1 => {
                    // Construct signature `new <T extends Base>(arg: T): T`.
                    // Consume `new`, then delegate as for an anonymous call
                    // signature — the cursor will be at `<` or `(`.
                    self.lexer.next();
                    let _ = self.parse_interface_method_signature_emitting_refs();
                }
                TokenKind::Lt | TokenKind::LParen | TokenKind::LBracket => {
                    depth += 1;
                    self.lexer.next();
                }
                TokenKind::Gt | TokenKind::RParen | TokenKind::RBracket => {
                    // Bug F (2026-05-26): a stray closer at the body's
                    // outer level (depth == 1, no nested bracket opened
                    // by this loop) used to drop depth to 0 and exit
                    // the loop with `last_end` still at its initial 0.
                    // That zeroed `body_end` then underflowed
                    // `body_end - body_start` u32-subtraction in
                    // `parse_interface_decl`'s `Span::new` call,
                    // panicking the parser. Gate the decrement on
                    // `depth > 1` so the outer `}` (depth == 1) can
                    // only be closed by the RBrace arm above, which
                    // updates `last_end`. Stray closers are tolerantly
                    // skipped without ending the body.
                    if depth > 1 {
                        depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::Ident => {
                    let span = t.span;
                    let name = self.text_of(span).to_string();
                    self.lexer.next();
                    let next_kind = self.lexer.peek().kind;
                    let is_method_header =
                        brace_in_type > 0 && matches!(next_kind, TokenKind::LParen | TokenKind::Lt);
                    let is_property_key = brace_in_type > 0
                        && matches!(next_kind, TokenKind::Colon | TokenKind::Question);
                    let is_contextual_keyword = matches!(
                        name.as_str(),
                        "keyof" | "typeof" | "infer" | "is" | "asserts" | "readonly" | "extends"
                    );
                    // G1.7 Fix 2 — mint member decls only for THIS body's
                    // top-level members (brace_in_type == 1) and only when
                    // parse_interface_decl armed the flag for the CURRENT
                    // owner (nested/local interfaces stay unarmed).
                    let minting = brace_in_type == 1
                        && self.type_member_minting_owner.is_some()
                        && self.type_member_minting_owner == self.current_owner();
                    if is_method_header {
                        if minting {
                            let refs_start = self.events.len();
                            self.parse_interface_method_signature_emitting_refs()?;
                            let refs_end = self.events.len();
                            let decl_end = self.lexer.peek().span.start();
                            self.record_type_member(
                                name.clone(),
                                span,
                                Span::new(span.start(), decl_end.saturating_sub(span.start())),
                                (refs_start, refs_end),
                            );
                        } else {
                            self.parse_interface_method_signature_emitting_refs()?;
                        }
                    } else if is_property_key {
                        // Property member `name: Type` / `name?: Type`. The key
                        // is suppressed (not a ref); delegate the VALUE type to
                        // the recursive parser so advanced types (conditional,
                        // mapped, `infer`, `keyof`, …) are parsed correctly —
                        // rather than token-walked here, where the property-key
                        // heuristic mis-fires on `Y ?`/`A :` inside a conditional
                        // and the mapped binder `[K in …]` is never scoped.
                        if matches!(self.lexer.peek().kind, TokenKind::Question) {
                            self.lexer.next();
                        }
                        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                            self.lexer.next();
                            // G1.7 Fix 2 — a FUNCTION-TYPED property
                            // (`get: (opts: T) => R`) is a callable member:
                            // mint its decl and lift its signature refs.
                            // Non-function values keep today's path.
                            if minting && self.peek_type_is_function_shaped() {
                                let refs_start = self.events.len();
                                self.parse_type_expr_emitting_refs();
                                let refs_end = self.events.len();
                                let decl_end = self.lexer.peek().span.start();
                                self.record_type_member(
                                    name.clone(),
                                    span,
                                    Span::new(span.start(), decl_end.saturating_sub(span.start())),
                                    (refs_start, refs_end),
                                );
                            } else {
                                self.parse_type_expr_emitting_refs();
                            }
                        }
                    } else if !is_contextual_keyword {
                        // Bare identifier in interface-body token-walk position
                        // (not a property value, method header, or keyword). The
                        // surrounding parse context is ambiguous here, so
                        // fail-open to `Other`.
                        let _ = self.emit_type_ref(name, span, TypeRefPosition::Other);
                    }
                }
                TokenKind::Eof => return Err("unterminated interface body"),
                _ => {
                    self.lexer.next();
                }
            }
        }
        Ok(last_end)
    }

    fn parse_interface_method_signature_emitting_refs(&mut self) -> Result<(), &'static str> {
        self.push_type_param_scope();
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.skip_type_param_list_collecting_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            self.lexer.next();
            let mut pd: i32 = 1;
            while pd > 0 {
                match self.lexer.peek().kind {
                    TokenKind::LParen => {
                        pd += 1;
                        self.lexer.next();
                    }
                    TokenKind::RParen => {
                        pd -= 1;
                        self.lexer.next();
                    }
                    TokenKind::Colon => {
                        self.lexer.next();
                        // G1.6 D4 — interface method-signature parameter
                        // (e.g. `onError(err: T): void` inside an
                        // `interface`); consistent with the shared
                        // parameter-list parser and `parse_method_member`'s
                        // object/interface-type method members.
                        self.parse_param_type_expr_emitting_refs();
                    }
                    TokenKind::Eof => {
                        self.pop_type_param_scope();
                        return Err("unterminated interface method params");
                    }
                    _ => {
                        self.lexer.next();
                    }
                }
            }
        }
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next();
            self.parse_type_expr_emitting_refs();
        }
        if matches!(self.lexer.peek().kind, TokenKind::Semi | TokenKind::Comma) {
            self.lexer.next();
        }
        self.pop_type_param_scope();
        Ok(())
    }

    fn parse_return_type_emitting_refs(&mut self) {
        // The recursive-descent parser stops at a `{` that begins a function body
        // (a `{` only enters the type if it starts an object type, which is
        // balanced), so the old `stop_at_top_brace` flag is unnecessary.
        // Transient scope: same rationale as `parse_type_expr_emitting_refs`.
        // F2-2: refs here are in return-type position (`ReturnType`); a union
        // return type still retags its direct members to `CompositionMember`.
        self.pos_stack.push(TypeRefPosition::ReturnType);
        self.push_type_param_scope();
        self.parse_type();
        self.pop_type_param_scope();
        self.pos_stack.pop();
    }

    /// Handle an object-literal method shorthand starting at the token after the
    /// key name (or computed key `[…]`) has already been consumed. The cursor is
    /// now at `<` (generic method) or `(` (non-generic method).
    ///
    /// Correct scoping for `{ on<Key extends keyof Events>(type: Key, handler: H) { … } }`:
    /// 1. Push a fresh type-param scope and value scope.
    /// 2. Skip the optional `<…>` generic param list (notes binders, emits
    ///    constraint refs as TypeRefs via `skip_type_param_list_collecting_refs`).
    /// 3. Consume `(…)` param list, binding param names as value binders and
    ///    routing `: TypeAnnotation` through `parse_type_expr_emitting_refs`
    ///    (same logic as `parse_param_list_emitting_type_refs`).
    /// 4. Route optional `: ReturnType` through `parse_return_type_emitting_refs`.
    /// 5. Walk the `{ body }` normally with `walk_balanced_braces_collecting_refs`.
    /// 6. Pop both scopes.
    ///
    /// Without this, the generic type-param list and param/return type annotations
    /// are token-walked in value-context, leaking `Key`/`extends`/`keyof`/`Events`/
    /// `Handler`/`Iter` as phantom ValueRef → UnresolvedReference diagnostics (the
    /// mitt 9-Unresolved cluster and ts-pattern Iterator/IteratorResult leaks).
    fn walk_object_method_shorthand_collecting_refs(&mut self) -> Result<Span, &'static str> {
        self.push_type_param_scope();
        self.push_value_scope();
        // Optional generic type-param list `<Key extends keyof Events>`.
        // `skip_type_param_list_collecting_refs` notes binders in the type-param
        // scope and emits constraint refs (e.g. `Events`) as TypeRefs.
        if matches!(self.lexer.peek().kind, TokenKind::Lt) {
            self.skip_type_param_list_collecting_refs();
        }
        // Param list `(type: Key, handler: Handler)`.
        if matches!(self.lexer.peek().kind, TokenKind::LParen) {
            self.lexer.next(); // consume `(`
            self.parse_param_list_emitting_type_refs()?;
        }
        // Optional return type annotation `: Iter`.
        if matches!(self.lexer.peek().kind, TokenKind::Colon) {
            self.lexer.next(); // consume `:`
            self.parse_return_type_emitting_refs();
        }
        // Method body `{ … }`.
        let mut body_span = Span::new(0, 0);
        if matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            let body_start = self.lexer.peek().span.start();
            self.lexer.next(); // consume `{`
            let body_end = self.walk_balanced_braces_collecting_refs()?;
            body_span = Span::new(body_start, body_end - body_start);
        }
        self.pop_value_scope();
        self.pop_type_param_scope();
        Ok(body_span)
    }

    fn skip_predeclared_binding_default(&mut self, pattern_close: TokenKind) {
        let mut paren_depth = 0i32;
        let mut bracket_depth = 0i32;
        let mut brace_depth = 0i32;
        loop {
            let kind = self.lexer.peek().kind;
            let at_default_depth = paren_depth == 0 && bracket_depth == 0 && brace_depth == 0;
            if matches!(kind, TokenKind::Eof)
                || (at_default_depth && (matches!(kind, TokenKind::Comma) || kind == pattern_close))
            {
                break;
            }
            match kind {
                TokenKind::LParen => paren_depth += 1,
                TokenKind::RParen if paren_depth > 0 => paren_depth -= 1,
                TokenKind::LBracket => bracket_depth += 1,
                TokenKind::RBracket if bracket_depth > 0 => bracket_depth -= 1,
                TokenKind::LBrace => brace_depth += 1,
                TokenKind::RBrace if brace_depth > 0 => brace_depth -= 1,
                _ => {}
            }
            self.lexer.next();
        }
    }

    /// Predeclare destructured names without emitting binding events or refs.
    /// This pass only establishes lexical shadowing before the real body walk;
    /// the normal binding-pattern parser remains the sole evidence emitter.
    fn predeclare_binding_pattern_names(
        &mut self,
        is_object: bool,
        depth: u32,
    ) -> Result<(), &'static str> {
        if !self.reference_depth_is_admitted(ReferenceRecursionKind::Expression, depth) {
            return Err("excessive binding pattern nesting");
        }
        let close = if is_object {
            TokenKind::RBrace
        } else {
            TokenKind::RBracket
        };
        let mut expect_binder = !is_object;
        loop {
            let token = self.lexer.peek().clone();
            match token.kind {
                kind if kind == close => {
                    self.lexer.next();
                    return Ok(());
                }
                TokenKind::Eof => return Err("unterminated binding pattern"),
                TokenKind::Spread => {
                    self.lexer.next();
                    let rest = self.lexer.peek().clone();
                    match rest.kind {
                        TokenKind::Ident => {
                            let name = self.text_of(rest.span).to_string();
                            self.note_predeclared_value_binder(&name, rest.span);
                            self.lexer.next();
                        }
                        TokenKind::LBrace | TokenKind::LBracket => {
                            let nested_is_object = matches!(rest.kind, TokenKind::LBrace);
                            self.lexer.next();
                            self.predeclare_binding_pattern_names(nested_is_object, depth + 1)?;
                        }
                        _ => {
                            self.lexer.next();
                        }
                    }
                }
                TokenKind::LBracket if is_object && !expect_binder => {
                    self.lexer.next();
                    let mut bracket_depth = 1u32;
                    while bracket_depth > 0 {
                        match self.lexer.peek().kind {
                            TokenKind::LBracket => bracket_depth += 1,
                            TokenKind::RBracket => bracket_depth -= 1,
                            TokenKind::Eof => return Err("unterminated computed key"),
                            _ => {}
                        }
                        self.lexer.next();
                    }
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        expect_binder = true;
                    }
                }
                TokenKind::LBrace | TokenKind::LBracket if expect_binder => {
                    let nested_is_object = matches!(token.kind, TokenKind::LBrace);
                    self.lexer.next();
                    self.predeclare_binding_pattern_names(nested_is_object, depth + 1)?;
                    expect_binder = !is_object;
                }
                TokenKind::Eq => {
                    self.lexer.next();
                    self.skip_predeclared_binding_default(close);
                    expect_binder = !is_object;
                }
                TokenKind::Colon if is_object => {
                    self.lexer.next();
                    expect_binder = true;
                }
                TokenKind::Comma => {
                    self.lexer.next();
                    expect_binder = !is_object;
                }
                TokenKind::Ident if expect_binder => {
                    let name = self.text_of(token.span).to_string();
                    self.note_predeclared_value_binder(&name, token.span);
                    self.lexer.next();
                    expect_binder = false;
                }
                TokenKind::Ident => {
                    let name = self.text_of(token.span).to_string();
                    self.lexer.next();
                    if matches!(self.lexer.peek().kind, TokenKind::Colon) {
                        self.lexer.next();
                        expect_binder = true;
                    } else {
                        self.note_predeclared_value_binder(&name, token.span);
                    }
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    fn predeclare_var_decl_binders_until_statement_end(&mut self) {
        let mut paren_depth = 0i32;
        let mut bracket_depth = 0i32;
        let mut brace_depth = 0i32;
        let mut expecting_binder = true;
        loop {
            let t = self.lexer.peek().clone();
            let at_decl_depth = paren_depth == 0 && bracket_depth == 0 && brace_depth == 0;
            match t.kind {
                TokenKind::Eof => break,
                TokenKind::Semi if at_decl_depth => {
                    self.lexer.next();
                    break;
                }
                TokenKind::RBrace if at_decl_depth => break,
                TokenKind::Ident if expecting_binder && at_decl_depth => {
                    let text = self.text_of(t.span).to_string();
                    self.note_predeclared_value_binder(&text, t.span);
                    self.lexer.next();
                    expecting_binder = false;
                }
                TokenKind::Comma if at_decl_depth => {
                    self.lexer.next();
                    expecting_binder = true;
                }
                TokenKind::Eq if at_decl_depth => {
                    self.lexer.next();
                    expecting_binder = false;
                }
                TokenKind::LBrace | TokenKind::LBracket if expecting_binder && at_decl_depth => {
                    let is_object = matches!(t.kind, TokenKind::LBrace);
                    self.lexer.next();
                    let _ = self.predeclare_binding_pattern_names(is_object, 0);
                    expecting_binder = false;
                }
                TokenKind::LParen => {
                    paren_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    bracket_depth += 1;
                    self.lexer.next();
                    expecting_binder = false;
                }
                TokenKind::RBracket => {
                    if bracket_depth > 0 {
                        bracket_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBrace => {
                    brace_depth += 1;
                    self.lexer.next();
                    expecting_binder = false;
                }
                TokenKind::RBrace => {
                    if brace_depth > 0 {
                        brace_depth -= 1;
                        self.lexer.next();
                    } else {
                        break;
                    }
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    fn predeclare_named_value_decl_binder(&mut self, allow_generator_marker: bool) {
        if allow_generator_marker && matches!(self.lexer.peek().kind, TokenKind::Star) {
            self.lexer.next();
        }
        let name = self.lexer.peek().clone();
        if Self::token_can_start_binding_identifier(name.kind) {
            let span = name.span;
            let name = self.text_of(span).to_string();
            self.note_const_string_decl_shadow(&name);
            self.predeclared_value_binders.push(PredeclaredValueBinder {
                scope: self.current_scope(),
                name,
                span,
                value_scope: None,
                const_scope: self.const_string_scopes.len() - 1,
            });
            self.lexer.next();
        }
    }

    fn skip_predeclared_balanced_brace_body(&mut self) {
        if !matches!(self.lexer.peek().kind, TokenKind::LBrace) {
            return;
        }
        self.lexer.next();
        let mut depth = 1u32;
        while depth > 0 {
            match self.lexer.next().kind {
                TokenKind::LBrace => depth += 1,
                TokenKind::RBrace => depth -= 1,
                TokenKind::Eof => break,
                _ => {}
            }
        }
    }

    /// Skip a nested function after its optional name has been consumed.
    /// `var` declarations inside that body belong to the nested function and
    /// must not be hoisted into the function currently being predeclared.
    fn skip_predeclared_function_body(&mut self) {
        let mut paren_depth = 0i32;
        let mut bracket_depth = 0i32;
        let mut angle_depth = 0i32;
        let mut saw_params = false;
        let mut in_return_type = false;
        let mut expecting_return_atom = false;
        loop {
            match self.lexer.peek().kind {
                TokenKind::Eof => return,
                TokenKind::Semi if paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 => {
                    return;
                }
                TokenKind::LParen => {
                    saw_params = true;
                    paren_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    bracket_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RBracket => {
                    if bracket_depth > 0 {
                        bracket_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::Lt if saw_params && paren_depth == 0 => {
                    angle_depth += 1;
                    self.lexer.next();
                }
                TokenKind::Gt if angle_depth > 0 => {
                    angle_depth -= 1;
                    self.lexer.next();
                }
                TokenKind::ShiftRight
                | TokenKind::ShiftRightUnsigned
                | TokenKind::ShiftRightEq
                | TokenKind::ShiftRightUnsignedEq
                    if angle_depth > 0 =>
                {
                    self.lexer.rescan_gt();
                }
                TokenKind::Colon
                    if saw_params && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 =>
                {
                    in_return_type = true;
                    expecting_return_atom = true;
                    self.lexer.next();
                }
                TokenKind::Pipe | TokenKind::Amp | TokenKind::Arrow if in_return_type => {
                    expecting_return_atom = true;
                    self.lexer.next();
                }
                TokenKind::LBrace
                    if in_return_type
                        && (expecting_return_atom || angle_depth > 0 || bracket_depth > 0) =>
                {
                    self.skip_predeclared_balanced_brace_body();
                    expecting_return_atom = false;
                }
                TokenKind::LBrace
                    if saw_params && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 =>
                {
                    self.skip_predeclared_balanced_brace_body();
                    return;
                }
                TokenKind::Ident if in_return_type => {
                    let token = self.lexer.peek().clone();
                    let contextual = self.text_of(token.span);
                    expecting_return_atom = matches!(contextual, "extends" | "keyof" | "infer");
                    self.lexer.next();
                }
                _ => {
                    if in_return_type && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0
                    {
                        expecting_return_atom = false;
                    }
                    self.lexer.next();
                }
            }
        }
    }

    fn skip_predeclared_class_body(&mut self) {
        let mut paren_depth = 0i32;
        let mut bracket_depth = 0i32;
        loop {
            match self.lexer.peek().kind {
                TokenKind::Eof => return,
                TokenKind::Semi if paren_depth == 0 && bracket_depth == 0 => return,
                TokenKind::LParen => {
                    paren_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    bracket_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RBracket => {
                    if bracket_depth > 0 {
                        bracket_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBrace if paren_depth == 0 && bracket_depth == 0 => {
                    self.skip_predeclared_balanced_brace_body();
                    return;
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
    }

    fn predeclare_current_block_value_binders(&mut self) {
        let saved = self.lexer.checkpoint();
        let mut brace_depth = 1i32;
        let mut paren_depth = 0i32;
        let mut bracket_depth = 0i32;
        while brace_depth > 0 {
            let t = self.lexer.peek().clone();
            let at_current_block = brace_depth == 1 && paren_depth == 0 && bracket_depth == 0;
            match t.kind {
                TokenKind::Eof => break,
                TokenKind::LBrace => {
                    brace_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RBrace => {
                    brace_depth -= 1;
                    self.lexer.next();
                }
                TokenKind::LParen => {
                    paren_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RParen => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::LBracket => {
                    bracket_depth += 1;
                    self.lexer.next();
                }
                TokenKind::RBracket => {
                    if bracket_depth > 0 {
                        bracket_depth -= 1;
                    }
                    self.lexer.next();
                }
                TokenKind::Const
                    if at_current_block && {
                        let save = self.lexer.checkpoint();
                        self.lexer.next();
                        let is_const_enum = matches!(self.lexer.peek().kind, TokenKind::Enum);
                        self.lexer.restore(save);
                        is_const_enum
                    } =>
                {
                    self.lexer.next();
                    self.lexer.next();
                    self.predeclare_named_value_decl_binder(false);
                }
                TokenKind::Let | TokenKind::Const if at_current_block => {
                    self.lexer.next();
                    self.predeclare_var_decl_binders_until_statement_end();
                }
                TokenKind::Var => {
                    self.lexer.next();
                    self.predeclare_var_decl_binders_until_statement_end();
                }
                TokenKind::Function => {
                    self.lexer.next();
                    if at_current_block {
                        self.predeclare_named_value_decl_binder(true);
                    } else {
                        if matches!(self.lexer.peek().kind, TokenKind::Star) {
                            self.lexer.next();
                        }
                        if Self::token_can_start_binding_identifier(self.lexer.peek().kind) {
                            self.lexer.next();
                        }
                    }
                    self.skip_predeclared_function_body();
                }
                TokenKind::Class => {
                    self.lexer.next();
                    if at_current_block {
                        self.predeclare_named_value_decl_binder(false);
                    } else if Self::token_can_start_binding_identifier(self.lexer.peek().kind) {
                        self.lexer.next();
                    }
                    self.skip_predeclared_class_body();
                }
                TokenKind::Enum if at_current_block => {
                    self.lexer.next();
                    self.predeclare_named_value_decl_binder(false);
                }
                TokenKind::Arrow => {
                    self.lexer.next();
                    self.skip_predeclared_balanced_brace_body();
                }
                TokenKind::Ident
                    if at_current_block && self.text_of(t.span) == "using" && {
                        let save = self.lexer.checkpoint();
                        self.lexer.next();
                        let ok = !self.lexer.had_line_terminator()
                            && matches!(self.lexer.peek().kind, TokenKind::Ident);
                        self.lexer.restore(save);
                        ok
                    } =>
                {
                    self.lexer.next();
                    self.predeclare_var_decl_binders_until_statement_end();
                }
                _ => {
                    self.lexer.next();
                }
            }
        }
        self.lexer.restore(saved);
    }

    fn recovery_statement_start_after_line_terminator(&self, kind: TokenKind, span: Span) -> bool {
        matches!(
            kind,
            TokenKind::At
                | TokenKind::Async
                | TokenKind::Await
                | TokenKind::Break
                | TokenKind::Class
                | TokenKind::Const
                | TokenKind::Continue
                | TokenKind::Do
                | TokenKind::Enum
                | TokenKind::Export
                | TokenKind::For
                | TokenKind::Function
                | TokenKind::If
                | TokenKind::Import
                | TokenKind::Interface
                | TokenKind::Let
                | TokenKind::Return
                | TokenKind::Switch
                | TokenKind::Throw
                | TokenKind::Try
                | TokenKind::Type
                | TokenKind::Var
                | TokenKind::While
        ) || (matches!(kind, TokenKind::Ident)
            && matches!(self.text_of(span), "declare" | "namespace"))
    }

    fn recover(&mut self, context: &'static str, start_span: Span) {
        let mut depth: i32 = 0;
        let mut entered_braces = false;
        let mut consumed_any = false;
        // Scan forward to the next statement boundary; the loop breaks with
        // the ending token's span so we can compute the recovered region end.
        //
        // Audit-5 round-4 R4-B: the additional `depth == 0 && entered_braces`
        // termination matches a closing `}` that brings us back to top level
        // AFTER we've entered a balanced brace pair. That's the natural end
        // of a punted construct with a body (e.g. `@Decorator class Foo {}`,
        // `namespace X {}`, `if (c) { … }`). Without this termination, the
        // recovery span kept scanning until the NEXT top-level `;`, which is
        // typically the semicolon of the *following* statement — so the
        // following declaration was silently consumed and lost from the IR.
        // Real-world impact: Angular `@Component class App {}\nconst x = 1;`
        // ate `const x`; NestJS / Vue decorators behaved the same.
        let end_pos: u32 = loop {
            let next = self.lexer.peek().clone();
            if context == "punted"
                && consumed_any
                && depth == 0
                && self.lexer.had_line_terminator()
                && self.recovery_statement_start_after_line_terminator(next.kind, next.span)
            {
                break next.span.start();
            }
            let t = self.lexer.next();
            consumed_any = true;
            match t.kind {
                TokenKind::LBrace => {
                    depth += 1;
                    entered_braces = true;
                }
                TokenKind::RBrace => {
                    depth -= 1;
                    if depth < 0 {
                        break t.span.end();
                    }
                    if depth == 0 && entered_braces {
                        break t.span.end();
                    }
                }
                TokenKind::Semi if depth == 0 => break t.span.end(),
                TokenKind::Eof => break t.span.end(),
                _ => {}
            }
        };
        // Audit-5 R5-2: when the dispatcher already pushed a primary
        // diagnostic (UnsupportedConstruct for declare/namespace/decorator,
        // or SyntaxRecovered{"jsx"} for JSX) and signalled "punted", do
        // NOT also emit a redundant `SyntaxRecovered{"punted"}` covering
        // the same span. The "punted" reason is the discriminant — it
        // means recovery should advance the lexer but not duplicate the
        // diagnostic the dispatcher already emitted.
        if context != "punted" {
            self.diagnostics.push(Diagnostic {
                kind: DiagnosticKind::SyntaxRecovered {
                    context: context.to_string(),
                },
                file_path: self.path.clone(),
                span: Span::new(start_span.start(), end_pos - start_span.start()),
            });
        }
    }
}

mod body_parser;
mod expression_parser;
mod type_parser;
