//! Triple-slash reference directives (known-v1-gaps #17).
//!
//! TypeScript honors `/// <reference path="…" />` and `/// <reference types="…" />`
//! directives only in the **leading comment block** of a file — before any
//! statement. They express a compile-time dependency (on a declaration file or a
//! `@types` package) that a raw token walk never sees, because `skip_trivia`
//! discards the comment.
//!
//! This module is a pure scanner: it reads the leading trivia run of the source
//! and returns one [`TripleSlashRef`] per recognized `path`/`types` directive,
//! mutating nothing. `parse_program` invokes it once and pushes a
//! `RefEvent::Import` for each. `lib=` / `no-default-lib` / unknown attributes are
//! ignored (a `lib` is a TS built-in, not a module). Malformed directives are
//! treated as ordinary comments — no ref, no diagnostic.
//!
//! See `docs/superpowers/specs/2026-06-01-triple-slash-directives-design.md`.

use crate::spans::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripleSlashRef {
    pub specifier: String,
    /// Covers the inner quoted text (quotes excluded), matching the
    /// `read_str_literal` convention so resolver diagnostics point at the path.
    pub specifier_span: Span,
    /// Always `true` for v1: triple-slash references pull in declaration files
    /// (compile-time only, never runtime JS).
    pub is_type_only: bool,
}

#[inline]
fn is_ws(b: u8) -> bool {
    // ASCII whitespace + line terminators. Triple-slash directives are ASCII;
    // the rare Unicode LS/PS in the leading region is out of scope for v1.
    matches!(b, b' ' | b'\t' | 0x0b | 0x0c | b'\r' | b'\n')
}

#[inline]
fn is_line_terminator(b: u8) -> bool {
    b == b'\n' || b == b'\r'
}

/// Scan the leading trivia run of `source` for `path`/`types` reference
/// directives. Stops at the first byte that begins a real token — a `///`
/// after any statement is an ordinary comment (matches `tsc`).
pub fn scan_leading_triple_slash_directives(source: &[u8]) -> Vec<TripleSlashRef> {
    let n = source.len();
    let mut refs = Vec::new();
    let mut pos = 0usize;

    // UTF-8 BOM (matches the lexer's skip_trivia).
    if n >= 3 && source[0] == 0xEF && source[1] == 0xBB && source[2] == 0xBF {
        pos = 3;
    }
    // Hashbang: `#!` to end-of-line, only at the logical file start.
    if pos + 1 < n && source[pos] == b'#' && source[pos + 1] == b'!' {
        pos += 2;
        while pos < n && !is_line_terminator(source[pos]) {
            pos += 1;
        }
    }

    loop {
        while pos < n && is_ws(source[pos]) {
            pos += 1;
        }
        if pos >= n {
            break;
        }
        // Line comment `// …`.
        if pos + 1 < n && source[pos] == b'/' && source[pos + 1] == b'/' {
            let mut line_end = pos;
            while line_end < n && !is_line_terminator(source[line_end]) {
                line_end += 1;
            }
            // Triple-slash: a third `/` immediately after `//`, but NOT a
            // quad-slash (`////` is an ordinary comment, not a directive).
            let is_triple =
                pos + 2 < n && source[pos + 2] == b'/' && !(pos + 3 < n && source[pos + 3] == b'/');
            if is_triple {
                let body_start = pos + 3;
                if let Some(r) = parse_reference_directive(source, body_start, line_end) {
                    refs.push(r);
                }
            }
            pos = line_end;
            continue;
        }
        // Block comment `/* … */`.
        if pos + 1 < n && source[pos] == b'/' && source[pos + 1] == b'*' {
            pos += 2;
            while pos + 1 < n && !(source[pos] == b'*' && source[pos + 1] == b'/') {
                pos += 1;
            }
            pos = if pos + 1 < n { pos + 2 } else { n };
            continue;
        }
        // First real token — directives only precede statements.
        break;
    }
    refs
}

/// Parse `<reference (path|types) = "…" />` from `source[start..end]` (one
/// line-comment body, after the `///`). Returns `None` for any non-matching or
/// malformed shape — the caller treats those as ordinary comments.
fn parse_reference_directive(source: &[u8], start: usize, end: usize) -> Option<TripleSlashRef> {
    let skip_ws = |mut i: usize| {
        while i < end && is_ws(source[i]) {
            i += 1;
        }
        i
    };

    let mut i = skip_ws(start);
    const TAG: &[u8] = b"<reference";
    if end - i < TAG.len() || &source[i..i + TAG.len()] != TAG {
        return None;
    }
    i += TAG.len();
    // Require at least one whitespace byte between `<reference` and the attribute
    // (rejects `<referencepath`).
    let after_tag = skip_ws(i);
    if after_tag == i {
        return None;
    }
    i = after_tag;

    // Attribute name: ASCII letters.
    let name_start = i;
    while i < end && source[i].is_ascii_alphabetic() {
        i += 1;
    }
    let name = &source[name_start..i];
    // Only `path` and `types` reference a module; `lib` / `no-default-lib` /
    // unknown attributes are not module edges.
    if name != b"path" && name != b"types" {
        return None;
    }

    i = skip_ws(i);
    if i >= end || source[i] != b'=' {
        return None;
    }
    i += 1;
    i = skip_ws(i);
    if i >= end {
        return None;
    }
    let quote = source[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    i += 1;
    let val_start = i;
    while i < end && source[i] != quote && !is_line_terminator(source[i]) {
        i += 1;
    }
    // Unterminated (hit EOL/end before the closing quote).
    if i >= end || source[i] != quote {
        return None;
    }
    let val_end = i;
    i += 1; // consume closing quote

    // Require a self-closing `/>` (after optional whitespace) so we don't accept
    // arbitrary trailing garbage as a directive.
    i = skip_ws(i);
    if end - i < 2 || source[i] != b'/' || source[i + 1] != b'>' {
        return None;
    }

    let specifier = String::from_utf8_lossy(&source[val_start..val_end]).into_owned();
    let specifier_span = Span::new(val_start as u32, (val_end - val_start) as u32);
    Some(TripleSlashRef {
        specifier,
        specifier_span,
        is_type_only: true,
    })
}
