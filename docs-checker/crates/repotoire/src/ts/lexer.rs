//! Streaming TypeScript lexer. See spec §4.

use crate::spans::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    // Filled in incrementally across Tasks 1-4. For Task 1: punctuation + Eof only.
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Colon,
    Dot,
    Eq,
    Lt,
    Gt,
    Plus,
    Minus,
    Star,
    Slash,
    // Multi-char punctuation / operators
    Arrow,
    Spread,
    PlusEq,
    MinusEq,
    StarEq,
    SlashEq,
    LtEq,
    GtEq,
    EqEq,
    EqEqEq,
    BangEq,
    BangEqEq,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Bang,
    AmpAmp,
    PipePipe,
    Question,
    QuestionQuestion,
    QuestionDot,
    AmpEq,
    PipeEq,
    CaretEq,
    AmpAmpEq,
    PipePipeEq,
    QuestionQuestionEq,
    ShiftLeft,
    ShiftRight,
    ShiftRightUnsigned,
    ShiftLeftEq,
    ShiftRightEq,
    ShiftRightUnsignedEq,
    Percent,
    PercentEq,
    StarStar,
    StarStarEq,
    PlusPlus,
    MinusMinus,
    At,
    // Keywords (truly reserved — contextual keywords stay as Ident)
    Import,
    Export,
    From,
    As,
    Type,
    Interface,
    Class,
    Enum,
    Function,
    Const,
    Let,
    Var,
    If,
    Else,
    For,
    While,
    Do,
    Switch,
    Case,
    Default,
    Return,
    Break,
    Continue,
    Throw,
    Try,
    Catch,
    Finally,
    New,
    Typeof,
    In,
    Of,
    Instanceof,
    Void,
    Delete,
    Yield,
    Async,
    Await,
    // Placeholders for later tasks (kept here so cross-references compile):
    Ident,
    Str,
    Number,
    Regex,
    TemplateStart,
    TemplateMid,
    TemplateEnd,
    // Recovery
    Error,
    Eof,
}

#[derive(Clone)]
struct TemplateContext {
    brace_depth: usize,
}

/// Opaque snapshot of the full lexer state, used by the parser for the rare
/// bounded rewind (e.g. type-predicate disambiguation: commit the subject
/// `Ident`, look for `is`, and rewind if it isn't a predicate after all).
/// Captures every field so a restore is exact regardless of where it's taken.
#[derive(Clone)]
pub struct LexerCheckpoint {
    pos: usize,
    regex_allowed: bool,
    peeked: Option<Token>,
    template_stack: Vec<TemplateContext>,
    brace_depth: usize,
    had_line_terminator: bool,
    unterminated_block_comment: Option<Span>,
}

pub struct Lexer<'src> {
    source: &'src [u8],
    pos: usize,
    regex_allowed: bool,
    peeked: Option<Token>,
    template_stack: Vec<TemplateContext>,
    brace_depth: usize,
    /// Set by `skip_trivia` whenever the trivia just consumed (before the
    /// next-to-be-returned token) contained an ECMA-262 §11.3 LineTerminator
    /// (LF, CR, LS U+2028, PS U+2029 — see `line_terminator_len_at`). Reset
    /// at the start of every `skip_trivia` call, so it reflects the trivia
    /// immediately preceding the currently-peeked or just-lexed token.
    /// Audit-5b review item P2 (added the flag); audit-5b round-2 R2-P2/P3
    /// completed the LineTerminator set across all trivia scanners
    /// (block comment, hashbang, single-line comment).
    had_line_terminator: bool,
    /// Span of an unterminated `/* … */` block comment that ran to EOF without
    /// its closing `*/` (known-v1-gaps #22). Set in `skip_trivia`; drained by
    /// `parse_program` into a `SyntaxRecovered` diagnostic. The lexer has no
    /// diagnostics channel of its own, so this carries the one trivia-level
    /// error the parser can't otherwise observe (block comments are skipped).
    unterminated_block_comment: Option<Span>,
}

impl<'src> Lexer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        Self {
            source,
            pos: 0,
            regex_allowed: true,
            peeked: None,
            template_stack: Vec::new(),
            brace_depth: 0,
            had_line_terminator: false,
            unterminated_block_comment: None,
        }
    }

    /// The span of an unterminated block comment seen during trivia scanning,
    /// if any. See [`Lexer::unterminated_block_comment`] field docs (#22).
    pub fn unterminated_block_comment(&self) -> Option<Span> {
        self.unterminated_block_comment
    }

    /// True iff the trivia immediately preceding the currently-peeked
    /// token (or the just-returned token, if `next()` was the last call
    /// since the previous `skip_trivia`) contained an ECMA-262
    /// LineTerminator. Used to implement the no-LineTerminator restricted
    /// productions: `throw [no LT] Expression`, `return [no LT] Expression`,
    /// postfix `++`/`--` [no LT before], etc. Call `peek()` immediately
    /// before consulting this — `peek()` will trigger `skip_trivia` if a
    /// fresh token hasn't been materialized since the last `next()`.
    pub fn had_line_terminator(&self) -> bool {
        self.had_line_terminator
    }

    // `next` is the natural name for a hand-rolled lexer's advance-and-
    // return. We deliberately do NOT implement `Iterator`: EOF is a real
    // terminal `Token` (not `None`), and the parser relies on `peek()`
    // returning `&Token` and `next()` yielding `Token` directly. clippy's
    // trait-confusion heuristic is a false positive for this design.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Token {
        if let Some(t) = self.peeked.take() {
            return t;
        }
        self.skip_trivia();
        if self.pos >= self.source.len() {
            return Token {
                kind: TokenKind::Eof,
                span: Span::new(self.pos as u32, 0),
            };
        }
        let start = self.pos;
        let c = self.source[self.pos];
        let kind = match c {
            b'{' => {
                self.pos += 1;
                TokenKind::LBrace
            }
            b'}' => {
                self.pos += 1;
                TokenKind::RBrace
            }
            b'(' => {
                self.pos += 1;
                TokenKind::LParen
            }
            b')' => {
                self.pos += 1;
                TokenKind::RParen
            }
            b'[' => {
                self.pos += 1;
                TokenKind::LBracket
            }
            b']' => {
                self.pos += 1;
                TokenKind::RBracket
            }
            b',' => {
                self.pos += 1;
                TokenKind::Comma
            }
            b';' => {
                self.pos += 1;
                TokenKind::Semi
            }
            b':' => {
                self.pos += 1;
                TokenKind::Colon
            }
            b'.' => {
                if self.starts_with(b"...") {
                    self.pos += 3;
                    TokenKind::Spread
                } else if self.pos + 1 < self.source.len()
                    && self.source[self.pos + 1].is_ascii_digit()
                {
                    // R9-B: DecimalLiteral may begin with `.` per
                    // ECMA-262 §12.9.3 — `.5` is shorthand for `0.5`.
                    // Pre-fix this lexed as `[Dot, Number]` which the
                    // parser then mis-handled (`f(.5)` parsed as
                    // `Call(f) + Dot + Number` instead of `Call(f, 0.5)`).
                    // Delegate to read_decimal_number from the `.`,
                    // which already handles the fractional-part path.
                    self.pos += 1; // consume `.`
                    self.read_decimal_number();
                    TokenKind::Number
                } else {
                    self.pos += 1;
                    TokenKind::Dot
                }
            }
            b'=' => {
                if self.starts_with(b"===") {
                    self.pos += 3;
                    TokenKind::EqEqEq
                } else if self.starts_with(b"=>") {
                    self.pos += 2;
                    TokenKind::Arrow
                } else if self.starts_with(b"==") {
                    self.pos += 2;
                    TokenKind::EqEq
                } else {
                    self.pos += 1;
                    TokenKind::Eq
                }
            }
            b'!' => {
                if self.starts_with(b"!==") {
                    self.pos += 3;
                    TokenKind::BangEqEq
                } else if self.starts_with(b"!=") {
                    self.pos += 2;
                    TokenKind::BangEq
                } else {
                    self.pos += 1;
                    TokenKind::Bang
                }
            }
            b'<' => {
                if self.starts_with(b"<<=") {
                    self.pos += 3;
                    TokenKind::ShiftLeftEq
                } else if self.starts_with(b"<<") {
                    self.pos += 2;
                    TokenKind::ShiftLeft
                } else if self.starts_with(b"<=") {
                    self.pos += 2;
                    TokenKind::LtEq
                } else {
                    self.pos += 1;
                    TokenKind::Lt
                }
            }
            b'>' => {
                if self.starts_with(b">>>=") {
                    self.pos += 4;
                    TokenKind::ShiftRightUnsignedEq
                } else if self.starts_with(b">>>") {
                    self.pos += 3;
                    TokenKind::ShiftRightUnsigned
                } else if self.starts_with(b">>=") {
                    self.pos += 3;
                    TokenKind::ShiftRightEq
                } else if self.starts_with(b">>") {
                    self.pos += 2;
                    TokenKind::ShiftRight
                } else if self.starts_with(b">=") {
                    self.pos += 2;
                    TokenKind::GtEq
                } else {
                    self.pos += 1;
                    TokenKind::Gt
                }
            }
            b'&' => {
                if self.starts_with(b"&&=") {
                    self.pos += 3;
                    TokenKind::AmpAmpEq
                } else if self.starts_with(b"&&") {
                    self.pos += 2;
                    TokenKind::AmpAmp
                } else if self.starts_with(b"&=") {
                    self.pos += 2;
                    TokenKind::AmpEq
                } else {
                    self.pos += 1;
                    TokenKind::Amp
                }
            }
            b'|' => {
                if self.starts_with(b"||=") {
                    self.pos += 3;
                    TokenKind::PipePipeEq
                } else if self.starts_with(b"||") {
                    self.pos += 2;
                    TokenKind::PipePipe
                } else if self.starts_with(b"|=") {
                    self.pos += 2;
                    TokenKind::PipeEq
                } else {
                    self.pos += 1;
                    TokenKind::Pipe
                }
            }
            b'?' => {
                if self.starts_with(b"??=") {
                    self.pos += 3;
                    TokenKind::QuestionQuestionEq
                } else if self.starts_with(b"??") {
                    self.pos += 2;
                    TokenKind::QuestionQuestion
                } else if self.starts_with(b"?.") {
                    self.pos += 2;
                    TokenKind::QuestionDot
                } else {
                    self.pos += 1;
                    TokenKind::Question
                }
            }
            b'+' => {
                if self.starts_with(b"+=") {
                    self.pos += 2;
                    TokenKind::PlusEq
                } else if self.starts_with(b"++") {
                    self.pos += 2;
                    TokenKind::PlusPlus
                } else {
                    self.pos += 1;
                    TokenKind::Plus
                }
            }
            b'-' => {
                if self.starts_with(b"-=") {
                    self.pos += 2;
                    TokenKind::MinusEq
                } else if self.starts_with(b"--") {
                    self.pos += 2;
                    TokenKind::MinusMinus
                } else {
                    self.pos += 1;
                    TokenKind::Minus
                }
            }
            b'*' => {
                if self.starts_with(b"**=") {
                    self.pos += 3;
                    TokenKind::StarStarEq
                } else if self.starts_with(b"**") {
                    self.pos += 2;
                    TokenKind::StarStar
                } else if self.starts_with(b"*=") {
                    self.pos += 2;
                    TokenKind::StarEq
                } else {
                    self.pos += 1;
                    TokenKind::Star
                }
            }
            b'%' => {
                if self.starts_with(b"%=") {
                    self.pos += 2;
                    TokenKind::PercentEq
                } else {
                    self.pos += 1;
                    TokenKind::Percent
                }
            }
            b'^' => {
                if self.starts_with(b"^=") {
                    self.pos += 2;
                    TokenKind::CaretEq
                } else {
                    self.pos += 1;
                    TokenKind::Caret
                }
            }
            b'~' => {
                self.pos += 1;
                TokenKind::Tilde
            }
            b'@' => {
                self.pos += 1;
                TokenKind::At
            }
            b'\'' | b'"' => {
                let quote = c;
                self.pos += 1;
                while self.pos < self.source.len() {
                    let b = self.source[self.pos];
                    if b == quote {
                        self.pos += 1;
                        break;
                    }
                    // ECMA-262 §11.8.4: StringCharacter excludes any
                    // LineTerminator (LF/CR/LS/PS). An unescaped LT mid-string
                    // is a syntax error; recover by terminating the string at
                    // the LT so the rest of the file isn't absorbed as part
                    // of the literal. Audit-5 round-4 R4-C — was previously
                    // `b == b'\n'` only, leaving CR-only / LS / PS sources
                    // (Classic Mac, some Unicode editors) to consume past
                    // the LT until EOF.
                    if self.line_terminator_len_at(self.pos).is_some() {
                        break; // recover; spec §11.8.4 + §11.3
                    }
                    if b == b'\\' && self.pos + 1 < self.source.len() {
                        self.pos += 2;
                        continue;
                    }
                    self.pos += 1;
                }
                TokenKind::Str
            }
            b'`' => {
                return self.start_template(start);
            }
            b'/' => {
                if self.regex_allowed {
                    self.pos += 1;
                    // Body until the closing unescaped '/' (outside a char class)
                    // or newline. Per ECMAScript, a '/' inside a `[...]` character
                    // class is a literal, NOT the closing delimiter, so we track
                    // char-class depth; without this, `/[/]/` truncates and the
                    // trailing tokens can hang the parser in call-arg position.
                    let mut in_class = false;
                    // ECMA-262 §11.8.5: RegularExpressionBody excludes any
                    // LineTerminator (LF/CR/LS/PS). An unterminated regex
                    // with a CR/LS/PS would otherwise consume past the LT
                    // until LF or EOF, eating any following code. Audit-5
                    // round-4 R4-C — was previously `!= b'\n'` only.
                    while self.pos < self.source.len()
                        && self.line_terminator_len_at(self.pos).is_none()
                    {
                        let c = self.source[self.pos];
                        if c == b'\\' && self.pos + 1 < self.source.len() {
                            self.pos += 2;
                            continue;
                        }
                        match c {
                            b'[' => in_class = true,
                            b']' => in_class = false,
                            b'/' if !in_class => break,
                            _ => {}
                        }
                        self.pos += 1;
                    }
                    if self.pos < self.source.len() && self.source[self.pos] == b'/' {
                        self.pos += 1;
                    }
                    // Flags
                    while self.pos < self.source.len() && self.source[self.pos].is_ascii_lowercase()
                    {
                        self.pos += 1;
                    }
                    TokenKind::Regex
                } else if self.starts_with(b"/=") {
                    self.pos += 2;
                    TokenKind::SlashEq
                } else {
                    self.pos += 1;
                    TokenKind::Slash
                }
            }
            // `#foo` ECMA-262 private name. Lexed as a single Ident token
            // whose text includes the leading `#`. Only valid as a class
            // member-name (parser enforces). `#!` shebang at file start is
            // handled earlier in `next()`; a bare `#` not followed by an
            // identifier-start character falls through to `Error`.
            b'#' if self.pos + 1 < self.source.len()
                && matches!(
                    self.source[self.pos + 1],
                    b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$'
                ) =>
            {
                self.pos += 1; // consume `#`
                while self.pos < self.source.len()
                    && matches!(self.source[self.pos], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$')
                {
                    self.pos += 1;
                }
                TokenKind::Ident
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                // IdentifierPart includes Unicode ID_Continue (#20) and `\u`
                // escapes (#25), so `caféBar` / `xA` stay a single Ident.
                while let Some(len) = self.ident_continue_len_at(self.pos) {
                    self.pos += len;
                }
                match &self.source[start..self.pos] {
                    b"import" => TokenKind::Import,
                    b"export" => TokenKind::Export,
                    b"from" => TokenKind::From,
                    b"as" => TokenKind::As,
                    b"type" => TokenKind::Type,
                    b"interface" => TokenKind::Interface,
                    b"class" => TokenKind::Class,
                    b"enum" => TokenKind::Enum,
                    b"function" => TokenKind::Function,
                    b"const" => TokenKind::Const,
                    b"let" => TokenKind::Let,
                    b"var" => TokenKind::Var,
                    b"if" => TokenKind::If,
                    b"else" => TokenKind::Else,
                    b"for" => TokenKind::For,
                    b"while" => TokenKind::While,
                    b"do" => TokenKind::Do,
                    b"switch" => TokenKind::Switch,
                    b"case" => TokenKind::Case,
                    b"default" => TokenKind::Default,
                    b"return" => TokenKind::Return,
                    b"break" => TokenKind::Break,
                    b"continue" => TokenKind::Continue,
                    b"throw" => TokenKind::Throw,
                    b"try" => TokenKind::Try,
                    b"catch" => TokenKind::Catch,
                    b"finally" => TokenKind::Finally,
                    b"new" => TokenKind::New,
                    b"typeof" => TokenKind::Typeof,
                    b"in" => TokenKind::In,
                    b"of" => TokenKind::Of,
                    b"instanceof" => TokenKind::Instanceof,
                    b"void" => TokenKind::Void,
                    b"delete" => TokenKind::Delete,
                    b"yield" => TokenKind::Yield,
                    b"async" => TokenKind::Async,
                    b"await" => TokenKind::Await,
                    _ => TokenKind::Ident,
                }
            }
            b'0'..=b'9' => {
                // Decimal / hex (0x) / oct (0o) / bin (0b). Optional . fractional, e/E exponent,
                // optional trailing 'n' for bigint. We accept-and-skip without value parsing —
                // the parser/resolver doesn't read numeric values.
                if c == b'0' && self.pos + 1 < self.source.len() {
                    match self.source[self.pos + 1] {
                        b'x' | b'X' => {
                            self.pos += 2;
                            while self.pos < self.source.len()
                                && (self.source[self.pos].is_ascii_hexdigit()
                                    || self.source[self.pos] == b'_')
                            {
                                self.pos += 1;
                            }
                        }
                        b'b' | b'B' => {
                            self.pos += 2;
                            while self.pos < self.source.len()
                                && matches!(self.source[self.pos], b'0' | b'1' | b'_')
                            {
                                self.pos += 1;
                            }
                        }
                        b'o' | b'O' => {
                            self.pos += 2;
                            while self.pos < self.source.len()
                                && matches!(self.source[self.pos], b'0'..=b'7' | b'_')
                            {
                                self.pos += 1;
                            }
                        }
                        _ => {
                            self.read_decimal_number();
                        }
                    }
                } else {
                    self.read_decimal_number();
                }
                if self.pos < self.source.len() && self.source[self.pos] == b'n' {
                    self.pos += 1;
                }
                TokenKind::Number
            }
            _ => {
                // Unicode IdentifierStart (#20: `π`, `中文`) or `\u`-escaped
                // start (#25: `A`). A non-ASCII / `\u` identifier can never
                // be a reserved word, so it's always Ident (escaped keywords
                // like `if` are identifiers per spec, not keywords).
                if let Some(start_len) = self.ident_start_len_at(start) {
                    self.pos = start + start_len;
                    while let Some(len) = self.ident_continue_len_at(self.pos) {
                        self.pos += len;
                    }
                    TokenKind::Ident
                } else {
                    self.pos += 1;
                    TokenKind::Error
                }
            }
        };

        // Brace tracking for template literal interpolation
        match kind {
            TokenKind::LBrace => {
                self.brace_depth += 1;
            }
            TokenKind::RBrace => {
                if self.brace_depth > 0 {
                    self.brace_depth -= 1;
                }
                if let Some(top) = self.template_stack.last() {
                    if top.brace_depth == self.brace_depth {
                        self.template_stack.pop();
                        return self.lex_template_continuation(start);
                    }
                }
            }
            _ => {}
        }

        self.regex_allowed = matches!(
            kind,
            TokenKind::Eq
                | TokenKind::EqEq
                | TokenKind::EqEqEq
                | TokenKind::BangEq
                | TokenKind::BangEqEq
                | TokenKind::Bang
                | TokenKind::LParen
                | TokenKind::LBrace
                | TokenKind::LBracket
                | TokenKind::Comma
                | TokenKind::Semi
                | TokenKind::Colon
                | TokenKind::Question
                | TokenKind::QuestionQuestion
                | TokenKind::QuestionDot
                | TokenKind::Arrow
                | TokenKind::Spread
                | TokenKind::Return
                | TokenKind::Throw
                | TokenKind::Yield
                | TokenKind::Await
                | TokenKind::Typeof
                | TokenKind::In
                | TokenKind::Of
                | TokenKind::Instanceof
                | TokenKind::Void
                | TokenKind::Delete
                | TokenKind::New
                | TokenKind::Plus
                | TokenKind::Minus
                | TokenKind::Star
                | TokenKind::StarStar
                | TokenKind::Slash
                | TokenKind::Percent
                | TokenKind::Lt
                | TokenKind::Gt
                | TokenKind::LtEq
                | TokenKind::GtEq
                | TokenKind::ShiftLeft
                | TokenKind::ShiftRight
                | TokenKind::ShiftRightUnsigned
                | TokenKind::Amp
                | TokenKind::Pipe
                | TokenKind::Caret
                | TokenKind::Tilde
                | TokenKind::AmpAmp
                | TokenKind::PipePipe
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
        );
        Token {
            kind,
            span: Span::new(start as u32, (self.pos - start) as u32),
        }
    }

    pub fn peek(&mut self) -> &Token {
        if self.peeked.is_none() {
            self.peeked = Some(self.next());
        }
        self.peeked.as_ref().unwrap()
    }

    /// Force the *next* lexed token to treat a leading `/` as division
    /// (`Slash`/`SlashEq`), not the start of a regex literal. Only affects a
    /// token not yet lexed (no-op if one is already `peek`ed). The JSX skipper
    /// uses this for a closing tag `</tag>`: after the `<` (a `Lt` operator)
    /// the lexer is in regex context, so without this the `/` would start an
    /// (unterminated) regex literal that consumes to the line terminator —
    /// eating whatever follows the element (e.g. the enclosing block's `}`).
    pub(crate) fn deny_regex_for_next(&mut self) {
        if self.peeked.is_none() {
            self.regex_allowed = false;
        }
    }

    /// Snapshot the full lexer state for a bounded rewind.
    pub fn checkpoint(&self) -> LexerCheckpoint {
        LexerCheckpoint {
            pos: self.pos,
            regex_allowed: self.regex_allowed,
            peeked: self.peeked.clone(),
            template_stack: self.template_stack.clone(),
            brace_depth: self.brace_depth,
            had_line_terminator: self.had_line_terminator,
            unterminated_block_comment: self.unterminated_block_comment,
        }
    }

    /// Restore a previously taken checkpoint.
    pub fn restore(&mut self, cp: LexerCheckpoint) {
        self.pos = cp.pos;
        self.regex_allowed = cp.regex_allowed;
        self.peeked = cp.peeked;
        self.template_stack = cp.template_stack;
        self.brace_depth = cp.brace_depth;
        self.had_line_terminator = cp.had_line_terminator;
        self.unterminated_block_comment = cp.unterminated_block_comment;
    }

    /// Re-scan a `>>`/`>>>`/`>>=`/`>>>=`/`>=` token at the cursor as a single
    /// `Gt`, leaving the remaining `>`(s)/`=` to be lexed as the next token.
    /// TypeScript's scanner calls this `reScanGreaterToken`; it's needed because
    /// nested generics like `Foo<Bar<T>>` lex the `>>` as one `ShiftRight` token.
    /// No-op when the current token is not a `>`-family token.
    pub fn rescan_gt(&mut self) {
        let t = self.peek().clone();
        let is_gt_family = matches!(
            t.kind,
            TokenKind::ShiftRight
                | TokenKind::ShiftRightUnsigned
                | TokenKind::ShiftRightEq
                | TokenKind::ShiftRightUnsignedEq
                | TokenKind::GtEq
        );
        if is_gt_family {
            let start = t.span.start();
            self.peeked = Some(Token {
                kind: TokenKind::Gt,
                span: Span::new(start, 1),
            });
            self.pos = start as usize + 1;
        }
    }

    /// Byte slice from the current lex cursor to end-of-source — used by
    /// the parser for bounded byte-level lookahead (generic-call vs
    /// comparison disambiguation). When `peeked` is `Some(_)`, the cursor
    /// has already advanced past that token, so the returned slice is
    /// the bytes *after* the peeked token. Callers do raw byte scanning,
    /// NOT relexing: they handle bracket-depth themselves and stop at
    /// statement terminators. This is a deliberate v1 trade-off — string
    /// literals containing `<` or `>` can cause false positives/negatives
    /// inside this scan, but the curated-package gate avoids that pattern.
    pub fn source_after_cursor(&self) -> &'src [u8] {
        &self.source[self.pos..]
    }

    /// Advance through JSX text without applying JavaScript trivia rules.
    ///
    /// The normal lexer treats `//` and `/* */` as comments. Inside JSX child
    /// text they are literal text, so parser JSX-skipping code must move to the
    /// next JSX boundary (`<` for nested/closing tags, `{` for expression
    /// containers) with a raw byte scan instead of calling `next()`.
    pub(crate) fn skip_raw_jsx_text_until_boundary(&mut self) {
        let start = self
            .peeked
            .take()
            .map(|token| token.span.start() as usize)
            .unwrap_or(self.pos);
        self.pos = start;
        while self.pos < self.source.len()
            && self.source[self.pos] != b'<'
            && self.source[self.pos] != b'{'
        {
            self.pos += 1;
        }
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.source[self.pos..].starts_with(needle)
    }

    /// Lex a template literal beginning at the opening backtick (`pos` is at
    /// the backtick). Emits `TemplateStart` covering `` `...${ `` (and pushes a
    /// template context + opens a brace level), OR — for a template with no
    /// interpolation — `TemplateStart` covering the whole `` `...` `` literal.
    fn start_template(&mut self, start: usize) -> Token {
        self.pos += 1; // consume opening backtick
        loop {
            if self.pos >= self.source.len() {
                // Unterminated at EOF: emit what we have (recovery). The parser
                // treats a trailing TemplateStart with no TemplateEnd as complete.
                self.regex_allowed = false;
                return Token {
                    kind: TokenKind::TemplateStart,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            let b = self.source[self.pos];
            if b == b'\\' && self.pos + 1 < self.source.len() {
                self.pos += 2;
                continue;
            }
            if b == b'`' {
                self.pos += 1; // consume closing backtick — full literal, no interpolation
                self.regex_allowed = false;
                return Token {
                    kind: TokenKind::TemplateStart,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            if b == b'$' && self.pos + 1 < self.source.len() && self.source[self.pos + 1] == b'{' {
                self.pos += 2; // consume `${`
                self.template_stack.push(TemplateContext {
                    brace_depth: self.brace_depth,
                });
                self.brace_depth += 1;
                self.regex_allowed = true; // an expression begins after `${`
                return Token {
                    kind: TokenKind::TemplateStart,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            self.pos += 1;
        }
    }

    /// Resume a template body after the `}` that closed an interpolation.
    /// `pos` is just past that `}`; `start` is the byte offset of the `}` (so the
    /// emitted token span begins at `}`). Emits `TemplateMid` (body ended at the
    /// next `${`) or `TemplateEnd` (body ended at the closing backtick).
    fn lex_template_continuation(&mut self, start: usize) -> Token {
        loop {
            if self.pos >= self.source.len() {
                self.regex_allowed = false;
                return Token {
                    kind: TokenKind::TemplateEnd,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            let b = self.source[self.pos];
            if b == b'\\' && self.pos + 1 < self.source.len() {
                self.pos += 2;
                continue;
            }
            if b == b'`' {
                self.pos += 1;
                self.regex_allowed = false;
                return Token {
                    kind: TokenKind::TemplateEnd,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            if b == b'$' && self.pos + 1 < self.source.len() && self.source[self.pos + 1] == b'{' {
                self.pos += 2;
                self.template_stack.push(TemplateContext {
                    brace_depth: self.brace_depth,
                });
                self.brace_depth += 1;
                self.regex_allowed = true;
                return Token {
                    kind: TokenKind::TemplateMid,
                    span: Span::new(start as u32, (self.pos - start) as u32),
                };
            }
            self.pos += 1;
        }
    }

    /// If the bytes at `pos` start an ECMA-262 §11.3 `LineTerminator`,
    /// return its UTF-8 byte length: 1 for LF (`\n`) and CR (`\r`),
    /// 3 for LS (U+2028, `E2 80 A8`) and PS (U+2029, `E2 80 A9`).
    /// Otherwise `None`. Audit-5b round-2 review item R2-P3 — used by
    /// every trivia scanner so the LineTerminator predicate is centralized
    /// (the audit-5b round-1 fix only handled LF + CR inline in each
    /// scanner, which left the Unicode line terminators silently swallowing
    /// post-comment / post-shebang source).
    #[inline]
    fn line_terminator_len_at(&self, pos: usize) -> Option<usize> {
        let s = self.source;
        if pos >= s.len() {
            return None;
        }
        match s[pos] {
            b'\n' | b'\r' => Some(1),
            // U+2028 = E2 80 A8, U+2029 = E2 80 A9 in UTF-8.
            0xE2 if pos + 2 < s.len()
                && s[pos + 1] == 0x80
                && matches!(s[pos + 2], 0xA8 | 0xA9) =>
            {
                Some(3)
            }
            _ => None,
        }
    }

    /// If the bytes at `pos` start an ECMA-262 §11.2 `WhiteSpace`
    /// (excluding the §11.3 LineTerminators handled by
    /// `line_terminator_len_at`), return its UTF-8 byte length.
    /// The §11.2 set is:
    ///
    /// * 1-byte: TAB (`\t` 0x09), VT (0x0B), FF (0x0C), SP (b' ' 0x20)
    /// * 2-byte UTF-8: NBSP (U+00A0 = C2 A0)
    /// * 3-byte UTF-8: ZWNBSP (U+FEFF = EF BB BF), OGHAM SPACE
    ///   (U+1680 = E1 9A 80), and the U+2000–200A / U+202F / U+205F /
    ///   U+3000 Unicode Zs cluster.
    ///
    /// Pre-R7 the lexer's whitespace loop matched only TAB and SP — a
    /// strict subset of §11.2. NBSP between tokens (common in
    /// Windows-Latin copy-paste), mid-source ZWNBSP, and the entire Zs
    /// category (common in CJK source) all cascaded into Error tokens
    /// and recovery diagnostics on otherwise valid source.
    #[inline]
    fn whitespace_len_at(&self, pos: usize) -> Option<usize> {
        let s = self.source;
        if pos >= s.len() {
            return None;
        }
        match s[pos] {
            // §11.2 single-byte WhiteSpace. (LF/CR are NOT whitespace
            // for §11.2 purposes — they are §11.3 LineTerminators,
            // handled separately so `had_line_terminator` stays accurate.)
            b'\t' | 0x0B | 0x0C | b' ' => Some(1),
            // 2-byte UTF-8: NBSP (U+00A0 = C2 A0).
            0xC2 if pos + 1 < s.len() && s[pos + 1] == 0xA0 => Some(2),
            // 3-byte UTF-8: OGHAM SPACE (U+1680 = E1 9A 80).
            0xE1 if pos + 2 < s.len() && s[pos + 1] == 0x9A && s[pos + 2] == 0x80 => Some(3),
            // 3-byte UTF-8: the U+2000–200A, U+202F, U+205F cluster,
            // all sharing the E2 leading byte.
            // * E2 80 80..8A — U+2000 (EN QUAD) through U+200A (HAIR SPACE)
            // * E2 80 AF    — U+202F (NARROW NO-BREAK SPACE)
            // * E2 81 9F    — U+205F (MEDIUM MATHEMATICAL SPACE)
            0xE2 if pos + 2 < s.len() => {
                let b1 = s[pos + 1];
                let b2 = s[pos + 2];
                // U+2000–200A / U+202F (both have b1 == 0x80) and
                // U+205F (b1 == 0x81, b2 == 0x9F).
                if (b1 == 0x80 && ((0x80..=0x8A).contains(&b2) || b2 == 0xAF))
                    || (b1 == 0x81 && b2 == 0x9F)
                {
                    Some(3)
                } else {
                    None
                }
            }
            // 3-byte UTF-8: IDEOGRAPHIC SPACE (U+3000 = E3 80 80).
            0xE3 if pos + 2 < s.len() && s[pos + 1] == 0x80 && s[pos + 2] == 0x80 => Some(3),
            // 3-byte UTF-8: ZWNBSP (U+FEFF = EF BB BF) — anywhere, not
            // just BOM position. The audit-5b R3-C BOM strip only
            // handled position 0; ECMA-262 §11.2 treats ZWNBSP as
            // WhiteSpace anywhere.
            0xEF if pos + 2 < s.len() && s[pos + 1] == 0xBB && s[pos + 2] == 0xBF => Some(3),
            _ => None,
        }
    }

    /// Decode the single UTF-8 scalar at `pos`, returning `(char, byte_len)`.
    /// `None` at EOF or on invalid UTF-8 (TS source is UTF-8; a bad sequence
    /// falls through to the caller's Error path).
    #[inline]
    fn decode_char_at(&self, pos: usize) -> Option<(char, usize)> {
        let b = *self.source.get(pos)?;
        let len = if b < 0x80 {
            1
        } else if b >> 5 == 0b110 {
            2
        } else if b >> 4 == 0b1110 {
            3
        } else if b >> 3 == 0b11110 {
            4
        } else {
            return None; // continuation byte or invalid lead
        };
        let slice = self.source.get(pos..pos + len)?;
        let ch = std::str::from_utf8(slice).ok()?.chars().next()?;
        Some((ch, len))
    }

    /// `\u Hex4` or `\u{ CodePoint }` UnicodeEscapeSequence at `pos` (which must
    /// point at the `\`). Returns the decoded char + the escape's byte length.
    /// ECMA-262 §11.6.1 allows such escapes in IdentifierStart / IdentifierPart.
    fn unicode_escape_at(&self, pos: usize) -> Option<(char, usize)> {
        if self.source.get(pos) != Some(&b'\\') || self.source.get(pos + 1) != Some(&b'u') {
            return None;
        }
        let mut i = pos + 2;
        let mut cp: u32 = 0;
        if self.source.get(i) == Some(&b'{') {
            i += 1;
            let digits_start = i;
            while let Some(&b) = self.source.get(i) {
                if !b.is_ascii_hexdigit() {
                    break;
                }
                cp = cp.checked_mul(16)?.checked_add((b as char).to_digit(16)?)?;
                i += 1;
            }
            if i == digits_start || self.source.get(i) != Some(&b'}') {
                return None;
            }
            i += 1; // consume `}`
        } else {
            for _ in 0..4 {
                let b = *self.source.get(i)?;
                if !b.is_ascii_hexdigit() {
                    return None;
                }
                cp = cp * 16 + (b as char).to_digit(16).unwrap();
                i += 1;
            }
        }
        let ch = char::from_u32(cp)?;
        Some((ch, i - pos))
    }

    /// Length in bytes of an IdentifierStart at `pos`, or `None`. Covers ASCII
    /// `[A-Za-z_$]`, Unicode ID_Start (approximated by `char::is_alphabetic`,
    /// dep-free; #20), and `\u`-escaped start chars (#25).
    #[inline]
    fn ident_start_len_at(&self, pos: usize) -> Option<usize> {
        let b = *self.source.get(pos)?;
        if b < 0x80 {
            return if matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$') {
                Some(1)
            } else if b == b'\\' {
                self.unicode_escape_at(pos).and_then(|(ch, len)| {
                    (ch.is_alphabetic() || ch == '_' || ch == '$').then_some(len)
                })
            } else {
                None
            };
        }
        let (ch, len) = self.decode_char_at(pos)?;
        ch.is_alphabetic().then_some(len)
    }

    /// Length in bytes of an IdentifierPart at `pos`, or `None`. ASCII
    /// `[A-Za-z0-9_$]`, Unicode ID_Continue (approximated by
    /// `char::is_alphanumeric`), and `\u`-escaped continue chars.
    #[inline]
    fn ident_continue_len_at(&self, pos: usize) -> Option<usize> {
        let b = *self.source.get(pos)?;
        if b < 0x80 {
            return if matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$') {
                Some(1)
            } else if b == b'\\' {
                self.unicode_escape_at(pos).and_then(|(ch, len)| {
                    (ch.is_alphanumeric() || ch == '_' || ch == '$').then_some(len)
                })
            } else {
                None
            };
        }
        let (ch, len) = self.decode_char_at(pos)?;
        ch.is_alphanumeric().then_some(len)
    }

    fn skip_trivia(&mut self) {
        // Reset the LineTerminator flag for the trivia we're about to
        // scan — `had_line_terminator()` is the parser's "was there an
        // LT between the previous token and the one I'm about to peek?"
        // predicate, and that question is answered by exactly this trivia.
        self.had_line_terminator = false;
        // UTF-8 BOM (EF BB BF) at the absolute start of source is treated
        // as ZWNBSP (U+FEFF) per ECMA-262 §11.2 WhiteSpace and stripped
        // before lexical analysis. MDN and V8/tsc/all major engines do
        // the same. Without this strip, the first byte (0xEF) is lexed
        // as an Error token and the parser emits a spurious recovery
        // diagnostic on the first real token (R3-C audit finding).
        //
        // `logical_start` is the position the *spec* considers the file's
        // start — 0 for plain source, 3 if BOM was present. Used by the
        // hashbang gate below so that a BOM + hashbang combo recognizes
        // the hashbang (which would otherwise fail its `pos == 0` gate
        // after the BOM strip bumped pos to 3).
        let logical_start = if self.source.len() >= 3
            && self.source[0] == 0xEF
            && self.source[1] == 0xBB
            && self.source[2] == 0xBF
        {
            if self.pos == 0 {
                self.pos = 3;
            }
            3
        } else {
            0
        };
        // HashbangComment per ECMA-262 (`#!` SingleLineCommentChars?) — only
        // valid at the absolute logical start of a Script or Module (after
        // any BOM strip). Consumes up to (but not including) any
        // LineTerminator (LF/CR/LS/PS); if the file ends mid-shebang we
        // run to EOF. Audit-5b round-2 R2-P3 widened the stop condition
        // from LF+CR-only to the full §11.3 LineTerminator set —
        // U+2028/U+2029 are valid line terminators that classic-Mac and
        // some Unicode-aware editors emit. R3-C followup: the gate moved
        // from `pos == 0` to `pos == logical_start` so a BOM doesn't
        // hide the hashbang.
        if self.pos == logical_start
            && self.pos + 1 < self.source.len()
            && self.source[self.pos] == b'#'
            && self.source[self.pos + 1] == b'!'
        {
            self.pos = 2;
            while self.pos < self.source.len() && self.line_terminator_len_at(self.pos).is_none() {
                self.pos += 1;
            }
        }
        loop {
            // Whitespace + LineTerminators. The flag is set when an LT is
            // consumed; the LT is consumed by `len` bytes (1 for LF/CR,
            // 3 for LS/PS).
            loop {
                if self.pos >= self.source.len() {
                    break;
                }
                if let Some(len) = self.line_terminator_len_at(self.pos) {
                    self.had_line_terminator = true;
                    self.pos += len;
                    continue;
                }
                // Full ECMA-262 §11.2 WhiteSpace set (TAB/VT/FF/SP/NBSP/
                // ZWNBSP/Zs). Audit-5 R7-D2 widened this from just
                // `b' ' | b'\t'`. The helper returns Some(len) for each
                // matching UTF-8 sequence (1/2/3 bytes).
                if let Some(len) = self.whitespace_len_at(self.pos) {
                    self.pos += len;
                    continue;
                }
                break;
            }
            // Line comment // ... — stops at any LineTerminator per §12.5
            // SingleLineCommentChars (any SourceCharacter except an LT).
            // Audit-5b round-2 R2-P3 widened this from LF-only to the full
            // §11.3 set; before the fix, `// note\rconst x = 1;` silently
            // consumed `const x = 1;` to EOF.
            if self.pos + 1 < self.source.len()
                && self.source[self.pos] == b'/'
                && self.source[self.pos + 1] == b'/'
            {
                while self.pos < self.source.len()
                    && self.line_terminator_len_at(self.pos).is_none()
                {
                    self.pos += 1;
                }
                continue;
            }
            // Block comment /* ... */ — per ECMA-262 §11.4 / §12.5 a
            // MultiLineComment that *contains* a LineTerminator is treated
            // as a LineTerminator for syntactic-grammar purposes (so it
            // triggers ASI on restricted productions like `throw EXPR`).
            // Audit-5b round-2 R2-P2: set the flag while consuming the
            // body so `throw /*\n*/ EXPR` recovers identically to
            // `throw\nEXPR`. The MultiLineComment itself does NOT advance
            // line counting beyond what the contained LTs already do.
            if self.pos + 1 < self.source.len()
                && self.source[self.pos] == b'/'
                && self.source[self.pos + 1] == b'*'
            {
                let comment_start = self.pos; // the `/` of `/*`
                self.pos += 2;
                while self.pos + 1 < self.source.len()
                    && !(self.source[self.pos] == b'*' && self.source[self.pos + 1] == b'/')
                {
                    if let Some(len) = self.line_terminator_len_at(self.pos) {
                        self.had_line_terminator = true;
                        self.pos += len;
                    } else {
                        self.pos += 1;
                    }
                }
                if self.pos + 1 < self.source.len() {
                    self.pos += 2; // consume '*/'
                } else {
                    // Ran to EOF without a closing `*/` (#22). Record the span
                    // (start → EOF) once; the parser surfaces it as a
                    // SyntaxRecovered diagnostic.
                    self.pos = self.source.len();
                    if self.unterminated_block_comment.is_none() {
                        self.unterminated_block_comment = Some(Span::new(
                            comment_start as u32,
                            (self.source.len() - comment_start) as u32,
                        ));
                    }
                }
                continue;
            }
            break;
        }
    }

    /// Consume a base-10 number body: integer digits, optional `.` fractional
    /// part, optional `e`/`E` exponent (with optional sign). Underscore digit
    /// separators are accepted anywhere a digit is. We accept-and-skip without
    /// parsing the value — the parser/resolver doesn't read numeric values.
    fn read_decimal_number(&mut self) {
        while self.pos < self.source.len() && matches!(self.source[self.pos], b'0'..=b'9' | b'_') {
            self.pos += 1;
        }
        // Fractional part.
        if self.pos < self.source.len() && self.source[self.pos] == b'.' {
            self.pos += 1;
            while self.pos < self.source.len()
                && matches!(self.source[self.pos], b'0'..=b'9' | b'_')
            {
                self.pos += 1;
            }
        }
        // Exponent part.
        if self.pos < self.source.len() && matches!(self.source[self.pos], b'e' | b'E') {
            self.pos += 1;
            if self.pos < self.source.len() && matches!(self.source[self.pos], b'+' | b'-') {
                self.pos += 1;
            }
            while self.pos < self.source.len()
                && matches!(self.source[self.pos], b'0'..=b'9' | b'_')
            {
                self.pos += 1;
            }
        }
    }
}
