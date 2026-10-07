#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownIntentGraph {
    pub schema: &'static str,
    pub file: String,
    pub facts: Vec<MarkdownFact>,
    pub diagnostics: Vec<MarkdownDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkdownFactKind {
    Heading,
    Task,
    FileRef,
    SymbolRef,
    Command,
    ReturnContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownFact {
    pub kind: MarkdownFactKind,
    pub text: String,
    pub line: u32,
    pub col: u32,
    pub level: Option<u8>,
    pub checked: Option<bool>,
    pub target: Option<String>,
    pub symbol: Option<String>,
    pub expected_return: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownDiagnostic {
    pub kind: String,
    pub message: String,
    pub line: u32,
    pub col: u32,
}

pub fn parse_markdown(file: &str, source: &str) -> MarkdownIntentGraph {
    let mut graph = MarkdownIntentGraph {
        schema: "repotoire.markdown_intent.v1",
        file: file.to_string(),
        facts: Vec::new(),
        diagnostics: Vec::new(),
    };

    // Fenced code blocks are literal text, not markdown: their contents must not
    // produce facts/diagnostics. Track the open fence (marker char + run length) so a
    // contract- or heading-shaped line inside ``` / ~~~ cannot manufacture evidence.
    let mut fence: Option<(u8, usize)> = None;
    let mut html: Option<HtmlEnd> = None;
    for (line_index, line) in source.lines().enumerate() {
        let line_no = (line_index + 1) as u32;
        let trimmed = line.trim_start();
        let mut scan_from = 0;
        let mut opaque = false;
        if let Some(end) = html {
            if end == HtmlEnd::BlankLine {
                if trimmed.is_empty() {
                    html = None;
                    continue;
                }
                add_html_diagnostic(file, line, line_no, &mut graph);
                continue;
            }
            opaque = true;
            if let Some(after) = end.close_at(line, 0) {
                html = None;
                scan_from = after;
            } else {
                add_html_diagnostic(file, line, line_no, &mut graph);
                continue;
            }
        }
        if !opaque {
            match fence {
                Some((fence_char, fence_len)) => {
                    if is_closing_fence(trimmed, fence_char, fence_len) {
                        fence = None;
                    }
                    // The fence line and everything inside it are skipped.
                    continue;
                }
                None => {
                    if let Some(open) = opening_fence(trimmed) {
                        fence = Some(open);
                        continue;
                    }
                }
            }
        }
        while let Some((start, end)) = html_start(line, scan_from) {
            opaque = true;
            if let Some(after) = end.close_at(line, start) {
                scan_from = after;
            } else {
                html = Some(end);
                break;
            }
        }
        if opaque {
            add_html_diagnostic(file, line, line_no, &mut graph);
            continue;
        }
        parse_line(file, line, line_no, &mut graph);
    }

    graph
}

/// A line that opens a fenced code block: 3+ backticks or 3+ tildes. Per CommonMark, a
/// backtick fence whose info string contains a backtick is not a fence.
fn opening_fence(trimmed: &str) -> Option<(u8, usize)> {
    let bytes = trimmed.as_bytes();
    let &first = bytes.first()?;
    if first != b'`' && first != b'~' {
        return None;
    }
    let len = bytes.iter().take_while(|&&byte| byte == first).count();
    if len < 3 {
        return None;
    }
    if first == b'`' && trimmed[len..].contains('`') {
        return None;
    }
    Some((first, len))
}

/// A closing fence is a run of the same marker char at least as long as the opening one,
/// followed only by whitespace.
fn is_closing_fence(trimmed: &str, fence_char: u8, fence_len: usize) -> bool {
    let run = trimmed
        .as_bytes()
        .iter()
        .take_while(|&&byte| byte == fence_char)
        .count();
    run >= fence_len && trimmed[run..].trim().is_empty()
}

fn parse_line(_file: &str, line: &str, line_no: u32, graph: &mut MarkdownIntentGraph) {
    let trimmed = line.trim_start();
    let col = (line.len() - trimmed.len() + 1) as u32;

    if let Some((level, text)) = heading(trimmed) {
        graph.facts.push(MarkdownFact {
            kind: MarkdownFactKind::Heading,
            text: text.to_string(),
            line: line_no,
            col,
            level: Some(level),
            checked: None,
            target: None,
            symbol: None,
            expected_return: None,
        });
    }

    if let Some((checked, text)) = task(trimmed) {
        graph.facts.push(MarkdownFact {
            kind: MarkdownFactKind::Task,
            text: text.to_string(),
            line: line_no,
            col,
            level: None,
            checked: Some(checked),
            target: None,
            symbol: None,
            expected_return: None,
        });
    }

    if let Some(contract) = return_contract(line, line_no) {
        graph.facts.push(contract);
    }

    for (code, code_col) in inline_code_spans(line) {
        if is_command(code) {
            graph.facts.push(MarkdownFact {
                kind: MarkdownFactKind::Command,
                text: code.to_string(),
                line: line_no,
                col: code_col,
                level: None,
                checked: None,
                target: None,
                symbol: None,
                expected_return: None,
            });
        }
        if let Some((target, symbol)) = symbol_ref(code) {
            graph.facts.push(MarkdownFact {
                kind: MarkdownFactKind::SymbolRef,
                text: code.to_string(),
                line: line_no,
                col: code_col,
                level: None,
                checked: None,
                target: Some(target.to_string()),
                symbol: Some(symbol.to_string()),
                expected_return: None,
            });
        }
        if is_file_ref(code) {
            graph.facts.push(MarkdownFact {
                kind: MarkdownFactKind::FileRef,
                text: code.to_string(),
                line: line_no,
                col: code_col,
                level: None,
                checked: None,
                target: Some(file_part(code).to_string()),
                symbol: None,
                expected_return: None,
            });
        }
    }
}

fn heading(trimmed: &str) -> Option<(u8, &str)> {
    let level = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let text = trimmed.get(level..)?.strip_prefix(' ')?;
    Some((level as u8, text.trim()))
}

fn task(trimmed: &str) -> Option<(bool, &str)> {
    for prefix in ["- [ ] ", "* [ ] "] {
        if let Some(text) = trimmed.strip_prefix(prefix) {
            return Some((false, text.trim()));
        }
    }
    for prefix in ["- [x] ", "- [X] ", "* [x] ", "* [X] "] {
        if let Some(text) = trimmed.strip_prefix(prefix) {
            return Some((true, text.trim()));
        }
    }
    None
}

fn return_contract(line: &str, line_no: u32) -> Option<MarkdownFact> {
    let start = line.find("Repotoire contract: `")?;
    let rest = &line[start + "Repotoire contract: `".len()..];
    let (subject, rest) = rest.split_once('`')?;
    let rest = rest.trim_start().strip_prefix("returns `")?;
    let (expected_return, tail) = rest.split_once('`')?;
    let end = line.len() - tail.len() + usize::from(tail.starts_with('.'));
    let (target, symbol) = symbol_ref(subject)?;
    Some(MarkdownFact {
        kind: MarkdownFactKind::ReturnContract,
        text: line[start..end].to_string(),
        line: line_no,
        col: (start + 1) as u32,
        level: None,
        checked: None,
        target: Some(target.to_string()),
        symbol: Some(symbol.to_string()),
        expected_return: Some(expected_return.to_string()),
    })
}

fn inline_code_spans(line: &str) -> Vec<(&str, u32)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(start) = line[offset..].find('`') {
        let content_start = offset + start + 1;
        let Some(end) = line[content_start..].find('`') else {
            break;
        };
        let content_end = content_start + end;
        out.push((
            &line[content_start..content_end],
            (content_start + 1) as u32,
        ));
        offset = content_end + 1;
    }
    out
}

fn symbol_ref(code: &str) -> Option<(&str, &str)> {
    let (target, symbol) = code.split_once('#')?;
    if !is_file_ref(target) || !is_identifier_path(symbol) {
        return None;
    }
    Some((target, symbol))
}

fn is_file_ref(code: &str) -> bool {
    let path = file_part(code);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || path.contains(' ')
    {
        return false;
    }
    path.contains('/')
        || matches!(
            path.rsplit('.').next(),
            Some("rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "md" | "json" | "toml")
        )
}

fn file_part(code: &str) -> &str {
    code.split_once('#').map(|(file, _)| file).unwrap_or(code)
}

fn is_identifier_path(symbol: &str) -> bool {
    !symbol.is_empty()
        && symbol
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_identifier_char))
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn is_command(code: &str) -> bool {
    matches!(
        code.split_whitespace().next(),
        Some(
            "cargo" | "npm" | "pnpm" | "yarn" | "repotoire" | "git" | "python" | "pytest" | "bash"
        )
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlEnd {
    BlankLine,
    Comment,
    ProcessingInstruction,
    Declaration,
    Cdata,
    ScriptLike,
    OneLine,
}

impl HtmlEnd {
    fn close_at(self, line: &str, start: usize) -> Option<usize> {
        let tail = &line[start..];
        let token = match self {
            Self::BlankLine => return None,
            Self::Comment => "-->",
            Self::ProcessingInstruction => "?>",
            Self::Declaration | Self::OneLine => ">",
            Self::Cdata => "]]>",
            Self::ScriptLike => {
                let lower = tail.to_ascii_lowercase();
                return ["</pre>", "</script>", "</style>", "</textarea>"]
                    .iter()
                    .filter_map(|tag| lower.find(tag).map(|at| start + at + tag.len()))
                    .min();
            }
        };
        tail.find(token).map(|at| start + at + token.len())
    }
}

fn add_html_diagnostic(file: &str, line: &str, line_no: u32, graph: &mut MarkdownIntentGraph) {
    graph.diagnostics.push(MarkdownDiagnostic {
        kind: "unsupported_html".to_string(),
        message: format!(
            "`{file}` line {line_no} contains raw HTML; markdown intent parser does not infer facts from HTML blocks"
        ),
        line: line_no,
        col: (line.len() - line.trim_start().len() + 1) as u32,
    });
}

fn code_span_ranges(line: &str, offset: usize) -> Vec<std::ops::Range<usize>> {
    let bytes = line.as_bytes();
    let mut ranges = Vec::new();
    let mut cursor = offset;
    while cursor < bytes.len() {
        if bytes[cursor] != b'`' || is_escaped(bytes, cursor) {
            cursor += 1;
            continue;
        }
        let open = cursor;
        while cursor < bytes.len() && bytes[cursor] == b'`' {
            cursor += 1;
        }
        let width = cursor - open;
        let mut candidate = cursor;
        while candidate < bytes.len() {
            if bytes[candidate] != b'`' {
                candidate += 1;
                continue;
            }
            let close = candidate;
            while candidate < bytes.len() && bytes[candidate] == b'`' {
                candidate += 1;
            }
            if candidate - close == width {
                ranges.push(open..candidate);
                cursor = candidate;
                break;
            }
        }
    }
    ranges
}

fn is_escaped(bytes: &[u8], index: usize) -> bool {
    let mut at = index;
    while at > 0 && bytes[at - 1] == b'\\' {
        at -= 1;
    }
    (index - at) % 2 == 1
}

fn html_start(line: &str, offset: usize) -> Option<(usize, HtmlEnd)> {
    let code_spans = code_span_ranges(line, offset);
    for (relative, _) in line[offset..].match_indices('<') {
        let start = offset + relative;
        if code_spans.iter().any(|span| span.contains(&start)) || is_escaped(line.as_bytes(), start)
        {
            continue;
        }
        let tail = &line[start + 1..];
        if tail.starts_with("!--") {
            return Some((start, HtmlEnd::Comment));
        }
        if tail.starts_with("![CDATA[") {
            return Some((start, HtmlEnd::Cdata));
        }
        if tail.starts_with('?') {
            return Some((start, HtmlEnd::ProcessingInstruction));
        }
        if tail.starts_with('!') {
            return Some((start, HtmlEnd::Declaration));
        }
        if let Some((inside, _)) = tail.split_once('>') {
            if is_markdown_autolink(inside) {
                continue;
            }
        }
        let tag = tail.strip_prefix('/').unwrap_or(tail);
        let name_len = tag
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            .count();
        let name = &tag[..name_len];
        if name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
            && tag[name_len..]
                .chars()
                .next()
                .is_none_or(|ch| ch.is_whitespace() || ch == '>' || ch == '/')
        {
            let at_line_start = line[..start].trim().is_empty();
            if at_line_start
                && !tail.starts_with('/')
                && ["pre", "script", "style", "textarea"]
                    .iter()
                    .any(|known| name.eq_ignore_ascii_case(known))
            {
                return Some((start, HtmlEnd::ScriptLike));
            }
            return Some((
                start,
                if at_line_start {
                    HtmlEnd::BlankLine
                } else {
                    HtmlEnd::OneLine
                },
            ));
        }
        if line[..start].trim().is_empty() {
            return Some((start, HtmlEnd::OneLine));
        }
    }
    None
}

fn is_markdown_autolink(inside: &str) -> bool {
    if inside
        .bytes()
        .any(|byte| byte <= b' ' || byte == b'<' || byte == b'>')
    {
        return false;
    }
    if let Some((scheme, _)) = inside.split_once(':') {
        return (2..=32).contains(&scheme.len())
            && scheme
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'));
    }
    let Some((local, domain)) = inside.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&byte))
    {
        return false;
    }
    domain.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}
