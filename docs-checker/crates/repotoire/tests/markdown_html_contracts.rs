use repotoire::docs::{decode_markdown_doc, DocDecodeOptions, DocNodeKind};
use repotoire::evidence::EvidenceRepoRef;
use repotoire::markdown::{parse_markdown, MarkdownFactKind};

fn options() -> DocDecodeOptions {
    DocDecodeOptions::new(
        EvidenceRepoRef::new("test"),
        "snapshot",
        "2026-10-07T00:00:00Z",
    )
}

// What: Raw tag blocks stay opaque through their blank-line terminator.
// Why: HTML prose is not supported contract evidence.
// Verify: Parse and decode hidden bad and later visible good claims.
// Detects: HTML content becoming a verified API contract.
#[test]
fn html_tag_block_cannot_create_claims_before_blank_line() {
    let source = "# API Contract\n<p>\nRepotoire contract: `src/lib.ts#answer` returns `bad`.\n</p>\n\nRepotoire contract: `src/lib.ts#answer` returns `ok`.\n";
    let parsed = parse_markdown("guide.md", source);
    assert_eq!(
        parsed
            .facts
            .iter()
            .filter(|fact| fact.kind == MarkdownFactKind::ReturnContract)
            .count(),
        1
    );
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 3));
    let decoded = decode_markdown_doc("guide.md", source, options());
    assert!(!decoded
        .nodes
        .iter()
        .any(|node| node.kind == DocNodeKind::APIContract && node.title.contains("bad")));
    assert!(decoded
        .nodes
        .iter()
        .any(|node| node.kind == DocNodeKind::APIContract && node.title.contains("ok")));
}

// What: Comments and scripts retain opaque multiline state.
// Why: Hidden content cannot establish API behavior.
// Verify: Run both HTML forms through parsing and document decoding.
// Detects: Claims leaking from comments or script bodies.
#[test]
fn comment_and_script_blocks_cannot_create_claims() {
    for source in [
        "<!--\nRepotoire contract: `src/lib.ts#answer` returns `bad`.\n-->\n",
        "<script>\nRepotoire contract: `src/lib.ts#answer` returns `bad`.\n</script>\n",
    ] {
        let parsed = parse_markdown("guide.md", source);
        assert!(!parsed
            .facts
            .iter()
            .any(|fact| fact.kind == MarkdownFactKind::ReturnContract));
        assert!(parsed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 2));
        let decoded = decode_markdown_doc("guide.md", source, options());
        assert!(!decoded
            .nodes
            .iter()
            .any(|node| node.kind == DocNodeKind::APIContract));
    }
}

// What: Raw HTML cannot create a Markdown requirement.
// Why: Unsupported markup must not enter verification work.
// Verify: Parse a checklist and decode a normative requirement inside HTML.
// Detects: Hidden HTML becoming task or requirement evidence.
#[test]
fn html_block_cannot_create_a_requirement() {
    let source = "# Requirements
<p>
- [ ] Must never be treated as verified.
- MUST never be treated as verified.
</p>
";
    let parsed = parse_markdown("guide.md", source);
    assert!(!parsed
        .facts
        .iter()
        .any(|fact| fact.kind == MarkdownFactKind::Task));
    let decoded = decode_markdown_doc("guide.md", source, options());
    assert!(!decoded
        .nodes
        .iter()
        .any(|node| node.kind == DocNodeKind::Requirement));
}

// What: Unsupported inline HTML invalidates that contract line.
// Why: Partial extraction cannot safely verify an opaque line.
// Verify: Parse a tag and a complete comment containing contract syntax.
// Detects: Partial contracts admitted from unsupported HTML.
#[test]
fn inline_html_and_comment_cannot_create_partial_contracts() {
    for source in [
        "Repotoire contract: `src/lib.ts#answer` returns `bad`. <span>text</span>\n",
        "<!-- Repotoire contract: `src/lib.ts#answer` returns `bad`. -->\n",
    ] {
        let parsed = parse_markdown("guide.md", source);
        assert!(!parsed
            .facts
            .iter()
            .any(|fact| fact.kind == MarkdownFactKind::ReturnContract));
    }
}

// What: Opaque HTML text cannot open a Markdown fence.
// Why: State from ignored text must not hide later real claims.
// Verify: Parse hidden fence text followed by a plain contract.
// Detects: HTML fence syntax corrupting later Markdown state.
#[test]
fn html_block_contents_cannot_open_a_markdown_fence() {
    let source = "<p>
```
Repotoire contract: `src/lib.ts#answer` returns `bad`.

Repotoire contract: `src/lib.ts#answer` returns `ok`.
";
    let parsed = parse_markdown("guide.md", source);
    let contracts = parsed
        .facts
        .iter()
        .filter(|fact| fact.kind == MarkdownFactKind::ReturnContract)
        .collect::<Vec<_>>();
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].line, 5);
}

// What: Every comment opener on a line affects following lines.
// Why: An earlier closed comment cannot consume a later opener.
// Verify: Parse two adjacent comments with a hidden and a visible claim.
// Detects: Later open comments losing opacity.
#[test]
fn later_comment_opener_on_same_line_keeps_following_line_opaque() {
    let source = "<!-- closed --> <!--
Repotoire contract: `src/lib.ts#answer` returns `bad`.
-->
Repotoire contract: `src/lib.ts#answer` returns `ok`.
";
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 2));
    let contracts = parsed
        .facts
        .iter()
        .filter(|fact| fact.kind == MarkdownFactKind::ReturnContract)
        .collect::<Vec<_>>();
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].line, 4);
}

// What: An inline tag affects only its own line.
// Why: Opacity must not discard unrelated supported Markdown.
// Verify: Parse a tag line followed by a plain API contract.
// Detects: Inline HTML hiding later supported evidence.
#[test]
fn inline_tag_does_not_hide_later_plain_markdown() {
    let source = "text <span>inline</span>
Repotoire contract: `src/lib.ts#answer` returns `ok`.
";
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 1));
    assert!(parsed
        .facts
        .iter()
        .any(|fact| fact.kind == MarkdownFactKind::ReturnContract && fact.line == 2));
}

// What: Malformed email-like angle text remains unsupported.
// Why: Autolink exceptions must not admit invalid HTML-like text.
// Verify: Parse an invalid domain and require an HTML diagnostic.
// Detects: Overbroad email recognition suppressing opacity.
#[test]
fn malformed_email_like_angle_text_stays_unsupported() {
    let parsed = parse_markdown(
        "guide.md",
        "<foo@-bad>
",
    );
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html"));
}

// What: Supported autolinks and code literals remain Markdown.
// Why: Valid literal text must not start HTML state.
// Verify: Parse URL, email, code span and fenced literal examples.
// Detects: HTML detection misclassifying literal Markdown.
#[test]
fn markdown_autolinks_and_literals_do_not_start_html() {
    let source = "<https://example.com/docs>\n<foo@example.com>\n<foo@localhost>\n`<span>literal</span>`\n``<span>literal</span>``\n```html\n<p>Repotoire contract: `src/lib.ts#answer` returns `bad`.</p>\n```\nRepotoire contract: `src/lib.ts#answer` returns `ok`.\n";
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(
        parsed
            .facts
            .iter()
            .filter(|fact| fact.kind == MarkdownFactKind::ReturnContract)
            .count(),
        1
    );
}
// What: An escaped backtick cannot open a code span.
// Why: A literal backtick must not conceal an HTML comment.
// Verify: Parse and decode escaped delimiters with hidden claims.
// Detects: Escape handling bypassing HTML opacity.
#[test]
fn escaped_backtick_does_not_hide_html_comment() {
    let source = r#"# Requirements
\`<!-- `
- [ ] Hidden requirement.
- MUST remain hidden.
Repotoire contract: `src/lib.ts#answer` returns `bad`.
"#;
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 3));
    assert!(!parsed.facts.iter().any(|fact| matches!(
        fact.kind,
        MarkdownFactKind::Task | MarkdownFactKind::ReturnContract
    )));
    let decoded = decode_markdown_doc("guide.md", source, options());
    assert!(!decoded.nodes.iter().any(|node| matches!(
        node.kind,
        DocNodeKind::Requirement | DocNodeKind::APIContract
    )));
}

// What: Opaque comment segments cannot supply code delimiters.
// Why: Consumed HTML must not affect interpretation of later text.
// Verify: Parse and decode hidden and visible tasks and requirements.
// Detects: Backticks pairing across ignored comments.
#[test]
fn code_spans_cannot_pair_across_adjacent_comments() {
    let source = r#"# Requirements
<!-- ` --> <!-- `
- [ ] Hidden requirement.
- MUST remain hidden.
Repotoire contract: `src/lib.ts#answer` returns `bad`.
-->
- [ ] Real requirement.
- MUST remain visible.
"#;
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 3));
    assert_eq!(
        parsed
            .facts
            .iter()
            .filter(|fact| fact.kind == MarkdownFactKind::Task)
            .count(),
        1
    );
    assert!(!parsed
        .facts
        .iter()
        .any(|fact| fact.kind == MarkdownFactKind::ReturnContract));
    let decoded = decode_markdown_doc("guide.md", source, options());
    let requirements = decoded
        .nodes
        .iter()
        .filter(|node| node.kind == DocNodeKind::Requirement)
        .map(|node| node.title.as_str())
        .collect::<Vec<_>>();
    assert_eq!(requirements, ["- MUST remain visible."]);
    assert!(!decoded
        .nodes
        .iter()
        .any(|node| node.kind == DocNodeKind::APIContract));
}

// What: A closing comment line stays opaque for fence parsing.
// Why: An ignored closing segment must not hide later requirements.
// Verify: Parse a task and decode a requirement after a fence-like closing line.
// Detects: Closing HTML text opening a Markdown fence.
#[test]
fn closing_comment_line_cannot_open_markdown_fence() {
    let source = r#"# Requirements
<!--
``` -->
- [ ] Real requirement.
- MUST remain visible.
"#;
    let parsed = parse_markdown("guide.md", source);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "unsupported_html" && diagnostic.line == 3));
    assert!(parsed
        .facts
        .iter()
        .any(|fact| fact.kind == MarkdownFactKind::Task && fact.line == 4));
    let decoded = decode_markdown_doc("guide.md", source, options());
    let requirements = decoded
        .nodes
        .iter()
        .filter(|node| node.kind == DocNodeKind::Requirement)
        .map(|node| node.title.as_str())
        .collect::<Vec<_>>();
    assert_eq!(requirements, ["- MUST remain visible."]);
}
