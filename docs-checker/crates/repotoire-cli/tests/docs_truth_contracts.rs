use repotoire_cli::cli::{self, CliIo};
use repotoire_cli::docs_truth;
use serde_json::Value;
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::process::{Command, ExitCode};
use tempfile::TempDir;

fn invoke(args: &[&str]) -> (ExitCode, String, String) {
    let args = std::iter::once("repotoire".to_string())
        .chain(args.iter().map(|value| (*value).to_string()))
        .collect::<Vec<_>>();
    let mut stdin = Cursor::new(Vec::<u8>::new());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = cli::run(
        &args,
        &mut CliIo {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    (
        status,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

fn json(root: &Path) -> Value {
    let (status, output, error) =
        invoke(&["docs-truth", "--format", "json", root.to_str().unwrap()]);
    assert_eq!(status, ExitCode::SUCCESS, "{error}");
    serde_json::from_str(&output).unwrap()
}

fn git(root: &Path, args: &[&str]) {
    let result = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "fixture"]);
}

fn git_fixture() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["config", "user.name", "Checker Fixture"]);
    git(
        root.path(),
        &["config", "user.email", "checker@example.invalid"],
    );
    root
}

#[test]
fn json_markdown_collection_and_version_keep_the_existing_command_surface() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("README.md"),
        "# Architecture\n\nThe system runs.\n",
    )
    .unwrap();
    let path = root.path().to_str().unwrap();
    let report = json(root.path());
    assert_eq!(report["schema"], "repotoire.docs_truth.v2");
    assert!(report.get("coverage").is_none());
    assert_eq!(report["scorecard"]["markdown_files"], 1);
    let (status, markdown, error) = invoke(&["docs_truth", path]);
    assert_eq!(status, ExitCode::SUCCESS, "{error}");
    assert!(markdown.starts_with("# Docs Truth\n"));
    assert!(markdown.ends_with('\n'));
    let (status, collection, error) = invoke(&["docs-truth", "--format", "collection-json", path]);
    assert_eq!(status, ExitCode::SUCCESS, "{error}");
    assert!(collection.ends_with('\n'));
    assert_eq!(
        serde_json::from_str::<Value>(&collection).unwrap()["schema"],
        "repotoire.docs_collection.v1"
    );
    let (status, version, error) = invoke(&["--version"]);
    assert_eq!(status, ExitCode::SUCCESS, "{error}");
    assert_eq!(
        version,
        format!("repotoire {}\n", env!("CARGO_PKG_VERSION"))
    );
    let (status, alias, error) = invoke(&["-V"]);
    assert_eq!(status, ExitCode::SUCCESS, "{error}");
    assert_eq!(alias, version);
}

#[test]
fn flags_usage_and_output_failures_never_report_success() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("README.md"), "# Guide\n").unwrap();
    for flag in ["--coverage-input", "--witness-run", "--witness-state"] {
        let (status, output, error) =
            invoke(&["docs-truth", flag, "value", root.path().to_str().unwrap()]);
        assert_eq!(status, ExitCode::from(2));
        assert!(output.is_empty());
        assert!(error.contains("unavailable in this checker package"));
    }
    let (status, _, error) = invoke(&["docs-truth", "--unknown"]);
    assert_eq!(status, ExitCode::from(64));
    assert!(error.starts_with("usage:"));
    let (status, _, error) = invoke(&["context"]);
    assert_eq!(status, ExitCode::from(64));
    assert!(error.starts_with("usage:"));
    let (status, _, error) = invoke(&["--version", "--format", "json"]);
    assert_eq!(status, ExitCode::from(64));
    assert!(error.starts_with("usage:"));

    let out_is_directory = root.path().join("output");
    std::fs::create_dir(&out_is_directory).unwrap();
    let (status, output, error) = invoke(&[
        "docs-truth",
        "--out",
        out_is_directory.to_str().unwrap(),
        root.path().to_str().unwrap(),
    ]);
    assert_eq!(status, ExitCode::from(2));
    assert!(output.is_empty());
    assert!(error.contains("write"));

    let args = vec![
        "repotoire".to_string(),
        "docs-truth".to_string(),
        root.path().display().to_string(),
    ];
    let mut stdin = Cursor::new(Vec::<u8>::new());
    let mut stdout = FailWriter;
    let mut stderr = Vec::new();
    let status = cli::run(
        &args,
        &mut CliIo {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    assert_eq!(status, ExitCode::from(2));
    assert!(String::from_utf8(stderr)
        .unwrap()
        .contains("write docs-truth report failed"));

    let mut stdout = FailWriter;
    let mut stderr = Vec::new();
    let args = vec!["repotoire".to_string(), "--version".to_string()];
    let status = cli::run(
        &args,
        &mut CliIo {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    assert_eq!(status, ExitCode::from(2));

    for flag in ["--help", "--version"] {
        let args = vec!["repotoire".to_string(), flag.to_string()];
        let mut stdout = FlushFailWriter;
        let mut stderr = Vec::new();
        let status = cli::run(
            &args,
            &mut CliIo {
                stdin: &mut stdin,
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
        );
        assert_eq!(status, ExitCode::from(2), "{flag}");
    }
}

struct FailWriter;
impl Write for FailWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture output failure",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FlushFailWriter;
impl Write for FlushFailWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture flush failure",
        ))
    }
}

#[test]
fn collection_limit_is_distinct_and_never_publishes_partial_output() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("large.md"),
        vec![b'x'; 4 * 1024 * 1024 + 1],
    )
    .unwrap();
    let (status, output, error) = invoke(&[
        "docs-truth",
        "--format",
        "collection-json",
        root.path().to_str().unwrap(),
    ]);
    assert_eq!(status, ExitCode::from(78));
    assert!(output.is_empty());
    assert!(error.contains("documentation collection limit"));
}

#[test]
fn committed_source_change_and_cosmetic_doc_refresh_do_not_verify_false_prose() {
    let root = git_fixture();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(
        root.path().join("src/service.ts"),
        "export function serve() { return 'ok'; }\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("README.md"),
        "# API Contract\n\nRepotoire contract: `src/service.ts#serve` returns `'ok'`.\n",
    )
    .unwrap();
    commit(root.path());
    let fresh = json(root.path());
    assert_eq!(fresh["scorecard"]["drifts"], 0);
    assert!(fresh["evidence"]["claim_verifications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["status"] == "verified"));

    std::fs::write(
        root.path().join("src/service.ts"),
        "export function serve() { return 'changed'; }\n",
    )
    .unwrap();
    commit(root.path());
    let changed = json(root.path());
    assert!(changed["scorecard"]["drifts"].as_u64().unwrap() > 0);
    assert!(!changed["evidence"]["claim_verifications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["status"] == "verified"
            && row["summary"].as_str().unwrap_or("").contains("serve")));

    std::fs::write(root.path().join("README.md"), "# API Contract\n\nRepotoire contract: `src/service.ts#serve` returns `'ok'`.\n\nOwner: docs team.\n").unwrap();
    commit(root.path());
    let cosmetic = json(root.path());
    assert!(cosmetic["scorecard"]["drifts"].as_u64().unwrap() > 0);
}

#[test]
fn missing_and_ambiguous_references_are_explained_without_positive_proof() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(
        root.path().join("src/ambiguous.ts"),
        "export function same() { return 1; }\nexport function same() { return 2; }\n",
    )
    .unwrap();
    std::fs::write(root.path().join("README.md"), "# API Contract\n\nRepotoire contract: `src/missing.ts#gone` returns `1`.\nRepotoire contract: `src/ambiguous.ts#same` returns `1`.\nThe generic `src/absent.ts#nope` reference is not proof.\n").unwrap();
    let report = json(root.path());
    let diagnostics = serde_json::to_string(&report["diagnostics"]).unwrap();
    assert!(diagnostics.contains("contract_source_read_failed"));
    assert!(diagnostics.contains("missing.ts"));
    assert!(
        diagnostics.contains("ambiguous") || diagnostics.contains("multiple"),
        "{diagnostics}"
    );
    assert_eq!(report["scorecard"]["drifts"], 0);
    let generic_claim = report["doc_decode"]["graphs"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| {
            node["title"]
                .as_str()
                .unwrap_or("")
                .contains("src/absent.ts#nope")
        })
        .expect("generic reference is decoded as a claim");
    let claim_id = generic_claim["node_id"].as_str().unwrap();
    assert!(report["evidence"]["claim_verifications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["claim_id"] == claim_id && row["status"] == "unverified"));
}

#[test]
fn ignore_exclusions_and_explicit_document_errors_are_visible() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/hidden.md"), "# Hidden\n").unwrap();
    std::fs::write(root.path().join(".repotoireignore"), "docs/hidden.md\n").unwrap();
    let report = json(root.path());
    assert!(serde_json::to_string(&report["diagnostics"])
        .unwrap()
        .contains("document_excluded"));
    std::fs::write(
        root.path().join(".repotoire-sources.toml"),
        "[[document_source]]\npath = 'docs'\nformat = 'markdown'\n",
    )
    .unwrap();
    let error = docs_truth::build_report(root.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("document_source path `docs`"), "{error}");
}

#[test]
fn an_existing_outside_root_document_is_excluded() {
    let container = tempfile::tempdir().unwrap();
    let root = container.path().join("repository");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("README.md"), "# In root\n").unwrap();
    std::fs::write(container.path().join("outside.md"), "# Outside\n").unwrap();
    std::fs::write(
        root.join(".repotoire-sources.toml"),
        "[[document_source]]\npath = '../outside.md'\nformat = 'markdown'\n",
    )
    .unwrap();
    let report = json(&root);
    assert_eq!(report["scorecard"]["markdown_files"], 1);
    assert!(!report["doc_decode"]["graphs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|graph| graph["file"] == "../outside.md"));
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["kind"] == "document_excluded"
            && row["file"] == "../outside.md"
            && row["message"]
                .as_str()
                .unwrap_or("")
                .contains("outside repository root")));
}

#[cfg(unix)]
#[test]
fn directory_symlink_outside_root_is_not_admitted() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.md"), "# Outside\n").unwrap();
    symlink(outside.path(), root.path().join("docs-link")).unwrap();
    let report = json(root.path());
    assert_eq!(report["scorecard"]["markdown_files"], 0);
}
