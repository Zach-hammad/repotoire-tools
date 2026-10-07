//! The existing `docs-truth` command, isolated for the checker package.
use crate::docs_truth::{self, DocsTruthError, DocsTruthOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str =
    "repotoire docs-truth [--format json|markdown|collection-json] [--out <path>] [<path>]";

pub struct CliIo<'a> {
    pub stdin: &'a mut dyn Read,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

pub fn run_os() -> ExitCode {
    let args = std::env::args().collect::<Vec<_>>();
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let mut io = CliIo {
        stdin: &mut stdin,
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    run(&args, &mut io)
}

pub fn run(args: &[String], io: &mut CliIo<'_>) -> ExitCode {
    match args.get(1).map(String::as_str) {
        Some("docs-truth" | "docs_truth") => run_docs_truth(&args[2..], io),
        Some("--version" | "-V") => {
            if args.len() != 2 {
                return usage_err(io, "repotoire --version");
            }
            if writeln!(io.stdout, "repotoire {}", env!("CARGO_PKG_VERSION"))
                .and_then(|()| io.stdout.flush())
                .is_err()
            {
                output_error(io, "write version failed")
            } else {
                ExitCode::SUCCESS
            }
        }
        Some("--help" | "-h") => {
            if writeln!(io.stdout, "{USAGE}")
                .and_then(|()| io.stdout.flush())
                .is_ok()
            {
                ExitCode::SUCCESS
            } else {
                output_error(io, "write help failed")
            }
        }
        _ => usage_err(io, USAGE),
    }
}

fn usage_err(io: &mut CliIo<'_>, message: &str) -> ExitCode {
    let _ = writeln!(io.stderr, "usage: {message}");
    ExitCode::from(64)
}

fn output_error(io: &mut CliIo<'_>, message: &str) -> ExitCode {
    let _ = writeln!(io.stderr, "error: {message}");
    ExitCode::from(2)
}

fn run_docs_truth(rest: &[String], io: &mut CliIo<'_>) -> ExitCode {
    let mut format = "markdown";
    let mut out_path = None::<&str>;
    let mut path = ".";
    let mut saw_path = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--format" => {
                i += 1;
                let Some(value) = rest.get(i) else {
                    return usage_err(io, USAGE);
                };
                if !["json", "markdown", "collection-json"].contains(&value.as_str()) {
                    return usage_err(io, USAGE);
                }
                format = value;
            }
            "--out" => {
                i += 1;
                let Some(value) = rest.get(i) else {
                    return usage_err(io, USAGE);
                };
                if out_path.replace(value).is_some() {
                    return usage_err(io, USAGE);
                }
            }
            "--coverage-input" | "--witness-run" | "--witness-state" => {
                return output_error(
                    io,
                    "native coverage and runtime Witness are unavailable in this checker package",
                );
            }
            value if value.starts_with('-') => return usage_err(io, USAGE),
            value => {
                if saw_path {
                    return usage_err(io, USAGE);
                }
                path = value;
                saw_path = true;
            }
        }
        i += 1;
    }

    let root = Path::new(path);
    let output = if format == "collection-json" {
        match docs_truth::build_collection_json(root, DocsTruthOptions::default()) {
            Ok(output) => output,
            Err(error) => return report_error(io, error),
        }
    } else {
        let report = match docs_truth::build_report(root) {
            Ok(report) => report,
            Err(error) => return report_error(io, error),
        };
        if format == "json" {
            match serde_json::to_vec(&report) {
                Ok(mut json) => {
                    json.push(b'\n');
                    json
                }
                Err(error) => {
                    return output_error(
                        io,
                        &format!("failed to serialize docs-truth report: {error}"),
                    );
                }
            }
        } else {
            let mut markdown = docs_truth::render_markdown(&report).into_bytes();
            if !markdown.ends_with(b"\n") {
                markdown.push(b'\n');
            }
            markdown
        }
    };

    if let Some(out_path) = out_path {
        if let Err(error) = write_report_out_path(out_path, &output) {
            return output_error(io, &error);
        }
    }
    if let Err(error) = io
        .stdout
        .write_all(&output)
        .and_then(|()| io.stdout.flush())
    {
        return output_error(io, &format!("write docs-truth report failed: {error}"));
    }
    ExitCode::SUCCESS
}

fn report_error(io: &mut CliIo<'_>, error: DocsTruthError) -> ExitCode {
    let code = if matches!(error, DocsTruthError::CollectionLimit(_)) {
        78
    } else {
        2
    };
    let _ = writeln!(io.stderr, "error: {error}");
    ExitCode::from(code)
}

fn write_report_out_path(out_path: &str, bytes: &[u8]) -> Result<(), String> {
    let out_path = Path::new(out_path);
    if let Some(parent) = out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {} failed: {error}", parent.display()))?;
    }
    std::fs::write(out_path, bytes)
        .map_err(|error| format!("write {} failed: {error}", out_path.display()))
}
