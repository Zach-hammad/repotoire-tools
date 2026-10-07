//! Env-gated diagnostic dump surface for the consumer-call-site walk
//! (`collect_consumer_call_site_pressure` in `compiler_pressure.rs`; G1.9
//! Task S0). Three prior arcs (M0-A/J, M0-D) have each hand-rolled
//! throwaway instrumentation of this exact walk to answer "what did the
//! BFS actually see"; this module commits it ONCE as a committed,
//! env-gated diagnostic surface instead of re-building it a fourth time.
//!
//! Three independently-gated JSONL sinks, each read from its own env var:
//! - `G19_ANCHOR_DUMP=<path>` — one row per eligible-callable `Calls`
//!   IN-edge, with every call-argument anchor decoded for that call site
//!   (`SpanView::call_argument_anchors_from_in`).
//! - `G19_PATH_DUMP=<path>` — one row per eligible callable: its
//!   seed→callable BFS parent path (node kind/name, edge kind, the
//!   RECORDED `TypeRefPosition`, depth — one entry per hop).
//! - `G19_ROUTE_DUMP=<path>` — one row per `ConsumerCallSite` row the walk
//!   actually emits, tagged with which of the three emission branches
//!   (§7 fork (a) on `collect_consumer_call_site_pressure`'s doc comment)
//!   produced it.
//!
//! All three are OFF by default (env unset). `WalkDumps::from_env` reads
//! each var ONCE per walk invocation; every `record_*` method short-
//! circuits on a cheap `is_some()` check when its dump is disabled, and
//! callers in `compiler_pressure.rs` skip constructing the (non-trivial)
//! arguments in the first place when disabled — see each call site. With
//! every var unset, NO file is ever created and
//! `collect_consumer_call_site_pressure`'s return value is byte-identical
//! to before this module existed. The original regression was
//! `consumer_call_site_walk.rs::no_dump_env_set_creates_no_dump_files_and_pins_ky_rows`;
//! that historical test is no longer part of the maintained suite.
//! (This is a SEPARATE byte-identity claim from the plan's Global
//! Constraints' `G19_ALIAS_MEMBER_CHAIN`/`G110_PROBE_MEMBER_ROUTE`
//! consumption-gate byte-identity, proven at M0-V0/MR Pass A/B for S2/D2
//! — those are different env vars gating different code.)
//!
//! Rows are buffered per walk invocation and SORTED before being appended
//! (JSONL, one record per line) — HashMap iteration order has produced
//! nondeterministic dumps before in this project (the J1b lesson);
//! buffering + sorting here removes that hazard independent of whatever
//! order the walk itself produces rows/edges/callables in. Writes are
//! best-effort: an IO failure is logged to stderr and never propagated —
//! this is a diagnostic surface, never a correctness dependency of the
//! walk's own return value.
//!
//! Output is limited to 8 MiB per destination file and 64 KiB per complete
//! JSONL row, including its newline. The same writer owns the separability
//! dump in `compiler_pressure.rs`. Cooperating writers take a nonblocking
//! file lock before checking the remaining budget. A full file, oversized
//! row, competing writer, or I/O error stops that append with a diagnostic;
//! it never changes analysis results. Existing files are never truncated.
//! These limits bound serialized output, not the walk's buffered graph data.
//!
//! ## Consumer contract (M0 / D1)
//!
//! - **The file is a concatenation of per-invocation batches, NOT a
//!   globally sorted file.** `collect_compiler_pressure` runs once per
//!   analyzed decl, and each invocation of the walk appends ONE
//!   independently-sorted batch to each enabled dump. A run analyzing
//!   many decls therefore produces sorted-batch × N; the same callable
//!   can appear in multiple batches (once per analyzed decl whose
//!   closure reaches it) — consumers must dedup.
//! - **Appends are cross-run too.** The file is opened in append mode
//!   and never truncated by this module; a consumer must delete/clear
//!   the dump file before each fresh run or it will read cross-run
//!   contamination.
//!   Use a fresh destination for each measurement and reject runs reporting
//!   a dump failure: a bounded diagnostic file is not a completeness oracle.
//! - **An enabled dump always creates its file at flush time, even when
//!   the batch is empty** — so "the walk ran and found nothing" (file
//!   exists, zero rows) is distinguishable from "the dump was never
//!   enabled" (no file).
//! - **`route_matches_eligibility` (PATH records).** A PATH record's
//!   `path` hops are the FIRST-ARRIVAL BFS route, while its top-level
//!   `depth` is the eligibility depth (`mark_eligible`'s min-depth
//!   winner); these can diverge (Contains expansion enqueues children at
//!   the container's SAME depth, so queue depth is non-monotonic and a
//!   callable can be first-visited by a non-eligibility edge). The flag
//!   is computed at the hook site in `compiler_pressure.rs` against the
//!   walk's ACTUAL admission outcome, not edge shape: `true` means the
//!   recorded route ends at the eligibility depth via a real eligibility
//!   route — `TypeRef` at recorded `ParamAnnotation` position, or a
//!   `Contains` membership the G1.7 guard pass actually ADMITTED — and
//!   can be read as the eligibility justification. `false` means the hop
//!   list shows a DIFFERENT route than the one that made the callable
//!   eligible (including a Contains arrival whose exact membership the
//!   guard REJECTED, even though the callable is eligible via another
//!   edge at the same depth) — trust the record's `depth`, treat the
//!   hops as "one way the BFS reached it", and do NOT present them as
//!   why it qualified.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::csr::CallArgumentAnchorView;
use crate::ids::NodeId;
use crate::schema::{EdgeKind, NodeKind, TypeRefPosition};
use crate::spans::Span;

const ENV_ANCHOR_DUMP: &str = "G19_ANCHOR_DUMP";
const ENV_PATH_DUMP: &str = "G19_PATH_DUMP";
const ENV_ROUTE_DUMP: &str = "G19_ROUTE_DUMP";
const MAX_DUMP_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DUMP_ROW_BYTES: usize = 64 * 1024;

/// JSON-friendly `[start, end)` byte span — `Span`'s own `Serialize` impl
/// encodes `{start, length}`, which is correct but less immediately
/// readable for an ad hoc diagnostic dump than an explicit end offset.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct SpanRecord {
    start: u32,
    end: u32,
}

impl From<Span> for SpanRecord {
    fn from(span: Span) -> Self {
        SpanRecord {
            start: span.start(),
            end: span.end(),
        }
    }
}

/// JSON mirror of `CallArgumentAnchorView` (internally tagged on
/// `anchor_kind` so both variants read as plain JSON objects).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "anchor_kind")]
enum AnchorRecord {
    CallbackHead {
        arg_index: u16,
        span: SpanRecord,
    },
    ObjectKey {
        arg_index: u16,
        name: String,
        path: String,
        span: SpanRecord,
    },
}

impl From<&CallArgumentAnchorView> for AnchorRecord {
    fn from(view: &CallArgumentAnchorView) -> Self {
        match view {
            CallArgumentAnchorView::CallbackHead { arg_index, span } => {
                AnchorRecord::CallbackHead {
                    arg_index: *arg_index,
                    span: (*span).into(),
                }
            }
            CallArgumentAnchorView::ObjectKey {
                arg_index,
                name,
                span,
                path,
            } => AnchorRecord::ObjectKey {
                arg_index: *arg_index,
                name: name.clone(),
                path: path.clone(),
                span: (*span).into(),
            },
        }
    }
}

/// One `G19_ANCHOR_DUMP` row: one eligible-callable `Calls` IN-edge (a
/// single call site reaching that callable), with every anchor decoded
/// for that call — regardless of whether the walk's own chain-key match
/// (`collect_consumer_call_site_pressure`'s §7 fork (a)) ended up emitting
/// a `ConsumerCallSite` row from any of them.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct AnchorDumpRow {
    callable_id: u32,
    callable_kind: String,
    callable_name: String,
    call_site_file: String,
    call_site_line: u32,
    call_span: SpanRecord,
    anchors: Vec<AnchorRecord>,
}

/// One hop of a `G19_PATH_DUMP` row's seed→callable path, as supplied by
/// the caller (`compiler_pressure.rs` owns the BFS parent-tracking state;
/// this module only serializes it). `edge_kind`/`position`/`depth`
/// describe the edge that reached THIS hop's node; the seed hop carries
/// `edge_kind: None`, `position: None`, `depth: 0`.
pub(crate) struct PathHopInput {
    pub(crate) node_id: NodeId,
    pub(crate) node_kind: NodeKind,
    pub(crate) node_name: String,
    pub(crate) edge_kind: Option<EdgeKind>,
    pub(crate) position: Option<TypeRefPosition>,
    pub(crate) depth: u8,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct PathHopRecord {
    node_id: u32,
    node_kind: String,
    node_name: String,
    edge_kind: Option<String>,
    position: Option<String>,
    depth: u8,
}

impl From<PathHopInput> for PathHopRecord {
    fn from(hop: PathHopInput) -> Self {
        PathHopRecord {
            node_id: hop.node_id.raw(),
            node_kind: format!("{:?}", hop.node_kind),
            node_name: hop.node_name,
            edge_kind: hop.edge_kind.map(|k| format!("{k:?}")),
            position: hop.position.map(|p| format!("{p:?}")),
            depth: hop.depth,
        }
    }
}

/// One `G19_PATH_DUMP` row: one eligible callable and its full
/// seed→callable path.
///
/// `route_matches_eligibility` self-flags the first-arrival-vs-eligibility
/// divergence (see the module doc's consumer contract). It is computed by
/// the caller (`compiler_pressure.rs::arrival_route_matches_eligibility`)
/// against the walk's ACTUAL admission outcome, never re-derived here
/// from edge shape: `true` means the recorded terminal hop reaches the
/// callable at the record's own eligibility `depth` via a real
/// eligibility route — a `TypeRef` at recorded `ParamAnnotation`
/// position, or a `Contains` membership the G1.7 admission pass actually
/// ADMITTED. `false` means the recorded hops show a DIFFERENT route than
/// the one `mark_eligible` admitted (possible because `parent_of` is
/// first-arrival-wins while eligibility is min-depth-wins, the Contains
/// expansion enqueues children at the container's SAME depth making
/// queue depth non-monotonic, and the guard can REJECT the very
/// membership the arrival displays while the callable is independently
/// eligible at the same depth).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct PathDumpRow {
    callable_id: u32,
    callable_kind: String,
    callable_name: String,
    depth: u8,
    route_matches_eligibility: bool,
    path: Vec<PathHopRecord>,
}

/// Which of the three `ConsumerCallSite` emission branches (§7 fork (a) on
/// `collect_consumer_call_site_pressure`'s doc comment) produced a given
/// row.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteBranch {
    CallHead,
    ObjectKey,
    CallbackHead,
}

/// One `G19_ROUTE_DUMP` row: one emitted `ConsumerCallSite` row, tagged
/// with the branch that produced it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct RouteDumpRow {
    branch: RouteBranch,
    callable_id: u32,
    callable_kind: String,
    callable_name: String,
    depth: u8,
    chain: String,
    file: String,
    line: u32,
}

/// A callable's identity, threaded through every `record_*` hook — every
/// row this module writes is keyed on some eligible callable, so this
/// avoids repeating the same `(NodeId, NodeKind, &str)` triple as three
/// separate parameters at every call site (and keeps each `record_*`
/// method under clippy's `too_many_arguments` threshold honestly, rather
/// than by `#[allow]`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallableRef<'a> {
    pub(crate) id: NodeId,
    pub(crate) kind: NodeKind,
    pub(crate) name: &'a str,
}

/// Env-gated, buffered JSONL dump sink for one
/// `collect_consumer_call_site_pressure` invocation. See the module doc
/// comment for the full contract (env vars, byte-identity when unset,
/// determinism).
pub(crate) struct WalkDumps {
    anchor_path: Option<PathBuf>,
    path_path: Option<PathBuf>,
    route_path: Option<PathBuf>,
    anchor_rows: Vec<AnchorDumpRow>,
    path_rows: Vec<PathDumpRow>,
    route_rows: Vec<RouteDumpRow>,
}

impl WalkDumps {
    /// Reads `G19_ANCHOR_DUMP`/`G19_PATH_DUMP`/`G19_ROUTE_DUMP` once.
    /// Every field is `None` (fully no-op) when its var is unset — no
    /// directory is touched, no file is opened, until `flush()` and only
    /// for whichever dumps are enabled.
    pub(crate) fn from_env() -> Self {
        WalkDumps {
            anchor_path: std::env::var_os(ENV_ANCHOR_DUMP).map(PathBuf::from),
            path_path: std::env::var_os(ENV_PATH_DUMP).map(PathBuf::from),
            route_path: std::env::var_os(ENV_ROUTE_DUMP).map(PathBuf::from),
            anchor_rows: Vec::new(),
            path_rows: Vec::new(),
            route_rows: Vec::new(),
        }
    }

    pub(crate) fn anchor_enabled(&self) -> bool {
        self.anchor_path.is_some()
    }

    pub(crate) fn path_enabled(&self) -> bool {
        self.path_path.is_some()
    }

    pub(crate) fn route_enabled(&self) -> bool {
        self.route_path.is_some()
    }

    /// Records one `G19_ANCHOR_DUMP` row. No-op when the dump is
    /// disabled — callers should still prefer checking `anchor_enabled()`
    /// before decoding anchors at all, since that decode is the
    /// expensive part this hook exists to make conditional.
    pub(crate) fn record_anchor_edge(
        &mut self,
        callable: CallableRef<'_>,
        call_site_file: &str,
        call_site_line: u32,
        call_span: Span,
        anchors: &[CallArgumentAnchorView],
    ) {
        if !self.anchor_enabled() {
            return;
        }
        let mut anchor_records: Vec<AnchorRecord> =
            anchors.iter().map(AnchorRecord::from).collect();
        anchor_records.sort();
        self.anchor_rows.push(AnchorDumpRow {
            callable_id: callable.id.raw(),
            callable_kind: format!("{:?}", callable.kind),
            callable_name: callable.name.to_string(),
            call_site_file: call_site_file.to_string(),
            call_site_line,
            call_span: call_span.into(),
            anchors: anchor_records,
        });
    }

    /// Records one `G19_PATH_DUMP` row. No-op when the dump is disabled.
    ///
    /// `depth` is the callable's ELIGIBILITY depth (`mark_eligible`'s
    /// min-depth); `hops` is the FIRST-ARRIVAL route; the two can
    /// legitimately describe different routes.
    /// `route_matches_eligibility` is computed BY THE CALLER
    /// (`compiler_pressure.rs::arrival_route_matches_eligibility`, which
    /// sits next to the eligibility rules and checks the G1.7 guard's
    /// actual admission outcome) — this module is pure serialization and
    /// holds no eligibility knowledge, so the flag can never silently
    /// drift from the walk's admission rules. See `PathDumpRow`.
    pub(crate) fn record_path(
        &mut self,
        callable: CallableRef<'_>,
        depth: u8,
        route_matches_eligibility: bool,
        hops: Vec<PathHopInput>,
    ) {
        if !self.path_enabled() {
            return;
        }
        self.path_rows.push(PathDumpRow {
            callable_id: callable.id.raw(),
            callable_kind: format!("{:?}", callable.kind),
            callable_name: callable.name.to_string(),
            depth,
            route_matches_eligibility,
            path: hops.into_iter().map(PathHopRecord::from).collect(),
        });
    }

    /// Records one `G19_ROUTE_DUMP` row. No-op when the dump is disabled.
    pub(crate) fn record_route(
        &mut self,
        branch: RouteBranch,
        callable: CallableRef<'_>,
        depth: u8,
        chain: &str,
        file: &str,
        line: u32,
    ) {
        if !self.route_enabled() {
            return;
        }
        self.route_rows.push(RouteDumpRow {
            branch,
            callable_id: callable.id.raw(),
            callable_kind: format!("{:?}", callable.kind),
            callable_name: callable.name.to_string(),
            depth,
            chain: chain.to_string(),
            file: file.to_string(),
            line,
        });
    }

    /// Sorts each buffered batch and appends it (JSONL) to its configured
    /// path, creating the file (and its parent directory) on first write.
    /// A dump left unset here is a strict no-op: no path to write, no
    /// file touched. Must be called exactly once, at every return point
    /// of the walk that constructed this `WalkDumps` (consumes `self`).
    pub(crate) fn flush(self) {
        write_batch(
            self.anchor_path.as_deref(),
            self.anchor_rows,
            ENV_ANCHOR_DUMP,
        );
        write_batch(self.path_path.as_deref(), self.path_rows, ENV_PATH_DUMP);
        write_batch(self.route_path.as_deref(), self.route_rows, ENV_ROUTE_DUMP);
    }
}

fn write_batch<T: Serialize + Ord>(path: Option<&Path>, mut rows: Vec<T>, env_name: &str) {
    let Some(path) = path else {
        return;
    };
    // No empty-batch early return: an ENABLED dump always creates its
    // file (append-mode open touches it even with zero rows), so an M0
    // consumer can distinguish "the walk ran and found nothing" (file
    // exists, empty) from "the dump was never enabled" (no file).
    rows.sort();
    if let Err(err) = append_jsonl(path, &rows) {
        // Diagnostic reporting must remain best-effort even when stderr fails.
        let _ = writeln!(
            io::stderr().lock(),
            "{env_name}: failed to write {}: {err}",
            path.display()
        );
    }
}

/// Append complete rows within the shared diagnostic budget. The lock
/// coordinates this producer's writers; unrelated external writers must
/// not share the destination while a measurement is running.
pub(crate) fn append_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    file.try_lock().map_err(io::Error::from)?;
    let mut remaining = MAX_DUMP_FILE_BYTES.saturating_sub(file.metadata()?.len());
    for row in rows {
        let mut line = BoundedJsonLine(Vec::new());
        serde_json::to_writer(&mut line, row).map_err(io::Error::other)?;
        line.0.push(b'\n');
        if line.0.len() as u64 > remaining {
            return Err(io::Error::other(
                "diagnostic dump reached its 8 MiB file limit",
            ));
        }
        file.write_all(&line.0)?;
        remaining -= line.0.len() as u64;
    }
    Ok(())
}

/// Reserve the newline before serialization, so an oversized record is
/// rejected in memory before any part of that record reaches the file.
struct BoundedJsonLine(Vec<u8>);

impl Write for BoundedJsonLine {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DUMP_ROW_BYTES - 1 - self.0.len() {
            return Err(io::Error::other(
                "diagnostic dump row exceeds its 64 KiB limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod contracts {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "repotoire-walk-dump-contract-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove only this test's unique fixture");
        }
    }

    // What: disabled sinks touch no files; enabled sinks create empty files
    // and append independently sorted batches of complete JSON rows.
    // Why: absent and empty diagnostics have different meanings for consumers.
    // Verify: real filesystem contents and literal JSONL, including a later batch.
    // Detects: unconditional output, empty-batch omission, and unsorted appends.
    #[test]
    fn diagnostic_batches_preserve_disabled_empty_and_sorted_behavior() {
        let fixture = Fixture::new();
        let mut disabled = WalkDumps {
            anchor_path: None,
            path_path: None,
            route_path: None,
            anchor_rows: Vec::new(),
            path_rows: Vec::new(),
            route_rows: Vec::new(),
        };
        disabled.record_route(
            RouteBranch::CallHead,
            CallableRef {
                id: NodeId::from_raw(1),
                kind: NodeKind::Function,
                name: "call",
            },
            1,
            "arg",
            "fixture.ts",
            4,
        );
        assert!(disabled.route_rows.is_empty());
        disabled.flush();
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);

        let empty = fixture.0.join("nested/empty.jsonl");
        write_batch(Some(&empty), Vec::<u8>::new(), "fixture");
        assert_eq!(fs::read(&empty).unwrap(), b"");
        let sorted = fixture.0.join("sorted.jsonl");
        write_batch(Some(&sorted), vec!["z", "a"], "fixture");
        write_batch(Some(&sorted), vec!["b"], "fixture");
        assert_eq!(fs::read(&sorted).unwrap(), b"\"a\"\n\"z\"\n\"b\"\n");
    }

    // What: repeated appends stop at 8 MiB without truncating existing data
    // or writing the prefix of a row that does not fit.
    // Why: diagnostics must not consume unlimited host disk across runs.
    // Verify: a real file four bytes below the boundary admits literal rows
    // "1\n" and "2\n", rejects "22\n" and any later row, and keeps its prefix.
    // Detects: per-call rather than per-file limits, off-by-one, and partial rows.
    #[test]
    fn diagnostic_file_budget_applies_across_appends() {
        let fixture = Fixture::new();
        let path = fixture.0.join("budget.jsonl");
        let prefix = b"0\n".repeat(4_194_302);
        fs::write(&path, &prefix).unwrap();
        assert!(append_jsonl(&path, &[1, 22]).is_err());
        append_jsonl(&path, &[2]).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(before.len(), 8_388_608);
        assert_eq!(&before[..prefix.len()], &prefix);
        assert_eq!(&before[prefix.len()..], b"1\n2\n");
        assert!(append_jsonl(&path, &[3]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    // What: a complete serialized row, including its newline, is at most 64 KiB.
    // Why: rejecting a large row after streaming it would leave invalid JSONL.
    // Verify: real output accepts the exact byte boundary, rejects the next byte,
    // and parses the surviving row back to its independently supplied input.
    // Detects: character-count limits, missing newline budget, and streamed fragments.
    #[test]
    fn diagnostic_row_budget_rejects_before_file_write() {
        let fixture = Fixture::new();
        let path = fixture.0.join("row.jsonl");
        let row = "a".repeat(65_533);
        append_jsonl(&path, &[&row]).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(before.len(), 65_536);
        assert_eq!(serde_json::from_slice::<String>(&before).unwrap(), row);
        assert!(append_jsonl(&path, &["a".repeat(65_534)]).is_err());
        assert!(append_jsonl(&path, &["é".repeat(32_767)]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    // What: another cooperating writer causes immediate diagnostic refusal.
    // Why: diagnostic contention must neither stall analysis nor race the file budget.
    // Verify: a real lock on an independently opened handle refuses an append,
    // preserves the file, and permits the same append after the lock is dropped.
    // Detects: missing/non-shared locks and blocking acquisition.
    #[test]
    fn diagnostic_lock_contention_refuses_then_recovers() {
        let fixture = Fixture::new();
        let path = fixture.0.join("locked.jsonl");
        let owner = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        owner.try_lock().unwrap();
        assert_eq!(
            append_jsonl(&path, &[1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(fs::read(&path).unwrap(), b"");
        drop(owner);
        append_jsonl(&path, &[1]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"1\n");
    }
}
