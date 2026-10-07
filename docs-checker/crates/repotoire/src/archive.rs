//! Sibling source archive format (`.rpts`).
//!
//! A content-addressed blob store: every unique source file's bytes get one
//! entry, keyed by SHA-256. Paths live in the IR's strings arena, not here —
//! the IR provides path↔SHA mapping, the archive provides SHA↔bytes mapping.
//!
//! See spec §3.4 / §4 (in `docs/superpowers/specs/2026-05-17-source-spans-design.md`)
//! for the on-disk layout and full invariant list.

use crate::source_role::{CompleteSourceRoleIndex, SourceRole};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ARCHIVE_MAGIC: [u8; 4] = *b"RPTS";
pub const ARCHIVE_VERSION: u32 = 1;
pub const ARCHIVE_ENDIAN_CHECK: u32 = 0x0102_0304;
/// Size of the fixed-position header at the start of every archive.
pub const ARCHIVE_HEADER_SIZE: usize = 16;
/// Size of one blob-index entry: 32-byte SHA + 8-byte offset + 8-byte length.
pub const BLOB_INDEX_ENTRY_SIZE: usize = 48;

/// Structural validation errors raised by `SourceArchive::view_from_bytes`.
///
/// All checks run at view-open time so subsequent queries are infallible
/// (same v0 invariant as `CodeGraph::view_from_bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// Magic bytes don't match `RPTS`.
    BadMagic,
    /// Version field is something other than the supported value (currently 1).
    BadVersion(u32),
    /// Endian-check sentinel `0x0102_0304` read in the wrong byte order.
    BadEndian,
    /// Buffer is shorter than the 16-byte header.
    HeaderTooShort,
    /// Buffer doesn't have room for `header + blob_count × 48` bytes of index.
    BlobIndexMalformed,
    /// Blob index SHAs are not strictly ascending.
    BlobIndexNotSorted,
    /// A blob's `content_offset` points into the blob index region (i.e., is
    /// less than `HEADER_SIZE + blob_count × BLOB_INDEX_ENTRY_SIZE`).
    BlobOffsetInsideIndex { blob_index: usize },
    /// `content_offset + content_length` overflows `u64`.
    BlobOffsetOverflow { blob_index: usize },
    /// `content_offset + content_length` exceeds the archive's byte length.
    BlobExtendsBeyondArchive { blob_index: usize },
    /// First blob's `content_offset` doesn't equal `CONTENT_ARENA_START`
    /// (= HEADER_SIZE + blob_count × 48). Canonical packing requires the
    /// content arena to start immediately after the index.
    ContentArenaNotPacked,
    /// A blob's `content_offset` is not equal to the previous blob's end
    /// position — a gap exists in the content arena.
    ContentArenaHasGap { blob_index: usize },
    /// Same SHA appears twice in the blob index. Encoder dedupes; only
    /// hand-corrupted archives hit this.
    DuplicateSha { blob_index: usize },
    /// File has bytes after the last blob's end position. Canonical packing
    /// forbids trailing data (otherwise hidden bytes could ride along
    /// undetected).
    TrailingBytesAfterContentArena { trailing_bytes: usize },
}

/// Verification errors raised by the optional `verify_*` helpers (Task 22).
/// Defined here for shared use; the verification implementations land in
/// `verify_blob` / `verify_all` / `verify_pair` (Task 22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    BlobNotInArchive {
        sha256: [u8; 32],
    },
    BlobLengthMismatch {
        sha256: [u8; 32],
        expected: u64,
        actual: u64,
    },
    BlobContentHashMismatch {
        sha256: [u8; 32],
        computed: [u8; 32],
    },
    MetadataCountMismatch {
        metadata_files: usize,
        archive_blobs: usize,
    },
    /// Source metadata is absent on the graph; the caller asked verify_pair
    /// to check completeness but there's nothing to verify against.
    SourceMetadataMissing {
        file_node_id: u32,
    },
}

/// Owned form of a source archive — holds the byte buffer.
#[derive(Debug, Clone)]
pub struct OwnedSourceArchive {
    bytes: Arc<[u8]>,
}

impl OwnedSourceArchive {
    /// Wrap a Vec of bytes. Does NOT validate — callers go through
    /// `SourceArchive::view_from_bytes` for the full check.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::from(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Validate-and-borrow as a SourceArchive view. Panics if the owned
    /// bytes don't parse — by construction this only happens if `from_bytes`
    /// was called with externally-supplied bytes. Internal callers (Task 20
    /// freeze pipeline) construct via `encode_archive` which always produces
    /// valid output.
    pub fn as_view(&self) -> SourceArchive<'_> {
        SourceArchive::view_from_bytes(self.bytes.as_ref())
            .expect("OwnedSourceArchive bytes must always parse")
    }
}

/// Borrowed view over a validated source archive byte buffer.
///
/// All structural invariants are checked in `view_from_bytes`; subsequent
/// queries are infallible. `get(sha)` does binary search over the sorted
/// blob index for O(log N) lookup.
#[derive(Debug)]
pub struct SourceArchive<'a> {
    bytes: &'a [u8],
    blob_count: usize,
}

impl<'a> SourceArchive<'a> {
    /// Parse an archive byte buffer and enforce all spec §4 invariants.
    ///
    /// On success the returned view is structurally sound — `get` will not
    /// panic for any in-range query. On failure returns the specific
    /// `ArchiveError` variant identifying which invariant was violated.
    pub fn view_from_bytes(bytes: &'a [u8]) -> Result<Self, ArchiveError> {
        // Header validation.
        if bytes.len() < ARCHIVE_HEADER_SIZE {
            return Err(ArchiveError::HeaderTooShort);
        }
        if bytes[0..4] != ARCHIVE_MAGIC {
            return Err(ArchiveError::BadMagic);
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != ARCHIVE_VERSION {
            return Err(ArchiveError::BadVersion(version));
        }
        let endian = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if endian != ARCHIVE_ENDIAN_CHECK {
            return Err(ArchiveError::BadEndian);
        }
        let blob_count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;

        // Index length check.
        let content_arena_start = ARCHIVE_HEADER_SIZE + blob_count * BLOB_INDEX_ENTRY_SIZE;
        if bytes.len() < content_arena_start {
            return Err(ArchiveError::BlobIndexMalformed);
        }

        // Per-blob checks: sort/uniqueness, offset bounds, canonical packing.
        let mut last_sha: Option<[u8; 32]> = None;
        let mut expected_offset = content_arena_start as u64;
        for i in 0..blob_count {
            let base = ARCHIVE_HEADER_SIZE + i * BLOB_INDEX_ENTRY_SIZE;
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&bytes[base..base + 32]);
            let content_offset =
                u64::from_le_bytes(bytes[base + 32..base + 40].try_into().unwrap());
            let content_length =
                u64::from_le_bytes(bytes[base + 40..base + 48].try_into().unwrap());

            // Sorted-ascending + no duplicates.
            if let Some(prev) = last_sha {
                match sha.cmp(&prev) {
                    std::cmp::Ordering::Equal => {
                        return Err(ArchiveError::DuplicateSha { blob_index: i });
                    }
                    std::cmp::Ordering::Less => {
                        return Err(ArchiveError::BlobIndexNotSorted);
                    }
                    std::cmp::Ordering::Greater => {}
                }
            }
            last_sha = Some(sha);

            // Offset must point into the content arena, not the index.
            if content_offset < content_arena_start as u64 {
                return Err(ArchiveError::BlobOffsetInsideIndex { blob_index: i });
            }
            // Checked add — defends against malicious u64 inputs that would
            // overflow on the bounds check below.
            let blob_end = content_offset
                .checked_add(content_length)
                .ok_or(ArchiveError::BlobOffsetOverflow { blob_index: i })?;
            if blob_end > bytes.len() as u64 {
                return Err(ArchiveError::BlobExtendsBeyondArchive { blob_index: i });
            }

            // Canonical packing: first blob starts at content_arena_start,
            // subsequent blobs immediately after the previous one.
            if i == 0 && content_offset != content_arena_start as u64 {
                return Err(ArchiveError::ContentArenaNotPacked);
            }
            if i > 0 && content_offset != expected_offset {
                return Err(ArchiveError::ContentArenaHasGap { blob_index: i });
            }
            expected_offset = blob_end;
        }

        // After the loop, the content arena must end exactly at bytes.len() —
        // no trailing junk allowed. (Canonical layout: tightly packed.)
        if expected_offset != bytes.len() as u64 {
            return Err(ArchiveError::TrailingBytesAfterContentArena {
                trailing_bytes: (bytes.len() as u64 - expected_offset) as usize,
            });
        }

        Ok(Self { bytes, blob_count })
    }

    /// Number of unique blobs in the archive.
    pub fn blob_count(&self) -> usize {
        self.blob_count
    }

    /// Binary-search the blob index for a SHA-256 digest. Returns the blob's
    /// bytes if found, `None` otherwise. O(log N) lookups.
    pub fn get(&self, sha256: &[u8; 32]) -> Option<&'a [u8]> {
        let mut lo = 0usize;
        let mut hi = self.blob_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base = ARCHIVE_HEADER_SIZE + mid * BLOB_INDEX_ENTRY_SIZE;
            let mid_sha = &self.bytes[base..base + 32];
            match mid_sha.cmp(sha256.as_slice()) {
                std::cmp::Ordering::Equal => {
                    let content_offset =
                        u64::from_le_bytes(self.bytes[base + 32..base + 40].try_into().unwrap())
                            as usize;
                    let content_length =
                        u64::from_le_bytes(self.bytes[base + 40..base + 48].try_into().unwrap())
                            as usize;
                    return Some(&self.bytes[content_offset..content_offset + content_length]);
                }
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    // ---- Task 22: opt-in content verification ----

    /// Hash one blob's bytes and verify the result matches the SHA the blob
    /// index claims. Catches byte-level corruption that the structural
    /// invariants in `view_from_bytes` don't (a writer could ship valid index
    /// + corrupted content with the SHA-index entry untouched).
    ///
    /// Cost: O(blob_length). Cheap per-call but linear in content size.
    pub fn verify_blob(&self, sha256: &[u8; 32]) -> Result<(), VerifyError> {
        let bytes = self
            .get(sha256)
            .ok_or(VerifyError::BlobNotInArchive { sha256: *sha256 })?;
        let computed = crate::hash::sha256(bytes);
        if computed != *sha256 {
            return Err(VerifyError::BlobContentHashMismatch {
                sha256: *sha256,
                computed,
            });
        }
        Ok(())
    }

    /// Hash every blob in the archive and verify each matches its index SHA.
    /// Catches any byte-level corruption anywhere in the content arena.
    ///
    /// Cost: O(archive_content_size). Use for security-critical scenarios
    /// (untrusted IR from network, mutual distrust). Most callers want
    /// `verify_pair` for the cheap structural check instead.
    pub fn verify_all(&self) -> Result<(), VerifyError> {
        for i in 0..self.blob_count {
            let base = ARCHIVE_HEADER_SIZE + i * BLOB_INDEX_ENTRY_SIZE;
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&self.bytes[base..base + 32]);
            self.verify_blob(&sha)?;
        }
        Ok(())
    }
}

/// Cross-check IR's SOURCE_METADATA against the sibling archive — every
/// File node's expected SHA must appear in the archive AND the archive
/// blob's length must match SOURCE_METADATA's content_length.
///
/// Does NOT recompute SHAs — catches "mismatched pair" (the common case)
/// without paying the full re-hash cost. For byte-level content corruption
/// detection, use `SourceArchive::verify_all` separately.
///
/// Returns `VerifyError::SourceMetadataMissing` if the graph has File nodes
/// but no SOURCE_METADATA — the section is OPTIONAL per spec §2.6, so this
/// isn't a panic-worthy condition. Caller decides how to interpret.
pub fn verify_pair(
    view: &crate::csr::CodeGraph,
    archive: &SourceArchive,
) -> Result<(), VerifyError> {
    for file in view.nodes_of_kind(crate::schema::NodeKind::File) {
        let meta = view
            .source_metadata(file)
            .ok_or(VerifyError::SourceMetadataMissing {
                file_node_id: file.raw(),
            })?;
        let bytes = archive
            .get(&meta.sha256)
            .ok_or(VerifyError::BlobNotInArchive {
                sha256: meta.sha256,
            })?;
        if bytes.len() as u64 != meta.content_length {
            return Err(VerifyError::BlobLengthMismatch {
                sha256: meta.sha256,
                expected: meta.content_length,
                actual: bytes.len() as u64,
            });
        }
    }
    Ok(())
}

/// Load both halves of a paired freeze output from disk.
///
/// Convention: given `ir_path` like `repo.rptg`, looks for `repo.rpts` in
/// the same directory. Returns `(graph, Some(archive))` if found,
/// `(graph, None)` if the sibling doesn't exist. Other I/O errors propagate
/// (permission denied, unreadable file, etc.) — only "sibling NotFound" maps
/// to `None`.
///
/// Does NOT verify hashes — that's a separate opt-in via `verify_pair` /
/// `verify_blob` / `verify_all`.
pub fn open_paired(
    ir_path: &std::path::Path,
) -> Result<(crate::csr::OwnedGraph, Option<OwnedSourceArchive>), std::io::Error> {
    let ir_bytes = std::fs::read(ir_path)?;
    crate::csr::CodeGraph::view_from_bytes(&ir_bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid graph bytes in {}: {error:?}", ir_path.display()),
        )
    })?;
    let graph = crate::csr::OwnedGraph::from_bytes(ir_bytes);
    let archive_path = ir_path.with_extension("rpts");
    let archive = match std::fs::read(&archive_path) {
        Ok(bytes) => {
            SourceArchive::view_from_bytes(&bytes).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "invalid source archive bytes in {}: {error:?}",
                        archive_path.display()
                    ),
                )
            })?;
            Some(OwnedSourceArchive::from_bytes(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    Ok((graph, archive))
}

/// Encode a set of `(sha, content)` pairs into a canonical archive byte
/// buffer. Dedupes by SHA, sorts by SHA ascending, packs the content arena
/// tightly. The output always validates via `view_from_bytes`.
pub fn encode_archive(blobs: &[(&[u8; 32], &[u8])]) -> Vec<u8> {
    use std::collections::HashSet;

    // Dedup by SHA — first occurrence wins.
    let mut unique: Vec<(&[u8; 32], &[u8])> = Vec::with_capacity(blobs.len());
    {
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(blobs.len());
        for &(sha, content) in blobs {
            if seen.insert(*sha) {
                unique.push((sha, content));
            }
        }
    }
    // Sort by SHA ascending — canonical order. HashSet iteration was for dedup
    // only; the deterministic Vec sort is what the output depends on.
    unique.sort_by(|a, b| a.0.cmp(b.0));

    let blob_count = unique.len() as u32;
    let content_arena_start = ARCHIVE_HEADER_SIZE + (blob_count as usize) * BLOB_INDEX_ENTRY_SIZE;
    let total_content_len: usize = unique.iter().map(|(_, c)| c.len()).sum();
    let total_size = content_arena_start + total_content_len;
    let mut out = Vec::with_capacity(total_size);

    // Header.
    out.extend_from_slice(&ARCHIVE_MAGIC);
    out.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
    out.extend_from_slice(&ARCHIVE_ENDIAN_CHECK.to_le_bytes());
    out.extend_from_slice(&blob_count.to_le_bytes());

    // Blob index — offsets are absolute, monotonic, tightly packed.
    let mut cursor = content_arena_start as u64;
    for (sha, content) in unique.iter() {
        out.extend_from_slice(sha.as_slice());
        out.extend_from_slice(&cursor.to_le_bytes());
        out.extend_from_slice(&(content.len() as u64).to_le_bytes());
        cursor += content.len() as u64;
    }

    // Content arena — concatenated bytes in the same order as the index.
    for (_sha, content) in unique.iter() {
        out.extend_from_slice(content);
    }

    out
}

// ---- Task 21: SourceBundle ----

/// Verified source-byte lookup for graph-only bundles.
///
/// The lookup returns candidate bytes by graph-relative path. `SourceBundle`
/// validates the bytes against `SOURCE_METADATA` before exposing them to
/// renderers, so a stale or mismatched lookup fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLookupMetadata {
    pub sha256: [u8; 32],
    pub content_length: u64,
}

#[derive(Clone, Copy)]
pub struct SourceLookup<'a> {
    pairs: &'a [(String, Vec<u8>)],
    path_index: Option<&'a BTreeMap<String, usize>>,
    metadata: Option<&'a BTreeMap<String, SourceLookupMetadata>>,
}

#[derive(Clone, Copy)]
struct SourceLookupEntry<'a> {
    bytes: &'a [u8],
    metadata: Option<SourceLookupMetadata>,
}

impl<'a> SourceLookup<'a> {
    pub fn from_pairs(
        pairs: &'a [(String, Vec<u8>)],
        path_index: Option<&'a BTreeMap<String, usize>>,
        metadata: Option<&'a BTreeMap<String, SourceLookupMetadata>>,
    ) -> Self {
        Self {
            pairs,
            path_index,
            metadata,
        }
    }

    fn source_bytes_for_path(self, path: &str) -> Option<SourceLookupEntry<'a>> {
        let metadata = self
            .metadata
            .and_then(|metadata| metadata.get(path).copied());
        if let Some(index) = self.path_index {
            let pair_index = *index.get(path)?;
            let (_, bytes) = self.pairs.get(pair_index)?;
            return Some(SourceLookupEntry {
                bytes: bytes.as_slice(),
                metadata,
            });
        }
        self.pairs.iter().find_map(|(candidate, bytes)| {
            if candidate == path {
                Some(SourceLookupEntry {
                    bytes: bytes.as_slice(),
                    metadata,
                })
            } else {
                None
            }
        })
    }
}

/// Ergonomic wrapper bundling a `CodeGraph` view with optional sibling source
/// bytes. Detectors that emit location-bearing diagnostics take a `&SourceBundle`
/// instead of threading both halves through their arguments.
///
/// Source bytes are optional: span queries (graph-only) always work, but
/// source-byte queries (`source_bytes`, `slice`, `line_col`, `format_location`)
/// return `None` when neither a valid archive nor a verified source lookup is
/// available. Detectors emit `"(source bytes unavailable)"` diagnostics in that
/// case rather than panicking — see the phantom-import demo in Task 25.
///
/// Public fields by design: callers may construct directly, and the helper
/// methods rely only on the public state (no hidden invariants).
pub struct SourceBundle<'a> {
    pub graph: crate::csr::CodeGraph<'a>,
    pub archive: Option<SourceArchive<'a>>,
    pub source_lookup: Option<SourceLookup<'a>>,
    pub source_roles: Option<&'a CompleteSourceRoleIndex>,
}

impl<'a> SourceBundle<'a> {
    pub fn without_source_roles(
        graph: crate::csr::CodeGraph<'a>,
        archive: Option<SourceArchive<'a>>,
    ) -> Self {
        Self {
            graph,
            archive,
            source_lookup: None,
            source_roles: None,
        }
    }

    pub fn with_source_roles(
        graph: crate::csr::CodeGraph<'a>,
        archive: Option<SourceArchive<'a>>,
        source_roles: &'a CompleteSourceRoleIndex,
    ) -> Self {
        Self::with_source_roles_and_lookup(graph, archive, source_roles, None)
    }

    pub fn with_source_roles_and_lookup(
        graph: crate::csr::CodeGraph<'a>,
        archive: Option<SourceArchive<'a>>,
        source_roles: &'a CompleteSourceRoleIndex,
        source_lookup: Option<SourceLookup<'a>>,
    ) -> Self {
        Self {
            graph,
            archive,
            source_lookup,
            source_roles: Some(source_roles),
        }
    }

    pub fn source_role_for_path(&self, rel_path: &str) -> Option<SourceRole> {
        self.source_roles?.role_for_path(rel_path)
    }

    pub fn source_role_for_file(&self, file: crate::ids::NodeId) -> Option<SourceRole> {
        self.source_roles?.role_for_file(&self.graph, file)
    }

    /// Look up the raw source bytes for a File node. Returns `Some` only when
    /// the file has SOURCE_METADATA and either:
    ///
    /// * the bundle has an archive with a matching SHA blob whose length
    ///   matches SOURCE_METADATA's content_length, or
    /// * the bundle has a source lookup whose path bytes match both
    ///   SOURCE_METADATA's content_length and sha256.
    ///
    /// These are fail-closed drift checks: mismatched bytes return `None`
    /// rather than handing renderers wrong source.
    pub fn source_bytes(&self, file: crate::ids::NodeId) -> Option<&'a [u8]> {
        let meta = self.graph.source_metadata(file)?;
        if let Some(archive) = self.archive.as_ref() {
            let bytes = archive.get(&meta.sha256)?;
            // Cheap drift check: SHA matched but length disagrees -> silent
            // corruption. Return None rather than handing back wrong-shape bytes.
            if bytes.len() as u64 != meta.content_length {
                return None;
            }
            return Some(bytes);
        }
        let path = self.graph.node_name(file);
        let entry = self.source_lookup?.source_bytes_for_path(path)?;
        let bytes = entry.bytes;
        if bytes.len() as u64 != meta.content_length {
            return None;
        }
        if let Some(lookup_meta) = entry.metadata {
            if lookup_meta.content_length != meta.content_length
                || lookup_meta.sha256 != meta.sha256
            {
                return None;
            }
        } else if crate::hash::sha256(bytes) != meta.sha256 {
            return None;
        }
        Some(bytes)
    }

    /// Slice source bytes by span. The span's offsets index into `file`'s
    /// source. Returns `None` when source bytes are unavailable or the span
    /// would slice past the file's end (defensive — view_from_bytes already
    /// validates spans against content_length, but consumers may construct
    /// arbitrary `Span` values for ad-hoc queries).
    pub fn slice(&self, file: crate::ids::NodeId, span: crate::spans::Span) -> Option<&'a [u8]> {
        let bytes = self.source_bytes(file)?;
        let start = span.start() as usize;
        let end = span.end() as usize;
        bytes.get(start..end)
    }

    /// Compute line:col for a byte offset in `file`. Builds a fresh
    /// `LineIndex` on every call — O(file_length) per query. For many
    /// queries on the same file, build a `LineIndex` once via `line_index`
    /// and reuse it (O(log lines) per query thereafter).
    pub fn line_col(
        &self,
        file: crate::ids::NodeId,
        byte_offset: u32,
    ) -> Option<crate::spans::LineCol> {
        let bytes = self.source_bytes(file)?;
        crate::spans::LineIndex::build(bytes).line_col(byte_offset)
    }

    /// Build a reusable `LineIndex` for a file. Use when emitting many
    /// diagnostics for the same file — amortizes the line-start scan.
    pub fn line_index(&self, file: crate::ids::NodeId) -> Option<crate::spans::LineIndex> {
        let bytes = self.source_bytes(file)?;
        Some(crate::spans::LineIndex::build(bytes))
    }

    /// Format a span's start position as `path:line:col` — the location half
    /// of a compiler-style diagnostic (e.g., the `main.ts:3:18` in *"phantom
    /// import of 'shimmer-utils' at main.ts:3:18"*).
    ///
    /// Reads path from `self.graph.node_name(file)` — relies on the
    /// invariant that File nodes' names are their paths (established by
    /// `GraphBuilder::add_file(path, content)` interning `path` as the
    /// node's name).
    ///
    /// Returns `None` when source bytes are unavailable (archive absent,
    /// hash mismatch) — line:col can't be computed without source bytes.
    pub fn format_location(
        &self,
        file: crate::ids::NodeId,
        span: crate::spans::Span,
    ) -> Option<String> {
        let path = self.graph.node_name(file);
        let lc = self.line_col(file, span.start())?;
        Some(format!("{}:{}:{}", path, lc.line, lc.column))
    }

    /// Format many `(file, span)` locations, building each file's `LineIndex`
    /// at most once and reusing it across all that file's spans.
    ///
    /// `format_location` rebuilds the index on every call (O(file_length) per
    /// query). A file emitting one diagnostic per statement — e.g. a compiled
    /// CJS barrel with thousands of statements — would otherwise cost
    /// O(statements · file_length) ≈ O(n²). This batches that to
    /// O(file_length + queries · log lines). Entries are returned in input
    /// order; `None` where source bytes are unavailable.
    pub fn format_locations(
        &self,
        items: &[(crate::ids::NodeId, crate::spans::Span)],
    ) -> Vec<Option<String>> {
        let mut index_cache: std::collections::HashMap<
            crate::ids::NodeId,
            Option<crate::spans::LineIndex>,
        > = std::collections::HashMap::new();
        items
            .iter()
            .map(|&(file, span)| {
                let index = index_cache
                    .entry(file)
                    .or_insert_with(|| self.line_index(file));
                let lc = index.as_ref()?.line_col(span.start())?;
                Some(format!(
                    "{}:{}:{}",
                    self.graph.node_name(file),
                    lc.line,
                    lc.column
                ))
            })
            .collect()
    }
}
