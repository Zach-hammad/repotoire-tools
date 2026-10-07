use core::ops::Range;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    start: u32,
    length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanRangeError {
    OffsetOverflowsU32 { offset: usize },
    LengthOverflowsU32 { length: usize },
    InvertedRange { start: usize, end: usize },
}

impl Span {
    pub const fn new(start: u32, length: u32) -> Self {
        // const-friendly checked add: panics at const-eval if overflow
        match start.checked_add(length) {
            Some(_) => Self { start, length },
            None => panic!("Span::new: start + length overflows u32"),
        }
    }

    pub fn try_from_range(range: Range<usize>) -> Result<Self, SpanRangeError> {
        if range.start > range.end {
            return Err(SpanRangeError::InvertedRange {
                start: range.start,
                end: range.end,
            });
        }
        let start = u32::try_from(range.start).map_err(|_| SpanRangeError::OffsetOverflowsU32 {
            offset: range.start,
        })?;
        let length_usize = range.end - range.start;
        let length =
            u32::try_from(length_usize).map_err(|_| SpanRangeError::LengthOverflowsU32 {
                length: length_usize,
            })?;
        // Final overflow check on start + length:
        start
            .checked_add(length)
            .ok_or(SpanRangeError::LengthOverflowsU32 {
                length: length_usize,
            })?;
        Ok(Self { start, length })
    }

    pub const fn start(self) -> u32 {
        self.start
    }
    pub const fn length(self) -> u32 {
        self.length
    }
    /// Total: the constructor invariant guarantees no overflow.
    pub const fn end(self) -> u32 {
        self.start + self.length
    }
}

// ---- Task 4 types: NodeSpans, SourceMetadata, LineCol, LineIndex, SourceEncodingError ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeSpans {
    pub name: Option<Span>,
    pub decl: Option<Span>,
    pub body: Option<Span>,
}

impl NodeSpans {
    pub const ABSENT: NodeSpans = NodeSpans {
        name: None,
        decl: None,
        body: None,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMetadata {
    pub content_length: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCol {
    /// 1-indexed.
    pub line: u32,
    /// 1-indexed, byte-counted (not codepoint-counted).
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceEncodingError {
    NotUtf8 {
        path: String,
        invalid_byte_offset: usize,
    },
}

/// Pre-built line-start index for a source file. Build once, query many.
///
/// Build cost: O(source_len). Per-query cost: O(log lines).
pub struct LineIndex {
    line_starts: Vec<u32>,
    source_len: u32,
}

impl LineIndex {
    /// Walk the source bytes, recording the byte offset of each line start.
    /// Line 1 always starts at byte 0; subsequent line starts are the byte
    /// immediately after each `\n`.
    ///
    /// Panics if `source.len() > u32::MAX` (the v0-spans format caps file
    /// length at 4 GB anyway).
    pub fn build(source: &[u8]) -> Self {
        let source_len = u32::try_from(source.len())
            .expect("Repotoire spans: source length must fit in u32 (4GB cap)");
        let mut line_starts = Vec::with_capacity(source.len() / 50 + 1);
        line_starts.push(0u32);
        for (i, &b) in source.iter().enumerate() {
            if b == b'\n' {
                // (i + 1) fits in u32 because source_len fits in u32 and i < source.len().
                line_starts.push((i + 1) as u32);
            }
        }
        Self {
            line_starts,
            source_len,
        }
    }

    /// Compute line:col for a byte offset.
    ///
    /// EOF semantics (per spec §5.4):
    /// - `offset < source.len()`: returns the line and byte-column containing that byte.
    /// - `offset == source.len()` (EOF):
    ///     - if source ends with `\n`: returns `(last_line + 1, 1)` — the empty line
    ///       *after* the trailing newline.
    ///     - otherwise: returns `(last_line, bytes_since_last_newline + 1)`.
    /// - `offset > source.len()`: returns `None`.
    ///
    /// Byte AT a `\n` belongs to the line containing it (column = position-of-`\n` + 1);
    /// the byte at `offset+1` is column 1 of the next line.
    pub fn line_col(&self, byte_offset: u32) -> Option<LineCol> {
        if byte_offset > self.source_len {
            return None;
        }

        if byte_offset == self.source_len {
            // EOF.
            let last_start = *self
                .line_starts
                .last()
                .expect("line_starts is non-empty by construction (always pushes 0 first)");
            if last_start == self.source_len {
                // Source ended with `\n` — we pushed a final line_start equal to source_len.
                // EOF is on the empty line after that newline.
                let line = self.line_starts.len() as u32;
                return Some(LineCol { line, column: 1 });
            }
            // Source does NOT end with `\n` — EOF is on the last existing line, just past
            // the final byte.
            let line = self.line_starts.len() as u32;
            let column = self.source_len - last_start + 1;
            return Some(LineCol { line, column });
        }

        // byte_offset < source_len: find the largest line_start <= byte_offset.
        // binary_search returns Ok(i) on exact match, Err(i) for insertion point.
        // Err(0) is unreachable because line_starts[0] == 0 <= every valid u32.
        let idx = match self.line_starts.binary_search(&byte_offset) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let line = (idx + 1) as u32; // 1-indexed
        let column = byte_offset - self.line_starts[idx] + 1;
        Some(LineCol { line, column })
    }
}
