use crate::csr::GraphError;
use crate::ids::StringId;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Pluggable hashing strategy. Production uses `SipHasher` (std `DefaultHasher`);
/// tests inject deterministic hashers (e.g. always-zero) to exercise the
/// `Bucket::Many` collision path without relying on accidental SipHash collisions.
pub trait StrHasher {
    fn hash(&self, s: &str) -> u64;
}

pub struct SipHasher;

impl StrHasher for SipHasher {
    fn hash(&self, s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }
}

pub struct StringInterner<H: StrHasher = SipHasher> {
    arena: Vec<u8>,
    index: Vec<(u32, u32)>,
    // hash(content) -> StringIds whose content hashes to that bucket.
    // String bytes are NOT duplicated here; they live only in `arena`.
    by_hash: HashMap<u64, Bucket>,
    hasher: H,
}

enum Bucket {
    One(StringId),
    Many(Vec<StringId>),
}

impl Default for StringInterner<SipHasher> {
    fn default() -> Self {
        Self::new()
    }
}

impl StringInterner<SipHasher> {
    pub fn new() -> Self {
        Self::with_hasher(SipHasher)
    }
}

impl<H: StrHasher> StringInterner<H> {
    /// Test seam — only used by the crate's own tests. External users go through `new()`.
    pub(crate) fn with_hasher(hasher: H) -> Self {
        Self {
            arena: Vec::new(),
            index: Vec::new(),
            by_hash: HashMap::new(),
            hasher,
        }
    }

    pub fn intern(&mut self, s: &str) -> StringId {
        let h = self.hasher.hash(s);
        // Pull the list of candidates whose content hashed to `h`. Cloning
        // releases the immutable self borrow so we can mutate `self` below.
        let candidates: Vec<StringId> = match self.by_hash.get(&h) {
            None => Vec::new(),
            Some(Bucket::One(id)) => vec![*id],
            Some(Bucket::Many(ids)) => ids.clone(),
        };
        // Linear scan inside the bucket. Non-colliding hashes have a single
        // candidate, so this is one byte comparison in the common case.
        for &id in &candidates {
            if self.resolve_internal(id) == s {
                return id;
            }
        }
        // Not present — append once and update the bucket.
        let new_id = self.append_new(s);
        if candidates.is_empty() {
            self.by_hash.insert(h, Bucket::One(new_id));
        } else {
            let mut all = candidates;
            all.push(new_id);
            self.by_hash.insert(h, Bucket::Many(all));
        }
        new_id
    }

    fn append_new(&mut self, s: &str) -> StringId {
        let offset = u32::try_from(self.arena.len())
            .expect("Repotoire v0 format limit: string arena exceeds u32 bytes");
        let len = u32::try_from(s.len())
            .expect("Repotoire v0 format limit: single string exceeds u32 bytes");
        self.arena.extend_from_slice(s.as_bytes());
        let id = StringId::from_raw(
            u32::try_from(self.index.len())
                .expect("Repotoire v0 format limit: unique string count exceeds u32"),
        );
        self.index.push((offset, len));
        id
    }

    pub(crate) fn resolve_internal(&self, id: StringId) -> &str {
        let (offset, len) = self.index[id.as_usize()];
        let bytes = &self.arena[offset as usize..(offset + len) as usize];
        // arena only ever holds UTF-8 input handed to intern(&str), so the
        // slice falls on valid char boundaries by construction.
        std::str::from_utf8(bytes).expect("interner arena is well-formed UTF-8")
    }

    /// Consume the builder-side interner and return the byte sections that
    /// will be written to disk: (arena_bytes, index_bytes).
    /// `index_bytes` is a flat `[u8]` of `[(offset: u32 LE, len: u32 LE); K]`.
    pub fn into_byte_sections(self) -> (Vec<u8>, Vec<u8>) {
        let mut index_bytes = Vec::with_capacity(self.index.len() * 8);
        for (offset, len) in &self.index {
            index_bytes.extend_from_slice(&offset.to_le_bytes());
            index_bytes.extend_from_slice(&len.to_le_bytes());
        }
        (self.arena, index_bytes)
    }
}

/// Resolve a `StringId` against the frozen `(arena, index)` byte sections.
/// Used by `CodeGraph::node_name` and any future name-querying API.
pub fn resolve_string<'a>(
    arena_bytes: &'a [u8],
    index_bytes: &[u8],
    id: StringId,
) -> Result<&'a str, GraphError> {
    let entry_start = id
        .as_usize()
        .checked_mul(8)
        .ok_or(GraphError::StringIndexOutOfBounds)?;
    let entry_end = entry_start
        .checked_add(8)
        .ok_or(GraphError::StringIndexOutOfBounds)?;
    if entry_end > index_bytes.len() {
        return Err(GraphError::StringIndexOutOfBounds);
    }
    let offset = u32::from_le_bytes(
        index_bytes[entry_start..entry_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let len =
        u32::from_le_bytes(index_bytes[entry_start + 4..entry_end].try_into().unwrap()) as usize;
    let arena_end = offset
        .checked_add(len)
        .ok_or(GraphError::StringArenaOutOfBounds)?;
    if arena_end > arena_bytes.len() {
        return Err(GraphError::StringArenaOutOfBounds);
    }
    std::str::from_utf8(&arena_bytes[offset..arena_end]).map_err(|_| GraphError::Utf8Error)
}
