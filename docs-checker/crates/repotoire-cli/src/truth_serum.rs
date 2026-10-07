//! Captured-byte provenance shared with the original truth-serum owner.
use std::path::Path;

/// Fingerprint exact bytes captured by the docs-truth request. The encoding is
/// the same `fnv1a64` path/byte stream used by the full product's strict
/// filesystem recomputation.
pub(crate) fn dirty_fingerprint_for_captured_paths<'a, I, P>(root: &Path, files: I) -> String
where
    I: IntoIterator<Item = (P, Option<&'a [u8]>)>,
    P: AsRef<Path>,
{
    let mut state = Fnv1a64::new();
    let mut captured = files
        .into_iter()
        .map(|(path, bytes)| {
            (
                repotoire::source_pipeline::canonical_project_path(root, path.as_ref()),
                bytes,
            )
        })
        .collect::<Vec<_>>();
    captured.sort_by(|left, right| left.0.cmp(&right.0));
    captured.dedup_by(|left, right| left.0 == right.0);
    for (logical, bytes) in captured {
        mix_dirty_fingerprint_entry(&mut state, &logical, bytes);
    }
    format!("fnv1a64:{:016x}", state.finish())
}

fn mix_dirty_fingerprint_entry(state: &mut Fnv1a64, logical: &str, bytes: Option<&[u8]>) {
    state.mix(logical.as_bytes());
    state.mix(&[0]);
    match bytes {
        Some(bytes) => state.mix(bytes),
        None => state.mix(format!("unreadable:{logical}").as_bytes()),
    }
    state.mix(&[0]);
}

struct Fnv1a64(u64);

impl Fnv1a64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        Self(Self::OFFSET_BASIS)
    }

    fn mix(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= byte as u64;
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}
