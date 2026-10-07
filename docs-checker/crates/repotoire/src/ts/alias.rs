//! Dependency-free tsconfig path-alias resolution (spec §3.2). The CLI builds
//! an `AliasMap` from tsconfig.json; the core consumes it in `canonicalize`.
//! All paths are the project-relative `./…` form (see `canonicalize::normalize_path`).

/// One resolved alias rule, scoped to the directory of the tsconfig that
/// defined it. `pattern` is a tsconfig `paths` key (`@app/*`, or exact `@app/x`)
/// or `*` (the baseUrl catch-all). `substitutions` are project-relative
/// `./…` targets, each possibly containing a single `*` placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasEntry {
    pub scope_dir: String,          // "./" or "./packages/foo"
    pub pattern: String,            // "@app/*", "@app/exact", or "*"
    pub substitutions: Vec<String>, // ["./src/*"], ...
}

/// A deterministic, ordered set of alias rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AliasMap {
    pub entries: Vec<AliasEntry>,
}

/// How well `pattern` matches `specifier`: the captured `*` text (if any) and a
/// specificity score (longer non-wildcard prefix = more specific; exact match
/// beats wildcard). Returns None if it doesn't match.
fn match_pattern<'a>(pattern: &str, specifier: &'a str) -> Option<(Option<&'a str>, usize)> {
    if let Some(star) = pattern.find('*') {
        let prefix = &pattern[..star];
        let suffix = &pattern[star + 1..];
        if specifier.len() >= prefix.len() + suffix.len()
            && specifier.starts_with(prefix)
            && specifier.ends_with(suffix)
        {
            let captured = &specifier[prefix.len()..specifier.len() - suffix.len()];
            // Specificity: prefix length (wildcard entries score by their fixed prefix).
            Some((Some(captured), prefix.len()))
        } else {
            None
        }
    } else if pattern == specifier {
        // Exact match — most specific (score above any wildcard prefix).
        Some((None, usize::MAX))
    } else {
        None
    }
}

/// Is `dir` an ancestor scope of `file`? `"./"` (root) matches everything.
fn is_ancestor(dir: &str, file: &str) -> bool {
    if dir == "./" || dir.is_empty() {
        return true;
    }
    let dir = dir.strip_suffix('/').unwrap_or(dir);
    file.len() > dir.len() && file.starts_with(dir) && file.as_bytes().get(dir.len()) == Some(&b'/')
}

impl AliasMap {
    /// Candidate project-relative target paths for `specifier` imported from
    /// `importing_file`, best first. Empty if no alias applies. The caller
    /// probes each candidate against the file set (extensions/index).
    ///
    /// Ranking (spec §3.2): nearest matching ENTRY wins — deepest `scope_dir`,
    /// then most-specific pattern, then `entries` order (the CLI builds that
    /// order deterministically — sorted by `(scope_dir, pattern)`, not JSON
    /// object insertion order — so equal-specificity ties resolve stably).
    /// A deeper non-matching entry never hides a shallower matching one.
    pub fn resolve(&self, specifier: &str, importing_file: &str) -> Vec<String> {
        let mut out = Vec::new();
        self.resolve_into(specifier, importing_file, &mut out);
        out
    }

    /// Like [`AliasMap::resolve`], but reuses `out` and avoids collecting and
    /// sorting all matching rules. Ties preserve `entries` order by only
    /// replacing the current best rule when the next match is strictly better.
    pub fn resolve_into(&self, specifier: &str, importing_file: &str, out: &mut Vec<String>) {
        out.clear();
        let mut best: Option<(&AliasEntry, Option<&str>, usize, usize)> = None;
        for e in &self.entries {
            if !is_ancestor(&e.scope_dir, importing_file) {
                continue;
            }
            let Some((captured, specificity)) = match_pattern(&e.pattern, specifier) else {
                continue;
            };
            let scope_len = e.scope_dir.len();
            let replace = best
                .map(|(_, _, best_scope_len, best_specificity)| {
                    scope_len > best_scope_len
                        || (scope_len == best_scope_len && specificity > best_specificity)
                })
                .unwrap_or(true);
            if replace {
                best = Some((e, captured, scope_len, specificity));
            }
        }
        let Some((best, captured, _, _)) = best else {
            return;
        };
        out.reserve(best.substitutions.len());
        for sub in &best.substitutions {
            out.push(match captured {
                Some(cap) => sub.replacen('*', cap, 1),
                None => sub.clone(),
            });
        }
    }
}
