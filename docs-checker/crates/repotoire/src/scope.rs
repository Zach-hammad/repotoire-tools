//! One scope algebra: parsing, overlap, and coverage for write scopes.
//!
//! ADR 0007; spec at docs/specs/2026-07-01-scope-algebra.md. This Rust module
//! is the only scope-algebra implementation.

use std::collections::BTreeSet;
use std::fmt;

/// Strings that mean "this worker claims no write authority".
pub const NO_WRITE_SENTINELS: [&str; 4] = ["none", "no-write", "read-only", "readonly"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// "." or "/": covers everything inside this repository, nothing outside it.
    RepoWide,
    /// A leading "../" run escaping the repo root: `hops` levels up, then `components`.
    CrossRepo { hops: u32, components: Vec<String> },
    /// A repo-relative path in canonical components (never "", ".", or "..").
    Path { components: Vec<String> },
    /// "none" | "no-write" | "read-only" | "readonly", case-insensitive, "./…/" decoration ok.
    NoWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeParseError {
    /// "", "///", "././", or a path resolving to nothing ("a/..").
    /// Whitespace-only claims are empty; concrete file paths preserve whitespace.
    Empty { raw: String },
    /// "/abs/path" or a drive-letter path. Scopes are repo-relative by contract.
    Absolute { raw: String },
    /// A file path whose lexical `..` resolution escapes the repository root.
    /// Only produced by [`Scope::from_file_path`]; claim parsing represents
    /// escapes as [`Scope::CrossRepo`] instead.
    EscapesRepo { raw: String },
}

impl fmt::Display for ScopeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeParseError::Empty { raw } => write!(
                f,
                "invalid write scope {raw:?}: empty or resolves to nothing (write \".\" for a repo-wide claim)"
            ),
            ScopeParseError::Absolute { raw } => write!(
                f,
                "invalid write scope {raw:?}: absolute paths are not allowed; scopes are repo-relative"
            ),
            ScopeParseError::EscapesRepo { raw } => write!(
                f,
                "invalid file path {raw:?}: resolves outside the repository root"
            ),
        }
    }
}

fn is_drive_letter_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!((chars.next(), chars.next()), (Some(c), Some(':')) if c.is_ascii_alphabetic())
}

impl Scope {
    pub fn parse(raw: &str) -> Result<Scope, ScopeParseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ScopeParseError::Empty {
                raw: raw.to_string(),
            });
        }
        let swapped = trimmed.replace('\\', "/");
        if swapped == "." || swapped == "/" {
            return Ok(Scope::RepoWide);
        }
        // Sentinel check on the decoration-stripped form ("./none/" == "none").
        let mut stripped = swapped.as_str();
        while let Some(rest) = stripped.strip_prefix("./") {
            stripped = rest;
        }
        let stripped = stripped.trim_end_matches('/');
        if stripped.is_empty() {
            return Err(ScopeParseError::Empty {
                raw: raw.to_string(),
            });
        }
        if NO_WRITE_SENTINELS.contains(&stripped.to_ascii_lowercase().as_str()) {
            return Ok(Scope::NoWrite);
        }
        // Absoluteness is tested BEFORE any slash stripping. (The old goal-lane
        // gate stripped first, which made its is_absolute() check dead code.)
        if swapped.starts_with('/') || is_drive_letter_prefix(&swapped) {
            return Err(ScopeParseError::Absolute {
                raw: raw.to_string(),
            });
        }
        let mut hops: u32 = 0;
        let mut components: Vec<String> = Vec::new();
        for segment in swapped.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    if components.pop().is_none() {
                        hops += 1;
                    }
                }
                other => components.push(other.to_string()),
            }
        }
        if hops == 0 && components.is_empty() {
            return Err(ScopeParseError::Empty {
                raw: raw.to_string(),
            });
        }
        if hops > 0 {
            Ok(Scope::CrossRepo { hops, components })
        } else {
            Ok(Scope::Path { components })
        }
    }

    /// Parse a concrete repository file path — the coveree side of a
    /// claim-vs-file check — into a Scope. Unlike [`Scope::parse`], this
    /// applies none of the claim vocabulary: sentinels are not recognized
    /// (a file literally named "none" is a one-component [`Scope::Path`]),
    /// and there is no cross-repo interpretation — a path whose lexical
    /// `..` resolution escapes the repository root is rejected
    /// ([`ScopeParseError::EscapesRepo`]), as are absolute and drive-letter
    /// paths. Whitespace is preserved because it belongs to the concrete
    /// filesystem identity. Separator normalization and interior `..`
    /// resolution match [`Scope::parse`]. Always yields [`Scope::Path`] on success.
    ///
    /// This file-side constructor is intentionally narrower than claim parsing.
    pub fn from_file_path(raw: &str) -> Result<Scope, ScopeParseError> {
        if raw.is_empty() {
            return Err(ScopeParseError::Empty {
                raw: raw.to_string(),
            });
        }
        let swapped = raw.replace('\\', "/");
        if swapped.starts_with('/') || is_drive_letter_prefix(&swapped) {
            return Err(ScopeParseError::Absolute {
                raw: raw.to_string(),
            });
        }
        let mut components: Vec<String> = Vec::new();
        for segment in swapped.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    if components.pop().is_none() {
                        return Err(ScopeParseError::EscapesRepo {
                            raw: raw.to_string(),
                        });
                    }
                }
                other => components.push(other.to_string()),
            }
        }
        if components.is_empty() {
            return Err(ScopeParseError::Empty {
                raw: raw.to_string(),
            });
        }
        Ok(Scope::Path { components })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::RepoWide => f.write_str("."),
            Scope::NoWrite => f.write_str("none"),
            Scope::Path { components } => f.write_str(&components.join("/")),
            Scope::CrossRepo { hops, components } => {
                let mut parts: Vec<&str> = vec![".."; *hops as usize];
                for component in components {
                    parts.push(component);
                }
                f.write_str(&parts.join("/"))
            }
        }
    }
}

fn is_prefix_or_equal(prefix: &[String], longer: &[String]) -> bool {
    prefix.len() <= longer.len() && longer[..prefix.len()] == *prefix
}

fn components_overlap(a: &[String], b: &[String]) -> bool {
    is_prefix_or_equal(a, b) || is_prefix_or_equal(b, a)
}

impl Scope {
    /// Symmetric: may these two claims touch the same files?
    pub fn overlaps(&self, other: &Scope) -> bool {
        use Scope::*;
        match (self, other) {
            (NoWrite, _) | (_, NoWrite) => false,
            (RepoWide, CrossRepo { .. }) | (CrossRepo { .. }, RepoWide) => false,
            (RepoWide, _) | (_, RepoWide) => true,
            (
                CrossRepo {
                    hops: a,
                    components: ca,
                },
                CrossRepo {
                    hops: b,
                    components: cb,
                },
            ) => {
                // Containment across hop counts isn't modeled; err toward conflict.
                a != b || components_overlap(ca, cb)
            }
            (CrossRepo { .. }, Path { .. }) | (Path { .. }, CrossRepo { .. }) => false,
            (Path { components: ca }, Path { components: cb }) => components_overlap(ca, cb),
        }
    }

    /// Directional: does `self` (an allowance) permit writing everywhere `other` claims?
    pub fn covers(&self, other: &Scope) -> bool {
        use Scope::*;
        match (self, other) {
            (NoWrite, _) | (_, NoWrite) => false,
            (RepoWide, RepoWide) | (RepoWide, Path { .. }) => true,
            (RepoWide, CrossRepo { .. }) => false,
            (_, RepoWide) => false,
            (
                CrossRepo {
                    hops: a,
                    components: ca,
                },
                CrossRepo {
                    hops: b,
                    components: cb,
                },
            ) => a == b && is_prefix_or_equal(ca, cb),
            (Path { components: ca }, Path { components: cb }) => is_prefix_or_equal(ca, cb),
            (CrossRepo { .. }, Path { .. }) | (Path { .. }, CrossRepo { .. }) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteScopeClaim {
    Parsed(Scope),
    Invalid {
        raw: String,
        normalized: String,
        error: ScopeParseError,
    },
}

impl WriteScopeClaim {
    pub fn parse_effective(raw: &str) -> Option<Self> {
        match Scope::parse(raw) {
            Ok(Scope::NoWrite) => None,
            Ok(scope) => Some(Self::Parsed(scope)),
            Err(error) => Some(Self::Invalid {
                raw: raw.to_string(),
                normalized: invalid_scope_marker(raw),
                error,
            }),
        }
    }

    pub fn parse_claim(raw: &str) -> Self {
        match Scope::parse(raw) {
            Ok(scope) => Self::Parsed(scope),
            Err(error) => Self::Invalid {
                raw: raw.to_string(),
                normalized: invalid_scope_marker(raw),
                error,
            },
        }
    }

    pub fn normalized(&self) -> String {
        match self {
            Self::Parsed(scope) => scope.to_string(),
            Self::Invalid { normalized, .. } => normalized.clone(),
        }
    }

    pub fn overlaps_fail_closed(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Parsed(left), Self::Parsed(right)) => left.overlaps(right),
            _ => true,
        }
    }
}

fn invalid_scope_marker(raw: &str) -> String {
    raw.trim().to_string()
}

pub fn normalize_write_scope_claim(raw: &str) -> String {
    WriteScopeClaim::parse_claim(raw).normalized()
}

pub fn normalize_effective_write_scopes<S: AsRef<str>>(raw: &[S]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for scope in raw {
        if let Some(claim) = WriteScopeClaim::parse_effective(scope.as_ref()) {
            let claim = claim.normalized();
            if seen.insert(claim.clone()) {
                normalized.push(claim);
            }
        }
    }
    normalized
}

pub fn write_scopes_overlap_fail_closed(left: &str, right: &str) -> bool {
    match (
        WriteScopeClaim::parse_effective(left),
        WriteScopeClaim::parse_effective(right),
    ) {
        (Some(left), Some(right)) => left.overlaps_fail_closed(&right),
        _ => false,
    }
}

pub fn write_scopes_overlap_if_parseable(left: &str, right: &str) -> bool {
    match (Scope::parse(left), Scope::parse(right)) {
        (Ok(left), Ok(right)) => left.overlaps(&right),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    pub fn parse_list<S: AsRef<str>>(raw: &[S]) -> Result<ScopeSet, ScopeParseError> {
        let mut scopes = raw
            .iter()
            .map(|s| Scope::parse(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        scopes.sort();
        scopes.dedup();
        Ok(ScopeSet(scopes))
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.0
    }

    pub fn first_overlap<'a>(&'a self, other: &'a ScopeSet) -> Option<(&'a Scope, &'a Scope)> {
        self.0.iter().find_map(|left| {
            other
                .0
                .iter()
                .find(|right| left.overlaps(right))
                .map(|right| (left, right))
        })
    }

    pub fn overlaps(&self, other: &ScopeSet) -> bool {
        self.first_overlap(other).is_some()
    }

    /// True when this set claims no write authority: empty, or only NoWrite entries.
    pub fn is_no_write(&self) -> bool {
        self.0.iter().all(|scope| matches!(scope, Scope::NoWrite))
    }

    pub fn has_cross_repo(&self) -> bool {
        self.0
            .iter()
            .any(|scope| matches!(scope, Scope::CrossRepo { .. }))
    }

    /// Goal-lane allowance: every non-NoWrite requested scope is covered by some allowed scope.
    pub fn allows(&self, requested: &ScopeSet) -> bool {
        requested
            .0
            .iter()
            .filter(|scope| !matches!(scope, Scope::NoWrite))
            .all(|req| self.0.iter().any(|allowed| allowed.covers(req)))
    }

    /// Canonical string forms in stable order.
    pub fn render(&self) -> Vec<String> {
        self.0.iter().map(Scope::to_string).collect()
    }
}
