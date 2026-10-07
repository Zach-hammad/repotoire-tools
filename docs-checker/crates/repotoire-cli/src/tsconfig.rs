//! Phase 2: multi-config AliasMap — discovery + extends + references + per-package scopes.
use crate::repository_path::ReadOnlyFiles;
use repotoire::ts::{AliasEntry, AliasMap};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// Strip JSONC comments + trailing commas via a string-aware state machine,
/// preserving `//` and `/* */` that occur inside string literals.
///
/// ASCII-only: bytes are pushed as `char`, so a non-ASCII byte inside a string
/// value becomes a U+0080–U+00FF scalar (still valid UTF-8, but a different
/// character). Phase-1 scope — tsconfig path keys/targets are ASCII in
/// practice; Phase 2 should switch to char-boundary iteration if non-ASCII
/// paths ever need support.
pub fn strip_jsonc(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char); // keep escaped char verbatim
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                out.push('"');
                i += 1;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    strip_trailing_commas(&out)
}

fn strip_trailing_commas(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        if c == b',' {
            let mut j = i + 1;
            while j < b.len() && (b[j] as char).is_whitespace() {
                j += 1;
            }
            if j < b.len() && (b[j] == b'}' || b[j] == b']') {
                i += 1; // drop the comma
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// Normalize a path to the project-relative `./…` form, given the config dir
/// (also `./…`) and a path that may be config-relative.
fn join_norm(scope_dir: &str, rel: &str) -> String {
    let scope = scope_dir.strip_prefix("./").unwrap_or(scope_dir);
    let joined = if scope.is_empty() {
        rel.to_string()
    } else {
        format!("{scope}/{rel}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("./{}", parts.join("/"))
}

const SKIP_DIRS: &[&str] = &["node_modules", "dist", "build", "target", ".git"];
const MAX_DEPTH: usize = 64;

/// The project-relative `./…` directory of a config file path under `root`.
/// Root-level config → `"./"`.
fn project_rel_dir(root: &Path, config_path: &Path) -> String {
    let dir = config_path.parent().unwrap_or(root);
    let rel = dir.strip_prefix(root).unwrap_or(dir);
    let s = rel
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    if s.is_empty() {
        "./".to_string()
    } else {
        format!("./{}", s.trim_end_matches('/'))
    }
}

/// All `tsconfig.json` files under `root`, skipping `SKIP_DIRS`. Sorted.
fn find_tsconfigs(inputs: ReadOnlyFiles<'_>, root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_tsconfigs(inputs, root, 0, &mut out);
    out.sort();
    out
}

fn collect_tsconfigs(inputs: ReadOnlyFiles<'_>, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if inputs.visit().is_err() {
            return;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if inputs.is_directory(&path) {
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            collect_tsconfigs(inputs, &path, depth + 1, out);
        } else if name == "tsconfig.json" && inputs.is_file(&path) {
            out.push(path);
        }
    }
}

/// A config's effective alias rules, fully resolved to project-relative `./…`.
#[derive(Debug, Clone, Default)]
struct Resolved {
    base_url_scope: Option<String>,
    paths: BTreeMap<String, Vec<String>>,
    types: Option<Vec<String>>,
    libs: Option<Vec<String>>,
    gaps: Vec<String>,
}

/// Missing configuration evidence applies only to this TypeScript source scope.
#[derive(Debug)]
pub(crate) struct ConfigGap {
    pub(crate) scope_dir: String,
    pub(crate) message: String,
}

pub(crate) struct AliasResolution {
    pub(crate) alias_map: AliasMap,
    pub(crate) gaps: Vec<ConfigGap>,
}

fn append_json_extension(path: &Path) -> PathBuf {
    let mut with_json = path.as_os_str().to_os_string();
    with_json.push(".json");
    PathBuf::from(with_json)
}

fn resolve_config_candidate(inputs: ReadOnlyFiles<'_>, cand: PathBuf) -> io::Result<PathBuf> {
    if inputs.try_is_file(&cand)? {
        return Ok(cand);
    }
    let with_json = append_json_extension(&cand);
    if inputs.try_is_file(&with_json)? {
        return Ok(with_json);
    }
    let with_tsconfig = cand.join("tsconfig.json");
    if inputs.try_is_file(&with_tsconfig)? {
        return Ok(with_tsconfig);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "configuration file not found",
    ))
}

/// Resolve an `extends` target to a config file path. Relative (`./`,`../`, or
/// a path ending `.json`) resolves against `config_dir` (node_modules first for
/// bare-`.json`); a bare package specifier under `root/node_modules/<spec>`.
/// Mirrors TypeScript's Node-style config lookup for extensionless config
/// files by trying the path as written, `<path>.json`, then
/// `<path>/tsconfig.json`. Denied or failed probes remain distinguishable from absence.
fn resolve_extends(
    inputs: ReadOnlyFiles<'_>,
    extends: &str,
    config_dir: &Path,
    root: &Path,
) -> io::Result<PathBuf> {
    let cand = if extends.starts_with('.') {
        config_dir.join(extends)
    } else if extends.ends_with(".json") {
        let nm = root.join("node_modules").join(extends);
        if inputs.try_is_file(&nm)? {
            nm
        } else {
            config_dir.join(extends)
        }
    } else {
        root.join("node_modules").join(extends)
    };
    resolve_config_candidate(inputs, cand)
}

fn extends_specs(json: &serde_json::Value) -> Vec<&str> {
    match json.get("extends") {
        Some(serde_json::Value::String(ext)) => vec![ext.as_str()],
        Some(serde_json::Value::Array(exts)) => exts.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn merge_resolved(base: Resolved, into: &mut Resolved) {
    if let Some(base_url_scope) = base.base_url_scope {
        into.base_url_scope = Some(base_url_scope);
    }
    for (pattern, substitutions) in base.paths {
        into.paths.insert(pattern, substitutions);
    }
    if base.types.is_some() {
        into.types = base.types;
    }
    if base.libs.is_some() {
        into.libs = base.libs;
    }
    into.gaps.extend(base.gaps);
}

/// Load a config (following `extends`) into fully-resolved `Resolved`.
fn load_resolved(
    inputs: ReadOnlyFiles<'_>,
    config_path: &Path,
    root: &Path,
    depth: usize,
) -> Resolved {
    let unavailable = |reason: String| Resolved {
        gaps: vec![format!(
            "TypeScript configuration `{}`: {reason}",
            rel_slash(root, config_path)
        )],
        ..Resolved::default()
    };
    if depth > 16 {
        return unavailable("extends chain exceeds the supported depth of 16".into());
    }
    let raw = match inputs.read_to_string(config_path) {
        Ok(raw) => raw,
        Err(error) => return unavailable(format!("configuration bytes unavailable ({error})")),
    };
    let json = match serde_json::from_str::<serde_json::Value>(&strip_jsonc(&raw)) {
        Ok(json) => json,
        Err(error) => return unavailable(format!("configuration could not be parsed ({error})")),
    };
    let config_dir = config_path.parent().unwrap_or(root);

    // 1. Base configs first — inherited, already resolved. TypeScript 5.0
    // array-form `extends` is equivalent to extending entries left-to-right,
    // with later entries winning conflicting fields.
    let mut resolved = Resolved::default();
    for ext in extends_specs(&json) {
        if inputs.visit().is_err() {
            break; // The owning request rejects the sticky metadata work limit.
        }
        match resolve_extends(inputs, ext, config_dir, root) {
            Ok(base) => merge_resolved(load_resolved(inputs, &base, root, depth + 1), &mut resolved),
            Err(error) => resolved.gaps.push(format!(
                "TypeScript configuration `{}`: extends `{ext}` is unavailable ({error}); inherited settings could not be fully examined",
                rel_slash(root, config_path)
            )),
        }
    }

    // 2. This config's own baseUrl (resolves against THIS dir), overrides base.
    let co = json.get("compilerOptions").cloned().unwrap_or_default();
    let this_dir_rel = project_rel_dir(root, config_path);
    let own_base_scope = co
        .get("baseUrl")
        .and_then(|v| v.as_str())
        .map(|b| join_norm(&this_dir_rel, b));
    if let Some(b) = &own_base_scope {
        resolved.base_url_scope = Some(b.clone());
    }
    // Own `paths` resolve against the EFFECTIVE baseUrl: own baseUrl if set,
    // else the INHERITED baseUrl (already in resolved.base_url_scope), else
    // this config's own dir.
    let sub_scope = own_base_scope
        .clone()
        .or_else(|| resolved.base_url_scope.clone())
        .unwrap_or_else(|| this_dir_rel.clone());

    // 3. This config's own paths (override base by pattern key).
    if let Some(paths) = co.get("paths").and_then(|v| v.as_object()) {
        for (pattern, subs) in paths {
            let resolved_subs: Vec<String> = subs
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str())
                        .map(|s| join_norm(&sub_scope, s.strip_prefix("./").unwrap_or(s)))
                        .collect()
                })
                .unwrap_or_default();
            if !resolved_subs.is_empty() {
                resolved.paths.insert(pattern.clone(), resolved_subs);
            }
        }
    }
    for (key, field) in [("types", &mut resolved.types), ("lib", &mut resolved.libs)] {
        if let Some(values) = co.get(key).and_then(|v| v.as_array()) {
            *field = Some(
                values
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    resolved
}

/// The config files named by a config's `references`. Not recursive, not
/// merged. Missing targets skipped.
fn referenced_configs(inputs: ReadOnlyFiles<'_>, config_path: &Path) -> Vec<PathBuf> {
    let Ok(raw) = inputs.read_to_string(config_path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(&raw)) else {
        return Vec::new();
    };
    let config_dir = config_path.parent().unwrap_or(config_path);
    let mut out = Vec::new();
    if let Some(refs) = json.get("references").and_then(|v| v.as_array()) {
        for r in refs {
            let Some(p) = r.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let cand = config_dir.join(p);
            let cfg = if inputs.is_file(&cand) {
                cand
            } else {
                cand.join("tsconfig.json")
            };
            if inputs.is_file(&cfg) {
                out.push(cfg);
            }
        }
    }
    out
}

/// Recursively collect `package.json` files under `root` (same dir-skip rules
/// as tsconfig discovery). Known-v1-gaps #19.
fn collect_package_jsons(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(md) = std::fs::metadata(&path) else {
            continue;
        };
        if md.is_dir() {
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            collect_package_jsons(&path, depth + 1, out);
        } else if md.is_file() && name == "package.json" {
            out.push(path);
        }
    }
}

/// Append the priority-ordered entry specifiers from a package.json `exports`
/// value (string, `"."` subpath, or a bare conditions object). Source-pointing
/// conditions (`types`/`import`/`module`) rank ahead of `default` so the
/// resolver prefers a real source file over a built `dist` artifact.
fn push_export_entry_strings(val: &serde_json::Value, out: &mut Vec<String>) {
    match val {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Object(map) => {
            for key in ["types", "import", "module", "node", "browser", "default"] {
                if let Some(v) = map.get(key) {
                    push_export_entry_strings(v, out);
                }
            }
        }
        _ => {}
    }
}

fn push_dedup(out: &mut Vec<String>, seen: &mut BTreeSet<String>, value: String) {
    if seen.insert(value.clone()) {
        out.push(value);
    }
}

fn push_package_entry_candidate(out: &mut Vec<String>, seen: &mut BTreeSet<String>, spec: &str) {
    for (runtime_ext, declaration_ext) in [
        (".js", ".d.ts"),
        (".jsx", ".d.ts"),
        (".mjs", ".d.mts"),
        (".cjs", ".d.cts"),
    ] {
        if let Some(base) = spec.strip_suffix(runtime_ext) {
            push_dedup(out, seen, format!("{base}{declaration_ext}"));
        }
    }
    push_dedup(out, seen, spec.to_string());
}

/// Ordered, deduped list of candidate entry specifiers for a package's root
/// import, from `exports["."]`, then top-level `types`/`typings`/`module`/`main`.
/// Runtime JS entries also contribute their declaration-file sibling first,
/// matching TypeScript's package lookup overlay for `.d.ts` files.
/// (Subpath `exports` patterns like `"./*"` are out of scope for this slice.)
fn package_entry_candidates(json: &serde_json::Value) -> Vec<String> {
    let mut raw = Vec::new();
    if let Some(exports) = json.get("exports") {
        match exports {
            serde_json::Value::String(s) => raw.push(s.clone()),
            serde_json::Value::Object(map) => {
                if let Some(dot) = map.get(".") {
                    push_export_entry_strings(dot, &mut raw);
                } else if !map.keys().any(|k| k.starts_with('.')) {
                    // No subpath keys → the object IS the "." conditions set.
                    push_export_entry_strings(exports, &mut raw);
                }
            }
            _ => {}
        }
    }
    for key in ["types", "typings", "module", "main"] {
        if let Some(serde_json::Value::String(s)) = json.get(key) {
            raw.push(s.clone());
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for spec in raw {
        push_package_entry_candidate(&mut out, &mut seen, &spec);
    }
    out
}

fn package_entry_subpath_root(entry: &str) -> Option<String> {
    let entry = entry
        .strip_prefix("./")
        .unwrap_or(entry)
        .trim_end_matches('/');
    if entry.is_empty() {
        return None;
    }
    let (parent, file) = entry.rsplit_once('/').unwrap_or(("", entry));
    if file == "index" || file.starts_with("index.") {
        return Some(if parent.is_empty() {
            "*".to_string()
        } else {
            format!("{parent}/*")
        });
    }
    if !file.contains('.') {
        return Some(format!("{entry}/*"));
    }
    None
}

fn package_subpath_substitutions(scope_dir: &str, cands: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    push_dedup(&mut out, &mut seen, join_norm(scope_dir, "*"));
    for cand in cands {
        if let Some(root) = package_entry_subpath_root(cand) {
            push_dedup(&mut out, &mut seen, join_norm(scope_dir, &root));
        }
    }
    out
}

/// Build globally-scoped alias entries mapping each in-project package `name`
/// to its entry-file candidates (known-v1-gaps #19). Purely additive: a bare
/// specifier matching a workspace package name gains candidate paths that
/// `canonicalize_import` probes; if none is a real source file it falls through
/// to `External(ImportedPackage)` exactly as before.
fn package_alias_entries(root: &Path) -> Vec<AliasEntry> {
    let mut pkgs = Vec::new();
    collect_package_jsons(root, 0, &mut pkgs);
    package_alias_entries_from_package_jsons(ReadOnlyFiles::Repository, root, pkgs)
}

fn package_alias_entries_from_package_jsons(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    mut pkgs: Vec<PathBuf>,
) -> Vec<AliasEntry> {
    pkgs.sort();
    pkgs.dedup();
    let mut entries = Vec::new();
    for pkg in &pkgs {
        let Ok(raw) = inputs.read_to_string(pkg) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(&raw)) else {
            continue;
        };
        let Some(name) = json.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let cands = package_entry_candidates(&json);
        if cands.is_empty() {
            continue;
        }
        let scope_dir = project_rel_dir(root, pkg); // the package's own dir
        let substitutions: Vec<String> = cands
            .iter()
            .map(|c| join_norm(&scope_dir, c.strip_prefix("./").unwrap_or(c)))
            .collect();
        // Package-name resolution is global (any importer), so scope at root.
        entries.push(AliasEntry {
            scope_dir: "./".into(),
            pattern: name.to_string(),
            substitutions,
        });
        let subpath_substitutions = package_subpath_substitutions(&scope_dir, &cands);
        if !subpath_substitutions.is_empty() {
            entries.push(AliasEntry {
                scope_dir: "./".into(),
                pattern: format!("{name}/*"),
                substitutions: subpath_substitutions,
            });
        }
    }
    entries
}

/// Build a multi-scope AliasMap: every discovered `tsconfig.json` (plus configs
/// named by `references`), each contributing alias entries scoped to its own
/// directory, with `extends` chains merged and `paths`/`baseUrl` resolved
/// against their defining config; plus in-project package.json name→entry
/// aliases (#19). Fail-open; deterministic (sorted).
pub fn build_alias_map(root: &Path) -> AliasMap {
    build_alias_map_from_scopes(
        ReadOnlyFiles::Repository,
        root,
        find_tsconfigs(ReadOnlyFiles::Repository, root),
        None,
    )
    .alias_map
}

pub(crate) fn build_alias_map_for_source_paths(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    rel_paths: &[&str],
) -> AliasResolution {
    build_alias_map_from_scopes(
        inputs,
        root,
        tsconfigs_for_source_paths(inputs, root, rel_paths),
        Some(rel_paths),
    )
}

fn build_alias_map_from_scopes(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    mut scopes: Vec<PathBuf>,
    source_paths: Option<&[&str]>,
) -> AliasResolution {
    let mut referenced: Vec<PathBuf> = scopes
        .iter()
        .flat_map(|c| referenced_configs(inputs, c))
        .collect();
    scopes.append(&mut referenced);
    scopes.sort();
    scopes.dedup();

    let mut entries: Vec<AliasEntry> = Vec::new();
    let mut gaps = Vec::new();
    for config in &scopes {
        let scope_dir = project_rel_dir(root, config);
        let rc = load_resolved(inputs, config, root, 0);
        for (pattern, substitutions) in &rc.paths {
            entries.push(AliasEntry {
                scope_dir: scope_dir.clone(),
                pattern: pattern.clone(),
                substitutions: substitutions.clone(),
            });
        }
        if let Some(base_scope) = &rc.base_url_scope {
            entries.push(AliasEntry {
                scope_dir: scope_dir.clone(),
                pattern: "*".into(),
                substitutions: vec![join_norm(base_scope, "*")],
            });
        }
        gaps.extend(rc.gaps.into_iter().map(|message| ConfigGap {
            scope_dir: scope_dir.clone(),
            message,
        }));
    }
    // #19: in-project package.json name→entry aliases (global scope).
    entries.extend(match source_paths {
        Some(rel_paths) => package_alias_entries_from_package_jsons(
            inputs,
            root,
            package_jsons_for_source_paths(inputs, root, rel_paths),
        ),
        None => package_alias_entries(root),
    });
    entries.sort_by(|a, b| {
        (a.scope_dir.as_str(), a.pattern.as_str(), &a.substitutions).cmp(&(
            b.scope_dir.as_str(),
            b.pattern.as_str(),
            &b.substitutions,
        ))
    });
    entries.dedup();
    gaps.sort_by(|a, b| (&a.scope_dir, &a.message).cmp(&(&b.scope_dir, &b.message)));
    gaps.dedup_by(|a, b| a.scope_dir == b.scope_dir && a.message == b.message);
    AliasResolution {
        alias_map: AliasMap { entries },
        gaps,
    }
}

fn tsconfigs_for_source_paths(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    rel_paths: &[&str],
) -> Vec<PathBuf> {
    let mut configs = BTreeSet::new();
    let root_config = root.join("tsconfig.json");
    if !matches!(inputs.try_is_file(&root_config), Ok(false)) {
        configs.insert(root_config);
    }
    for rel_path in rel_paths {
        let source_path = root.join(rel_path);
        let Some(mut dir) = source_path.parent() else {
            continue;
        };
        loop {
            if !dir.starts_with(root) {
                break;
            }
            let config = dir.join("tsconfig.json");
            if !matches!(inputs.try_is_file(&config), Ok(false)) {
                configs.insert(config);
            }
            if dir == root {
                break;
            }
            let Some(parent) = dir.parent() else {
                break;
            };
            dir = parent;
        }
    }
    configs.into_iter().collect()
}

fn type_package_dir_name(type_name: &str) -> String {
    if let Some(scoped) = type_name.strip_prefix('@') {
        if let Some((scope, name)) = scoped.split_once('/') {
            return format!("{scope}__{name}");
        }
    }
    type_name.to_string()
}

fn type_package_entry_candidates(inputs: ReadOnlyFiles<'_>, package_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let package_json = package_dir.join("package.json");
    if let Ok(raw) = inputs.read_to_string(&package_json) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(&raw)) {
            for key in ["types", "typings"] {
                if let Some(entry) = json.get(key).and_then(|v| v.as_str()) {
                    out.push(package_dir.join(entry));
                }
            }
        }
    }
    out.push(package_dir.join("index.d.ts"));
    out
}

fn resolve_type_package_file(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    config_dir: &Path,
    type_name: &str,
) -> Option<PathBuf> {
    let package_dir_name = type_package_dir_name(type_name);
    for ancestor in config_dir.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        let package_dir = ancestor
            .join("node_modules")
            .join("@types")
            .join(&package_dir_name);
        if !package_dir.is_dir() {
            continue;
        }
        for candidate in type_package_entry_candidates(inputs, &package_dir) {
            if inputs.is_file(&candidate) {
                return candidate.canonicalize().ok();
            }
            let index = candidate.join("index.d.ts");
            if inputs.is_file(&index) {
                return index.canonicalize().ok();
            }
        }
    }
    None
}

fn collect_type_package_reference_files(
    root: &Path,
    file: PathBuf,
    seen: &mut BTreeSet<PathBuf>,
    files: &mut Vec<PathBuf>,
    read_source: &mut impl FnMut(&Path) -> Option<Vec<u8>>,
) {
    let Ok(file) = file.canonicalize() else {
        return;
    };
    if !file.starts_with(root) || !seen.insert(file.clone()) {
        return;
    }
    files.push(file.clone());

    let Some(bytes) = read_source(&file) else {
        return;
    };
    let Some(parent) = file.parent() else {
        return;
    };
    for directive in repotoire::ts::directives::scan_leading_triple_slash_directives(&bytes) {
        let specifier = directive.specifier.as_str();
        if !(specifier == "."
            || specifier == ".."
            || specifier.starts_with("./")
            || specifier.starts_with("../"))
        {
            continue;
        }
        let candidate = parent.join(specifier);
        let candidate = if candidate.is_file() {
            candidate
        } else {
            let with_dts = candidate.with_extension("d.ts");
            if with_dts.is_file() {
                with_dts
            } else {
                let index = candidate.join("index.d.ts");
                if index.is_file() {
                    index
                } else {
                    continue;
                }
            }
        };
        collect_type_package_reference_files(root, candidate, seen, files, read_source);
    }
}

/// Declaration files pulled into global scope by explicit
/// `compilerOptions.types` entries. This is intentionally bounded: it does not
/// crawl `node_modules`; it resolves only the packages the project's tsconfig
/// names plus declaration files reached through relative triple-slash `path`
/// directives from those entries, using the same `@types/foo` /
/// `@types/scope__pkg` convention as TypeScript.
/// The caller owns source admission. Rejected or unavailable source bytes do
/// not contribute transitive reference directives.
pub(crate) fn explicit_type_package_files(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    mut read_source: impl FnMut(&Path) -> Option<Vec<u8>>,
) -> Vec<PathBuf> {
    let mut scopes: Vec<PathBuf> = find_tsconfigs(inputs, root);
    let mut referenced: Vec<PathBuf> = scopes
        .iter()
        .flat_map(|c| referenced_configs(inputs, c))
        .collect();
    scopes.append(&mut referenced);
    scopes.sort();
    scopes.dedup();

    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for config in &scopes {
        let Some(types) = load_resolved(inputs, config, root, 0).types else {
            continue;
        };
        let config_dir = config.parent().unwrap_or(root);
        for type_name in types {
            if let Some(file) = resolve_type_package_file(inputs, root, config_dir, &type_name) {
                collect_type_package_reference_files(
                    root,
                    file,
                    &mut seen,
                    &mut files,
                    &mut read_source,
                );
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn ts_lib_file_name(lib_name: &str) -> Option<String> {
    let name = lib_name.trim().to_ascii_lowercase();
    if name.is_empty()
        || name
            .bytes()
            .any(|b| !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return None;
    }
    if name.starts_with("lib.") && name.ends_with(".d.ts") {
        return Some(name);
    }
    let normalized = match name.as_str() {
        "es6" => "es2015",
        "es7" => "es2016",
        other => other,
    };
    Some(format!("lib.{normalized}.d.ts"))
}

fn resolve_ts_lib_file(root: &Path, config_dir: &Path, lib_name: &str) -> Option<PathBuf> {
    let file_name = ts_lib_file_name(lib_name)?;
    for ancestor in config_dir.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        let candidate = ancestor
            .join("node_modules")
            .join("typescript")
            .join("lib")
            .join(&file_name);
        if candidate.is_file() {
            return candidate.canonicalize().ok();
        }
    }
    None
}

fn reference_attr_value(line: &str, attr: &str) -> Option<String> {
    let reference_start = line.find("<reference")?;
    let mut rest = &line[reference_start + "<reference".len()..];
    loop {
        rest = rest.trim_start();
        if rest.starts_with("/>") || rest.starts_with('>') || rest.is_empty() {
            return None;
        }
        let name_len = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphabetic() || *b == b'-')
            .count();
        if name_len == 0 {
            return None;
        }
        let name = &rest[..name_len];
        rest = rest[name_len..].trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        rest = rest[1..].trim_start();
        let quote = rest.as_bytes().first().copied()?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        rest = &rest[1..];
        let end = rest.bytes().position(|b| b == quote)?;
        let value = &rest[..end];
        if name == attr {
            return Some(value.to_string());
        }
        rest = &rest[end + 1..];
    }
}

fn scan_leading_reference_libs(source: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(source);
    let mut libs = Vec::new();
    let mut in_block_comment = false;
    for line in text.lines() {
        let mut trimmed = line.trim_start();
        if in_block_comment {
            if let Some(end) = trimmed.find("*/") {
                in_block_comment = false;
                trimmed = trimmed[end + 2..].trim_start();
            } else {
                continue;
            }
        }
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("/*") {
            if let Some(end) = trimmed.find("*/") {
                trimmed = trimmed[end + 2..].trim_start();
                if trimmed.is_empty() {
                    continue;
                }
            } else {
                in_block_comment = true;
                continue;
            }
        }
        if trimmed.starts_with("///") {
            if let Some(lib) = reference_attr_value(trimmed, "lib") {
                libs.push(lib);
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        break;
    }
    libs
}

fn collect_ts_lib_reference_files(
    root: &Path,
    file: PathBuf,
    seen: &mut BTreeSet<PathBuf>,
    files: &mut Vec<PathBuf>,
    read_source: &mut impl FnMut(&Path) -> Option<Vec<u8>>,
) {
    let Ok(file) = file.canonicalize() else {
        return;
    };
    if !file.starts_with(root) || !seen.insert(file.clone()) {
        return;
    }
    files.push(file.clone());

    let Some(bytes) = read_source(&file) else {
        return;
    };
    let Some(parent) = file.parent() else {
        return;
    };
    for lib in scan_leading_reference_libs(&bytes) {
        let Some(file_name) = ts_lib_file_name(&lib) else {
            continue;
        };
        let candidate = parent.join(file_name);
        if candidate.is_file() {
            collect_ts_lib_reference_files(root, candidate, seen, files, read_source);
        }
    }
}

/// TypeScript built-in declaration files pulled into global scope by explicit
/// `compilerOptions.lib` entries. Bounded to discovered configs and their
/// `extends`/`references`, plus nested `/// <reference lib="..." />` entries
/// from the selected TypeScript lib files.
/// Source reads use the caller's admission policy, including recursive libs.
pub(crate) fn explicit_lib_files(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    mut read_source: impl FnMut(&Path) -> Option<Vec<u8>>,
) -> Vec<PathBuf> {
    let mut scopes: Vec<PathBuf> = find_tsconfigs(inputs, root);
    let mut referenced: Vec<PathBuf> = scopes
        .iter()
        .flat_map(|c| referenced_configs(inputs, c))
        .collect();
    scopes.append(&mut referenced);
    scopes.sort();
    scopes.dedup();

    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for config in &scopes {
        let Some(libs) = load_resolved(inputs, config, root, 0).libs else {
            continue;
        };
        let config_dir = config.parent().unwrap_or(root);
        for lib in libs {
            if let Some(file) = resolve_ts_lib_file(root, config_dir, &lib) {
                collect_ts_lib_reference_files(root, file, &mut seen, &mut files, &mut read_source);
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

// ---------------------------------------------------------------------------
// graph_input_hash compatibility: config-file inputs
// ---------------------------------------------------------------------------

/// A config file whose contents affect module/alias resolution, contributing to
/// `graph_input_hash`. `key` is a stable, machine-portable logical identifier;
/// `bytes` is the raw file content, or `None` when the file is referenced (via
/// `extends`) but unreadable — hashed as a stable "missing" marker so a later
/// appearance/disappearance still busts the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashConfigInput {
    pub key: String,
    pub bytes: Option<Vec<u8>>,
}

/// Stable, portable hash key for a config file. Targets under `root` (incl.
/// `node_modules/<pkg>/...`, whose install path is project-relative-stable) are
/// keyed by their project-relative slash path. A target that escapes the project
/// root (e.g. `extends: "../../shared/tsconfig.json"`) is keyed by the `extends`
/// specifier that pulled it in — content still hashed, key stays machine-portable.
fn config_hash_key(path: &Path, root: &Path, via_spec: &str) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!(
            "tsconfig:{}",
            rel.to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
        ),
        Err(_) => format!("tsconfig-extends:{via_spec}"),
    }
}

/// Walk a config and its full `extends` chain, recording each visited file's raw
/// bytes under a stable key. Covers in-tree non-standard-named bases (e.g.
/// `tsconfig.base.json`, which `find_tsconfigs` does NOT discover) and external
/// / `node_modules` bases. Unresolved/unreadable targets record a `None` marker
/// + a diagnostic.
fn visit_extends_chain(
    config_path: &Path,
    root: &Path,
    logical_key: String,
    map: &mut BTreeMap<String, Option<Vec<u8>>>,
    diags: &mut Vec<String>,
    depth: usize,
) {
    if depth > 16 || map.contains_key(&logical_key) {
        return;
    }
    let bytes = std::fs::read(config_path).ok();
    if bytes.is_none() {
        diags.push(format!(
            "graph_input_hash: unreadable tsconfig `{logical_key}` ({})",
            config_path.display()
        ));
    }
    let parsed = bytes
        .as_deref()
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&strip_jsonc(s)).ok());
    map.insert(logical_key.clone(), bytes);

    let Some(json) = parsed else { return };
    let config_dir = config_path.parent().unwrap_or(root);
    for ext in extends_specs(&json) {
        match resolve_extends(ReadOnlyFiles::Repository, ext, config_dir, root) {
            Ok(base) => {
                let key = config_hash_key(&base, root, ext);
                visit_extends_chain(&base, root, key, map, diags, depth + 1);
            }
            Err(_) => {
                let key = format!("tsconfig-extends-missing:{ext}");
                if map.insert(key, None).is_none() {
                    diags.push(format!(
                        "graph_input_hash: unresolved extends `{ext}` from `{logical_key}`"
                    ));
                }
            }
        }
    }
}

/// The relative-slash path of a file under `root` (fallback: lossy full path).
fn rel_slash(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// Collect every config file whose contents affect module/alias resolution, for
/// the `graph_input_hash`: all discovered `tsconfig.json` + their `references`,
/// the full `extends` chain of each (in-tree non-standard bases AND external /
/// `node_modules` bases), and all in-project `package.json` (whole-file). Keyed
/// stably & portably; unreadable external targets yield a `None` entry + a
/// diagnostic. Deterministic (BTreeMap-ordered).
pub fn collect_hash_config_inputs(root: &Path) -> (Vec<HashConfigInput>, Vec<String>) {
    collect_hash_config_inputs_from_roots(
        root,
        find_tsconfigs(ReadOnlyFiles::Repository, root),
        None,
    )
}

pub fn collect_hash_config_inputs_for_source_paths(
    root: &Path,
    rel_paths: &[&str],
) -> (Vec<HashConfigInput>, Vec<String>) {
    collect_hash_config_inputs_from_roots(
        root,
        tsconfigs_for_source_paths(ReadOnlyFiles::Repository, root, rel_paths),
        Some(rel_paths),
    )
}

fn collect_hash_config_inputs_from_roots(
    root: &Path,
    mut roots: Vec<PathBuf>,
    rel_paths: Option<&[&str]>,
) -> (Vec<HashConfigInput>, Vec<String>) {
    let mut map: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut diags: Vec<String> = Vec::new();

    // tsconfig.json (+ `references`) and every config in their `extends` chains.
    let refs: Vec<PathBuf> = roots
        .iter()
        .flat_map(|c| referenced_configs(ReadOnlyFiles::Repository, c))
        .collect();
    roots.extend(refs);
    roots.sort();
    roots.dedup();
    for cfg in &roots {
        let key = config_hash_key(cfg, root, "");
        visit_extends_chain(cfg, root, key, &mut map, &mut diags, 0);
    }

    // package.json (whole-file — name/exports/workspaces all affect resolution).
    let mut pkgs = match rel_paths {
        Some(rel_paths) => {
            package_jsons_for_source_paths(ReadOnlyFiles::Repository, root, rel_paths)
        }
        None => {
            let mut pkgs = Vec::new();
            collect_package_jsons(root, 0, &mut pkgs);
            pkgs
        }
    };
    pkgs.sort();
    pkgs.dedup();
    for pkg in &pkgs {
        let key = format!("package_json:{}", rel_slash(root, pkg));
        if map.contains_key(&key) {
            continue;
        }
        match std::fs::read(pkg) {
            Ok(b) => {
                map.insert(key, Some(b));
            }
            Err(e) => {
                diags.push(format!(
                    "graph_input_hash: unreadable package.json `{key}`: {e}"
                ));
                map.insert(key, None);
            }
        }
    }

    for file in explicit_type_package_files(ReadOnlyFiles::Repository, root, |path| {
        std::fs::read(path).ok()
    }) {
        let key = format!("types_package:{}", rel_slash(root, &file));
        if map.contains_key(&key) {
            continue;
        }
        match std::fs::read(&file) {
            Ok(b) => {
                map.insert(key, Some(b));
            }
            Err(e) => {
                diags.push(format!(
                    "graph_input_hash: unreadable explicit types package `{key}`: {e}"
                ));
                map.insert(key, None);
            }
        }
    }
    for file in explicit_lib_files(ReadOnlyFiles::Repository, root, |path| {
        std::fs::read(path).ok()
    }) {
        let key = format!("ts_lib:{}", rel_slash(root, &file));
        if map.contains_key(&key) {
            continue;
        }
        match std::fs::read(&file) {
            Ok(b) => {
                map.insert(key, Some(b));
            }
            Err(e) => {
                diags.push(format!(
                    "graph_input_hash: unreadable explicit ts lib `{key}`: {e}"
                ));
                map.insert(key, None);
            }
        }
    }

    let inputs = map
        .into_iter()
        .map(|(key, bytes)| HashConfigInput { key, bytes })
        .collect();
    (inputs, diags)
}

fn package_jsons_for_source_paths(
    inputs: ReadOnlyFiles<'_>,
    root: &Path,
    rel_paths: &[&str],
) -> Vec<PathBuf> {
    let mut packages = BTreeSet::new();
    let root_pkg = root.join("package.json");
    if inputs.is_file(&root_pkg) {
        packages.insert(root_pkg);
    }
    for rel_path in rel_paths {
        let source_path = root.join(rel_path);
        let Some(mut dir) = source_path.parent() else {
            continue;
        };
        loop {
            if !dir.starts_with(root) {
                break;
            }
            let package_json = dir.join("package.json");
            if inputs.is_file(&package_json) {
                packages.insert(package_json);
            }
            if dir == root {
                break;
            }
            let Some(parent) = dir.parent() else {
                break;
            };
            dir = parent;
        }
    }
    packages.into_iter().collect()
}
