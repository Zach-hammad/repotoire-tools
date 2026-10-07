//! Import-specifier path canonicalization. See spec §6.5.

/// The filesystem portion of an import specifier. Loader queries and URL
/// fragments select a representation of the same path; they are not part of
/// its project-file identity.
pub(crate) fn specifier_path(specifier: &str) -> &str {
    specifier.split(['?', '#']).next().unwrap_or(specifier)
}

/// True for a relative import specifier (`./x`, `../x`). A relative specifier
/// that fails to canonicalize is a genuine phantom (missing local file); a
/// NON-relative specifier (`idb`, `react`, `@scope/pkg`, `node:fs`) is a bare
/// package import that resolves to an External(ImportedPackage), not a phantom.
pub fn is_relative_specifier(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
}

/// True for a web/URI module specifier — `data:`, `file://`, `http://`,
/// `https://` (known-v1-gaps #28). These are valid module specifiers per the
/// HTML/JS spec but are NOT npm packages, so the resolver tags them
/// `External(Unknown)` rather than `External(ImportedPackage)` (which would
/// inflate npm-dependency counts). `node:` builtins are intentionally excluded
/// — they remain package-like.
pub fn is_external_uri_specifier(specifier: &str) -> bool {
    specifier.starts_with("data:")
        || specifier.starts_with("file://")
        || specifier.starts_with("http://")
        || specifier.starts_with("https://")
}

pub fn canonicalize_import(
    importing_path: &str,
    specifier: &str,
    project_files: &std::collections::BTreeMap<String, usize>,
    alias_map: &crate::ts::alias::AliasMap,
) -> Option<String> {
    let mut alias_candidates = Vec::new();
    canonicalize_import_with_scratch(
        importing_path,
        specifier,
        project_files,
        alias_map,
        &mut alias_candidates,
    )
}

pub fn relative_import_probe_paths(importing_path: &str, specifier: &str) -> Vec<String> {
    let specifier = specifier_path(specifier);
    if !is_relative_specifier(specifier) {
        return Vec::new();
    }
    let base_dir = importing_path
        .rsplit_once('/')
        .map(|(d, _)| d)
        .unwrap_or(".");
    let normalized = normalize_path(&format!("{}/{}", base_dir, specifier));
    probe_paths_for_normalized(&normalized, importer_prefers_runtime_js(importing_path))
}

pub(crate) fn canonicalize_import_with_scratch(
    importing_path: &str,
    specifier: &str,
    project_files: &std::collections::BTreeMap<String, usize>,
    alias_map: &crate::ts::alias::AliasMap,
    alias_candidates: &mut Vec<String>,
) -> Option<String> {
    let specifier = specifier_path(specifier);
    let prefer_runtime_js = importer_prefers_runtime_js(importing_path);
    // 1. Relative specifier: resolve against the importing file's directory.
    if is_relative_specifier(specifier) {
        let base_dir = importing_path
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap_or(".");
        let normalized = normalize_path(&format!("{}/{}", base_dir, specifier));
        return probe_path(&normalized, project_files, prefer_runtime_js);
    }
    // 2. tsconfig alias: try each candidate target (already project-relative).
    alias_map.resolve_into(specifier, importing_path, alias_candidates);
    for cand in alias_candidates.iter() {
        if let Some(hit) = probe_path(
            &normalize_path(cand.as_str()),
            project_files,
            prefer_runtime_js,
        ) {
            return Some(hit);
        }
    }
    // 3. Bare/scoped package with no alias → External (caller's job).
    None
}

/// Probe a normalized `./…` path against the file set: exact, then by
/// extension, then `index.<ext>`. The shared tail of relative and alias
/// resolution.
///
/// TS-source variants (`.ts`/`.tsx`/`.d.ts`) are tried before JS variants for
/// TS importers so a compiled `.js` beside source does not hide the source. JS
/// importers use runtime-first probing so source-only JS exports are not hidden
/// by incomplete declaration siblings.
const TS_PROBE_EXTS: &[&str] = &[".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs"];
const JS_PROBE_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".d.ts"];
const RUNTIME_TO_SOURCE_EXTS: &[(&str, &[&str])] = &[
    (".js", &[".ts", ".tsx", ".d.ts"]),
    (".jsx", &[".tsx"]),
    (".mjs", &[".mts", ".d.mts"]),
    (".cjs", &[".cts", ".d.cts"]),
];

fn importer_prefers_runtime_js(importing_path: &str) -> bool {
    importing_path.ends_with(".js")
        || importing_path.ends_with(".jsx")
        || importing_path.ends_with(".mjs")
        || importing_path.ends_with(".cjs")
}

fn probe_path(
    normalized: &str,
    project_files: &std::collections::BTreeMap<String, usize>,
    prefer_runtime_js: bool,
) -> Option<String> {
    if prefer_runtime_js {
        if project_files.contains_key(normalized) {
            return Some(normalized.to_string());
        }
        for ext in JS_PROBE_EXTS {
            let with_ext = format!("{}{}", normalized, ext);
            if project_files.contains_key(&with_ext) {
                return Some(with_ext);
            }
        }
        for ext in JS_PROBE_EXTS {
            let idx_path = format!("{}/index{}", normalized, ext);
            if project_files.contains_key(&idx_path) {
                return Some(idx_path);
            }
        }
        if let Some(hit) = probe_runtime_source_rewrite(normalized, project_files) {
            return Some(hit);
        }
        return None;
    }
    if let Some(hit) = probe_runtime_source_rewrite(normalized, project_files) {
        return Some(hit);
    }
    if project_files.contains_key(normalized) {
        return Some(normalized.to_string());
    }
    for ext in TS_PROBE_EXTS {
        let with_ext = format!("{}{}", normalized, ext);
        if project_files.contains_key(&with_ext) {
            return Some(with_ext);
        }
    }
    for ext in TS_PROBE_EXTS {
        let idx_path = format!("{}/index{}", normalized, ext);
        if project_files.contains_key(&idx_path) {
            return Some(idx_path);
        }
    }
    None
}

fn probe_paths_for_normalized(normalized: &str, prefer_runtime_js: bool) -> Vec<String> {
    let mut paths = Vec::new();
    if prefer_runtime_js {
        paths.push(normalized.to_string());
        for ext in JS_PROBE_EXTS {
            paths.push(format!("{}{}", normalized, ext));
        }
        for ext in JS_PROBE_EXTS {
            paths.push(format!("{}/index{}", normalized, ext));
        }
        push_runtime_source_rewrite_probe_paths(normalized, &mut paths);
        return paths;
    }

    push_runtime_source_rewrite_probe_paths(normalized, &mut paths);
    paths.push(normalized.to_string());
    for ext in TS_PROBE_EXTS {
        paths.push(format!("{}{}", normalized, ext));
    }
    for ext in TS_PROBE_EXTS {
        paths.push(format!("{}/index{}", normalized, ext));
    }
    paths
}

fn probe_runtime_source_rewrite(
    normalized: &str,
    project_files: &std::collections::BTreeMap<String, usize>,
) -> Option<String> {
    for (runtime_ext, source_exts) in RUNTIME_TO_SOURCE_EXTS {
        let Some(base) = normalized.strip_suffix(runtime_ext) else {
            continue;
        };
        for source_ext in *source_exts {
            let candidate = format!("{base}{source_ext}");
            if project_files.contains_key(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn push_runtime_source_rewrite_probe_paths(normalized: &str, paths: &mut Vec<String>) {
    for (runtime_ext, source_exts) in RUNTIME_TO_SOURCE_EXTS {
        let Some(base) = normalized.strip_suffix(runtime_ext) else {
            continue;
        };
        for source_ext in *source_exts {
            paths.push(format!("{base}{source_ext}"));
        }
    }
}

pub(crate) fn normalize_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                // Don't pop above the project root. A `..` that would escape
                // the root must be PRESERVED so the result stays out-of-root
                // (failing to match any internal `./x` key → phantom), rather
                // than silently collapsing `../../x` to `./x` and falsely
                // resolving it as internal. Pop only a real prior segment; at
                // root, or when the previous entry is itself a `..`, keep it.
                if out.last().is_none_or(|s| *s == "..") {
                    out.push("..");
                } else {
                    out.pop();
                }
            }
            _ => out.push(seg),
        }
    }
    if out.is_empty() {
        ".".to_string()
    } else {
        format!("./{}", out.join("/"))
    }
}
