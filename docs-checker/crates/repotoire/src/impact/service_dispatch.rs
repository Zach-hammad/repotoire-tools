use crate::archive::SourceBundle;
use crate::csr::SpanView;
use crate::ids::NodeId;
use crate::impact::deadline::{ImpactDeadline, ImpactDeadlineExceeded};
use crate::schema::{EdgeKind, NodeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum ServiceMethodDispatchKind {
    DynamicImportBinding,
    NamespaceImport,
    YieldStarAcquisition,
    InjectAcquisition,
    ContainerGetAcquisition,
    ContainerResolveAcquisition,
    ResolveAcquisition,
    GetServiceAcquisition,
    DestructuredBinding,
    DestructuredServiceAcquisition,
}

impl ServiceMethodDispatchKind {
    pub fn label(self) -> &'static str {
        match self {
            ServiceMethodDispatchKind::DynamicImportBinding => {
                "verified_static service method call via dynamic import binding"
            }
            ServiceMethodDispatchKind::NamespaceImport => {
                "verified_static service method call via namespace import"
            }
            ServiceMethodDispatchKind::YieldStarAcquisition => {
                "possible_static service method call via yield* service acquisition binding"
            }
            ServiceMethodDispatchKind::InjectAcquisition => {
                "possible_static service method call via inject() service acquisition binding"
            }
            ServiceMethodDispatchKind::ContainerGetAcquisition => {
                "possible_static service method call via container.get() service acquisition binding"
            }
            ServiceMethodDispatchKind::ContainerResolveAcquisition => {
                "possible_static service method call via container.resolve() service acquisition binding"
            }
            ServiceMethodDispatchKind::ResolveAcquisition => {
                "possible_static service method call via resolve() service acquisition binding"
            }
            ServiceMethodDispatchKind::GetServiceAcquisition => {
                "possible_static service method call via getService() service acquisition binding"
            }
            ServiceMethodDispatchKind::DestructuredBinding => {
                "possible_static service method call via destructured binding"
            }
            ServiceMethodDispatchKind::DestructuredServiceAcquisition => {
                "possible_static service method call via destructured service acquisition binding"
            }
        }
    }

    pub fn caveat(self) -> &'static str {
        match self {
            ServiceMethodDispatchKind::DynamicImportBinding
            | ServiceMethodDispatchKind::NamespaceImport => {
                "module binding resolves to the declaration file; TypeScript symbol identity is not proven"
            }
            ServiceMethodDispatchKind::DestructuredBinding => {
                "destructured binding is source-tracked from the module binding; TypeScript symbol identity is not proven"
            }
            ServiceMethodDispatchKind::YieldStarAcquisition
            | ServiceMethodDispatchKind::InjectAcquisition
            | ServiceMethodDispatchKind::ContainerGetAcquisition
            | ServiceMethodDispatchKind::ContainerResolveAcquisition
            | ServiceMethodDispatchKind::ResolveAcquisition
            | ServiceMethodDispatchKind::GetServiceAcquisition
            | ServiceMethodDispatchKind::DestructuredServiceAcquisition => {
                "service binding is source-tracked from an imported token; TypeScript symbol identity is not proven"
            }
        }
    }

    fn destructured_kind(self) -> Self {
        match self {
            ServiceMethodDispatchKind::YieldStarAcquisition
            | ServiceMethodDispatchKind::InjectAcquisition
            | ServiceMethodDispatchKind::ContainerGetAcquisition
            | ServiceMethodDispatchKind::ContainerResolveAcquisition
            | ServiceMethodDispatchKind::ResolveAcquisition
            | ServiceMethodDispatchKind::GetServiceAcquisition => {
                ServiceMethodDispatchKind::DestructuredServiceAcquisition
            }
            _ => ServiceMethodDispatchKind::DestructuredBinding,
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct ServiceModuleBinding {
    name: String,
    kind: ServiceMethodDispatchKind,
    trace: Vec<ServiceDispatchTraceStep>,
    service_token: Option<String>,
}

struct DestructuredServiceMethodAlias {
    alias: String,
    bound_line: u32,
    kind: ServiceMethodDispatchKind,
    trace: Vec<ServiceDispatchTraceStep>,
    service_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceMethodDispatchSite {
    /// Captured source and resolved module endpoint used by this inference.
    pub contributing_files: std::collections::BTreeSet<String>,
    pub file: String,
    pub line: u32,
    pub call: String,
    pub kind: ServiceMethodDispatchKind,
    pub trace: Vec<ServiceDispatchTraceStep>,
    pub service_token: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct ServiceTokenSource {
    name: String,
    trace: Vec<ServiceDispatchTraceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceDispatchTraceStep {
    pub text: String,
}

impl ServiceDispatchTraceStep {
    fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

pub(crate) fn collect_service_method_dispatch<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file: Option<NodeId>,
    name: &str,
    deadline: &D,
) -> Result<Vec<ServiceMethodDispatchSite>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let Some(decl_file_id) = decl_file else {
        return Ok(Vec::new());
    };
    if graph.node_kind(decl) != NodeKind::Property {
        return Ok(Vec::new());
    }
    let Some(owner) = graph.incoming(decl, EdgeKind::Contains).next() else {
        return Ok(Vec::new());
    };
    if graph.node_kind(owner) == NodeKind::File {
        return Ok(Vec::new());
    }

    let mut rows = Vec::new();
    for (slot, edge) in graph
        .in_slots(decl_file_id, EdgeKind::Imports)
        .zip(span_view.in_edges(decl_file_id, EdgeKind::Imports))
    {
        deadline.check()?;
        let Some(source_file) = graph.file_of(edge.source) else {
            continue;
        };
        if source_file == decl_file_id {
            continue;
        }
        let Some(span) = edge.span else {
            continue;
        };
        let Some(import_line) = source_line_at_offset(bundle, source_file, span.start()) else {
            continue;
        };
        let import_line_number = source_line_number_at_offset(bundle, source_file, span.start());
        let file = graph.node_name(source_file).to_string();
        let lines = source_lines(bundle, source_file);
        let mut bindings =
            service_module_bindings_from_import_line(&file, import_line_number, &import_line);
        let mut imported_service_tokens = graph
            .edge_label_str(
                EdgeKind::Imports,
                span_view.in_to_out(EdgeKind::Imports, slot),
            )
            .map(|label| import_label_local_value_tokens(label, &file, import_line_number))
            .unwrap_or_default();
        imported_service_tokens.extend(dynamic_import_destructured_tokens(
            &file,
            import_line_number,
            &import_line,
        ));
        if let Some(import_line_number) = import_line_number {
            imported_service_tokens.extend(promise_all_destructured_tokens(
                &file,
                &lines,
                import_line_number,
                deadline,
            )?);
        }
        imported_service_tokens
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.trace.len().cmp(&b.trace.len())));
        imported_service_tokens.dedup_by(|a, b| a.name == b.name);
        bindings.extend(service_acquisition_bindings_from_lines(
            &file,
            &lines,
            &imported_service_tokens,
            deadline,
        )?);
        collect_direct_destructured_service_acquisition_calls(
            &mut rows,
            &file,
            &lines,
            &imported_service_tokens,
            name,
            deadline,
        )?;
        if bindings.is_empty() {
            continue;
        }
        bindings.sort_by(|a, b| a.name.cmp(&b.name).then(a.kind.cmp(&b.kind)));
        bindings.dedup_by(|a, b| a.name == b.name && a.kind == b.kind);
        collect_direct_service_method_calls(&mut rows, &file, &lines, &bindings, name, deadline)?;
        collect_destructured_service_method_calls(
            &mut rows, &file, &lines, &bindings, name, deadline,
        )?;
    }

    for row in &mut rows {
        deadline.check()?;
        row.contributing_files.insert(row.file.clone());
        row.contributing_files
            .insert(graph.node_name(decl_file_id).to_owned());
    }

    rows.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.kind.cmp(&b.kind))
            .then(a.call.cmp(&b.call))
    });
    rows.dedup_by(|a, b| {
        a.file == b.file && a.line == b.line && a.call == b.call && a.kind == b.kind
    });
    deadline.check()?;
    Ok(rows)
}

fn service_module_bindings_from_import_line(
    file: &str,
    line_number: Option<u32>,
    line: &str,
) -> Vec<ServiceModuleBinding> {
    let mut out = Vec::new();
    if let Some(name) = namespace_import_binding_name(line) {
        let trace = line_number
            .map(|line| {
                vec![ServiceDispatchTraceStep::new(format!(
                    "namespace import binding `{name}` at `{file}:L{line}`"
                ))]
            })
            .unwrap_or_default();
        out.push(ServiceModuleBinding {
            name,
            kind: ServiceMethodDispatchKind::NamespaceImport,
            trace,
            service_token: None,
        });
    }
    if let Some(name) = dynamic_import_binding_name(line) {
        let trace = line_number
            .map(|line| {
                vec![ServiceDispatchTraceStep::new(format!(
                    "dynamic import binding `{name}` at `{file}:L{line}`"
                ))]
            })
            .unwrap_or_default();
        out.push(ServiceModuleBinding {
            name,
            kind: ServiceMethodDispatchKind::DynamicImportBinding,
            trace,
            service_token: None,
        });
    }
    out
}

fn service_acquisition_bindings_from_lines<D: ImpactDeadline + ?Sized>(
    file: &str,
    lines: &[(u32, String)],
    imported_service_tokens: &[ServiceTokenSource],
    deadline: &D,
) -> Result<Vec<ServiceModuleBinding>, ImpactDeadlineExceeded> {
    if imported_service_tokens.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (line_number, line) in lines {
        deadline.check()?;
        for token in imported_service_tokens {
            if let Some(name) = yield_star_acquisition_binding_name(line, &token.name) {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("yield* {}", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::YieldStarAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
            if let Some(name) = bare_call_acquisition_binding_name(line, "inject", &token.name) {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("inject({})", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::InjectAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
            if let Some(name) =
                service_locator_member_acquisition_binding_name(line, "get", &token.name)
            {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("container.get({})", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::ContainerGetAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
            if let Some(name) =
                service_locator_member_acquisition_binding_name(line, "resolve", &token.name)
            {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("container.resolve({})", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::ContainerResolveAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
            if let Some(name) = bare_call_acquisition_binding_name(line, "resolve", &token.name) {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("resolve({})", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::ResolveAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
            if let Some(name) = bare_call_acquisition_binding_name(line, "getService", &token.name)
            {
                out.push(ServiceModuleBinding {
                    trace: service_acquisition_trace(
                        &token.trace,
                        file,
                        *line_number,
                        &name,
                        &format!("getService({})", token.name),
                    ),
                    name,
                    kind: ServiceMethodDispatchKind::GetServiceAcquisition,
                    service_token: Some(token.name.clone()),
                });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.kind.cmp(&b.kind)));
    out.dedup_by(|a, b| a.name == b.name && a.kind == b.kind);
    Ok(out)
}

fn service_acquisition_trace(
    token_trace: &[ServiceDispatchTraceStep],
    file: &str,
    line: u32,
    binding: &str,
    expression: &str,
) -> Vec<ServiceDispatchTraceStep> {
    let mut trace = token_trace.to_vec();
    trace.push(ServiceDispatchTraceStep::new(format!(
        "service binding `{binding}` from `{expression}` at `{file}:L{line}`"
    )));
    trace
}

fn import_label_local_value_tokens(
    label: &str,
    file: &str,
    line_number: Option<u32>,
) -> Vec<ServiceTokenSource> {
    import_label_local_value_names(label)
        .into_iter()
        .map(|name| {
            let trace = line_number
                .map(|line| {
                    vec![ServiceDispatchTraceStep::new(format!(
                        "imported token `{name}` at `{file}:L{line}`"
                    ))]
                })
                .unwrap_or_default();
            ServiceTokenSource { name, trace }
        })
        .collect()
}

fn import_label_local_value_names(label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = label.trim_start();
    if let Some(rest) = trimmed.strip_prefix("default as ") {
        if let Some((name, _)) = identifier_at_start(rest) {
            out.push(name.to_string());
        }
    }

    if let Some(brace_start) = label.find('{') {
        if let Some(brace_end) = label[brace_start..].find('}') {
            let inside = &label[brace_start + 1..brace_start + brace_end];
            for entry in inside.split(',') {
                let entry = entry.trim();
                if entry.is_empty() || entry.starts_with("type ") {
                    continue;
                }
                if let Some(as_pos) = entry.find(" as ") {
                    let local = entry[as_pos + 4..].trim();
                    if let Some((name, _)) = identifier_at_start(local) {
                        out.push(name.to_string());
                    }
                    continue;
                }
                if let Some((name, _)) = identifier_at_start(entry) {
                    out.push(name.to_string());
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn dynamic_import_destructured_tokens(
    file: &str,
    line_number: Option<u32>,
    line: &str,
) -> Vec<ServiceTokenSource> {
    if find_dynamic_import_call(line).is_none() {
        return Vec::new();
    }
    let Some(eq_pos) = line.find('=') else {
        return Vec::new();
    };
    destructured_lhs_local_names(&line[..eq_pos])
        .into_iter()
        .map(|name| {
            let trace = line_number
                .map(|line| {
                    vec![ServiceDispatchTraceStep::new(format!(
                        "token `{name}` from dynamic import destructure at `{file}:L{line}`"
                    ))]
                })
                .unwrap_or_default();
            ServiceTokenSource { name, trace }
        })
        .collect()
}

fn promise_all_destructured_tokens<D: ImpactDeadline + ?Sized>(
    file: &str,
    lines: &[(u32, String)],
    import_line_number: u32,
    deadline: &D,
) -> Result<Vec<ServiceTokenSource>, ImpactDeadlineExceeded> {
    let Some((start_idx, start_line_number, lhs, array_start)) =
        promise_all_assignment_start(lines, import_line_number, deadline)?
    else {
        return Ok(Vec::new());
    };
    let Some(element_index) = promise_all_element_index_at_import(
        lines,
        start_idx,
        array_start,
        import_line_number,
        deadline,
    )?
    else {
        return Ok(Vec::new());
    };
    let elements = array_destructure_elements(&lhs);
    let Some(element) = elements.get(element_index) else {
        return Ok(Vec::new());
    };
    let import_trace = dynamic_import_call_text(
        lines
            .iter()
            .find(|(line_number, _)| *line_number == import_line_number)
            .map(|(_, text)| text.as_str())
            .unwrap_or(""),
    )
    .map(|call| {
        ServiceDispatchTraceStep::new(format!(
            "dynamic import `{call}` at `{file}:L{import_line_number}`"
        ))
    });
    Ok(destructured_lhs_local_names(element)
        .into_iter()
        .map(|name| {
            let mut trace = Vec::new();
            if let Some(import_trace) = import_trace.clone() {
                trace.push(import_trace);
            }
            trace.push(ServiceDispatchTraceStep::new(format!(
                "token `{name}` from Promise.all element {element} at `{file}:L{start_line_number}`",
                element = element_index + 1,
            )));
            ServiceTokenSource { name, trace }
        })
        .collect())
}

fn promise_all_assignment_start<D: ImpactDeadline + ?Sized>(
    lines: &[(u32, String)],
    import_line_number: u32,
    deadline: &D,
) -> Result<Option<(usize, u32, String, usize)>, ImpactDeadlineExceeded> {
    let Some(import_idx) = lines
        .iter()
        .position(|(line_number, _)| *line_number == import_line_number)
    else {
        return Ok(None);
    };
    for idx in (0..=import_idx).rev() {
        deadline.check()?;
        let (line_number, text) = &lines[idx];
        let Some(promise_pos) = text.find("Promise.all") else {
            continue;
        };
        let Some(open_rel) = text[promise_pos..].find('[') else {
            continue;
        };
        let Some(eq_pos) = text[..promise_pos].rfind('=') else {
            continue;
        };
        let array_start = promise_pos + open_rel + 1;
        return Ok(Some((
            idx,
            *line_number,
            text[..eq_pos].to_string(),
            array_start,
        )));
    }
    Ok(None)
}

fn promise_all_element_index_at_import<D: ImpactDeadline + ?Sized>(
    lines: &[(u32, String)],
    start_idx: usize,
    array_start: usize,
    import_line_number: u32,
    deadline: &D,
) -> Result<Option<usize>, ImpactDeadlineExceeded> {
    let mut element_index = 0;
    let mut depth = NestingDepth::default();
    for (idx, (line_number, text)) in lines.iter().enumerate().skip(start_idx) {
        deadline.check()?;
        let start = if idx == start_idx { array_start } else { 0 };
        let mut end = text.len();
        if *line_number == import_line_number {
            let Some(import_pos) = find_dynamic_import_call(&text[start..]) else {
                return Ok(None);
            };
            end = start + import_pos;
        }
        element_index += count_top_level_commas(&text[start..end], &mut depth);
        if *line_number == import_line_number {
            return Ok(Some(element_index));
        }
    }
    Ok(None)
}

fn array_destructure_elements(left: &str) -> Vec<String> {
    let Some(open) = left.find('[') else {
        return Vec::new();
    };
    let Some(close) = left.rfind(']') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    split_top_level_commas(&left[open + 1..close])
}

#[derive(Default, serde::Serialize)]
struct NestingDepth {
    paren: u32,
    brace: u32,
    bracket: u32,
}

impl NestingDepth {
    fn is_top_level(&self) -> bool {
        self.paren == 0 && self.brace == 0 && self.bracket == 0
    }

    fn observe(&mut self, ch: char) {
        match ch {
            '(' => self.paren += 1,
            ')' => self.paren = self.paren.saturating_sub(1),
            '{' => self.brace += 1,
            '}' => self.brace = self.brace.saturating_sub(1),
            '[' => self.bracket += 1,
            ']' => self.bracket = self.bracket.saturating_sub(1),
            _ => {}
        }
    }
}

fn count_top_level_commas(text: &str, depth: &mut NestingDepth) -> usize {
    let mut count = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch == ',' && depth.is_top_level() {
            count += 1;
            continue;
        }
        depth.observe(ch);
    }
    count
}

fn split_top_level_commas(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = NestingDepth::default();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut segment_start = 0;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch == ',' && depth.is_top_level() {
            out.push(text[segment_start..idx].trim().to_string());
            segment_start = idx + ch.len_utf8();
            continue;
        }
        depth.observe(ch);
    }
    out.push(text[segment_start..].trim().to_string());
    out
}

fn destructured_lhs_local_names(left: &str) -> Vec<String> {
    let Some(open) = left.find('{') else {
        return Vec::new();
    };
    let Some(close_rel) = left[open + 1..].find('}') else {
        return Vec::new();
    };
    let close = open + 1 + close_rel;
    let inside = &left[open + 1..close];
    let mut names = Vec::new();
    for entry in inside.split(',') {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with("...") {
            continue;
        }
        if let Some(colon) = entry.find(':') {
            let local = entry[colon + 1..].trim();
            if let Some((name, _)) = identifier_at_start(local) {
                names.push(name.to_string());
            }
            continue;
        }
        if let Some((name, _)) = identifier_at_start(entry) {
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn yield_star_acquisition_binding_name(line: &str, token: &str) -> Option<String> {
    let eq_pos = line.find('=')?;
    let rhs = &line[eq_pos + 1..];
    let has_yield_star = rhs.contains("yield*") || rhs.contains("yield *");
    if !has_yield_star || !line_mentions_identifier(rhs, token) {
        return None;
    }
    assignment_binding_before(line, line.len()).map(str::to_string)
}

fn bare_call_acquisition_binding_name(line: &str, call_name: &str, token: &str) -> Option<String> {
    let (call_start, _) = identifier_occurrence(line, call_name, |start, end| {
        if line[..start].ends_with('.') {
            return false;
        }
        first_call_arg_is_token(&line[end..], token)
    })?;
    assignment_binding_before(line, call_start).map(str::to_string)
}

fn service_locator_member_acquisition_binding_name(
    line: &str,
    method: &str,
    token: &str,
) -> Option<String> {
    let needle = format!(".{method}");
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(&needle) {
        let dot = search_from + pos;
        let method_start = dot + 1;
        let method_end = method_start + method.len();
        if line[method_end..].chars().next().is_some_and(is_ident_char) {
            search_from = method_end;
            continue;
        }
        let Some(receiver) = identifier_at_end(&line[..dot]) else {
            search_from = method_end;
            continue;
        };
        if !is_service_locator_receiver(receiver) {
            search_from = method_end;
            continue;
        }
        if first_call_arg_is_token(&line[method_end..], token) {
            return assignment_binding_before(line, dot).map(str::to_string);
        }
        search_from = method_end;
    }
    None
}

fn is_service_locator_receiver(receiver: &str) -> bool {
    matches!(
        receiver,
        "container" | "Container" | "injector" | "Injector" | "moduleRef" | "ModuleRef"
    )
}

fn assignment_binding_before(line: &str, before: usize) -> Option<&str> {
    let prefix = &line[..before];
    let eq_pos = prefix.rfind('=')?;
    let lhs = prefix[..eq_pos].trim_end();
    let lhs_without_type = lhs.rsplit_once(':').map(|(left, _)| left).unwrap_or(lhs);
    identifier_at_end(lhs_without_type)
}

fn first_call_arg_is_token(after_name: &str, token: &str) -> bool {
    let rest = after_name.trim_start();
    let Some(after_open) = rest.strip_prefix('(') else {
        return false;
    };
    let arg = after_open.trim_start();
    let Some((name, end)) = identifier_at_start(arg) else {
        return false;
    };
    name == token && !arg[end..].chars().next().is_some_and(is_ident_char)
}

fn collect_direct_service_method_calls<D: ImpactDeadline + ?Sized>(
    rows: &mut Vec<ServiceMethodDispatchSite>,
    file: &str,
    lines: &[(u32, String)],
    bindings: &[ServiceModuleBinding],
    method: &str,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    for (line, text) in lines {
        deadline.check()?;
        for binding in bindings {
            if line_mentions_member_call(text, &binding.name, method) {
                let mut trace = binding.trace.clone();
                trace.push(ServiceDispatchTraceStep::new(format!(
                    "method call `{}.{}()` at `{file}:L{line}`",
                    binding.name, method
                )));
                rows.push(ServiceMethodDispatchSite {
                    contributing_files: Default::default(),
                    file: file.to_string(),
                    line: *line,
                    call: format!("{}.{}()", binding.name, method),
                    kind: binding.kind,
                    trace,
                    service_token: binding.service_token.clone(),
                });
            }
        }
    }
    Ok(())
}

fn collect_destructured_service_method_calls<D: ImpactDeadline + ?Sized>(
    rows: &mut Vec<ServiceMethodDispatchSite>,
    file: &str,
    lines: &[(u32, String)],
    bindings: &[ServiceModuleBinding],
    method: &str,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    let mut aliases: Vec<DestructuredServiceMethodAlias> = Vec::new();
    for (line, text) in lines {
        deadline.check()?;
        for binding in bindings {
            for alias in destructured_method_aliases(text, &binding.name, method) {
                let mut trace = binding.trace.clone();
                trace.push(ServiceDispatchTraceStep::new(format!(
                    "destructured method binding `{alias}` from `{binding}.{method}` at `{file}:L{line}`",
                    binding = binding.name
                )));
                aliases.push(DestructuredServiceMethodAlias {
                    alias,
                    bound_line: *line,
                    kind: binding.kind.destructured_kind(),
                    trace,
                    service_token: binding.service_token.clone(),
                });
            }
        }
    }
    aliases.sort_by(|a, b| {
        a.alias
            .cmp(&b.alias)
            .then(a.bound_line.cmp(&b.bound_line))
            .then(a.kind.cmp(&b.kind))
    });
    aliases.dedup_by(|a, b| a.alias == b.alias && a.bound_line == b.bound_line && a.kind == b.kind);

    for alias_info in aliases {
        for (line, text) in lines {
            deadline.check()?;
            if *line <= alias_info.bound_line {
                continue;
            }
            if line_mentions_function_call(text, &alias_info.alias) {
                let mut trace = alias_info.trace.clone();
                trace.push(ServiceDispatchTraceStep::new(format!(
                    "method call `{alias}()` at `{file}:L{line}`",
                    alias = alias_info.alias
                )));
                rows.push(ServiceMethodDispatchSite {
                    contributing_files: Default::default(),
                    file: file.to_string(),
                    line: *line,
                    call: format!("{}()", alias_info.alias),
                    kind: alias_info.kind,
                    trace,
                    service_token: alias_info.service_token.clone(),
                });
            }
        }
    }
    Ok(())
}

fn collect_direct_destructured_service_acquisition_calls<D: ImpactDeadline + ?Sized>(
    rows: &mut Vec<ServiceMethodDispatchSite>,
    file: &str,
    lines: &[(u32, String)],
    imported_service_tokens: &[ServiceTokenSource],
    method: &str,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    let mut aliases: Vec<(String, u32, Vec<ServiceDispatchTraceStep>, Option<String>)> = Vec::new();
    for (line, text) in lines {
        deadline.check()?;
        for (alias, trace, service_token) in direct_destructured_service_acquisition_aliases(
            file,
            *line,
            text,
            imported_service_tokens,
            method,
        ) {
            aliases.push((alias, *line, trace, service_token));
        }
    }
    aliases.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    aliases.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    for (alias, bound_line, alias_trace, service_token) in aliases {
        for (line, text) in lines {
            deadline.check()?;
            if *line <= bound_line {
                continue;
            }
            if line_mentions_function_call(text, &alias) {
                let mut trace = alias_trace.clone();
                trace.push(ServiceDispatchTraceStep::new(format!(
                    "method call `{alias}()` at `{file}:L{line}`"
                )));
                rows.push(ServiceMethodDispatchSite {
                    contributing_files: Default::default(),
                    file: file.to_string(),
                    line: *line,
                    call: format!("{alias}()"),
                    kind: ServiceMethodDispatchKind::DestructuredServiceAcquisition,
                    trace,
                    service_token: service_token.clone(),
                });
            }
        }
    }
    Ok(())
}

fn namespace_import_binding_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_import = trimmed.strip_prefix("import")?.trim_start();
    let after_star = after_import.strip_prefix('*')?.trim_start();
    let after_as = after_star.strip_prefix("as")?.trim_start();
    let (name, end) = identifier_at_start(after_as)?;
    let rest = after_as[end..].trim_start();
    if rest.starts_with("from") {
        Some(name.to_string())
    } else {
        None
    }
}

fn dynamic_import_binding_name(line: &str) -> Option<String> {
    let import_pos = find_dynamic_import_call(line)?;
    let prefix = &line[..import_pos];
    let eq_pos = prefix.rfind('=')?;
    identifier_at_end(&prefix[..eq_pos]).map(str::to_string)
}

fn find_dynamic_import_call(line: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find("import") {
        let start = search_from + pos;
        let end = start + "import".len();
        let before = line[..start].chars().next_back();
        let after = line[end..].chars().next();
        if !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char) {
            let rest = line[end..].trim_start();
            if rest.starts_with('(') {
                return Some(start);
            }
        }
        search_from = end;
    }
    None
}

fn dynamic_import_call_text(line: &str) -> Option<String> {
    let start = find_dynamic_import_call(line)?;
    let after_import = &line[start + "import".len()..];
    let open_offset = after_import.find('(')? + start + "import".len();
    let mut depth = 0_u32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in line[open_offset..].char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                let end = open_offset + idx + ch.len_utf8();
                return Some(line[start..end].trim().to_string());
            }
        }
    }
    None
}

fn destructured_method_aliases(line: &str, binding: &str, method: &str) -> Vec<String> {
    let Some(eq_pos) = line.find('=') else {
        return Vec::new();
    };
    if !line_mentions_identifier(&line[eq_pos + 1..], binding) {
        return Vec::new();
    }
    destructured_aliases_from_lhs(&line[..eq_pos], method)
}

fn direct_destructured_service_acquisition_aliases(
    file: &str,
    line_number: u32,
    line: &str,
    imported_service_tokens: &[ServiceTokenSource],
    method: &str,
) -> Vec<(String, Vec<ServiceDispatchTraceStep>, Option<String>)> {
    let Some(eq_pos) = line.find('=') else {
        return Vec::new();
    };
    let Some(token) = acquisition_rhs_imported_token(&line[eq_pos + 1..], imported_service_tokens)
    else {
        return Vec::new();
    };
    destructured_aliases_from_lhs(&line[..eq_pos], method)
        .into_iter()
        .map(|alias| {
            let mut trace = token.trace.clone();
            trace.push(ServiceDispatchTraceStep::new(format!(
                "destructured service method `{alias}` from token `{token}` at `{file}:L{line_number}`",
                token = token.name
            )));
            (alias, trace, Some(token.name.clone()))
        })
        .collect()
}

fn destructured_aliases_from_lhs(left: &str, method: &str) -> Vec<String> {
    let Some(open) = left.find('{') else {
        return Vec::new();
    };
    let Some(close_rel) = left[open + 1..].find('}') else {
        return Vec::new();
    };
    let close = open + 1 + close_rel;
    let inside = &left[open + 1..close];
    let mut aliases = Vec::new();
    for entry in inside.split(',') {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with("...") {
            continue;
        }
        if let Some(colon) = entry.find(':') {
            let prop = entry[..colon].trim();
            if prop == method {
                if let Some((alias, _)) = identifier_at_start(entry[colon + 1..].trim_start()) {
                    aliases.push(alias.to_string());
                }
            }
            continue;
        }
        if let Some((prop, _)) = identifier_at_start(entry) {
            if prop == method {
                aliases.push(method.to_string());
            }
        }
    }
    aliases
}

fn acquisition_rhs_imported_token<'a>(
    rhs: &str,
    imported_service_tokens: &'a [ServiceTokenSource],
) -> Option<&'a ServiceTokenSource> {
    for token in imported_service_tokens {
        if (rhs.contains("yield*") || rhs.contains("yield *"))
            && line_mentions_identifier(rhs, &token.name)
        {
            return Some(token);
        }
        if bare_call_rhs_has_token(rhs, "inject", &token.name)
            || bare_call_rhs_has_token(rhs, "resolve", &token.name)
            || bare_call_rhs_has_token(rhs, "getService", &token.name)
            || service_locator_member_rhs_has_token(rhs, "get", &token.name)
            || service_locator_member_rhs_has_token(rhs, "resolve", &token.name)
        {
            return Some(token);
        }
    }
    None
}

fn bare_call_rhs_has_token(rhs: &str, call_name: &str, token: &str) -> bool {
    identifier_occurrence(rhs, call_name, |start, end| {
        if rhs[..start].ends_with('.') {
            return false;
        }
        first_call_arg_is_token(&rhs[end..], token)
    })
    .is_some()
}

fn service_locator_member_rhs_has_token(rhs: &str, method: &str, token: &str) -> bool {
    let needle = format!(".{method}");
    let mut search_from = 0;
    while let Some(pos) = rhs[search_from..].find(&needle) {
        let dot = search_from + pos;
        let method_start = dot + 1;
        let method_end = method_start + method.len();
        if rhs[method_end..].chars().next().is_some_and(is_ident_char) {
            search_from = method_end;
            continue;
        }
        let Some(receiver) = identifier_at_end(&rhs[..dot]) else {
            search_from = method_end;
            continue;
        };
        if is_service_locator_receiver(receiver)
            && first_call_arg_is_token(&rhs[method_end..], token)
        {
            return true;
        }
        search_from = method_end;
    }
    false
}

fn line_mentions_member_call(line: &str, binding: &str, method: &str) -> bool {
    any_identifier_occurrence(line, binding, |_, end| {
        let Some(after_dot) = line[end..].trim_start().strip_prefix('.') else {
            return false;
        };
        let after_dot = after_dot.trim_start();
        if !after_dot.starts_with(method) {
            return false;
        }
        let after_method = &after_dot[method.len()..];
        if after_method.chars().next().is_some_and(is_ident_char) {
            return false;
        }
        after_method.trim_start().starts_with('(')
    })
}

fn line_mentions_function_call(line: &str, name: &str) -> bool {
    any_identifier_occurrence(line, name, |_, end| {
        line[end..].trim_start().starts_with('(')
    })
}

fn source_line_number_at_offset(
    bundle: &SourceBundle<'_>,
    file: NodeId,
    byte_offset: u32,
) -> Option<u32> {
    let bytes = bundle.source_bytes(file)?;
    let start = byte_offset as usize;
    if start >= bytes.len() {
        return None;
    }
    Some((bytes[..start].iter().filter(|byte| **byte == b'\n').count() + 1) as u32)
}

fn source_line_at_offset(
    bundle: &SourceBundle<'_>,
    file: NodeId,
    byte_offset: u32,
) -> Option<String> {
    let bytes = bundle.source_bytes(file)?;
    let start = byte_offset as usize;
    if start >= bytes.len() {
        return None;
    }
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut line_end = start;
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    Some(String::from_utf8_lossy(&bytes[line_start..line_end]).to_string())
}

fn source_lines(bundle: &SourceBundle<'_>, file: NodeId) -> Vec<(u32, String)> {
    let Some(bytes) = bundle.source_bytes(file) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .enumerate()
        .map(|(idx, line)| ((idx + 1) as u32, line.to_string()))
        .collect()
}

fn line_mentions_identifier(line: &str, name: &str) -> bool {
    any_identifier_occurrence(line, name, |_, _| true)
}

fn any_identifier_occurrence(
    line: &str,
    name: &str,
    predicate: impl FnMut(usize, usize) -> bool,
) -> bool {
    identifier_occurrence(line, name, predicate).is_some()
}

fn identifier_occurrence(
    line: &str,
    name: &str,
    mut predicate: impl FnMut(usize, usize) -> bool,
) -> Option<(usize, usize)> {
    if name.is_empty() {
        return None;
    }
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(name) {
        let start = search_from + pos;
        let end = start + name.len();
        let before = line[..start].chars().next_back();
        let after = line[end..].chars().next();
        if !before.is_some_and(is_ident_char)
            && !after.is_some_and(is_ident_char)
            && predicate(start, end)
        {
            return Some((start, end));
        }
        search_from = end;
    }
    None
}

fn identifier_at_start(text: &str) -> Option<(&str, usize)> {
    let mut chars = text.char_indices();
    let (_, first) = chars.next()?;
    if !is_identifier_start(first) {
        return None;
    }
    let mut end = first.len_utf8();
    for (idx, ch) in chars {
        if !is_ident_char(ch) {
            break;
        }
        end = idx + ch.len_utf8();
    }
    Some((&text[..end], end))
}

fn identifier_at_end(text: &str) -> Option<&str> {
    let trimmed = text.trim_end();
    let mut end = trimmed.len();
    while end > 0 {
        let Some((idx, ch)) = trimmed[..end].char_indices().next_back() else {
            break;
        };
        if is_ident_char(ch) {
            end = idx;
            continue;
        }
        break;
    }
    let start = end;
    let ident = &trimmed[start..];
    if ident.is_empty() {
        return None;
    }
    let first = ident.chars().next()?;
    if is_identifier_start(first) {
        Some(ident)
    } else {
        None
    }
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
}
