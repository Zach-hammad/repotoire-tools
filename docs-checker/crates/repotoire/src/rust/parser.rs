//! Authoritative Rust source parser.
//!
//! `ra_ap_syntax` owns Rust grammar recognition. This module owns the bounded
//! projection from one validated syntax tree into RepoToire's `ParsedFile`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ra_ap_syntax::ast::{self, AstNode, HasModuleItem, HasName, HasVisibility};
use ra_ap_syntax::{Edition, SourceFile, SyntaxKind, SyntaxNode, TextRange};
use serde::{Deserialize, Serialize};

use crate::rust::events::{
    ParsedFile, RustItem, RustItemKind, RustMacroCall, RustPathRefKind, RustRef, RustRefTarget,
    RustUse, RustUseBinding, RustValueBinding, RustValueScopeIndex, RustVisibility,
};
use crate::spans::Span;

pub const MAX_RUST_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUST_ITEMS: usize = 200_000;
const MAX_RUST_SYNTAX_NODES: usize = 2_000_000;
const MAX_RUST_SYNTAX_ERRORS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RustEdition {
    #[default]
    Edition2015,
    Edition2018,
    Edition2021,
    Edition2024,
}

impl RustEdition {
    fn parser_edition(self) -> Edition {
        match self {
            Self::Edition2015 => Edition::Edition2015,
            Self::Edition2018 => Edition::Edition2018,
            Self::Edition2021 => Edition::Edition2021,
            Self::Edition2024 => Edition::Edition2024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustParseMode {
    Items,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustParseOptions {
    pub edition: RustEdition,
    pub mode: RustParseMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSyntaxDiagnostic {
    pub message: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustParseError {
    SourceEncoding {
        invalid_byte_offset: usize,
    },
    SourceTooLarge {
        bytes: usize,
        max_bytes: usize,
    },
    Syntax {
        total_errors: usize,
        diagnostics: Vec<RustSyntaxDiagnostic>,
    },
    ProjectionLimit {
        resource: &'static str,
        limit: usize,
    },
    ProjectionInvariant {
        message: &'static str,
    },
}

impl fmt::Display for RustParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceEncoding {
                invalid_byte_offset,
            } => write!(f, "Rust source is not UTF-8 at byte {invalid_byte_offset}"),
            Self::SourceTooLarge { bytes, max_bytes } => {
                write!(f, "Rust source has {bytes} bytes; limit is {max_bytes}")
            }
            Self::Syntax {
                total_errors,
                diagnostics,
            } => {
                let first = diagnostics
                    .first()
                    .map(|diagnostic| diagnostic.message.as_str())
                    .unwrap_or("unknown syntax error");
                write!(f, "Rust source has {total_errors} syntax error(s): {first}")
            }
            Self::ProjectionLimit { resource, limit } => {
                write!(f, "Rust {resource} projection limit exceeded: {limit}")
            }
            Self::ProjectionInvariant { message } => {
                write!(f, "Rust syntax projection invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for RustParseError {}

pub fn parse_file(
    path: &str,
    source: &[u8],
    options: RustParseOptions,
) -> Result<ParsedFile, RustParseError> {
    if source.len() > MAX_RUST_SOURCE_BYTES {
        return Err(RustParseError::SourceTooLarge {
            bytes: source.len(),
            max_bytes: MAX_RUST_SOURCE_BYTES,
        });
    }
    let src = std::str::from_utf8(source).map_err(|error| RustParseError::SourceEncoding {
        invalid_byte_offset: error.valid_up_to(),
    })?;
    let parsed = SourceFile::parse(src, options.edition.parser_edition());
    let errors = parsed.errors();
    if !errors.is_empty() {
        let total_errors = errors.len();
        let diagnostics = errors
            .into_iter()
            .take(MAX_RUST_SYNTAX_ERRORS)
            .map(|error| RustSyntaxDiagnostic {
                message: error.to_string(),
                span: span_from_range(error.range()),
            })
            .collect();
        return Err(RustParseError::Syntax {
            total_errors,
            diagnostics,
        });
    }

    let tree = parsed.tree();
    let include_refs = options.mode == RustParseMode::Complete;
    let mut projection = Projection::new(src, include_refs);
    let local_value_bindings = if include_refs {
        projection.project_block_scopes(tree.syntax())?
    } else {
        Vec::new()
    };
    projection.value_scope = RustValueScopeIndex::new(&local_value_bindings);
    projection.project(tree.items())?;
    projection
        .uses
        .sort_by_key(|use_item| (use_item.span.start(), use_item.span.end()));
    Ok(ParsedFile {
        path: path.to_string(),
        items: projection.items,
        uses: projection.uses,
        local_value_bindings,
        macro_calls: projection.macro_calls,
    })
}

struct PendingItem {
    item: ast::Item,
    parent_path: Vec<usize>,
    module_suffix: String,
    public_module_path: bool,
}

struct Projection<'a> {
    src: &'a str,
    include_refs: bool,
    items: Vec<RustItem>,
    uses: Vec<RustUse>,
    macro_calls: Vec<RustMacroCall>,
    projected_items: usize,
    visited_nodes: usize,
    value_scope: RustValueScopeIndex,
}

impl<'a> Projection<'a> {
    fn new(src: &'a str, include_refs: bool) -> Self {
        Self {
            src,
            include_refs,
            items: Vec::new(),
            uses: Vec::new(),
            macro_calls: Vec::new(),
            projected_items: 0,
            visited_nodes: 0,
            value_scope: RustValueScopeIndex::default(),
        }
    }

    fn project(&mut self, items: impl Iterator<Item = ast::Item>) -> Result<(), RustParseError> {
        let mut pending = items
            .map(|item| PendingItem {
                item,
                parent_path: Vec::new(),
                module_suffix: String::new(),
                public_module_path: true,
            })
            .collect::<Vec<_>>();
        pending.reverse();

        while let Some(work) = pending.pop() {
            self.reserve_item()?;

            if let ast::Item::Use(node) = &work.item {
                if let Some(use_item) =
                    project_use(node, &work.module_suffix, work.public_module_path, false)
                {
                    self.uses.push(use_item);
                }
                continue;
            }
            if let ast::Item::MacroCall(node) = &work.item {
                if let Some(path) = node.path() {
                    self.macro_calls.push(RustMacroCall {
                        path: normalize_path_syntax(path.syntax()),
                        span: span_from_range(path.syntax().text_range()),
                    });
                }
                continue;
            }

            let child_context =
                module_child_context(&work.item, &work.module_suffix, work.public_module_path);
            let child_items = child_module_items(&work.item);
            let Some(projected) = self.project_item(&work.item)? else {
                continue;
            };

            let target = items_at_path_mut(&mut self.items, &work.parent_path);
            target.push(projected);
            let mut child_path = work.parent_path;
            child_path.push(target.len() - 1);

            if let Some((module_suffix, public_module_path)) = child_context {
                let mut children = child_items.collect::<Vec<_>>();
                children.reverse();
                for item in children {
                    pending.push(PendingItem {
                        item,
                        parent_path: child_path.clone(),
                        module_suffix: module_suffix.clone(),
                        public_module_path,
                    });
                }
            }
        }
        Ok(())
    }

    fn project_block_scopes(
        &mut self,
        root: &SyntaxNode,
    ) -> Result<Vec<RustValueBinding>, RustParseError> {
        let mut bindings = BTreeSet::new();
        for node in root.descendants() {
            self.reserve_syntax_node()?;

            if let Some(pattern) = ast::IdentPat::cast(node.clone()) {
                if let Some(name) = pattern.name() {
                    bindings.insert((
                        name.syntax().text().to_string(),
                        syntax_start(pattern.syntax()),
                        value_binding_scope_end(pattern.syntax(), root),
                    ));
                }
                continue;
            }
            let Some(item) = ast::Item::cast(node) else {
                continue;
            };
            let Some(scope) = block_item_scope(item.syntax(), root) else {
                continue;
            };
            if let ast::Item::Use(node) = &item {
                let module_suffix = enclosing_module_suffix(node.syntax(), root);
                if let Some(use_item) = project_use(node, &module_suffix, false, true) {
                    self.uses.push(use_item);
                }
            }
            let mut names = Vec::new();
            project_block_item_value_names(&item, &mut names);
            bindings.extend(names.into_iter().map(|name| (name, scope.start, scope.end)));
        }
        Ok(bindings
            .into_iter()
            .map(|(name, start, end)| RustValueBinding {
                name,
                scope: Span::try_from_range(start..end)
                    .expect("Rust source limit keeps binding spans within u32"),
            })
            .collect())
    }

    fn project_item(&mut self, item: &ast::Item) -> Result<Option<RustItem>, RustParseError> {
        let projected = match item {
            ast::Item::Module(node) => self.named_item(RustItemKind::Module, node)?,
            ast::Item::Struct(node) => self.named_item(RustItemKind::Struct, node)?,
            ast::Item::Union(node) => self.named_item(RustItemKind::Union, node)?,
            ast::Item::Enum(node) => self.named_item(RustItemKind::Enum, node)?,
            ast::Item::Trait(node) => {
                let mut item = self.named_item(RustItemKind::Trait, node)?;
                if let Some(list) = node.assoc_item_list() {
                    for child in list.assoc_items() {
                        if let Some(child) =
                            self.project_assoc_item(child, RustItemKind::Function)?
                        {
                            item.children.push(child);
                        }
                    }
                }
                item
            }
            ast::Item::TraitAlias(node) => self.named_item(RustItemKind::Trait, node)?,
            ast::Item::TypeAlias(node) => self.named_item(RustItemKind::TypeAlias, node)?,
            ast::Item::Fn(node) => self.named_item(RustItemKind::Function, node)?,
            ast::Item::Const(node) => self.const_item(RustItemKind::Const, node)?,
            ast::Item::Static(node) => self.named_item(RustItemKind::Static, node)?,
            ast::Item::Impl(node) => {
                let Some(self_ty) = node.self_ty() else {
                    return Ok(None);
                };
                let Some(name) = type_path(&self_ty) else {
                    return Ok(None);
                };
                let trait_path = node.trait_().and_then(|ty| type_path(&ty));
                let mut item = self.unnamed_item(
                    RustItemKind::Impl,
                    name,
                    self_ty.syntax().text_range(),
                    node,
                    trait_path,
                    visibility(node),
                )?;
                if let Some(list) = node.assoc_item_list() {
                    for child in list.assoc_items() {
                        if let Some(child) = self.project_assoc_item(child, RustItemKind::Method)? {
                            item.children.push(child);
                        }
                    }
                }
                item
            }
            ast::Item::ExternBlock(node) => {
                let (name, name_range) = node
                    .abi()
                    .map(|abi| {
                        (
                            normalize_ws(&syntax_text_without_comments(abi.syntax())),
                            abi.syntax().text_range(),
                        )
                    })
                    .unwrap_or_else(|| ("extern".to_string(), node.syntax().text_range()));
                let mut item = self.unnamed_item(
                    RustItemKind::ExternBlock,
                    name,
                    name_range,
                    node,
                    None,
                    RustVisibility::Private,
                )?;
                if let Some(list) = node.extern_item_list() {
                    for child in list.extern_items() {
                        if let Some(child) = self.project_extern_item(child)? {
                            item.children.push(child);
                        }
                    }
                }
                item
            }
            ast::Item::MacroDef(node) => self.named_item(RustItemKind::Macro, node)?,
            ast::Item::MacroRules(node) => self.named_item(RustItemKind::Macro, node)?,
            ast::Item::ExternCrate(_) | ast::Item::MacroCall(_) | ast::Item::Use(_) => {
                return Ok(None)
            }
        };
        Ok(Some(projected))
    }

    fn project_assoc_item(
        &mut self,
        item: ast::AssocItem,
        function_kind: RustItemKind,
    ) -> Result<Option<RustItem>, RustParseError> {
        self.reserve_item()?;
        Ok(Some(match item {
            ast::AssocItem::Fn(node) => self.named_item(function_kind, &node),
            ast::AssocItem::Const(node) => self.const_item(RustItemKind::AssociatedConst, &node),
            ast::AssocItem::TypeAlias(node) => self.named_item(RustItemKind::AssociatedType, &node),
            ast::AssocItem::MacroCall(_) => return Ok(None),
        }?))
    }

    fn project_extern_item(
        &mut self,
        item: ast::ExternItem,
    ) -> Result<Option<RustItem>, RustParseError> {
        self.reserve_item()?;
        Ok(Some(match item {
            ast::ExternItem::Fn(node) => self.named_item(RustItemKind::Function, &node),
            ast::ExternItem::Static(node) => self.named_item(RustItemKind::Static, &node),
            ast::ExternItem::TypeAlias(node) => self.named_item(RustItemKind::TypeAlias, &node),
            ast::ExternItem::MacroCall(_) => return Ok(None),
        }?))
    }

    fn named_item<N>(&mut self, kind: RustItemKind, node: &N) -> Result<RustItem, RustParseError>
    where
        N: AstNode + HasName + HasVisibility,
    {
        let Some(name_node) = node.name() else {
            return Err(RustParseError::ProjectionInvariant {
                message: "validated named item has no name",
            });
        };
        self.unnamed_item(
            kind,
            name_node.syntax().text().to_string(),
            name_node.syntax().text_range(),
            node,
            None,
            visibility(node),
        )
    }

    fn const_item(
        &mut self,
        named_kind: RustItemKind,
        node: &ast::Const,
    ) -> Result<RustItem, RustParseError> {
        let (kind, name, name_range) = match (node.name(), node.underscore_token()) {
            (Some(name), None) => (
                named_kind,
                name.syntax().text().to_string(),
                name.syntax().text_range(),
            ),
            (None, Some(underscore)) => (
                RustItemKind::AnonymousConst,
                underscore.text().to_string(),
                underscore.text_range(),
            ),
            _ => Err(RustParseError::ProjectionInvariant {
                message: "validated const item must have exactly one name or underscore",
            })?,
        };
        self.unnamed_item(kind, name, name_range, node, None, visibility(node))
    }

    fn unnamed_item<N>(
        &mut self,
        kind: RustItemKind,
        name: String,
        name_range: TextRange,
        node: &N,
        impl_trait_path: Option<String>,
        visibility: RustVisibility,
    ) -> Result<RustItem, RustParseError>
    where
        N: AstNode,
    {
        let syntax = node.syntax();
        let is_pub = visibility.is_explicit();
        let pub_visibility_is_restricted = is_pub && !visibility.is_public();
        let body_range = body_range(syntax);
        let signature_start = signature_start(syntax);
        let signature_end = body_range
            .map(|range| range.start())
            .unwrap_or_else(|| signature_boundary(syntax));
        let signature_end = trim_ascii_whitespace_end(self.src, signature_end);
        let refs = if self.include_refs {
            self.collect_refs(syntax, &name)?
        } else {
            Vec::new()
        };
        Ok(RustItem {
            kind,
            name,
            name_span: span_from_range(name_range),
            decl_span: span_from_range(syntax.text_range()),
            signature_span: span_from_offsets(signature_start, signature_end),
            body_span: body_range.map(span_from_range),
            refs,
            children: Vec::new(),
            visibility,
            is_pub,
            pub_visibility_is_restricted,
            impl_trait_path,
        })
    }

    fn reserve_item(&mut self) -> Result<(), RustParseError> {
        self.projected_items += 1;
        if self.projected_items > MAX_RUST_ITEMS {
            return Err(RustParseError::ProjectionLimit {
                resource: "item",
                limit: MAX_RUST_ITEMS,
            });
        }
        Ok(())
    }

    fn collect_refs(
        &mut self,
        root: &SyntaxNode,
        item_name: &str,
    ) -> Result<Vec<RustRef>, RustParseError> {
        let bindings = self.collect_receiver_bindings(root)?;
        let mut refs = Vec::new();
        let mut stack = root.children().collect::<Vec<_>>();
        stack.reverse();
        while let Some(node) = stack.pop() {
            self.reserve_syntax_node()?;
            if ast::Item::cast(node.clone()).is_some() {
                continue;
            }
            if let Some(method) = ast::MethodCallExpr::cast(node.clone()) {
                if let (Some(receiver), Some(name)) = (method.receiver(), method.name_ref()) {
                    let receiver_text = canonical_expression(&receiver);
                    refs.push(RustRef {
                        span: span_from_range(name.syntax().text_range()),
                        target: RustRefTarget::MethodCall {
                            receiver_type: receiver_type_for(
                                &bindings,
                                &receiver_text,
                                u32::from(name.syntax().text_range().start()) as usize,
                            ),
                            receiver: receiver_text,
                            method: name.syntax().text().to_string(),
                        },
                    });
                }
            } else if let Some(call) = ast::CallExpr::cast(node.clone()) {
                if let Some(ast::Expr::PathExpr(path_expr)) = call.expr() {
                    if let Some(path) = path_expr.path() {
                        if let Some((self_type, trait_path, method)) = qualified_trait_call(&path) {
                            refs.extend(qualified_type_refs(&path));
                            refs.push(RustRef {
                                span: last_path_segment_span(&path),
                                target: RustRefTarget::QualifiedTraitCall {
                                    self_type,
                                    trait_path,
                                    method,
                                },
                            });
                        } else {
                            let text = path_without_generic_arguments(&path);
                            if !is_ignored_path(&text) {
                                refs.push(RustRef {
                                    span: span_from_range(path.syntax().text_range()),
                                    target: RustRefTarget::Path {
                                        path: text,
                                        kind: RustPathRefKind::Call,
                                    },
                                });
                            }
                        }
                    }
                }
            } else if let Some(record) = ast::RecordExpr::cast(node.clone()) {
                if let Some(path) = record.path() {
                    let target = path_without_generic_arguments(&path);
                    if !is_ignored_path(&target) {
                        refs.push(RustRef {
                            span: span_from_range(path.syntax().text_range()),
                            target: RustRefTarget::Path {
                                path: target,
                                kind: RustPathRefKind::Value,
                            },
                        });
                    }
                }
            } else if let Some(path_expr) = ast::PathExpr::cast(node.clone()) {
                let parent_is_call = node
                    .parent()
                    .and_then(ast::CallExpr::cast)
                    .is_some_and(|call| call.expr().is_some_and(|expr| expr.syntax() == &node));
                if !parent_is_call {
                    if let Some(path) = path_expr.path() {
                        let text = path_without_generic_arguments(&path);
                        let offset = u32::from(path.syntax().text_range().start());
                        if (text.contains("::") || is_bare_nominal_value_path(&text))
                            && !is_ignored_path(&text)
                            && (!is_simple_identifier(&text)
                                || !self.value_scope.binds_name(&text, offset))
                        {
                            refs.push(RustRef {
                                span: span_from_range(path.syntax().text_range()),
                                target: RustRefTarget::Path {
                                    path: text,
                                    kind: RustPathRefKind::Value,
                                },
                            });
                        }
                    }
                }
            } else if let Some(path) = pattern_path(&node) {
                let target = path_without_generic_arguments(&path);
                if !is_ignored_path(&target) {
                    refs.push(RustRef {
                        span: span_from_range(path.syntax().text_range()),
                        target: RustRefTarget::Path {
                            path: target,
                            kind: RustPathRefKind::Value,
                        },
                    });
                }
            } else if let Some(path) = ast::Path::cast(node.clone()) {
                let is_outer = node.parent().and_then(ast::Path::cast).is_none();
                if is_outer && path_has_type_role(&path) {
                    let target = path_without_generic_arguments(&path);
                    if target != item_name && !is_ignored_path(&target) {
                        refs.push(RustRef {
                            span: span_from_range(path.syntax().text_range()),
                            target: RustRefTarget::Path {
                                path: target,
                                kind: RustPathRefKind::Type,
                            },
                        });
                    }
                }
            }

            let mut children = node.children().collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
        refs.sort_by_key(|reference| (reference.span.start(), reference.span.end()));
        refs.dedup();
        Ok(refs)
    }

    fn reserve_syntax_node(&mut self) -> Result<(), RustParseError> {
        if self.visited_nodes == MAX_RUST_SYNTAX_NODES {
            return Err(RustParseError::ProjectionLimit {
                resource: "syntax node",
                limit: MAX_RUST_SYNTAX_NODES,
            });
        }
        self.visited_nodes += 1;
        Ok(())
    }

    fn collect_receiver_bindings(
        &mut self,
        root: &SyntaxNode,
    ) -> Result<ReceiverTypeIndex, RustParseError> {
        let mut events = Vec::new();
        for node in root.descendants() {
            self.reserve_syntax_node()?;
            if let Some(param) = ast::Param::cast(node.clone()) {
                if belongs_to_projection_root(param.syntax(), root) {
                    if let Some(name) = param.pat().as_ref().and_then(simple_binding_name) {
                        events.push(ReceiverBindingEvent::Declare(ReceiverBinding {
                            name,
                            type_path: param.ty().and_then(|ty| type_path(&ty)),
                            start: syntax_start(param.syntax()),
                            end: parameter_scope_end(param.syntax(), root),
                        }));
                    }
                }
                continue;
            }
            if let Some(statement) = ast::LetStmt::cast(node.clone()) {
                if belongs_to_projection_root(statement.syntax(), root) {
                    if let Some(name) = statement.pat().as_ref().and_then(simple_binding_name) {
                        let type_path =
                            statement.ty().and_then(|ty| type_path(&ty)).or_else(|| {
                                statement
                                    .initializer()
                                    .and_then(|expr| constructor_type(&expr))
                            });
                        events.push(ReceiverBindingEvent::Declare(ReceiverBinding {
                            name,
                            type_path,
                            start: syntax_start(statement.syntax()),
                            end: block_scope_end(statement.syntax(), root),
                        }));
                    }
                }
                continue;
            }
            let Some(assignment) = ast::BinExpr::cast(node) else {
                continue;
            };
            if !belongs_to_projection_root(assignment.syntax(), root)
                || !matches!(
                    assignment.op_kind(),
                    Some(ast::BinaryOp::Assignment { op: None })
                )
            {
                continue;
            }
            let Some(ast::Expr::PathExpr(lhs)) = assignment.lhs() else {
                continue;
            };
            let Some(path) = lhs.path() else {
                continue;
            };
            let name = path_without_generic_arguments(&path);
            if !is_simple_identifier(&name) {
                continue;
            }
            let Some(type_path) = assignment.rhs().and_then(|rhs| constructor_type(&rhs)) else {
                continue;
            };
            events.push(ReceiverBindingEvent::Assign {
                name,
                type_path,
                start: syntax_end(assignment.syntax()),
            });
        }

        events.sort_by_key(ReceiverBindingEvent::start);
        let mut active = BTreeMap::<String, Vec<ReceiverBinding>>::new();
        let mut bindings = Vec::with_capacity(events.len());
        for event in events {
            match event {
                ReceiverBindingEvent::Declare(binding) => {
                    active
                        .entry(binding.name.clone())
                        .or_default()
                        .push(binding.clone());
                    bindings.push(binding);
                }
                ReceiverBindingEvent::Assign {
                    name,
                    type_path,
                    start,
                } => {
                    let Some(scopes) = active.get_mut(&name) else {
                        continue;
                    };
                    while scopes.last().is_some_and(|binding| start >= binding.end) {
                        scopes.pop();
                    }
                    let Some(end) = scopes.last().map(|binding| binding.end) else {
                        continue;
                    };
                    if start >= end {
                        continue;
                    }
                    let binding = ReceiverBinding {
                        name,
                        type_path: Some(type_path),
                        start,
                        end,
                    };
                    scopes.push(binding.clone());
                    bindings.push(binding);
                }
            }
        }
        Ok(ReceiverTypeIndex::new(bindings))
    }
}

fn project_block_item_value_names(item: &ast::Item, out: &mut Vec<String>) {
    let name = match item {
        ast::Item::Fn(item) => item.name(),
        ast::Item::Const(item) => item.name(),
        ast::Item::Static(item) => item.name(),
        ast::Item::Struct(item) if !matches!(item.kind(), ast::StructKind::Record(_)) => {
            item.name()
        }
        ast::Item::Use(item) => {
            let Some(tree) = item.use_tree() else {
                return;
            };
            let mut bindings = Vec::new();
            project_use_bindings(&tree, "", false, &mut bindings);
            out.extend(
                bindings
                    .into_iter()
                    .map(|binding| binding.export_name)
                    .filter(|name| name != "*" && name != "_" && !name.is_empty()),
            );
            return;
        }
        _ => return,
    };
    if let Some(name) = name {
        out.push(name.syntax().text().to_string());
    }
}

/// Returns true when the path's nearest syntactic role is a type.
///
/// A local annotation lives inside a block expression, so checking every
/// ancestor would incorrectly classify its type path as an expression. The
/// nearest role owns the edge kind: type syntax wins before an enclosing
/// expression, pattern, or macro boundary.
fn path_has_type_role(path: &ast::Path) -> bool {
    path.syntax()
        .ancestors()
        .skip(1)
        .find_map(|ancestor| {
            if ast::Type::cast(ancestor.clone()).is_some() {
                Some(true)
            } else if ast::Expr::cast(ancestor.clone()).is_some()
                || ast::Pat::cast(ancestor.clone()).is_some()
                || ast::MacroCall::cast(ancestor).is_some()
            {
                Some(false)
            } else {
                None
            }
        })
        .unwrap_or(false)
}

fn child_module_items(item: &ast::Item) -> impl Iterator<Item = ast::Item> {
    match item {
        ast::Item::Module(module) => module
            .item_list()
            .map(|list| list.items().collect::<Vec<_>>())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
    .into_iter()
}

fn module_child_context(
    item: &ast::Item,
    module_suffix: &str,
    public_module_path: bool,
) -> Option<(String, bool)> {
    let ast::Item::Module(module) = item else {
        return None;
    };
    let name = module.name()?.syntax().text().to_string();
    let is_pub = visibility(module).is_public();
    let suffix = if module_suffix.is_empty() {
        name
    } else {
        format!("{module_suffix}::{name}")
    };
    Some((suffix, public_module_path && is_pub))
}

fn project_use(
    node: &ast::Use,
    module_suffix: &str,
    public_module_path: bool,
    is_block_local: bool,
) -> Option<RustUse> {
    let tree = node.use_tree()?;
    let label = canonical_use_text(tree.syntax());
    let mut bindings = Vec::new();
    project_use_bindings(&tree, "", false, &mut bindings);
    let visibility = visibility(node);
    let is_pub = visibility.is_explicit();
    Some(RustUse {
        label,
        label_span: span_from_range(tree.syntax().text_range()),
        bindings,
        module_suffix: module_suffix.to_string(),
        is_block_local,
        public_module_path,
        span: span_from_range(node.syntax().text_range()),
        visibility,
        is_pub,
    })
}

fn enclosing_module_suffix(node: &SyntaxNode, root: &SyntaxNode) -> String {
    let mut modules = node
        .ancestors()
        .take_while(|ancestor| ancestor != root)
        .filter_map(ast::Module::cast)
        .filter_map(|module| module.name())
        .map(|name| name.syntax().text().to_string())
        .collect::<Vec<_>>();
    modules.reverse();
    modules.join("::")
}

fn project_use_bindings(
    tree: &ast::UseTree,
    prefix: &str,
    in_group: bool,
    out: &mut Vec<RustUseBinding>,
) {
    let tree_path = tree
        .path()
        .map(|path| path_without_generic_arguments(&path))
        .unwrap_or_default();
    let grouped_self = in_group && tree_path == "self";
    let path = if grouped_self {
        prefix.to_string()
    } else {
        join_path(prefix, &tree_path)
    };

    if let Some(list) = tree.use_tree_list() {
        for child in list.use_trees() {
            project_use_bindings(&child, &path, true, out);
        }
        return;
    }

    let path = if tree.star_token().is_some() {
        join_path(&path, "*")
    } else {
        path
    };
    if path.is_empty() {
        return;
    }
    let target_name = final_path_segment(&path);
    let export_name = tree
        .rename()
        .and_then(|rename| {
            rename
                .name()
                .map(|name| name.syntax().text().to_string())
                .or_else(|| rename.underscore_token().map(|_| "_".to_string()))
        })
        .unwrap_or_else(|| target_name.clone());
    let label = canonical_use_text(tree.syntax());
    out.push(RustUseBinding {
        path,
        label,
        target_name,
        export_name,
    });
}

fn join_path(prefix: &str, suffix: &str) -> String {
    let prefix = prefix.trim().trim_end_matches("::");
    let suffix = suffix.trim().trim_start_matches("::");
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix.to_string(),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{prefix}::{suffix}"),
    }
}

fn final_path_segment(path: &str) -> String {
    path.rsplit("::").next().unwrap_or(path).to_string()
}

fn canonical_use_text(node: &SyntaxNode) -> String {
    let text = syntax_text_without_comments(node);
    canonicalize_use_text(&text)
}

/// Canonicalize the source slice of an already-validated Rust use tree.
///
/// This is formatting only: parser consumers must validate the complete file
/// once and carry the resulting span instead of parsing the slice again.
pub(crate) fn canonicalize_use_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        match ch {
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                trim_trailing_space(&mut out);
                out.push_str("::");
                pending_space = false;
            }
            '{' => {
                trim_trailing_space(&mut out);
                out.push('{');
                pending_space = false;
            }
            '}' => {
                trim_trailing_space(&mut out);
                if out.ends_with(',') {
                    out.pop();
                }
                out.push('}');
                pending_space = false;
            }
            ',' => {
                trim_trailing_space(&mut out);
                if !out.ends_with('{') && !out.ends_with(',') {
                    out.push_str(", ");
                }
                pending_space = false;
            }
            _ => {
                if pending_space && needs_use_space(out.chars().next_back(), ch) {
                    out.push(' ');
                }
                out.push(ch);
                pending_space = false;
            }
        }
    }
    out.trim_end().to_string()
}

fn trim_trailing_space(text: &mut String) {
    while text.ends_with(' ') {
        text.pop();
    }
}

fn needs_use_space(previous: Option<char>, next: char) -> bool {
    previous.is_some_and(|previous| {
        (previous.is_alphanumeric() || matches!(previous, '_' | '#'))
            && (next.is_alphanumeric() || matches!(next, '_' | '#'))
    })
}

fn items_at_path_mut<'a>(items: &'a mut Vec<RustItem>, path: &[usize]) -> &'a mut Vec<RustItem> {
    let mut current = items;
    for &index in path {
        current = &mut current[index].children;
    }
    current
}

fn visibility<N: HasVisibility>(node: &N) -> RustVisibility {
    let Some(visibility) = node.visibility() else {
        return RustVisibility::Private;
    };
    match visibility.kind() {
        ast::VisibilityKind::Pub => RustVisibility::Public,
        ast::VisibilityKind::PubCrate => RustVisibility::Crate,
        ast::VisibilityKind::PubSuper => RustVisibility::Super,
        ast::VisibilityKind::PubSelf => RustVisibility::SelfModule,
        ast::VisibilityKind::In(path) => RustVisibility::In(path_without_generic_arguments(&path)),
    }
}

fn body_range(root: &SyntaxNode) -> Option<TextRange> {
    root.children().find_map(|child| {
        let kind = child.kind();
        (ast::BlockExpr::can_cast(kind)
            || ast::ItemList::can_cast(kind)
            || ast::AssocItemList::can_cast(kind)
            || ast::ExternItemList::can_cast(kind)
            || ast::RecordFieldList::can_cast(kind)
            || ast::TupleFieldList::can_cast(kind)
            || ast::VariantList::can_cast(kind)
            || ast::TokenTree::can_cast(kind))
        .then(|| child.text_range())
    })
}

fn signature_start(root: &SyntaxNode) -> ra_ap_syntax::TextSize {
    let after_outer_attributes = root
        .children()
        .filter_map(ast::Attr::cast)
        .map(|attribute| attribute.syntax().text_range().end())
        .max()
        .unwrap_or_else(|| root.text_range().start());
    root.descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| {
            token.text_range().start() >= after_outer_attributes && !token.kind().is_trivia()
        })
        .map(|token| token.text_range().start())
        .unwrap_or_else(|| root.text_range().start())
}

fn signature_boundary(root: &SyntaxNode) -> ra_ap_syntax::TextSize {
    root.children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| matches!(token.text(), "=" | ";"))
        .map(|token| token.text_range().start())
        .unwrap_or_else(|| root.text_range().end())
}

#[derive(Debug, Clone)]
struct ReceiverBinding {
    name: String,
    type_path: Option<String>,
    start: usize,
    end: usize,
}

#[derive(Debug)]
enum ReceiverBindingEvent {
    Declare(ReceiverBinding),
    Assign {
        name: String,
        type_path: String,
        start: usize,
    },
}

impl ReceiverBindingEvent {
    fn start(&self) -> usize {
        match self {
            Self::Declare(binding) => binding.start,
            Self::Assign { start, .. } => *start,
        }
    }
}

#[derive(Debug)]
struct ReceiverTypeSegment {
    start: usize,
    end: usize,
    type_path: Option<String>,
}

#[derive(Debug, Default)]
struct ReceiverTypeIndex {
    segments_by_name: BTreeMap<String, Vec<ReceiverTypeSegment>>,
    #[cfg(test)]
    work: ReceiverTypeIndexWork,
}

impl ReceiverTypeIndex {
    fn new(bindings: Vec<ReceiverBinding>) -> Self {
        #[cfg(test)]
        let binding_count = bindings.len();
        let mut bindings_by_name = BTreeMap::<String, Vec<ReceiverBinding>>::new();
        for binding in bindings {
            bindings_by_name
                .entry(binding.name.clone())
                .or_default()
                .push(binding);
        }

        let mut segments_by_name = BTreeMap::new();
        #[cfg(test)]
        let mut processed_boundary_count = 0;
        for (name, bindings) in bindings_by_name {
            let mut boundaries = Vec::with_capacity(bindings.len() * 2);
            for (index, binding) in bindings.iter().enumerate() {
                boundaries.push((binding.start, true, index));
                boundaries.push((binding.end, false, index));
            }
            boundaries.sort_unstable_by_key(|(offset, is_start, _)| (*offset, *is_start));

            let mut active = BTreeSet::<(usize, usize)>::new();
            let mut segments: Vec<ReceiverTypeSegment> = Vec::new();
            let mut cursor = boundaries.first().map(|boundary| boundary.0).unwrap_or(0);
            let mut boundary_index = 0;
            while boundary_index < boundaries.len() {
                let offset = boundaries[boundary_index].0;
                if cursor < offset {
                    if let Some((_, binding_index)) = active.last() {
                        let type_path = bindings[*binding_index].type_path.clone();
                        if let Some(previous) = segments.last_mut().filter(|segment| {
                            segment.end == cursor && segment.type_path == type_path
                        }) {
                            previous.end = offset;
                        } else {
                            segments.push(ReceiverTypeSegment {
                                start: cursor,
                                end: offset,
                                type_path,
                            });
                        }
                    }
                }

                while boundary_index < boundaries.len()
                    && boundaries[boundary_index].0 == offset
                    && !boundaries[boundary_index].1
                {
                    let binding_index = boundaries[boundary_index].2;
                    active.remove(&(bindings[binding_index].start, binding_index));
                    boundary_index += 1;
                    #[cfg(test)]
                    {
                        processed_boundary_count += 1;
                    }
                }
                while boundary_index < boundaries.len()
                    && boundaries[boundary_index].0 == offset
                    && boundaries[boundary_index].1
                {
                    let binding_index = boundaries[boundary_index].2;
                    active.insert((bindings[binding_index].start, binding_index));
                    boundary_index += 1;
                    #[cfg(test)]
                    {
                        processed_boundary_count += 1;
                    }
                }
                cursor = offset;
            }
            segments_by_name.insert(name, segments);
        }
        Self {
            segments_by_name,
            #[cfg(test)]
            work: ReceiverTypeIndexWork {
                binding_count,
                processed_boundary_count,
            },
        }
    }

    fn type_at(&self, name: &str, offset: usize) -> Option<String> {
        let segments = self.segments_by_name.get(name)?;
        let index = segments.partition_point(|segment| segment.start <= offset);
        let segment = index.checked_sub(1).and_then(|index| segments.get(index))?;
        (offset < segment.end)
            .then(|| segment.type_path.clone())
            .flatten()
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct ReceiverTypeIndexWork {
    binding_count: usize,
    processed_boundary_count: usize,
}

fn receiver_type_for(
    bindings: &ReceiverTypeIndex,
    receiver: &str,
    offset: usize,
) -> Option<String> {
    if !is_simple_identifier(receiver) {
        return constructor_type_from_text(receiver);
    }
    bindings.type_at(receiver, offset)
}

fn belongs_to_projection_root(node: &SyntaxNode, root: &SyntaxNode) -> bool {
    node.ancestors()
        .find_map(ast::Item::cast)
        .is_none_or(|item| item.syntax() == root)
}

fn simple_binding_name(pat: &ast::Pat) -> Option<String> {
    let ast::Pat::IdentPat(pat) = pat else {
        return None;
    };
    Some(pat.name()?.syntax().text().to_string())
}

/// Rust's syntax tree does not distinguish an unresolved bare value name from
/// a local read. Emit bare candidates only for nominal value syntax (unit
/// structs, unit variants, and conventionally named constants/statics).
/// Qualified paths remain unambiguous enough for resolver-owned lookup.
fn is_bare_nominal_value_path(path: &str) -> bool {
    path.strip_prefix("r#")
        .unwrap_or(path)
        .chars()
        .next()
        .is_some_and(char::is_uppercase)
}

fn syntax_start(node: &SyntaxNode) -> usize {
    u32::from(node.text_range().start()) as usize
}

fn syntax_end(node: &SyntaxNode) -> usize {
    u32::from(node.text_range().end()) as usize
}

fn parameter_scope_end(node: &SyntaxNode, root: &SyntaxNode) -> usize {
    node.ancestors()
        .take_while(|ancestor| ancestor != root)
        .find_map(ast::ClosureExpr::cast)
        .map(|closure| u32::from(closure.syntax().text_range().end()) as usize)
        .unwrap_or_else(|| u32::from(root.text_range().end()) as usize)
}

fn block_scope_end(node: &SyntaxNode, root: &SyntaxNode) -> usize {
    block_item_scope(node, root)
        .map(|scope| scope.end)
        .unwrap_or_else(|| syntax_end(root))
}

fn block_item_scope(node: &SyntaxNode, root: &SyntaxNode) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find_map(ast::StmtList::cast)
        .map(|list| syntax_start(list.syntax())..syntax_end(list.syntax()))
        .filter(|scope| scope.end <= syntax_end(root))
}

fn value_binding_scope_end(node: &SyntaxNode, root: &SyntaxNode) -> usize {
    node.ancestors()
        .find_map(|ancestor| {
            ast::MatchArm::cast(ancestor.clone())
                .map(|arm| syntax_end(arm.syntax()))
                .or_else(|| {
                    ast::ClosureExpr::cast(ancestor.clone()).map(|expr| syntax_end(expr.syntax()))
                })
                .or_else(|| {
                    ast::ForExpr::cast(ancestor.clone()).map(|expr| syntax_end(expr.syntax()))
                })
                .or_else(|| ast::Fn::cast(ancestor.clone()).map(|item| syntax_end(item.syntax())))
                .or_else(|| ast::StmtList::cast(ancestor).map(|list| syntax_end(list.syntax())))
        })
        .unwrap_or_else(|| syntax_end(root))
}

fn constructor_type(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::CallExpr(call) => match call.expr()? {
            ast::Expr::PathExpr(path) => path.path().and_then(|path| {
                let text = path_without_generic_arguments(&path);
                if let Some(owner) = text
                    .rsplit_once("::")
                    .filter(|(_, segment)| *segment == "new" || *segment == "default")
                    .map(|(owner, _)| owner.to_string())
                {
                    Some(owner)
                } else if text
                    .rsplit("::")
                    .next()
                    .and_then(|segment| segment.chars().next())
                    .is_some_and(char::is_uppercase)
                {
                    Some(text)
                } else {
                    None
                }
            }),
            _ => None,
        },
        ast::Expr::ParenExpr(paren) => paren.expr().and_then(|expr| constructor_type(&expr)),
        ast::Expr::BlockExpr(block) => block.tail_expr().and_then(|expr| constructor_type(&expr)),
        ast::Expr::TryExpr(try_expr) => try_expr.expr().and_then(|expr| constructor_type(&expr)),
        ast::Expr::AwaitExpr(await_expr) => {
            await_expr.expr().and_then(|expr| constructor_type(&expr))
        }
        _ => None,
    }
}

fn constructor_type_from_text(text: &str) -> Option<String> {
    let text = text.strip_suffix('?').unwrap_or(text);
    let text = text.strip_suffix(".await").unwrap_or(text);
    let callee = text.strip_suffix("()")?;
    let (owner, method) = callee.rsplit_once("::")?;
    matches!(method, "new" | "default").then(|| owner.to_string())
}

fn type_path(ty: &ast::Type) -> Option<String> {
    let path = ty.syntax().descendants().find_map(ast::Path::cast)?;
    Some(path_without_generic_arguments(&path))
}

fn qualified_trait_call(path: &ast::Path) -> Option<(String, String, String)> {
    let mut segments = path.segments();
    let qualification = segments.next()?;
    let ast::PathSegmentKind::Type {
        type_ref: Some(self_type),
        trait_ref: Some(trait_ref),
    } = qualification.kind()?
    else {
        return None;
    };
    let method = segments.last()?.name_ref()?.syntax().text().to_string();
    Some((
        normalize_path_syntax(self_type.syntax()),
        normalize_path_syntax(trait_ref.syntax()),
        method,
    ))
}

fn qualified_type_refs(path: &ast::Path) -> Vec<RustRef> {
    let Some(segment) = path.segments().next() else {
        return Vec::new();
    };
    let Some(ast::PathSegmentKind::Type {
        type_ref: Some(self_type),
        trait_ref: Some(trait_ref),
    }) = segment.kind()
    else {
        return Vec::new();
    };
    let mut refs = syntax_type_paths(self_type.syntax());
    refs.extend(syntax_type_paths(trait_ref.syntax()));
    refs
}

fn syntax_type_paths(root: &SyntaxNode) -> Vec<RustRef> {
    root.descendants()
        .filter_map(ast::Path::cast)
        .filter(|path| path.parent_path().is_none())
        .filter_map(|path| {
            let target = path_without_generic_arguments(&path);
            (!is_ignored_path(&target)).then(|| RustRef {
                span: span_from_range(path.syntax().text_range()),
                target: RustRefTarget::Path {
                    path: target,
                    kind: RustPathRefKind::Type,
                },
            })
        })
        .collect()
}

fn pattern_path(node: &SyntaxNode) -> Option<ast::Path> {
    if let Some(pattern) = ast::PathPat::cast(node.clone()) {
        pattern.path()
    } else if let Some(pattern) = ast::RecordPat::cast(node.clone()) {
        pattern.path()
    } else if let Some(pattern) = ast::TupleStructPat::cast(node.clone()) {
        pattern.path()
    } else {
        None
    }
}

fn last_path_segment_span(path: &ast::Path) -> Span {
    path.syntax()
        .descendants()
        .filter_map(ast::NameRef::cast)
        .last()
        .map(|name| span_from_range(name.syntax().text_range()))
        .unwrap_or_else(|| span_from_range(path.syntax().text_range()))
}

fn is_ignored_path(path: &str) -> bool {
    matches!(
        path,
        "" | "_"
            | "self"
            | "Self"
            | "super"
            | "crate"
            | "bool"
            | "char"
            | "str"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "f32"
            | "f64"
    )
}

fn path_without_generic_arguments(path: &ast::Path) -> String {
    path.segments()
        .filter_map(|segment| match segment.kind()? {
            ast::PathSegmentKind::Name(name) => Some(name.syntax().text().to_string()),
            ast::PathSegmentKind::SelfTypeKw => Some("Self".to_string()),
            ast::PathSegmentKind::SelfKw => Some("self".to_string()),
            ast::PathSegmentKind::SuperKw => Some("super".to_string()),
            ast::PathSegmentKind::CrateKw => Some("crate".to_string()),
            ast::PathSegmentKind::Type { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("::")
}

fn normalize_path_syntax(node: &SyntaxNode) -> String {
    normalize_ws(&syntax_text_without_comments(node))
        .replace(" :: ", "::")
        .replace(":: ", "::")
        .replace(" ::", "::")
        .replace(" <", "<")
        .replace("< ", "<")
        .replace(" >", ">")
        .replace(" ,", ",")
}

fn syntax_text_without_comments(node: &SyntaxNode) -> String {
    node.descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| token.kind() != SyntaxKind::COMMENT)
        .map(|token| token.text().to_string())
        .collect()
}

fn canonical_expression(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::ParenExpr(paren) => paren
            .expr()
            .map(|expr| canonical_expression(&expr))
            .unwrap_or_default(),
        ast::Expr::CallExpr(call) => match call.expr() {
            Some(ast::Expr::PathExpr(path)) => path
                .path()
                .map(|path| format!("{}()", path_without_generic_arguments(&path)))
                .unwrap_or_default(),
            Some(callee) => format!("{}()", canonical_expression(&callee)),
            None => String::new(),
        },
        ast::Expr::TryExpr(try_expr) => try_expr
            .expr()
            .map(|expr| format!("{}?", canonical_expression(&expr)))
            .unwrap_or_default(),
        ast::Expr::AwaitExpr(await_expr) => await_expr
            .expr()
            .map(|expr| format!("{}.await", canonical_expression(&expr)))
            .unwrap_or_default(),
        ast::Expr::FieldExpr(field) => match (field.expr(), field.name_ref()) {
            (Some(receiver), Some(name)) => format!(
                "{}.{}",
                canonical_expression(&receiver),
                name.syntax().text()
            ),
            _ => String::new(),
        },
        _ => normalize_ws(&syntax_text_without_comments(expr.syntax())),
    }
}

fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_simple_identifier(text: &str) -> bool {
    let text = text.strip_prefix("r#").unwrap_or(text);
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn span_from_range(range: TextRange) -> Span {
    span_from_offsets(range.start(), range.end())
}

fn trim_ascii_whitespace_end(src: &str, end: ra_ap_syntax::TextSize) -> ra_ap_syntax::TextSize {
    let mut offset = u32::from(end) as usize;
    while offset > 0 && src.as_bytes()[offset - 1].is_ascii_whitespace() {
        offset -= 1;
    }
    ra_ap_syntax::TextSize::from(offset as u32)
}

fn span_from_offsets(start: ra_ap_syntax::TextSize, end: ra_ap_syntax::TextSize) -> Span {
    Span::try_from_range((u32::from(start) as usize)..(u32::from(end) as usize))
        .expect("bounded Rust source span must fit in u32")
}
