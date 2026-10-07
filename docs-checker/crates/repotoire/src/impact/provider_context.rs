use crate::archive::SourceBundle;
use crate::impact::deadline::{ImpactDeadline, ImpactDeadlineExceeded};
use crate::impact::service_dispatch::ServiceMethodDispatchSite;
use crate::schema::NodeKind;
use crate::source_pipeline::{source_language_for_path, SourceLanguage};
use crate::spans::LineIndex;
use crate::ts::lexer::{Lexer, Token, TokenKind};

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProviderContextEvidence {
    /// All captured files contributing to the join, including the dispatch.
    pub contributing_files: BTreeSet<String>,
    pub file: String,
    pub line: u32,
    pub token: String,
    pub provider: String,
    pub kind: ProviderContextKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ProviderContextKind {
    SourceVisibleComposition,
    MissingComposition,
}

struct ProviderContextIndex {
    providers_by_token: BTreeMap<String, BTreeSet<String>>,
    composition_by_provider: BTreeMap<String, (String, u32)>,
    definitions: BTreeMap<(String, String), BTreeSet<String>>,
}

impl ProviderContextIndex {
    fn build<D: ImpactDeadline + ?Sized>(
        bundle: &SourceBundle<'_>,
        dispatch_rows: &[ServiceMethodDispatchSite],
        deadline: &D,
    ) -> Result<Self, ImpactDeadlineExceeded> {
        let graph = &bundle.graph;
        let mut providers_by_token: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut composition_by_provider = BTreeMap::new();
        let mut definitions: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();

        // The TypeScript lexer owns lexical identity. One token pass discovers
        // both provider definitions and actual Effect.provide(...) calls while
        // excluding comments, strings, and unrelated functions by construction.
        for file in graph.nodes_of_kind(NodeKind::File) {
            deadline.check()?;
            let file_name = graph.node_name(file);
            if source_language_for_path(Path::new(file_name)) != SourceLanguage::TypeScript {
                continue;
            }
            let Some(bytes) = bundle.source_bytes(file) else {
                continue;
            };
            let mut file_providers = BTreeMap::new();
            scan_provider_context_source(
                bytes,
                file_name,
                &mut file_providers,
                &mut composition_by_provider,
                deadline,
            )?;
            for (token, providers) in file_providers {
                deadline.check()?;
                for provider in &providers {
                    definitions
                        .entry((token.clone(), provider.clone()))
                        .or_default()
                        .insert(file_name.to_owned());
                }
                providers_by_token
                    .entry(token)
                    .or_default()
                    .extend(providers);
            }
        }

        // Every dispatch token has at least its conventional `TokenLive`
        // candidate. Keeping that invariant in the index removes an empty-set
        // branch from every consumer.
        let mut requested_providers = BTreeSet::new();
        for dispatch in dispatch_rows {
            deadline.check()?;
            let Some(token) = dispatch.service_token.as_deref() else {
                continue;
            };
            let providers = providers_by_token.entry(token.to_string()).or_default();
            providers.insert(format!("{token}Live"));
            requested_providers.extend(providers.iter().cloned());
        }

        composition_by_provider.retain(|provider, _| requested_providers.contains(provider));

        deadline.check()?;
        Ok(Self {
            providers_by_token,
            composition_by_provider,
            definitions,
        })
    }

    fn providers_for_token(&self, token: &str) -> &BTreeSet<String> {
        let providers = self
            .providers_by_token
            .get(token)
            .expect("every dispatch token must be indexed");
        assert!(
            !providers.is_empty(),
            "every dispatch token must have a provider candidate"
        );
        providers
    }

    fn composition_for_provider(&self, provider: &str) -> Option<&(String, u32)> {
        self.composition_by_provider.get(provider)
    }
}

fn scan_provider_context_source<D: ImpactDeadline + ?Sized>(
    source: &[u8],
    file: &str,
    providers_by_token: &mut BTreeMap<String, BTreeSet<String>>,
    composition_by_provider: &mut BTreeMap<String, (String, u32)>,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    let mut lexer = Lexer::new(source);
    let mut line_index = None;

    loop {
        deadline.check()?;
        let token = lexer.next();
        match token.kind {
            TokenKind::Const | TokenKind::Let | TokenKind::Var => {
                let checkpoint = lexer.checkpoint();
                if let Some((service_token, provider)) =
                    provider_definition_after_declaration(&mut lexer, source, deadline)?
                {
                    providers_by_token
                        .entry(service_token)
                        .or_default()
                        .insert(provider);
                } else {
                    lexer.restore(checkpoint);
                }
            }
            TokenKind::Ident if matches!(token_text(source, &token), Some("Effect" | "Layer")) => {
                let checkpoint = lexer.checkpoint();
                if let Some(providers) =
                    provider_identifiers_after_receiver(&mut lexer, source, deadline)?
                {
                    let index = line_index.get_or_insert_with(|| LineIndex::build(source));
                    let line = index
                        .line_col(token.span.start())
                        .expect("lexer token span must belong to the indexed source")
                        .line;
                    for provider in providers {
                        composition_by_provider
                            .entry(provider)
                            .or_insert_with(|| (file.to_string(), line));
                    }
                } else {
                    lexer.restore(checkpoint);
                }
            }
            TokenKind::Eof => break,
            _ => {}
        }
    }
    Ok(())
}

fn provider_definition_after_declaration<D: ImpactDeadline + ?Sized>(
    lexer: &mut Lexer<'_>,
    source: &[u8],
    deadline: &D,
) -> Result<Option<(String, String)>, ImpactDeadlineExceeded> {
    let Some(provider) = next_identifier(lexer, source) else {
        return Ok(None);
    };
    let provider = provider.to_string();
    if lexer.next().kind != TokenKind::Eq {
        return Ok(None);
    }
    let layer = lexer.next();
    if token_text(source, &layer) != Some("Layer") || lexer.next().kind != TokenKind::Dot {
        return Ok(None);
    }
    let method = lexer.next();
    if !matches!(token_text(source, &method), Some("effect" | "succeed")) {
        return Ok(None);
    }
    let Some(service_token) = first_identifier_call_argument(lexer, source, deadline)? else {
        return Ok(None);
    };
    Ok(Some((service_token.to_string(), provider)))
}

fn provider_identifiers_after_receiver<D: ImpactDeadline + ?Sized>(
    lexer: &mut Lexer<'_>,
    source: &[u8],
    deadline: &D,
) -> Result<Option<Vec<String>>, ImpactDeadlineExceeded> {
    if lexer.next().kind != TokenKind::Dot {
        return Ok(None);
    }
    let method = lexer.next();
    if token_text(source, &method) != Some("provide") {
        return Ok(None);
    }
    identifiers_in_call(lexer, source, deadline)
}

fn first_identifier_call_argument<'a, D: ImpactDeadline + ?Sized>(
    lexer: &mut Lexer<'_>,
    source: &'a [u8],
    deadline: &D,
) -> Result<Option<&'a str>, ImpactDeadlineExceeded> {
    if lexer.peek().kind == TokenKind::Lt && !skip_type_arguments(lexer, deadline)? {
        return Ok(None);
    }
    if lexer.next().kind != TokenKind::LParen {
        return Ok(None);
    }
    Ok(next_identifier(lexer, source))
}

fn identifiers_in_call<D: ImpactDeadline + ?Sized>(
    lexer: &mut Lexer<'_>,
    source: &[u8],
    deadline: &D,
) -> Result<Option<Vec<String>>, ImpactDeadlineExceeded> {
    if lexer.peek().kind == TokenKind::Lt && !skip_type_arguments(lexer, deadline)? {
        return Ok(None);
    }
    if lexer.next().kind != TokenKind::LParen {
        return Ok(None);
    }

    let mut identifiers = Vec::new();
    let mut parenthesis_depth = 1usize;
    while parenthesis_depth > 0 {
        deadline.check()?;
        let token = lexer.next();
        match token.kind {
            TokenKind::LParen => parenthesis_depth += 1,
            TokenKind::RParen => parenthesis_depth -= 1,
            TokenKind::Ident => {
                if let Some(identifier) = token_text(source, &token) {
                    identifiers.push(identifier.to_string());
                }
            }
            TokenKind::Eof => return Ok(None),
            _ => {}
        }
    }
    Ok(Some(identifiers))
}

fn skip_type_arguments<D: ImpactDeadline + ?Sized>(
    lexer: &mut Lexer<'_>,
    deadline: &D,
) -> Result<bool, ImpactDeadlineExceeded> {
    if lexer.next().kind != TokenKind::Lt {
        return Ok(false);
    }

    let mut depth = 1usize;
    while depth > 0 {
        deadline.check()?;
        lexer.rescan_gt();
        match lexer.next().kind {
            TokenKind::Lt => depth += 1,
            TokenKind::Gt => depth -= 1,
            TokenKind::Eof => return Ok(false),
            _ => {}
        }
    }
    Ok(true)
}

fn next_identifier<'a>(lexer: &mut Lexer<'_>, source: &'a [u8]) -> Option<&'a str> {
    let token = lexer.next();
    if token.kind != TokenKind::Ident {
        return None;
    }
    token_text(source, &token)
}

fn token_text<'a>(source: &'a [u8], token: &Token) -> Option<&'a str> {
    let start = usize::try_from(token.span.start()).ok()?;
    let end = usize::try_from(token.span.end()).ok()?;
    std::str::from_utf8(source.get(start..end)?).ok()
}

pub(crate) fn collect_provider_context_evidence<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    dispatch_rows: &[ServiceMethodDispatchSite],
    deadline: &D,
) -> Result<Vec<ProviderContextEvidence>, ImpactDeadlineExceeded> {
    let index = ProviderContextIndex::build(bundle, dispatch_rows, deadline)?;
    let mut rows = Vec::new();

    for dispatch in dispatch_rows {
        deadline.check()?;
        let Some(token) = dispatch.service_token.as_deref() else {
            continue;
        };
        let providers = index.providers_for_token(token);

        let mut found_composition = false;
        for provider in providers {
            deadline.check()?;
            if let Some((file, line)) = index.composition_for_provider(provider) {
                let mut contributing_files = dispatch.contributing_files.clone();
                contributing_files.insert(file.clone());
                if let Some(files) = index
                    .definitions
                    .get(&(token.to_string(), provider.clone()))
                {
                    contributing_files.extend(files.iter().cloned());
                }
                rows.push(ProviderContextEvidence {
                    contributing_files,
                    file: file.clone(),
                    line: *line,
                    token: token.to_string(),
                    provider: provider.clone(),
                    kind: ProviderContextKind::SourceVisibleComposition,
                });
                found_composition = true;
            }
        }

        if !found_composition {
            if let Some(provider) = providers.iter().next() {
                rows.push(ProviderContextEvidence {
                    // Absence is based on the entire index. Restricted views
                    // omit this variant rather than claiming scoped absence.
                    contributing_files: dispatch.contributing_files.clone(),
                    file: dispatch.file.clone(),
                    line: dispatch.line,
                    token: token.to_string(),
                    provider: provider.clone(),
                    kind: ProviderContextKind::MissingComposition,
                });
            }
        }
    }

    rows.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.token.cmp(&b.token))
            .then(a.provider.cmp(&b.provider))
            .then(a.contributing_files.cmp(&b.contributing_files))
    });
    rows.dedup_by(|a, b| {
        a.file == b.file
            && a.line == b.line
            && a.token == b.token
            && a.provider == b.provider
            && a.contributing_files == b.contributing_files
    });
    deadline.check()?;
    Ok(rows)
}
