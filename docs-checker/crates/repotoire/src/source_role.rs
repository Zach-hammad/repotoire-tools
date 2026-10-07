use crate::csr::CodeGraph;
use crate::ids::NodeId;
use crate::schema::NodeKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRole {
    Product,
    ContractTest,
    Corpus,
    Benchmark,
    Generated,
    VendorFixture,
    CalibrationSample,
}

impl SourceRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "product" => Some(Self::Product),
            "contract_test" | "contract-test" => Some(Self::ContractTest),
            "corpus" => Some(Self::Corpus),
            "benchmark" => Some(Self::Benchmark),
            "generated" => Some(Self::Generated),
            "vendor_fixture" | "vendor-fixture" => Some(Self::VendorFixture),
            "calibration_sample" | "calibration-sample" => Some(Self::CalibrationSample),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::ContractTest => "contract_test",
            Self::Corpus => "corpus",
            Self::Benchmark => "benchmark",
            Self::Generated => "generated",
            Self::VendorFixture => "vendor_fixture",
            Self::CalibrationSample => "calibration_sample",
        }
    }
}

/// Source-role slice to render or query from a complete `SourceBundle` role index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRoleFilter {
    Product,
    Corpus,
    All,
}

impl SourceRoleFilter {
    pub fn includes(self, role: SourceRole) -> bool {
        match self {
            Self::Product => matches!(role, SourceRole::Product | SourceRole::ContractTest),
            Self::Corpus => matches!(
                role,
                SourceRole::Corpus
                    | SourceRole::Benchmark
                    | SourceRole::Generated
                    | SourceRole::VendorFixture
                    | SourceRole::CalibrationSample
            ),
            Self::All => true,
        }
    }

    pub fn requires_source_role_index(self) -> bool {
        !matches!(self, Self::All)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSourceRoleIndex {
    roles_by_rel_path: BTreeMap<String, SourceRole>,
}

impl CompleteSourceRoleIndex {
    pub fn new<'a, I>(
        roles_by_rel_path: BTreeMap<String, SourceRole>,
        source_paths: I,
    ) -> Result<Self, SourceRoleCompletenessError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let expected = source_paths
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>();
        let actual = roles_by_rel_path
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let missing_paths = expected
            .difference(&actual)
            .cloned()
            .collect::<Vec<String>>();
        let unexpected_paths = actual
            .difference(&expected)
            .cloned()
            .collect::<Vec<String>>();
        if !missing_paths.is_empty() || !unexpected_paths.is_empty() {
            return Err(SourceRoleCompletenessError {
                missing_paths,
                unexpected_paths,
            });
        }
        Ok(Self { roles_by_rel_path })
    }

    pub fn from_entries<'a, E, P>(
        entries: E,
        source_paths: P,
    ) -> Result<Self, SourceRoleCompletenessError>
    where
        E: IntoIterator<Item = (String, SourceRole)>,
        P: IntoIterator<Item = &'a str>,
    {
        Self::new(entries.into_iter().collect(), source_paths)
    }

    pub fn role_for_path(&self, rel_path: &str) -> Option<SourceRole> {
        self.roles_by_rel_path.get(rel_path).copied()
    }

    pub fn role_for_file(&self, graph: &CodeGraph<'_>, node_id: NodeId) -> Option<SourceRole> {
        let file = if graph.node_kind(node_id) == NodeKind::File {
            node_id
        } else {
            graph.file_of(node_id)?
        };
        self.role_for_path(graph.node_name(file))
    }

    pub fn as_map(&self) -> &BTreeMap<String, SourceRole> {
        &self.roles_by_rel_path
    }

    pub fn into_map(self) -> BTreeMap<String, SourceRole> {
        self.roles_by_rel_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRoleCompletenessError {
    pub missing_paths: Vec<String>,
    pub unexpected_paths: Vec<String>,
}

impl fmt::Display for SourceRoleCompletenessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (
            self.missing_paths.is_empty(),
            self.unexpected_paths.is_empty(),
        ) {
            (false, false) => write!(
                f,
                "source role index missing roles for {:?} and has unexpected roles for {:?}",
                self.missing_paths, self.unexpected_paths
            ),
            (false, true) => write!(
                f,
                "source role index missing roles for {:?}",
                self.missing_paths
            ),
            (true, false) => write!(
                f,
                "source role index has unexpected roles for {:?}",
                self.unexpected_paths
            ),
            (true, true) => write!(f, "source role index is complete"),
        }
    }
}

impl std::error::Error for SourceRoleCompletenessError {}
