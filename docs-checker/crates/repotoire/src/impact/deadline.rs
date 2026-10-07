//! Cooperative cancellation contract for core Impact analysis.

use std::fmt;

/// The request-owned stop condition observed by potentially long Impact work.
///
/// This trait owns no clock and starts no worker. Front doors retain deadline
/// policy; core traversal only observes the same request token at safe points.
pub trait ImpactDeadline {
    fn check(&self) -> Result<(), ImpactDeadlineExceeded>;
}

/// Typed signal that core Impact analysis stopped at its request deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactDeadlineExceeded;

impl fmt::Display for ImpactDeadlineExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("impact analysis deadline expired")
    }
}

impl std::error::Error for ImpactDeadlineExceeded {}

/// Explicit opt-out for library operations that do not have a request budget.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoImpactDeadline;

pub const NO_IMPACT_DEADLINE: NoImpactDeadline = NoImpactDeadline;

impl ImpactDeadline for NoImpactDeadline {
    fn check(&self) -> Result<(), ImpactDeadlineExceeded> {
        Ok(())
    }
}
