use std::io;
use std::time::{Duration, Instant};

/// Lifecycle of a synchronous observation owned by one request. The scope is
/// installed only inside the request's joined blocking job, never across an
/// async suspension. Explicit observation readers opt in; ordinary unbounded
/// deadlines keep their existing semantics. Nested scopes restore their parent
/// on success, error, and unwind, so a pooled thread cannot retain a request.
#[derive(Clone)]
pub(crate) struct ObservationScope {
    pub(crate) deadline: RequestDeadline,
    pub(crate) cancellation: crate::worker_runtime::WorkerRuntimeCancellation,
}

thread_local! {
    static OBSERVATION: std::cell::RefCell<Option<ObservationScope>> = const { std::cell::RefCell::new(None) };
}

impl ObservationScope {
    pub(crate) fn check_current(operation: &'static str) -> io::Result<()> {
        OBSERVATION.with(|scope| {
            scope
                .borrow()
                .as_ref()
                .map_or(Ok(()), |scope| scope.check(operation))
        })
    }

    pub(crate) fn deadline_current() -> RequestDeadline {
        OBSERVATION.with(|scope| {
            scope
                .borrow()
                .as_ref()
                .map_or(RequestDeadline::unbounded(), |scope| scope.deadline)
        })
    }

    pub(crate) fn current() -> Self {
        OBSERVATION
            .with(|scope| scope.borrow().clone())
            .unwrap_or_else(|| Self {
                deadline: RequestDeadline::unbounded(),
                cancellation: Default::default(),
            })
    }

    /// Tighten a child observation without extending its parent's lifetime or
    /// replacing the cancellation token inherited from the request owner.
    pub(crate) fn with_deadline(mut self, deadline: RequestDeadline) -> Self {
        self.deadline = self.deadline.earlier(deadline);
        self
    }

    pub(crate) fn check(&self, operation: &'static str) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            // Interrupted means "retry this read" to BufRead and serde. A
            // cancelled request is terminal and must not become a retry loop.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("observation cancelled during {operation}"),
            ));
        }
        self.deadline.check(operation)
    }

    pub(crate) fn run<T>(&self, work: impl FnOnce() -> T) -> io::Result<T> {
        self.check("observation admission")?;
        struct Restore(Option<ObservationScope>);
        impl Drop for Restore {
            fn drop(&mut self) {
                OBSERVATION.with(|scope| *scope.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(OBSERVATION.with(|scope| scope.replace(Some(self.clone()))));
        let result = work();
        self.check("observation completion")?;
        Ok(result)
    }
}

/// One cooperative request deadline, created once and copied into bounded work.
///
/// The token carries no cancellation thread or mutable lifecycle. Consumers may
/// only check it and stop; the request owner still waits for scoped work to retire.
#[derive(Clone, Copy, Debug)]
pub struct RequestDeadline {
    bound: Option<DeadlineBound>,
}

#[derive(Clone, Copy, Debug)]
struct DeadlineBound {
    started: Instant,
    timeout: Duration,
}

impl RequestDeadline {
    pub(crate) const fn unbounded() -> Self {
        Self { bound: None }
    }

    pub fn new(started: Instant, timeout: Duration) -> Self {
        Self {
            bound: Some(DeadlineBound { started, timeout }),
        }
    }

    fn earlier(self, other: Self) -> Self {
        match (self.bound, other.bound) {
            (None, _) => other,
            (_, None) => self,
            (Some(left), Some(right)) => {
                let now = Instant::now();
                let left_remaining = left
                    .timeout
                    .saturating_sub(now.saturating_duration_since(left.started));
                let right_remaining = right
                    .timeout
                    .saturating_sub(now.saturating_duration_since(right.started));
                if left_remaining <= right_remaining {
                    self
                } else {
                    other
                }
            }
        }
    }

    pub(crate) fn is_expired(self) -> bool {
        self.bound
            .is_some_and(|bound| bound.started.elapsed() >= bound.timeout)
    }

    pub(crate) fn check(self, operation: &'static str) -> io::Result<()> {
        if self.is_expired() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("query deadline expired during {operation}"),
            ));
        }
        Ok(())
    }

    /// Return the finite time still owned by this request.
    ///
    /// Cooperative file reads may use an unbounded token, but blocking child
    /// processes must not. Requiring a concrete duration at this seam makes
    /// an unbounded subprocess lifecycle an explicit error instead of a
    /// second execution mode.
    pub(crate) fn remaining(self, operation: &'static str) -> io::Result<Duration> {
        let Some(bound) = self.bound else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("finite query deadline required during {operation}"),
            ));
        };
        let Some(remaining) = bound.timeout.checked_sub(bound.started.elapsed()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("query deadline expired during {operation}"),
            ));
        };
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("query deadline expired during {operation}"),
            ));
        }
        Ok(remaining)
    }

    /// Return one finite child-process budget. A bounded request keeps its
    /// absolute deadline; an intentionally unbounded caller still receives
    /// the owner's finite safety cap rather than an unbounded subprocess.
    pub(crate) fn subprocess_timeout(
        self,
        operation: &'static str,
        safety_cap: Duration,
    ) -> io::Result<Duration> {
        if safety_cap.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("positive subprocess safety cap required during {operation}"),
            ));
        }
        match self.bound {
            Some(_) => self
                .remaining(operation)
                .map(|remaining| remaining.min(safety_cap)),
            None => Ok(safety_cap),
        }
    }
}
