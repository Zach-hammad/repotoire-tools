//! Fail-closed process-group signal targeting (issue #216).
//!
//! Signalling a process group is `kill(-pgid, sig)` or `killpg(pgid, sig)`.
//! Three pgid values are catastrophic rather than merely wrong, so every
//! escalation path in this crate resolves its target through this module
//! instead of negating a PID inline:
//!
//! * `pgid == 1` renders `kill(-1, sig)`, which POSIX defines as delivery to
//!   *every* process the caller has permission to signal. Under a systemd user
//!   session that set includes `systemd --user` itself, so one stray SIGKILL
//!   ends `user@<uid>.service` and tears down the entire `user-<uid>.slice` —
//!   the runner-host failure reported in issue #216.
//! * `pgid == 0` renders `kill(0, sig)` / `killpg(0, sig)`, which signals the
//!   *caller's own* process group. Under a test runner that is every sibling
//!   test process, and under a CI shell it is the whole job.
//! * A PID above `i32::MAX` cannot be negated into a `kill(2)` target at all.
//!
//! None of those can be a legitimate spawned-child process group, so a PID
//! that resolves to one is refused. The refusal is deliberate: a supervisor
//! that cannot name its target must report that it could not clean up, never
//! fall back to a value that happens to be signallable.

/// Validate `pid` as a process-group id suitable for `killpg(2)`.
///
/// Returns the pgid as a positive `i32`. Fails closed for `0`, `1`, and any
/// value that does not fit in an `i32`.
#[cfg(unix)]
pub(crate) fn process_group_id(pid: u32) -> Result<i32, String> {
    let pgid = i32::try_from(pid)
        .map_err(|_| format!("process group {pid} is out of range for a signal target"))?;
    if pgid <= 1 {
        return Err(format!(
            "refusing to signal process group {pgid}: {} is not a spawned child group",
            if pgid == 0 {
                "0 targets the caller's own process group"
            } else {
                "1 targets every process of this user"
            }
        ));
    }
    Ok(pgid)
}

/// Validate `pid` and render the negative `kill(2)` process-group target.
///
/// `kill(-pgid, sig)` is the portable spelling of "signal every member of the
/// group led by `pgid`". Fails closed exactly like [`process_group_id`].
#[cfg(unix)]
pub(crate) fn process_group_signal_target(pid: u32) -> Result<i32, String> {
    Ok(-process_group_id(pid)?)
}
