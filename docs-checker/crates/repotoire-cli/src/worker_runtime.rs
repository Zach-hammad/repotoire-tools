//! Bounded process supervision retained from the existing worker runtime.
//! This package uses it only for Git/source inventory observation.
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRuntimeError {
    message: String,
    // A failure after spawn can lose termination proof. Machine must retain
    // its Core lease instead of converting that error into an Exited receipt.
    process_may_be_running: bool,
}

impl WorkerRuntimeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            process_may_be_running: false,
        }
    }

    pub(crate) fn process_may_be_running(&self) -> bool {
        self.process_may_be_running
    }
}

impl std::fmt::Display for WorkerRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WorkerRuntimeError {}

#[derive(Debug, Clone, Default)]
pub struct WorkerRuntimeCancellation {
    cancelled: Arc<AtomicBool>,
}

impl WorkerRuntimeCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub(crate) struct BoundedOutputCapture {
    output_limit_exceeded: Arc<AtomicBool>,
    retirement_started: Arc<OnceLock<Instant>>,
    stdout_reader: Option<std::thread::JoinHandle<CapturedStream>>,
    stderr_reader: Option<std::thread::JoinHandle<CapturedStream>>,
}

struct CapturedStream {
    bytes: Vec<u8>,
    failure: Option<std::io::Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BoundedProcessTermination {
    Exited,
    Cancelled,
    TimedOut,
    OutputLimit,
}

pub(crate) struct BoundedProcessOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) termination: BoundedProcessTermination,
}

/// Negative evidence survives a failed observation, but cannot be consumed as
/// a completed process. Keep the existing I/O result contract for callers.
#[derive(Debug)]
pub(crate) struct BoundedProcessFailure {
    pub(crate) status: Option<ExitStatus>,
    pub(crate) termination: Option<BoundedProcessTermination>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    cause: std::io::Error,
}

impl std::fmt::Display for BoundedProcessFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(termination) = self.termination {
            write!(formatter, "process termination {termination:?}; ")?;
        }
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for BoundedProcessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Spawn and supervise one command under the process-tree and output-capture
/// invariant. Callers retain command construction and exit-status semantics;
/// this owner makes isolation, bounded output, and finite retirement atomic.
pub(crate) fn run_bounded_command(
    command: &mut Command,
    max_output_bytes: usize,
    timeout: Duration,
) -> std::io::Result<BoundedProcessOutput> {
    let scope = crate::deadline::ObservationScope::current();
    scope.check("subprocess admission")?;
    let timeout = scope
        .deadline
        .subprocess_timeout("subprocess admission", timeout)?;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    isolate_process_group(command);
    let child = command.spawn()?;
    wait_for_bounded_output_inner(
        child,
        max_output_bytes,
        timeout,
        Duration::ZERO,
        Some(&scope.cancellation),
    )
}

/// Waits for one isolated child while applying one deadline and one aggregate
/// output budget. The caller must pipe both output streams and call
/// `isolate_process_group` before spawning. The process group is terminated
/// before return even when its leader exits successfully. A descendant that
/// escapes that group can survive; if it retains an output pipe beyond the
/// finite drain allowance, collection fails explicitly after joining readers.
/// This is the shared subprocess lifecycle seam for non-worker users.
pub(crate) fn wait_for_bounded_output(
    child: std::process::Child,
    max_output_bytes: usize,
    timeout: Duration,
) -> std::io::Result<BoundedProcessOutput> {
    wait_for_bounded_output_inner(child, max_output_bytes, timeout, Duration::ZERO, None)
}

fn wait_for_bounded_output_inner(
    mut child: std::process::Child,
    max_output_bytes: usize,
    timeout: Duration,
    termination_grace: Duration,
    cancellation: Option<&WorkerRuntimeCancellation>,
) -> std::io::Result<BoundedProcessOutput> {
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(terminate_after_output_observation_failure(
                &mut child,
                "child stdout pipe is unavailable",
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err(terminate_after_output_observation_failure(
                &mut child,
                "child stderr pipe is unavailable",
            ));
        }
    };
    let output_capture =
        BoundedOutputCapture::start(stdout, stderr, max_output_bytes).map_err(|error| {
            terminate_after_output_observation_failure(
                &mut child,
                &format!("start output capture failed: {error}"),
            )
        })?;
    let deadline = match Instant::now().checked_add(timeout) {
        Some(deadline) => deadline,
        None => {
            let retired = terminate_isolated_child(
                &mut child,
                "timeout exceeds the host clock range",
                Duration::ZERO,
            );
            let (stdout, stderr, _) = output_capture.finish();
            let mut cause = "timeout exceeds the host clock range".to_string();
            for error in [
                retired.as_ref().err(),
                stdout.failure.as_ref(),
                stderr.failure.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                cause.push_str(&format!("; cleanup failed: {error}"));
            }
            return Err(std::io::Error::other(BoundedProcessFailure {
                status: retired.ok(),
                termination: None,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
                cause: std::io::Error::other(cause),
            }));
        }
    };
    let result = supervise_isolated_child(
        &mut child,
        deadline,
        termination_grace,
        || cancellation.is_some_and(WorkerRuntimeCancellation::is_cancelled),
        || output_capture.limit_exceeded(),
    );
    // Always join both drains, including a failed observation or termination.
    let (stdout, stderr, output_truncated) = output_capture.finish();
    let drain = match (stdout.failure, stderr.failure) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(stdout), Some(stderr)) => Some(std::io::Error::new(
            stdout.kind(),
            format!("stdout: {stdout}; stderr: {stderr}"),
        )),
    };
    let (status, termination) = match (result, drain) {
        (Ok(process), None) => process,
        (process, drain) => {
            let (status, termination, cause) = match process {
                Ok((status, termination)) => (Some(status), Some(termination), drain.unwrap()),
                Err(process) => {
                    let cause = match drain {
                        Some(drain) => {
                            std::io::Error::new(process.kind(), format!("{process}; {drain}"))
                        }
                        None => process,
                    };
                    (child.try_wait().ok().flatten(), None, cause)
                }
            };
            return Err(std::io::Error::new(
                cause.kind(),
                BoundedProcessFailure {
                    status,
                    termination,
                    stdout: stdout.bytes,
                    stderr: stderr.bytes,
                    cause,
                },
            ));
        }
    };
    let termination = if output_truncated {
        BoundedProcessTermination::OutputLimit
    } else {
        termination
    };
    Ok(BoundedProcessOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        termination,
    })
}

/// The process-tree retirement loop shared by captured commands and streaming
/// protocols. It observes exit before reaping, so descendant cleanup cannot
/// accidentally target a recycled leader PID.
fn supervise_isolated_child(
    child: &mut std::process::Child,
    deadline: Instant,
    termination_grace: Duration,
    cancelled: impl Fn() -> bool,
    output_limit_exceeded: impl Fn() -> bool,
) -> std::io::Result<(ExitStatus, BoundedProcessTermination)> {
    loop {
        if cancelled() {
            return Ok((
                terminate_isolated_child(child, "cancellation", termination_grace)?,
                BoundedProcessTermination::Cancelled,
            ));
        }
        if output_limit_exceeded() {
            return Ok((
                terminate_isolated_child(child, "output limit", termination_grace)?,
                BoundedProcessTermination::OutputLimit,
            ));
        }
        if Instant::now() >= deadline {
            return Ok((
                terminate_isolated_child(child, "timeout", termination_grace)?,
                BoundedProcessTermination::TimedOut,
            ));
        }
        #[cfg(unix)]
        match child_exited_without_reaping(child.id()) {
            Ok(true) => {
                let process_group = crate::process_group_signal::process_group_id(child.id())
                    .map_err(std::io::Error::other)?;
                signal_process_group_after_leader_exit(
                    process_group,
                    libc::SIGKILL,
                    "successful command exit descendant cleanup",
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                return Ok((child.wait()?, BoundedProcessTermination::Exited));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(terminate_after_output_observation_failure(
                    child,
                    &format!("observe child process failed: {error}"),
                ));
            }
        }
        #[cfg(not(unix))]
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, BoundedProcessTermination::Exited)),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn terminate_after_output_observation_failure(
    child: &mut std::process::Child,
    failure: &str,
) -> std::io::Error {
    match terminate_isolated_child(child, failure, Duration::ZERO) {
        Ok(_) => std::io::Error::other(failure.to_string()),
        Err(termination_error) => std::io::Error::other(format!(
            "{failure}; terminating the isolated child also failed: {termination_error}"
        )),
    }
}

pub(crate) fn terminate_isolated_child(
    child: &mut std::process::Child,
    reason: &str,
    grace: Duration,
) -> std::io::Result<ExitStatus> {
    terminate_child(child, reason, grace).map_err(|error| std::io::Error::other(error.to_string()))
}

// Cleanup allowance starts once supervision is terminal, independently of its
// reason. It accommodates queued bytes and kernel pipe closure, but cannot be
// renewed by an escaped writer. This is additional to the execution timeout.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(250);
const OUTPUT_READ_POLL: Duration = Duration::from_millis(5);

impl BoundedOutputCapture {
    fn start(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        max_output_bytes: usize,
    ) -> std::io::Result<Self> {
        // Prepare both before starting either thread. A partial startup is
        // owned by Drop, including failure to create the second thread.
        stdout.prepare_nonblocking()?;
        stderr.prepare_nonblocking()?;
        let total_output = Arc::new(AtomicUsize::new(0));
        let mut capture = Self {
            output_limit_exceeded: Arc::new(AtomicBool::new(false)),
            retirement_started: Arc::new(OnceLock::new()),
            stdout_reader: None,
            stderr_reader: None,
        };
        capture.stdout_reader = Some(spawn_bounded_reader(
            stdout,
            Arc::clone(&total_output),
            Arc::clone(&capture.output_limit_exceeded),
            Arc::clone(&capture.retirement_started),
            max_output_bytes,
        )?);
        capture.stderr_reader = Some(spawn_bounded_reader(
            stderr,
            total_output,
            Arc::clone(&capture.output_limit_exceeded),
            Arc::clone(&capture.retirement_started),
            max_output_bytes,
        )?);
        Ok(capture)
    }

    fn limit_exceeded(&self) -> bool {
        self.output_limit_exceeded.load(Ordering::Acquire)
    }

    fn finish(mut self) -> (CapturedStream, CapturedStream, bool) {
        let (stdout, stderr) = self.join_readers();
        (stdout, stderr, self.limit_exceeded())
    }

    fn join_readers(&mut self) -> (CapturedStream, CapturedStream) {
        self.retirement_started.get_or_init(Instant::now);
        // Take and join BOTH before propagating any error. Drop also uses this
        // path, so no reader can be detached by an early return or startup error.
        let stdout = join_bounded_reader(self.stdout_reader.take(), "stdout");
        let stderr = join_bounded_reader(self.stderr_reader.take(), "stderr");
        (stdout, stderr)
    }
}

impl Drop for BoundedOutputCapture {
    fn drop(&mut self) {
        let _ = self.join_readers();
    }
}

// Every read must return without waiting for a writer. The capture owns the
// sole reader of each pipe; no cloned handles may race availability checks.
trait NonblockingOutputPipe: Read + Send + 'static {
    fn prepare_nonblocking(&self) -> std::io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<usize>;
}

#[cfg(unix)]
impl<R: Read + Send + std::os::fd::AsRawFd + 'static> NonblockingOutputPipe for R {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        let fd = self.as_raw_fd();
        // SAFETY: this owned pipe remains open for both descriptor operations.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.read(buffer)
    }
}

#[cfg(windows)]
impl<R: Read + Send + std::os::windows::io::AsRawHandle + 'static> NonblockingOutputPipe for R {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut available = 0;
        // SAFETY: this is the sole reader and has no pending synchronous I/O.
        // Peek does not wait for data. Read at most the available bytes so the
        // following synchronous read cannot wait on the writer either.
        if unsafe {
            PeekNamedPipe(
                self.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(0)
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let count = buffer.len().min(available as usize);
        self.read(&mut buffer[..count])
    }
}

#[cfg(not(any(unix, windows)))]
impl<R: Read + Send + 'static> NonblockingOutputPipe for R {
    fn prepare_nonblocking(&self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bounded output capture requires nonblocking pipe support",
        ))
    }
    fn read_available(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

fn spawn_bounded_reader<R: NonblockingOutputPipe>(
    mut reader: R,
    total_output: Arc<AtomicUsize>,
    output_limit_exceeded: Arc<AtomicBool>,
    retirement_started: Arc<OnceLock<Instant>>,
    max_output_bytes: usize,
) -> std::io::Result<std::thread::JoinHandle<CapturedStream>> {
    std::thread::Builder::new().spawn(move || {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            // Check on every iteration, even if an escaped writer continuously
            // supplies bytes. Data and EINTR cannot extend the drain allowance.
            if retirement_started.get().is_some_and(|start| start.elapsed() >= OUTPUT_DRAIN_GRACE) {
                return CapturedStream { bytes: captured, failure: Some(std::io::Error::other(
                    "output drain exceeded its retirement allowance; capture incomplete; an escaped pipe holder may remain",
                )) };
            }
            let count = match reader.read_available(&mut chunk) {
                Ok(0) => return CapturedStream { bytes: captured, failure: None },
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(OUTPUT_READ_POLL);
                    continue;
                }
                Err(error) => return CapturedStream { bytes: captured, failure: Some(error) },
            };
            let previous = total_output.fetch_add(count, Ordering::AcqRel);
            let remaining = max_output_bytes.saturating_sub(previous);
            captured.extend_from_slice(&chunk[..count.min(remaining)]);
            if count > remaining {
                output_limit_exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn join_bounded_reader(
    reader: Option<std::thread::JoinHandle<CapturedStream>>,
    stream: &str,
) -> CapturedStream {
    let Some(reader) = reader else {
        return CapturedStream {
            bytes: Vec::new(),
            failure: None,
        };
    };
    reader.join().unwrap_or_else(|_| CapturedStream {
        bytes: Vec::new(),
        failure: Some(std::io::Error::other(format!("{stream} reader panicked"))),
    })
}

pub(crate) fn isolate_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

#[cfg(unix)]
fn child_exited_without_reaping(child_pid: u32) -> Result<bool, WorkerRuntimeError> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let observed = unsafe {
        libc::waitid(
            libc::P_PID,
            child_pid as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if observed != 0 {
        return Err(WorkerRuntimeError::new(format!(
            "observe Codex worker pid {child_pid} without reaping failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let info = unsafe { info.assume_init() };
    Ok(unsafe { info.si_pid() } != 0)
}

fn terminate_child(
    child: &mut std::process::Child,
    reason: &str,
    grace: Duration,
) -> Result<ExitStatus, WorkerRuntimeError> {
    #[cfg(unix)]
    {
        let process_group =
            crate::process_group_signal::process_group_id(child.id()).map_err(|error| {
                WorkerRuntimeError::new(format!(
                    "Codex worker pid {} cannot identify a process group: {error}",
                    child.id()
                ))
            })?;
        if grace.is_zero() {
            return terminate_process_group_immediately(child, process_group, reason);
        }
        signal_process_group(process_group, libc::SIGTERM, reason)?;
        let deadline = Instant::now() + grace;
        loop {
            // Observe without reaping: the exited group leader must retain its
            // PID until the final group signal, otherwise a high-churn host can
            // reuse the numeric PGID for an unrelated process group.
            if child_exited_without_reaping(child.id())? {
                signal_process_group_after_leader_exit(process_group, libc::SIGKILL, reason)?;
                return child.wait().map_err(|error| {
                    WorkerRuntimeError::new(format!(
                        "reap Codex worker after {reason} termination failed: {error}"
                    ))
                });
            }
            if Instant::now() >= deadline {
                signal_process_group(process_group, libc::SIGKILL, reason)?;
                return child.wait().map_err(|error| {
                    WorkerRuntimeError::new(format!(
                        "reap Codex worker after {reason} escalation failed: {error}"
                    ))
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(not(unix))]
    {
        let _ = grace;
        child.kill().map_err(|error| {
            WorkerRuntimeError::new(format!(
                "terminate Codex worker after {reason} failed: {error}"
            ))
        })?;
        child.wait().map_err(|error| {
            WorkerRuntimeError::new(format!("reap Codex worker after {reason} failed: {error}"))
        })
    }
}

#[cfg(unix)]
fn terminate_process_group_immediately(
    child: &mut std::process::Child,
    process_group: i32,
    reason: &str,
) -> Result<ExitStatus, WorkerRuntimeError> {
    refuse_unsignalable_process_group(process_group, libc::SIGKILL, reason)?;
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            #[cfg(target_os = "macos")]
            if error.raw_os_error() == Some(libc::EPERM) {
                // Darwin can return EPERM while a process-group leader is
                // crossing into exit. Pin and reap that exact child, then
                // retry the group signal; only ESRCH proves no descendant
                // remains under the old group identity.
                let _ = child.kill();
                let status = child.wait().map_err(|wait_error| {
                    WorkerRuntimeError::new(format!(
                        "reap Codex worker after {reason} termination failed: {wait_error}"
                    ))
                })?;
                if unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0 {
                    let retry_error = std::io::Error::last_os_error();
                    if retry_error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(WorkerRuntimeError::new(format!(
                            "retry signal 9 to Codex worker process group {process_group} after {reason} failed: {retry_error}"
                        )));
                    }
                }
                return Ok(status);
            }
            return Err(WorkerRuntimeError::new(format!(
                "signal 9 to Codex worker process group {process_group} after {reason} failed: {error}"
            )));
        }
    }
    child.wait().map_err(|error| {
        WorkerRuntimeError::new(format!(
            "reap Codex worker after {reason} termination failed: {error}"
        ))
    })
}

#[cfg(unix)]
fn signal_process_group_after_leader_exit(
    process_group: i32,
    signal: i32,
    reason: &str,
) -> Result<(), WorkerRuntimeError> {
    refuse_unsignalable_process_group(process_group, signal, reason)?;
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    // Darwin's explicit-process-group path excludes zombies from the group
    // iterator and returns EPERM when no signalable live member remains. We
    // reach this helper only after waitid(WNOWAIT) proved the pinned leader
    // exited; an actual same-user descendant would make kill(2) succeed.
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(libc::EPERM) {
        return Ok(());
    }
    Err(WorkerRuntimeError::new(format!(
        "signal {signal} to Codex worker process group {process_group} after {reason} failed: {error}"
    )))
}

/// Last line of defence for the two group-signal helpers: `kill(-1, sig)`
/// reaches every process of this user (it ended the CI host's systemd user
/// session in issue #216) and `kill(0, sig)` reaches the caller's own group.
/// Neither can be a Codex worker group, so refuse instead of signalling.
#[cfg(unix)]
fn refuse_unsignalable_process_group(
    process_group: i32,
    signal: i32,
    reason: &str,
) -> Result<(), WorkerRuntimeError> {
    if process_group > 1 {
        return Ok(());
    }
    Err(WorkerRuntimeError::new(format!(
        "refusing signal {signal} to process group {process_group} after {reason}: \
         only a spawned worker group (> 1) may be signalled"
    )))
}

#[cfg(unix)]
fn signal_process_group(
    process_group: i32,
    signal: i32,
    reason: &str,
) -> Result<(), WorkerRuntimeError> {
    refuse_unsignalable_process_group(process_group, signal, reason)?;
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(WorkerRuntimeError::new(format!(
        "signal {signal} to Codex worker process group {process_group} after {reason} failed: {error}"
    )))
}
