//! Bounded regular-file reading retained from the existing durable I/O owner.
use std::io::Read;
use std::path::Path;

const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Artifact readers accept regular files, including atomically replaced files,
/// but must never wait for a FIFO peer during open. Validate the opened handle
/// so replacing the path cannot bypass this contract.
pub(crate) fn open_artifact_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "artifact must be a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn read_bytes_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    read_bytes_bounded_until(
        path,
        max_bytes,
        crate::deadline::RequestDeadline::unbounded(),
        "bounded artifact read",
    )
}

pub(crate) fn read_bytes_bounded_until(
    path: &Path,
    max_bytes: u64,
    deadline: crate::deadline::RequestDeadline,
    operation: &'static str,
) -> std::io::Result<Vec<u8>> {
    crate::deadline::ObservationScope::check_current(operation)?;
    deadline.check(operation)?;
    let file = open_artifact_file(path)?;
    crate::deadline::ObservationScope::check_current(operation)?;
    deadline.check(operation)?;
    let length = file.metadata()?.len();
    if length > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} is {length} bytes; limit is {max_bytes} bytes",
                path.display()
            ),
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} length does not fit memory address space",
                path.display()
            ),
        )
    })?;
    let mut body = Vec::with_capacity(capacity);
    let mut bounded = file.take(max_bytes + 1);
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        crate::deadline::ObservationScope::check_current(operation)?;
        deadline.check(operation)?;
        let read = bounded.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    crate::deadline::ObservationScope::check_current(operation)?;
    deadline.check(operation)?;
    if body.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} grew beyond the {max_bytes}-byte limit", path.display()),
        ));
    }
    Ok(body)
}
