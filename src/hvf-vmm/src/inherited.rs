// SPDX-License-Identifier: Apache-2.0
//! Revoke ambient descriptors before the exec'd VMM reads guest inputs.
use crate::Result;

pub(crate) fn restrict_child() -> Result<()> {
    let mut keep = vec![0, 1, 2]; // Explicit inherited console, not ambient files.
    for name in ["HVF_READY_FD", "HVF_METRICS_FD", "HVF_LEASE_FD"] {
        retain(&mut keep, &std::env::var(name)?)?;
    }
    let drives = std::env::var("HVF_DRIVE_FDS")?;
    if !drives.is_empty() {
        for value in drives.split(',') {
            retain(&mut keep, value)?;
        }
    }
    // Enumerate actual descriptors, including those above a subsequently lowered
    // RLIMIT_NOFILE. Finish and drop the directory iterator before closing any FD.
    // Failure to enumerate is fatal; never fall back to an incomplete limit scan.
    let descriptors = std::fs::read_dir("/dev/fd")?
        .map(|entry| -> Result<i32> {
            Ok(entry?
                .file_name()
                .to_str()
                .ok_or("non-UTF8 descriptor name")?
                .parse()?)
        })
        .collect::<Result<Vec<_>>>()?;
    for fd in descriptors {
        if !keep.contains(&fd) {
            // SAFETY: called only in the single-threaded, freshly exec'd child,
            // before opening config/guest files or creating workers. No Rust
            // object owns these ambient FDs. The directory FD is already closed.
            if unsafe { libc::close(fd) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EBADF) {
                    return Err(error.into());
                }
            }
        }
    }
    Ok(())
}

fn retain(keep: &mut Vec<i32>, value: &str) -> Result<()> {
    let fd: i32 = value.parse()?;
    if fd < 3 || keep.contains(&fd) {
        return Err("invalid or duplicate supervisor descriptor".into());
    }
    // SAFETY: query only; supervisor handoff descriptors must still be open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    keep.push(fd);
    Ok(())
}
