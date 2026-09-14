// SPDX-License-Identifier: Apache-2.0
//! Stage selected boot inputs from validated, locked descriptors before exec.
use crate::Result;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
fn open_validated(path: &Path, writable: bool, expected: &std::fs::Metadata) -> Result<File> {
    let source = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let current = source.metadata()?;
    if !current.is_file() {
        return Err("boot input is not a regular file after open".into());
    }
    if current.dev() != expected.dev() || current.ino() != expected.ino() {
        return Err("path replaced between validation and open".into());
    }
    Ok(source)
}
pub(crate) fn open_regular(path: &Path, writable: bool) -> Result<File> {
    let expected = std::fs::symlink_metadata(path)?;
    if !expected.is_file() {
        return Err("boot input must be a regular file, not a symlink or device".into());
    }
    open_validated(path, writable, &expected)
}
pub(crate) fn stage(
    path: &Path,
    destination: &Path,
    maximum: u64,
    cancel: &AtomicBool,
) -> Result<PathBuf> {
    let mut source = open_regular(path, false)?;
    let metadata = source.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err("boot input exceeds its size limit or is not regular".into());
    }
    // SAFETY: live input descriptor, nonblocking shared advisory lock.
    if unsafe { libc::flock(source.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err("boot input lock failed".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut buffer = vec![0u8; 128 << 10];
    let mut total = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("boot input staging cancelled".into());
        }
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("boot input size overflow")?;
        if total > maximum {
            return Err("boot input grew beyond its size limit".into());
        }
        output.write_all(&buffer[..n])?;
    }
    output.sync_all()?;
    Ok(destination.to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_rejects_symlinks_locks_and_limits() {
        use std::os::unix::fs::symlink;
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source");
        let target = work.path().join("target");
        let cancel = AtomicBool::new(false);
        std::fs::write(&source, [1, 2, 3, 4]).unwrap();
        let link = work.path().join("link");
        symlink(&source, &link).unwrap();
        assert!(stage(&link, &target, 4, &cancel).is_err());
        assert!(stage(&source, &target, 3, &cancel).is_err());
        let locked = std::fs::File::open(&source).unwrap();
        assert_eq!(
            unsafe { libc::flock(locked.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(stage(&source, &target, 4, &cancel).is_err());
        drop(locked);
        stage(&source, &target, 4, &cancel).unwrap();
        std::fs::write(&source, [9]).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), [1, 2, 3, 4]);
    }
}
