// SPDX-License-Identifier: Apache-2.0
use crate::{Drive, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
fn lock(file: &File, readonly: bool) -> Result<()> {
    let mode = if readonly {
        libc::LOCK_SH
    } else {
        libc::LOCK_EX
    };
    // SAFETY: valid open descriptor; nonblocking advisory BSD lock.
    if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
        return Err(format!("disk lock failed: {}", std::io::Error::last_os_error()).into());
    }
    let m = file.metadata()?;
    if !m.is_file() || m.len() < 512 || m.len() % 512 != 0 {
        return Err("invalid block file".into());
    }
    Ok(())
}
pub(super) fn open(drive: &Drive, copy: &Path) -> Result<File> {
    open_cancellable(drive, copy, None, u64::MAX)
}
pub(super) fn inherited(file: File, readonly: bool) -> Result<File> {
    lock(&file, readonly)?;
    Ok(file)
}
pub(super) fn open_cancellable(
    drive: &Drive,
    copy: &Path,
    cancel: Option<&AtomicBool>,
    maximum: u64,
) -> Result<File> {
    let writable = !drive.copy_on_start && !drive.is_read_only;
    let mut source = crate::resources::open_regular(&drive.path_on_host, writable)?;
    lock(&source, drive.copy_on_start || drive.is_read_only)?;
    if !drive.copy_on_start {
        return Ok(source);
    }
    if source.metadata()?.len() > maximum {
        return Err("disk copy exceeds file size limit".into());
    }
    let mut total = 0u64;
    let mut target = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(copy)?;
    // Copy from the very descriptor whose inode we locked. Keep the source lock
    // throughout copying, including failures; never reopen the path for copying.
    let mut buffer = vec![0u8; 128 << 10];
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err("disk copy cancelled".into());
        }
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or("disk copy overflow")?;
        if total > maximum {
            return Err("disk copy grew beyond size limit".into());
        }
        target.write_all(&buffer[..n])?;
    }
    target.sync_all()?;
    lock(&target, drive.is_read_only)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    fn drive(path: &Path, copy: bool) -> Drive {
        Drive {
            drive_id: "d".into(),
            path_on_host: path.into(),
            is_root_device: false,
            copy_on_start: copy,
            is_read_only: false,
        }
    }
    #[test]
    fn copy_rejects_locked_source() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        let f = File::create(&source).unwrap();
        f.set_len(4096).unwrap();
        lock(&f, false).unwrap();
        assert!(open(&drive(&source, true), &t.path().join("copy")).is_err());
        assert!(!t.path().join("copy").exists());
    }
    #[test]
    fn copy_is_private_and_persistent_writer_is_exclusive() {
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        std::fs::write(&source, vec![7u8; 4096]).unwrap();
        let mut copy = open(&drive(&source, true), &t.path().join("copy")).unwrap();
        copy.seek(SeekFrom::Start(0)).unwrap();
        copy.write_all(&[9]).unwrap();
        let mut original = File::open(&source).unwrap();
        let mut b = [0];
        original.read_exact(&mut b).unwrap();
        assert_eq!(b, [7]);
        let _writer = open(&drive(&source, false), &t.path().join("unused")).unwrap();
        assert!(open(&drive(&source, false), &t.path().join("unused")).is_err());
    }
}
