// SPDX-License-Identifier: Apache-2.0
use crate::{Drive, Result};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    let source = crate::resources::open_regular(&drive.path_on_host, writable)?;
    lock(&source, drive.copy_on_start || drive.is_read_only)?;
    if !drive.copy_on_start {
        return Ok(source);
    }
    let size = source.metadata()?.len();
    if size > maximum {
        return Err("disk copy exceeds file size limit".into());
    }
    // Copy from the very descriptor whose inode we locked. Keep the source lock
    // throughout copying, including failures; never reopen the path for copying.
    // On APFS the copy is a clone sharing the source's blocks; otherwise only
    // its data is copied and runs of zeros stay holes.
    let target = if crate::sparse::clone_to(&source, copy)? {
        // A clone keeps the source's mode, which may be read-only.
        std::fs::set_permissions(copy, std::fs::Permissions::from_mode(0o600))?;
        OpenOptions::new().read(true).write(true).open(copy)?
    } else {
        let target = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(copy)?;
        let check = || -> Result<()> {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err("disk copy cancelled".into());
            }
            Ok(())
        };
        crate::sparse::copy(&source, size, Some(&target), None, &check)?;
        target
    };
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
    // Jerboa keeps stored disks read-only; their private copy must be
    // writable, hold the same bytes and keep the source's holes.
    #[test]
    fn copy_of_read_only_sparse_source_is_writable() {
        use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        let source = t.path().join("source");
        let f = File::create(&source).unwrap();
        f.set_len(64 << 20).unwrap();
        f.write_all_at(b"boot", 0).unwrap();
        f.write_all_at(b"tail", (64 << 20) - 512).unwrap();
        drop(f);
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut d = drive(&source, true);
        d.is_read_only = false;
        let copy = open(&d, &t.path().join("copy")).unwrap();
        assert_eq!(
            std::fs::read(t.path().join("copy")).unwrap(),
            std::fs::read(&source).unwrap()
        );
        copy.write_all_at(b"x", 4096).unwrap();
        assert!(copy.metadata().unwrap().blocks() * 512 < 4 << 20);
        assert_eq!(std::fs::read(&source).unwrap()[4096], 0);
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
