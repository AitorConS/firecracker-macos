// SPDX-License-Identifier: Apache-2.0
//! Copies that share or skip unwritten blocks. On APFS a copy is a clone of
//! the source; elsewhere only the source's data extents are read, and blocks
//! of zeros are left as holes in the copy instead of being written.
use crate::Result;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::Path;

const CHUNK: usize = 128 << 10;

/// Receives every byte of a copy in order, holes included as zeros.
pub(crate) type Observer<'a> = &'a mut dyn FnMut(&[u8]);
static ZEROS: [u8; CHUNK] = [0; CHUNK];

/// Clones the file open as `source` to a new file at `target`, sharing its
/// blocks copy-on-write. Cloning from the descriptor, not the path, copies the
/// very inode the caller opened and locked. Returns false when the volume
/// cannot clone (not APFS, or another volume), so the caller copies instead.
pub(crate) fn clone_to(source: &File, target: &Path) -> Result<bool> {
    let path = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: a live descriptor and a terminated path; fclonefileat creates
    // `target` and fails if anything already exists there.
    if unsafe { libc::fclonefileat(source.as_raw_fd(), libc::AT_FDCWD, path.as_ptr(), 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOTSUP) | Some(libc::EXDEV) => Ok(false),
        _ => Err(error.into()),
    }
}

/// Calls `visit(offset, length, data)` for consecutive extents covering
/// `[0, size)` of `file`. Holes (`data == false`) read as zeros. A file system
/// without hole information reports a single data extent.
fn extents(
    file: &File,
    size: u64,
    mut visit: impl FnMut(u64, u64, bool) -> Result<()>,
) -> Result<()> {
    let fd = file.as_raw_fd();
    let mut position = 0u64;
    while position < size {
        // SAFETY: lseek on a live descriptor only moves its offset.
        let data = unsafe { libc::lseek(fd, position as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                // No data at or after `position`: the rest is a hole.
                Some(libc::ENXIO) => visit(position, size - position, false),
                Some(libc::EINVAL) | Some(libc::ENOTSUP) => visit(position, size - position, true),
                _ => Err(error.into()),
            };
        }
        let data = (data as u64).min(size);
        if data > position {
            visit(position, data - position, false)?;
        }
        if data == size {
            break;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data as libc::off_t, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let hole = (hole as u64).clamp(data + 1, size);
        visit(data, hole - data, true)?;
        position = hole;
    }
    Ok(())
}

/// Reads the first `size` bytes of `source`, writing them to `target` when
/// given and passing every byte, holes included as zeros, to `hash` when given.
/// `target` must be a new, empty file: it is extended to `size` first, and
/// chunks of zeros are not written, so they stay holes. `check` runs before
/// each chunk and aborts the copy when it fails. A source shorter than `size`
/// is an error.
pub(crate) fn copy(
    source: &File,
    size: u64,
    target: Option<&File>,
    mut hash: Option<Observer<'_>>,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    // Past the end of the file SEEK_DATA reports no data, which would read as
    // a hole, so a short source is rejected up front and after copying.
    if source.metadata()?.len() < size {
        return Err("source is shorter than the copy".into());
    }
    if let Some(target) = target {
        target.set_len(size)?;
    }
    let mut buffer = vec![0u8; CHUNK];
    extents(source, size, |offset, length, data| {
        let end = offset + length;
        let mut at = offset;
        while at < end {
            check()?;
            let n = (end - at).min(CHUNK as u64) as usize;
            if !data {
                if let Some(hash) = hash.as_mut() {
                    hash(&ZEROS[..n]);
                }
                at += n as u64;
                continue;
            }
            let chunk = &mut buffer[..n];
            source.read_exact_at(chunk, at).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    "source shrank during copy".into()
                } else {
                    Box::<dyn std::error::Error>::from(e)
                }
            })?;
            if let Some(hash) = hash.as_mut() {
                hash(chunk);
            }
            if let Some(target) = target.filter(|_| chunk.iter().any(|&b| b != 0)) {
                target.write_all_at(chunk, at)?;
            }
            at += n as u64;
        }
        Ok(())
    })?;
    if source.metadata()?.len() < size {
        return Err("source shrank during copy".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::MetadataExt;

    /// A file of `size` bytes with `data` written at each offset and holes
    /// everywhere else.
    fn sparse_file(path: &Path, size: u64, data: &[(u64, &[u8])]) -> File {
        let f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        f.set_len(size).unwrap();
        for (offset, bytes) in data {
            f.write_all_at(bytes, *offset).unwrap();
        }
        f.sync_all().unwrap();
        f
    }

    fn new_file(path: &Path) -> File {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn extents_cover_the_file_in_order() {
        let t = tempfile::tempdir().unwrap();
        let size = 64 << 20;
        let f = sparse_file(
            &t.path().join("s"),
            size,
            &[(8 << 20, b"x"), (40 << 20, b"y")],
        );
        let mut seen = Vec::new();
        extents(&f, size, |o, l, d| {
            seen.push((o, l, d));
            Ok(())
        })
        .unwrap();
        let mut next = 0;
        for &(o, l, _) in &seen {
            assert_eq!(o, next);
            next = o + l;
        }
        assert_eq!(next, size);
        let data: u64 = seen.iter().filter(|e| e.2).map(|e| e.1).sum();
        assert!(data < size / 4, "holes not reported: {seen:?}");
    }

    #[test]
    fn copy_keeps_holes_and_content() {
        let t = tempfile::tempdir().unwrap();
        let size = 64 << 20;
        let mut zeros_in_data = vec![0u8; 1 << 20];
        zeros_in_data[0] = 1;
        let source = sparse_file(
            &t.path().join("s"),
            size,
            &[
                (4096, b"hello"),
                (32 << 20, &zeros_in_data),
                (size - 3, b"end"),
            ],
        );
        let target = new_file(&t.path().join("t"));
        let mut hashed = Vec::new();
        let mut hash = |b: &[u8]| hashed.extend_from_slice(b);
        copy(&source, size, Some(&target), Some(&mut hash), &|| Ok(())).unwrap();
        let expected = std::fs::read(t.path().join("s")).unwrap();
        assert_eq!(std::fs::read(t.path().join("t")).unwrap(), expected);
        assert_eq!(hashed, expected);
        // A 64 MiB copy holding ~1 MiB of data allocates about that much.
        let allocated = target.metadata().unwrap().blocks() * 512;
        assert!(allocated < 4 << 20, "copy allocated {allocated} bytes");
    }

    #[test]
    fn copy_checks_and_rejects_short_source() {
        let t = tempfile::tempdir().unwrap();
        let source = sparse_file(&t.path().join("s"), 4096, &[(0, b"abc")]);
        let target = new_file(&t.path().join("t"));
        assert!(copy(&source, 8192, Some(&target), None, &|| Ok(())).is_err());
        let target = new_file(&t.path().join("u"));
        assert!(copy(&source, 4096, Some(&target), None, &|| Err("stop".into())).is_err());
    }

    #[test]
    fn clone_shares_content_and_refuses_existing_target() {
        let t = tempfile::tempdir().unwrap();
        let source = sparse_file(&t.path().join("s"), 1 << 20, &[(100, b"data")]);
        let target = t.path().join("t");
        if !clone_to(&source, &target).unwrap() {
            return; // the temporary directory is not on APFS
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            std::fs::read(t.path().join("s")).unwrap()
        );
        assert!(clone_to(&source, &target).is_err());
    }
}
