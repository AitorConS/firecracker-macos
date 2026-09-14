// SPDX-License-Identifier: Apache-2.0
//! Reclaim only private directories with a verifiable identity and released lease.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const PREFIX: &str = "hvf-supervisor-";
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Identity {
    pid: u32,
    uid: u32,
    seconds: u64,
    micros: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    directory: String,
    owner: Identity,
}
fn identity(pid: u32) -> std::io::Result<Option<Identity>> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: writable correctly sized buffer; initialized only on a full result.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n == size {
        let info = unsafe { info.assume_init() };
        Ok(Some(Identity {
            pid: info.pbi_pid,
            uid: info.pbi_uid,
            seconds: info.pbi_start_tvsec,
            micros: info.pbi_start_tvusec,
        }))
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(error)
        }
    }
}
fn lock(file: &File) -> bool {
    // SAFETY: flock only refers to the open file descriptor and uses no pointers.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}
pub(super) struct Workspace {
    directory: tempfile::TempDir,
    lease: File,
}
impl Workspace {
    pub fn new() -> Result<Self> {
        let root = std::env::temp_dir();
        recover(&root)?;
        let directory = tempfile::Builder::new().prefix(PREFIX).tempdir_in(root)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join(".lease"))?;
        if !lock(&lease) {
            return Err("cannot acquire supervisor workspace lease".into());
        }
        let marker = Marker {
            version: 1,
            directory: directory
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            owner: identity(std::process::id())?.ok_or("missing supervisor identity")?,
        };
        serde_json::to_writer(&lease, &marker)?;
        lease.sync_all()?;
        Ok(Self { directory, lease })
    }
    pub fn path(&self) -> &Path {
        self.directory.path()
    }
    // Every VMM inherits this same open-file-description lock through exec.
    // A dead supervisor's directory remains locked until its final VMM exits.
    pub fn lease_fd(&self) -> RawFd {
        self.lease.as_raw_fd()
    }
}
fn recover(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)?.take(1024) {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        // Refuse unfamiliar, malformed, foreign, locked or ambiguous entries.
        let _ = recover_one(&entry.path());
    }
    Ok(())
}
fn recover_one(path: &Path) -> Result<()> {
    let original = fs::symlink_metadata(path)?;
    let uid = unsafe { libc::geteuid() };
    if !original.is_dir() || original.uid() != uid || original.mode() & 0o777 != 0o700 {
        return Ok(());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join(".lease"))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 4096
        || !lock(&file)
    {
        return Ok(());
    }
    let marker: Marker = serde_json::from_reader((&file).take(4096))?;
    if marker.version != 1
        || marker.owner.uid != uid
        || Some(std::ffi::OsStr::new(&marker.directory)) != path.file_name()
    {
        return Ok(());
    }
    if identity(marker.owner.pid)?.as_ref() == Some(&marker.owner) {
        return Ok(());
    }
    let current = fs::symlink_metadata(path)?;
    if current.dev() != original.dev() || current.ino() != original.ino() {
        return Ok(());
    }
    fs::remove_dir_all(path)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keeps_live_and_malformed_workspaces() {
        let workspace = Workspace::new().unwrap();
        recover_one(workspace.path()).unwrap();
        assert!(workspace.path().exists());
        let malformed = tempfile::Builder::new().prefix(PREFIX).tempdir().unwrap();
        let _ = recover_one(malformed.path());
        assert!(malformed.path().exists());
    }
    #[test]
    fn distinguishes_reused_pid_and_rejects_live_identity() {
        let directory = tempfile::Builder::new().prefix(PREFIX).tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut marker = Marker {
            version: 1,
            directory: directory
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .into(),
            owner: identity(std::process::id()).unwrap().unwrap(),
        };
        let path = directory.path().join(".lease");
        let write = |marker: &Marker| {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            serde_json::to_writer(file, marker).unwrap();
        };
        write(&marker);
        recover_one(directory.path()).unwrap();
        assert!(
            directory.path().exists(),
            "matching live process identity must be retained even without lock"
        );
        marker.owner.seconds -= 1;
        write(&marker);
        recover_one(directory.path()).unwrap();
        assert!(
            !directory.path().exists(),
            "PID reuse must not identify the unrelated process as owner"
        );
    }
}
