// SPDX-License-Identifier: Apache-2.0
//! Child ownership, asynchronous startup and deterministic teardown.
use super::SHUTDOWN;
use super::control::{Message, Reader};
use crate::{Config, Result};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(super) struct StartTask {
    pub cancel: Arc<AtomicBool>,
    pub thread: Option<std::thread::JoinHandle<std::result::Result<Guest, String>>>,
}
impl Drop for StartTask {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub(super) fn start_task(config: Value, path: PathBuf, operation: u64, lease_fd: i32) -> StartTask {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let thread = std::thread::spawn(move || {
        launch(&config, &path, &worker_cancel, operation, lease_fd, None).map_err(|e| e.to_string())
    });
    StartTask {
        cancel,
        thread: Some(thread),
    }
}
pub(super) fn discard_task(guest: Guest) -> StartTask {
    StartTask {
        cancel: Arc::new(AtomicBool::new(true)),
        thread: Some(std::thread::spawn(move || {
            drop(guest);
            Err("startup cancelled".into())
        })),
    }
}

pub(super) struct Guest(
    pub Child,
    #[allow(dead_code)] pub tempfile::TempDir,
    pub UnixStream,
    pub Reader,
    pub super::metrics::NativeMetrics,
    pub crate::limits::Watchdog,
    pub Option<Value>,
);
/// startup.log stays under LOG_MAX_BYTES: the VMM appends its stderr there,
/// and output a guest can trigger must not fill the host disk. Trimming keeps
/// the first LOG_HEAD_BYTES (early boot) and the last LOG_TAIL_BYTES (what
/// `Guest::diagnostic` reports).
const LOG_MAX_BYTES: u64 = 8 << 20;
const LOG_HEAD_BYTES: u64 = 1 << 20;
const LOG_TAIL_BYTES: u64 = 64 << 10;

/// Opens the VMM's log without following a link the VMM may have put there.
fn open_log(path: &Path, write: bool) -> std::io::Result<fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .append(write)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(std::io::Error::other(
            "startup.log is not a private regular file",
        ));
    }
    Ok(file)
}

/// Trims the log at `path` back to its head and tail once it exceeds LOG_MAX_BYTES.
pub(super) fn cap_log(path: &Path) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = open_log(path, true)?;
    let length = file.metadata()?.len();
    if length <= LOG_MAX_BYTES {
        return Ok(());
    }
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(length - LOG_TAIL_BYTES))?;
    (&mut file).take(LOG_TAIL_BYTES).read_to_end(&mut tail)?;
    file.set_len(LOG_HEAD_BYTES)?;
    // Appends: anything the VMM writes meanwhile lands after, not inside, this.
    let dropped = length - LOG_HEAD_BYTES - LOG_TAIL_BYTES;
    file.write_all(format!("\n[startup.log: {dropped} bytes dropped]\n").as_bytes())?;
    file.write_all(&tail)
}

impl Guest {
    pub fn diagnostic(&self) -> String {
        use std::io::{Seek, SeekFrom};
        let mut bytes = Vec::new();
        if let Ok(mut file) = open_log(&self.1.path().join("startup.log"), false) {
            let length = file.metadata().map(|m| m.len()).unwrap_or(0);
            let _ = file.seek(SeekFrom::Start(length.saturating_sub(LOG_TAIL_BYTES)));
            let _ = file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).trim().to_owned()
    }
    /// Keeps the VMM's log bounded; called with the resource watchdog. The log
    /// is diagnostics only, so a failure leaves it as it is.
    pub fn cap_log(&self) {
        let _ = cap_log(&self.1.path().join("startup.log"));
    }
    pub fn kill_group(&mut self) -> std::io::Result<()> {
        // The leader is owned and unreaped, preventing reuse of its group ID.
        if unsafe { libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }
}
impl std::ops::Deref for Guest {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for Guest {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for Guest {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // SAFETY: this Child is still unreaped, so its PID cannot be reused.
            unsafe {
                libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while self.0.try_wait().ok().flatten().is_none() && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.kill_group();
            }
            let _ = self.0.wait();
        }
    }
}
fn launch(
    config: &Value,
    path: &Path,
    cancelled: &AtomicBool,
    operation: u64,
    lease_fd: i32,
    restore: Option<&Path>,
) -> Result<Guest> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let mut typed: Config = serde_json::from_value(config.clone())?;
    typed.validate()?;
    let work = tempfile::tempdir_in(path.parent().ok_or("missing supervisor directory")?)?;
    let maximum =
        (u64::from(typed.machine_config.mem_size_mib) << 20).min(typed.limits.file_size_bytes);
    typed.boot_source.kernel_image_path = crate::resources::stage(
        &typed.boot_source.kernel_image_path,
        &work.path().join("kernel"),
        maximum,
        cancelled,
    )?;
    if let Some(initrd) = &typed.boot_source.initrd_path {
        typed.boot_source.initrd_path = Some(crate::resources::stage(
            initrd,
            &work.path().join("initrd"),
            maximum,
            cancelled,
        )?);
    }
    for (i, path) in typed.firmware.values_mut().enumerate() {
        *path = crate::resources::stage(
            path,
            &work.path().join(format!("firmware-{i}")),
            65536,
            cancelled,
        )?;
    }
    let indices: Vec<_> = (0..typed.drives.len())
        .filter(|&i| typed.drives[i].is_root_device)
        .chain((0..typed.drives.len()).filter(|&i| !typed.drives[i].is_root_device))
        .collect();
    let mut disk_files = Vec::new();
    for (ordinal, index) in indices.into_iter().enumerate() {
        if cancelled.load(Ordering::Relaxed) {
            return Err("startup cancelled".into());
        }
        let drive = &mut typed.drives[index];
        let copy = work.path().join(format!("disk-{ordinal}.img"));
        let file = crate::block::open_cancellable(
            drive,
            &copy,
            Some(cancelled),
            typed.limits.file_size_bytes,
        )?;
        if drive.copy_on_start {
            drive.path_on_host = copy;
            drive.copy_on_start = false;
        }
        disk_files.push(file);
    }
    let disk_fds: Vec<_> = disk_files.iter().map(AsRawFd::as_raw_fd).collect();
    let config_path = work.path().join("config.json");
    serde_json::to_writer(fs::File::create(&config_path)?, &typed)?;
    let log_path = work.path().join("startup.log");
    let (reader, writer) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_millis(100)))?;
    let fd = writer.as_raw_fd();
    let (metrics_reader, metrics_writer) = UnixDatagram::pair()?;
    metrics_reader.set_nonblocking(true)?;
    let metrics_fd = metrics_writer.as_raw_fd();
    fs::create_dir(work.path().join("native-snapshot"))?;
    if let Some(source) = restore {
        let mut names = vec![
            "ram.bin".to_string(),
            "devices.bin".to_string(),
            "gic.bin".to_string(),
        ];
        names.extend((0..typed.machine_config.vcpu_count).map(|i| format!("cpu-{i}.bin")));
        for name in names {
            crate::resources::stage(
                &source.join(&name),
                &work.path().join("native-snapshot").join(&name),
                (u64::from(typed.machine_config.mem_size_mib) << 20).max(64 << 20),
                cancelled,
            )?;
        }
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--hvf-child", "--no-api", "--config-file"])
        .arg(config_path)
        .env("TMPDIR", work.path())
        .env("HVF_SNAPSHOT_DIR", work.path().join("native-snapshot"))
        .env("HVF_RESTORE", if restore.is_some() { "1" } else { "0" })
        .env("HVF_READY_FD", fd.to_string())
        .env("HVF_OPERATION_ID", operation.to_string())
        .env("HVF_METRICS_FD", metrics_fd.to_string())
        .env("HVF_LEASE_FD", lease_fd.to_string())
        .env(
            "HVF_DRIVE_FDS",
            disk_fds
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        // Append-only, so cap_log can shorten it while the VMM keeps writing.
        .stderr(
            fs::OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(&log_path)?,
        );
    // SAFETY: only async-signal-safe fcntl executes between fork and exec. The
    // private socket descriptor remains alive until spawn completes.
    unsafe {
        command.pre_exec(move || {
            for &disk in &disk_fds {
                if libc::fcntl(disk, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setpgid(0, 0) < 0
                || libc::fcntl(fd, libc::F_SETFD, 0) < 0
                || libc::fcntl(metrics_fd, libc::F_SETFD, 0) < 0
                || libc::fcntl(lease_fd, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guest = Guest(
        command.spawn()?,
        work,
        reader,
        Reader::default(),
        super::metrics::NativeMetrics::new(metrics_reader),
        crate::limits::Watchdog::new(&typed.limits),
        if restore.is_some() {
            Some(serde_json::to_value(&typed)?)
        } else {
            None
        },
    );
    drop(disk_files);
    drop(writer);
    drop(metrics_writer);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut reason = "VMM exited before initialization completed";
    let mut resource_error = None;
    let initialized = loop {
        let pid = guest.id();
        if let Some(error) = guest.5.poll(pid) {
            resource_error = Some(error);
            break false;
        }
        guest.cap_log();
        if SHUTDOWN.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
            reason = "startup cancelled by supervisor shutdown";
            break false;
        }
        if std::time::Instant::now() >= deadline {
            reason = "VMM initialization timed out after 30 seconds";
            break false;
        }
        match guest.3.receive(&mut guest.2) {
            Ok(Some(message)) => {
                break message
                    == Message {
                        kind: if restore.is_some() { b'P' } else { b'R' },
                        operation,
                    };
            }
            Ok(None) => continue,
            Err(_) => break false,
        }
    };
    if !initialized {
        if let Some(error) = resource_error {
            return Err(error.into());
        }
        let status = guest.try_wait()?;
        let mut detail = String::new();
        fs::File::open(log_path)?
            .take(65536)
            .read_to_string(&mut detail)?;
        return Err(format!(
            "BOOT_FAILED: {reason} (status {status:?}): {}",
            detail.trim()
        )
        .into());
    }
    guest.2.set_nonblocking(true)?;
    Ok(guest)
}

pub(super) fn restore_task(
    source: PathBuf,
    path: PathBuf,
    operation: u64,
    lease_fd: i32,
    restore_config: Value,
) -> StartTask {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let thread = std::thread::spawn(move || {
        (|| -> Result<Guest> {
            let stage = tempfile::tempdir_in(path.parent().ok_or("missing supervisor directory")?)?;
            let config = crate::snapshot::materialize(
                &source,
                stage.path(),
                &worker_cancel,
                &restore_config,
            )?;
            let mut guest = launch(
                &config.config,
                &path,
                &worker_cancel,
                operation,
                lease_fd,
                Some(stage.path()),
            )?;
            guest.6 = Some(config.public_config);
            Ok(guest)
        })()
        .map_err(|e| e.to_string())
    });
    StartTask {
        cancel,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn log_file(dir: &Path, bytes: &[u8]) -> PathBuf {
        let path = dir.join("startup.log");
        fs::File::create(&path).unwrap().write_all(bytes).unwrap();
        path
    }

    #[test]
    fn cap_log_keeps_head_and_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![b'h'; LOG_HEAD_BYTES as usize];
        bytes.resize((LOG_MAX_BYTES + 1) as usize - LOG_TAIL_BYTES as usize, b'x');
        bytes.resize((LOG_MAX_BYTES + 1) as usize, b't');
        let path = log_file(dir.path(), &bytes);
        cap_log(&path).unwrap();
        let trimmed = fs::read(&path).unwrap();
        assert!(trimmed.len() < (LOG_HEAD_BYTES + LOG_TAIL_BYTES + 100) as usize);
        assert!(
            trimmed[..LOG_HEAD_BYTES as usize]
                .iter()
                .all(|&b| b == b'h')
        );
        assert!(
            trimmed[trimmed.len() - LOG_TAIL_BYTES as usize..]
                .iter()
                .all(|&b| b == b't')
        );
        let marker = String::from_utf8_lossy(
            &trimmed[LOG_HEAD_BYTES as usize..trimmed.len() - LOG_TAIL_BYTES as usize],
        )
        .into_owned();
        assert!(marker.contains("bytes dropped"), "{marker}");
        // Under the cap nothing changes.
        cap_log(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), trimmed);
    }

    #[test]
    fn cap_log_refuses_links() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("other");
        fs::write(&target, vec![b'o'; (LOG_MAX_BYTES + 1) as usize]).unwrap();
        let link = dir.path().join("startup.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(cap_log(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&target, &link).unwrap();
        assert!(cap_log(&link).is_err());
        assert_eq!(fs::metadata(&target).unwrap().len(), LOG_MAX_BYTES + 1);
    }
}
