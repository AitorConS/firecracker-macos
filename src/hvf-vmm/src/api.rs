// SPDX-License-Identifier: Apache-2.0
//! Small Unix HTTP control plane for the experimental Darwin backend.
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[derive(Clone, Copy, PartialEq, serde::Serialize)]
enum State {
    #[serde(rename = "Not started")]
    NotStarted,
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
}
struct StartTask {
    cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<std::result::Result<Guest, String>>>,
}
impl Drop for StartTask {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn start_task(config: Value, path: PathBuf) -> StartTask {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let thread = std::thread::spawn(move || {
        launch(&config, &path, &worker_cancel).map_err(|e| e.to_string())
    });
    StartTask {
        cancel,
        thread: Some(thread),
    }
}
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}
struct Guest(Child, #[allow(dead_code)] tempfile::TempDir, UnixStream);
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
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
}
use crate::{Config, Result};
use serde_json::{Value, json};

struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}
fn request(stream: &mut UnixStream) -> Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    let header_end = loop {
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if bytes.len() > 8192 {
            return Err("HTTP headers exceed 8 KiB".into());
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err("incomplete HTTP headers".into());
        }
        bytes.extend_from_slice(&buf[..n]);
    };
    if header_end > 8192 {
        return Err("HTTP headers exceed 8 KiB".into());
    }
    let headers = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = headers.split("\r\n");
    let first: Vec<_> = lines
        .next()
        .ok_or("request line missing")?
        .split_whitespace()
        .collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err("expected HTTP/1.1".into());
    }
    let method = first[0].to_owned();
    let path = first[1].to_owned();
    let mut length = None;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked requests are unsupported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate Content-Length".into());
            }
            let n: usize = value.trim().parse()?;
            if n > 1024 * 1024 {
                return Err("HTTP body exceeds 1 MiB".into());
            }
            length = Some(n);
        }
    }
    let length = length.unwrap_or(0);
    while bytes.len() - header_end < length {
        let need = (length - (bytes.len() - header_end)).min(buf.len());
        let n = stream.read(&mut buf[..need])?;
        if n == 0 {
            return Err("incomplete HTTP body".into());
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    Ok(Request {
        method,
        path,
        body: bytes[header_end..header_end + length].to_vec(),
    })
}
fn respond(stream: &mut UnixStream, code: u16, value: Option<Value>) -> Result<()> {
    let body = value.map(|v| v.to_string()).unwrap_or_default();
    let reason = match code {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}
fn launch(config: &Value, path: &Path, cancelled: &AtomicBool) -> Result<Guest> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let typed: Config = serde_json::from_value(config.clone())?;
    typed.validate()?;
    let work = tempfile::tempdir_in(path.parent().ok_or("missing supervisor directory")?)?;
    let config_path = work.path().join("config.json");
    serde_json::to_writer(fs::File::create(&config_path)?, &typed)?;
    let log_path = work.path().join("startup.log");
    let (reader, writer) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_millis(100)))?;
    let fd = writer.as_raw_fd();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--no-api", "--config-file"])
        .arg(config_path)
        .env("TMPDIR", work.path())
        .env("HVF_READY_FD", fd.to_string())
        .stderr(fs::File::create(&log_path)?);
    // SAFETY: only async-signal-safe fcntl executes between fork and exec. The
    // private socket descriptor remains alive until spawn completes.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guest = Guest(command.spawn()?, work, reader);
    drop(writer);
    let mut ready = [0];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut reason = "VMM exited before initialization completed";
    let initialized = loop {
        if SHUTDOWN.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
            reason = "startup cancelled by supervisor shutdown";
            break false;
        }
        if std::time::Instant::now() >= deadline {
            reason = "VMM initialization timed out after 30 seconds";
            break false;
        }
        match guest.2.read(&mut ready) {
            Ok(1) => break ready[0] == b'R',
            Ok(_) => break false,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break false,
        }
    };
    if !initialized {
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
pub fn serve(socket: &Path, initial: Option<Config>) -> Result<i32> {
    // Never replace another process's socket or follow a user-provided existing path.
    if fs::symlink_metadata(socket).is_ok() {
        return Err("API socket path already exists".into());
    }
    // SAFETY: the handler only stores to a lock-free AtomicBool. Installed before
    // the child starts; the previous dispositions are irrelevant in this CLI process.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            stop_signal as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, stop_signal as *const () as libc::sighandler_t);
    }
    // SAFETY: this process has not spawned any worker threads. Restore the umask
    // immediately after creating the private Unix socket, including the error path.
    let old_mask = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(socket);
    unsafe { libc::umask(old_mask) };
    let listener = bound?;
    let _guard = SocketGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let work = tempfile::tempdir()?;
    let child_config = work.path().join("config.json");
    let mut config = initial
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"drives":[]}));
    let mut state = State::NotStarted;
    let mut exit_code: Option<i32> = None;
    let mut last_error: Option<Value> = None;
    let mut operation_id = 0u64;
    let mut shutdown_deadline: Option<(std::time::Instant, bool)> = None;
    let mut shutdown_delivered = false;
    let mut child: Option<Guest> = None;
    let mut pending = if initial.is_some() {
        state = State::Starting;
        operation_id = 1;
        Some(start_task(config.clone(), child_config.clone()))
    } else {
        None
    };
    eprintln!("HVF API: {}", socket.display());
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            return Ok(0);
        }
        if pending
            .as_ref()
            .is_some_and(|p| p.thread.as_ref().unwrap().is_finished())
        {
            let mut task = pending.take().unwrap();
            let cancelled = task.cancel.load(Ordering::Relaxed);
            match task.thread.take().unwrap().join() {
                Ok(Ok(guest)) if !cancelled => {
                    child = Some(guest);
                    state = State::Running;
                }
                Ok(Ok(guest)) => {
                    drop(guest);
                    state = State::Exited;
                    last_error = Some(
                        json!({"fault_code":"START_CANCELLED","fault_message":"startup cancelled"}),
                    );
                }
                Ok(Err(error)) => {
                    state = if cancelled {
                        State::Exited
                    } else {
                        State::Failed
                    };
                    last_error = Some(
                        json!({"fault_code":if cancelled{"START_CANCELLED"}else{"BOOT_FAILED"},"fault_message":error}),
                    );
                }
                Err(_) => {
                    state = State::Failed;
                    last_error = Some(
                        json!({"fault_code":"INTERNAL_ERROR","fault_message":"startup worker panicked"}),
                    );
                }
            }
        }
        if let Some(process) = &mut child {
            let mut message = [0];
            match process.2.read(&mut message) {
                Ok(1) if message[0] == b'A' => shutdown_delivered = true,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    last_error =
                        Some(json!({"fault_code":"CONTROL_ERROR","fault_message":e.to_string()}));
                }
            }
        }
        if let Some(ref mut process) = child
            && let Some(status) = process.try_wait()?
        {
            exit_code = Some(status.code().unwrap_or(1));
            state = State::Exited;
            child = None;
            shutdown_deadline = None;
        }
        if let Some(process) = &mut child
            && let Some((deadline, force)) = shutdown_deadline
            && std::time::Instant::now() >= deadline
        {
            let _ = process.2.write_all(b"X");
            shutdown_deadline = None;
            last_error = Some(
                json!({"fault_code":"SHUTDOWN_TIMEOUT","fault_message":"guest did not power off before deadline","forced":force}),
            );
            if force {
                process.kill()?;
            } else {
                state = State::Running;
            }
        }
        let (mut stream, _) = match listener.accept() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let request = match request(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                let _ = respond(
                    &mut stream,
                    400,
                    Some(json!({"fault_message":e.to_string()})),
                );
                continue;
            }
        };
        let outcome = (|| -> Result<(u16, Option<Value>, bool)> {
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/") => Ok((
                    200,
                    Some(
                        json!({"id":"anonymous-instance","state":state,"vmm_version":"experimental-hvf","app_name":"Firecracker","exit_code":exit_code,"operation_id":operation_id,"last_error":last_error,"shutdown_delivered":shutdown_delivered,"api_version":"0.3"}),
                    ),
                    false,
                )),
                ("GET", "/capabilities") => Ok((
                    200,
                    Some(
                        json!({"api_version":"0.3","boot_protocols":["elf","linux-image"],"network_backends":["slirp"],"max_vcpus":4,"memory_mib":[64,2048],"max_drives":4,"snapshots":false,"pause":false,"guest_shutdown":true,"shutdown_transport":"virtio-input-key-power"}),
                    ),
                    false,
                )),
                ("GET", "/vm/config") => Ok((200, Some(config.clone()), false)),
                ("PUT", "/actions") => {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Action {
                        action_type: String,
                        timeout_ms: Option<u64>,
                        #[serde(default)]
                        force_on_timeout: bool,
                    }
                    let action: Action = serde_json::from_slice(&request.body)?;
                    match action.action_type.as_str() {
                        "InstanceStart" => {
                            if child.is_some() || pending.is_some() {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"INVALID_STATE","fault_message":"VM is busy"}),
                                    ),
                                    false,
                                ));
                            }
                            operation_id += 1;
                            state = State::Starting;
                            last_error = None;
                            exit_code = None;
                            shutdown_delivered = false;
                            pending = Some(start_task(config.clone(), child_config.clone()));
                            Ok((
                                202,
                                Some(json!({"operation_id":operation_id,"state":state})),
                                false,
                            ))
                        }
                        "Shutdown" => {
                            if state != State::Running {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"INVALID_STATE","fault_message":"shutdown requires Running"}),
                                    ),
                                    false,
                                ));
                            }
                            if config["machine-config"]["power_button"] != true {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"UNSUPPORTED_CAPABILITY","fault_message":"power_button is disabled for this VM"}),
                                    ),
                                    false,
                                ));
                            }
                            let timeout = action.timeout_ms.unwrap_or(5000);
                            if !(1..=300000).contains(&timeout) {
                                return Err("timeout_ms must be 1..300000".into());
                            }
                            child.as_mut().unwrap().2.write_all(b"S")?;
                            operation_id += 1;
                            state = State::Stopping;
                            last_error = None;
                            shutdown_delivered = false;
                            shutdown_deadline = Some((
                                std::time::Instant::now() + Duration::from_millis(timeout),
                                action.force_on_timeout,
                            ));
                            Ok((
                                202,
                                Some(json!({"operation_id":operation_id,"state":state})),
                                false,
                            ))
                        }
                        "Stop" | "ForceStop" => {
                            shutdown_deadline = None;
                            operation_id += 1;
                            if let Some(task) = &pending {
                                task.cancel.store(true, Ordering::Relaxed);
                                state = State::Stopping;
                            } else if let Some(ref mut p) = child {
                                p.kill()?;
                                state = State::Stopping;
                            } else {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"INVALID_STATE","fault_message":"no active VM"}),
                                    ),
                                    false,
                                ));
                            }
                            Ok((
                                202,
                                Some(json!({"operation_id":operation_id,"state":state})),
                                false,
                            ))
                        }
                        _ => Err(
                            "unsupported action; use InstanceStart, Shutdown or ForceStop".into(),
                        ),
                    }
                }
                ("PUT", path) if child.is_none() && pending.is_none() => {
                    let value: Value = serde_json::from_slice(&request.body)?;
                    match path {
                        "/boot-source" => {
                            let _: crate::BootSource = serde_json::from_value(value.clone())?;
                            config["boot-source"] = value;
                        }
                        "/machine-config" => {
                            let _: crate::Machine = serde_json::from_value(value.clone())?;
                            config["machine-config"] = value;
                        }
                        "/firmware" => {
                            let _: std::collections::BTreeMap<String, PathBuf> =
                                serde_json::from_value(value.clone())?;
                            config["firmware"] = value;
                        }
                        "/network-interfaces" => {
                            let _: Vec<crate::Network> = serde_json::from_value(value.clone())?;
                            config["network-interfaces"] = value;
                        }
                        "/hvf" => {
                            let _: crate::Options = serde_json::from_value(value.clone())?;
                            config["hvf"] = value;
                        }
                        path if path.starts_with("/drives/") => {
                            let drive: crate::Drive = serde_json::from_value(value.clone())?;
                            if drive.drive_id != path.trim_start_matches("/drives/") {
                                return Err("drive_id does not match URL".into());
                            }
                            // The current backend supports one root drive; replacement is explicit by ID.
                            let drives = config["drives"]
                                .as_array_mut()
                                .ok_or("invalid drives state")?;
                            if let Some(old) =
                                drives.iter_mut().find(|d| d["drive_id"] == drive.drive_id)
                            {
                                *old = value;
                            } else {
                                drives.push(value);
                            }
                        }
                        _ => {
                            return Ok((
                                404,
                                Some(json!({"fault_message":"unsupported endpoint"})),
                                false,
                            ));
                        }
                    }
                    Ok((204, None, false))
                }
                ("PUT", _) => Ok((
                    409,
                    Some(json!({"fault_message":"configuration cannot change while running"})),
                    false,
                )),
                _ => Ok((
                    404,
                    Some(json!({"fault_message":"unsupported endpoint"})),
                    false,
                )),
            }
        })();
        match outcome {
            Ok((code, value, stop)) => {
                let _ = respond(&mut stream, code, value);
                if stop {
                    return Ok(0);
                }
            }
            Err(e) => {
                let _ = respond(
                    &mut stream,
                    400,
                    Some(json!({"fault_message":e.to_string()})),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(bytes: &[u8]) -> Result<Request> {
        let (mut server, mut client) = UnixStream::pair()?;
        client.write_all(bytes)?;
        client.shutdown(std::net::Shutdown::Write)?;
        request(&mut server)
    }
    #[test]
    fn valid_body() {
        let r = parse(b"PUT /actions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(r.body, b"{}");
        assert_eq!(r.path, "/actions");
    }
    #[test]
    fn rejects_ambiguous_framing() {
        for b in [
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(parse(b).is_err());
        }
    }
    #[test]
    fn rejects_truncated_body() {
        assert!(parse(b"PUT / HTTP/1.1\r\nContent-Length: 3\r\n\r\n{}").is_err());
    }
    #[test]
    fn rejects_large_body() {
        assert!(parse(b"PUT / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n").is_err());
    }
}
