// SPDX-License-Identifier: Apache-2.0
//! Small Unix HTTP control plane for the experimental Darwin backend.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
mod control;
mod http;
mod metrics;
mod operations;
mod recovery;
use control::Message;
mod supervisor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use supervisor::{Guest, discard_task, start_task};
#[derive(Clone, Copy, PartialEq, serde::Serialize)]
enum State {
    #[serde(rename = "Not started")]
    NotStarted,
    Starting,
    Running,
    Pausing,
    Paused,
    Resuming,
    Snapshotting,
    Restoring,
    Stopping,
    Exited,
    Failed,
}
impl State {
    fn metric_name(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Resuming => "resuming",
            Self::Snapshotting => "snapshotting",
            Self::Restoring => "restoring",
            Self::Stopping => "stopping",
            Self::Exited => "exited",
            Self::Failed => "failed",
        }
    }
}
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn stop_signal(_: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}
use crate::{Config, Result};
use serde_json::{Value, json};

struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub fn serve(socket: &Path, initial: Option<Config>) -> Result<i32> {
    serve_inner(socket, initial, false)
}
pub fn headless(config: Config) -> Result<i32> {
    config.validate()?;
    let work = tempfile::tempdir()?;
    serve_inner(&work.path().join("control.sock"), Some(config), true)
}
fn serve_inner(socket: &Path, initial: Option<Config>, headless: bool) -> Result<i32> {
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
    let work = recovery::Workspace::new()?;
    let child_config = work.path().join("config.json");
    let mut config = initial
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"drives":[],"security":crate::security::Security::default(),"limits":crate::limits::Limits::default()}));
    let mut state = State::NotStarted;
    let mut exit_code: Option<i32> = None;
    let mut last_error: Option<Value> = None;
    let mut operation_id = 0u64;
    let mut operations = operations::Operations::default();
    let mut shutdown_deadline: Option<(std::time::Instant, bool)> = None;
    let mut shutdown_delivered = false;
    let mut child: Option<Guest> = None;
    let mut capture_path: Option<PathBuf> = None;
    let mut snapshot_task: Option<crate::snapshot::Task> = None;
    let mut pending = if initial.is_some() {
        state = State::Starting;
        operation_id = operations.begin("InstanceStart");
        Some(start_task(
            config.clone(),
            child_config.clone(),
            operation_id,
            work.lease_fd(),
        ))
    } else {
        None
    };
    let mut transport = http::Transport::new();
    let mut metrics = metrics::Metrics::new();
    let mut previous_state = State::NotStarted;
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
                Ok(Ok(mut guest)) if !cancelled => {
                    state = if let Some(restored) = guest.6.take() {
                        config = restored;
                        State::Paused
                    } else {
                        State::Running
                    };
                    child = Some(guest);
                    operations.finish("succeeded",if state==State::Paused{Some(json!({"restored_state":"Paused","network_reset":true,"format_version":1}))}else{None});
                }
                Ok(Ok(guest)) => {
                    // Reaping a cancelled child may take two seconds. Keep that
                    // teardown on a worker so the control plane stays responsive.
                    pending = Some(discard_task(guest));
                    state = State::Stopping;
                }
                Ok(Err(error)) => {
                    if cancelled {
                        operations.finish("succeeded", Some(json!({"start_cancelled":true})));
                    }
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
        if snapshot_task
            .as_ref()
            .is_some_and(|t| t.thread.as_ref().unwrap().is_finished())
        {
            let mut task = snapshot_task.take().unwrap();
            let result = task.thread.take().unwrap().join();
            if task.id == operation_id && state == State::Snapshotting && child.is_some() {
                state = State::Paused;
                match result {
                    Ok(Ok(())) => operations.finish(
                        "succeeded",
                        Some(json!({"snapshot_path":task.destination,"format_version":1})),
                    ),
                    other => {
                        let error = match other {
                            Ok(Err(e)) => e,
                            _ => "snapshot worker panicked".into(),
                        };
                        last_error =
                            Some(json!({"fault_code":"SNAPSHOT_FAILED","fault_message":error}));
                        operations.finish("failed", last_error.clone());
                    }
                }
            }
        }
        if matches!(state, State::Failed | State::Exited) && pending.is_none() {
            operations.finish("failed", last_error.clone());
        }
        if let Some(process) = &mut child {
            let pid = process.id();
            if let Some(error) = process.5.poll(pid) {
                last_error = Some(json!({"fault_code":"RESOURCE_LIMIT","fault_message":error}));
                operations.finish("failed", last_error.clone());
                process.kill_group()?;
            }
            process.4.poll();
            match process.3.receive(&mut process.2) {
                Ok(Some(message))
                    if message
                        == (Message {
                            kind: b'A',
                            operation: operation_id,
                        })
                        && shutdown_deadline.is_some() =>
                {
                    shutdown_delivered = true
                }
                Ok(Some(message))
                    if message.operation == operation_id
                        && ((state == State::Pausing && message.kind == b'P')
                            || (state == State::Resuming && message.kind == b'U')) =>
                {
                    state = if state == State::Pausing {
                        State::Paused
                    } else {
                        State::Running
                    };
                    operations.finish("succeeded", None);
                }
                Ok(Some(message))
                    if message.operation == operation_id
                        && state == State::Snapshotting
                        && capture_path.is_some() =>
                {
                    let destination = capture_path.take().unwrap();
                    if message.kind == b'C' {
                        snapshot_task = Some(crate::snapshot::task(
                            operation_id,
                            config.clone(),
                            process.1.path().to_owned(),
                            destination,
                        ));
                    } else {
                        state = State::Paused;
                        last_error = Some(
                            json!({"fault_code":"SNAPSHOT_CAPTURE_FAILED","fault_message":process.diagnostic()}),
                        );
                        operations.finish("failed", last_error.clone());
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    if process.try_wait()?.is_none() && last_error.is_none() {
                        last_error = Some(
                            json!({"fault_code":"CONTROL_ERROR","fault_message":e.to_string()}),
                        );
                    }
                }
            }
        }
        if let Some(ref mut process) = child
            && let Some(status) = process.try_wait()?
        {
            exit_code = Some(status.code().unwrap_or(1));
            let forced = operations.expects_forced_exit();
            if !status.success() && last_error.is_none() && !forced {
                last_error = Some(
                    json!({"fault_code":"VMM_EXIT","fault_message":process.diagnostic(),"exit_code":exit_code}),
                );
                operations.finish("failed", last_error.clone());
            }
            operations.exited(status.success(), exit_code);
            state = State::Exited;
            child = None;
            capture_path = None;
            if let Some(task) = &snapshot_task {
                task.cancel.store(true, Ordering::Relaxed);
            }
            shutdown_deadline = None;
        }
        if let Some(process) = &mut child
            && let Some((deadline, force)) = shutdown_deadline
            && std::time::Instant::now() >= deadline
        {
            let _ = Message {
                kind: b'X',
                operation: operation_id,
            }
            .send(&mut process.2);
            shutdown_deadline = None;
            last_error = Some(
                json!({"fault_code":"SHUTDOWN_TIMEOUT","fault_message":"guest did not power off before deadline","forced":force}),
            );
            operations.finish("failed", last_error.clone());
            if force {
                process.kill_group()?;
            } else {
                state = State::Running;
            }
        }
        if headless
            && pending.is_none()
            && child.is_none()
            && matches!(state, State::Exited | State::Failed)
        {
            if let Some(error) = &last_error {
                eprintln!("{error}");
            }
            return Ok(exit_code.unwrap_or(1));
        }
        if previous_state != state {
            metrics.transitions += 1;
            metrics.enter(state.metric_name());
            previous_state = state;
        }
        transport.accept(&listener)?;
        let Some((request, reply)) = transport.next() else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        metrics.requests += 1;
        let outcome = (|| -> Result<(u16, Option<Value>, bool)> {
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/") => Ok((
                    200,
                    Some(
                        json!({"id":"anonymous-instance","state":state,"vmm_version":"1.0-hvf","app_name":"Firecracker","exit_code":exit_code,"operation_id":operation_id,"last_error":last_error,"shutdown_delivered":shutdown_delivered,"api_version":"1.0"}),
                    ),
                    false,
                )),
                ("GET", "/capabilities") => Ok((
                    200,
                    Some(
                        json!({"api_version":"1.0","boot_protocols":["elf","linux-image"],"network_backends":["slirp","unix-stream"],"unix_stream":{"framing":"u32be-length-ethernet","max_frame_bytes":65536,"reconnect_ms":1000,"snapshots":true,"snapshot_restore":"compatible-interface-fresh-socket","policy":"external-switch"},"max_vcpus":4,"memory_mib":[64,2048],"max_drives":4,"snapshots":true,"snapshot_format_version":1,"snapshot_restore_state":"Paused","snapshot_network":"restart-no-established-connections","snapshot_compatibility":"same-host-macos-build-vmm-build-device-model","vmm_build_id":env!("HVF_BUILD_ID"),"pause":true,"guest_shutdown":true,"shutdown_transport":"virtio-input-key-power","control_protocol_version":1,"operation_history":64,"metrics_formats":["json","prometheus"],"isolation_available":"seatbelt-macos26","isolation":if child.is_none(){"not-running"}else if config["security"]["mode"]=="development"{"unrestricted-development"}else{"seatbelt-macos26"},"network_policy":if config["network-interfaces"].as_array().is_some_and(|nets| nets.iter().any(|n| n["backend"] == "unix-stream")){"external-switch-unix-capability"}else if config["security"]["mode"]=="development"{"unrestricted-development"}else{"deny-by-default-ipv4"},"development_mode":true,"limits":{"hard_per_process":["open_files","file_size_bytes"],"cpu_enforcement":"reactive-group-and-hard-network-processes","rss_scope":"vmm-process-group","rss_enforcement":"reactive","rss_sample_interval_ms":100,"cpu_priority":"nice","io_scope":"aggregate-virtio-devices","disk_burst_bytes":4194304,"disk_burst_operations":32,"network_burst_bytes":262144,"network_burst_packets":256}}),
                    ),
                    false,
                )),
                ("GET", "/metrics") => {
                    let mut sample = metrics.sample(
                        child.as_ref().map(|p| p.id()),
                        child.as_ref().and_then(|p| p.4.broker_pid()),
                        transport.connections(),
                        transport.rejected,
                    );
                    operations.metrics(&mut sample);
                    sample["http_queued_requests"] = json!(transport.queued());
                    if let Some(process) = &child {
                        process.4.merge(&mut sample);
                        sample["resource_group_resident_bytes"] = json!(process.5.rss_bytes);
                        sample["resource_group_cpu_nanoseconds_total"] = json!(process.5.cpu_ns);
                        sample["resource_monitor_samples_total"] = json!(process.5.samples);
                    }
                    Ok((200, Some(sample), false))
                }
                ("GET", "/operations") => {
                    Ok((200, Some(serde_json::to_value(operations.list())?), false))
                }
                ("GET", path) if path.starts_with("/operations/") => {
                    let id: u64 = path.trim_start_matches("/operations/").parse()?;
                    match operations.get(id) {
                        Some(op) => Ok((200, Some(serde_json::to_value(op)?), false)),
                        None => Ok((
                            404,
                            Some(json!({"fault_code":"OPERATION_NOT_FOUND"})),
                            false,
                        )),
                    }
                }
                ("GET", "/vm/config") => Ok((200, Some(config.clone()), false)),
                ("PUT", "/snapshot/create" | "/snapshot/load") => {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct SnapshotRequest {
                        snapshot_path: PathBuf,
                    }
                    let request_body: SnapshotRequest = serde_json::from_slice(&request.body)?;
                    if !request_body.snapshot_path.is_absolute() {
                        return Err("snapshot_path must be absolute".into());
                    }
                    let create = request.path == "/snapshot/create";
                    if !create {
                        crate::snapshot::validate_restore_network(
                            &request_body.snapshot_path,
                            &config,
                        )?;
                    }
                    if snapshot_task.is_some()
                        || pending.is_some()
                        || (create && state != State::Paused)
                        || (!create && child.is_some())
                    {
                        return Ok((
                            409,
                            Some(
                                json!({"fault_code":"INVALID_STATE","fault_message":"create requires Paused; load requires no active VM"}),
                            ),
                            false,
                        ));
                    }
                    last_error = None;
                    if create {
                        Message {
                            kind: b'C',
                            operation: operation_id + 1,
                        }
                        .send(&mut child.as_mut().unwrap().2)?;
                        operation_id = operations.begin("SnapshotCreate");
                        state = State::Snapshotting;
                        capture_path = Some(request_body.snapshot_path);
                    } else {
                        operation_id = operations.begin("SnapshotLoad");
                        state = State::Restoring;
                        exit_code = None;
                        pending = Some(supervisor::restore_task(
                            request_body.snapshot_path,
                            child_config.clone(),
                            operation_id,
                            work.lease_fd(),
                            config.clone(),
                        ));
                    }
                    Ok((
                        202,
                        Some(json!({"operation_id":operation_id,"state":state})),
                        false,
                    ))
                }
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
                            if child.is_some() || pending.is_some() || snapshot_task.is_some() {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"INVALID_STATE","fault_message":"VM is busy"}),
                                    ),
                                    false,
                                ));
                            }
                            operation_id = operations.begin("InstanceStart");
                            state = State::Starting;
                            last_error = None;
                            exit_code = None;
                            shutdown_delivered = false;
                            pending = Some(start_task(
                                config.clone(),
                                child_config.clone(),
                                operation_id,
                                work.lease_fd(),
                            ));
                            Ok((
                                202,
                                Some(json!({"operation_id":operation_id,"state":state})),
                                false,
                            ))
                        }
                        "Pause" | "Resume" => {
                            let pause=action.action_type=="Pause";
                            let required=if pause {State::Running} else {State::Paused};
                            if state!=required {
                                return Ok((409,Some(json!({"fault_code":"INVALID_STATE","fault_message":"Pause requires Running; Resume requires Paused"})),false));
                            }
                            if action.timeout_ms.is_some() || action.force_on_timeout {
                                return Err("pause/resume do not accept shutdown timeout options".into());
                            }
                            Message {kind:if pause {b'P'} else {b'U'},operation:operation_id+1}
                                .send(&mut child.as_mut().unwrap().2)?;
                            operation_id=operations.begin(&action.action_type);
                            state=if pause {State::Pausing} else {State::Resuming};
                            last_error=None;
                            Ok((202,Some(json!({"operation_id":operation_id,"state":state})),false))
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
                            Message {
                                kind: b'S',
                                operation: operation_id + 1,
                            }
                            .send(&mut child.as_mut().unwrap().2)?;
                            operation_id = operations.begin("Shutdown");
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
                            if child.is_none() && pending.is_none()
                                || (state == State::Stopping && shutdown_deadline.is_none())
                            {
                                return Ok((
                                    409,
                                    Some(
                                        json!({"fault_code":"INVALID_STATE","fault_message":"no cancellable VM operation"}),
                                    ),
                                    false,
                                ));
                            }
                            shutdown_deadline = None;
                            capture_path=None;
                            if let Some(task)=&snapshot_task{task.cancel.store(true,Ordering::Relaxed);}
                            operation_id = operations.begin("ForceStop");
                            if let Some(task) = &pending {
                                task.cancel.store(true, Ordering::Relaxed);
                                state = State::Stopping;
                            } else if let Some(ref mut p) = child {
                                p.kill_group()?;
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
                            "unsupported action; use InstanceStart, Shutdown, ForceStop, Pause or Resume".into(),
                        ),
                    }
                }
                ("PUT", path) if child.is_none() && pending.is_none() => {
                    let value: Value = serde_json::from_slice(&request.body)?;
                    match path {
                        "/limits" => {
                            let limits: crate::limits::Limits =
                                serde_json::from_value(value.clone())?;
                            limits.validate()?;
                            config["limits"] = serde_json::to_value(limits)?;
                        }
                        "/security" => {
                            let policy: crate::security::Security =
                                serde_json::from_value(value.clone())?;
                            policy.validate()?;
                            config["security"] = value;
                        }
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
                            // Replacement is explicit by ID; bound configuration before starting.
                            let drives = config["drives"]
                                .as_array_mut()
                                .ok_or("invalid drives state")?;
                            if let Some(old) =
                                drives.iter_mut().find(|d| d["drive_id"] == drive.drive_id)
                            {
                                *old = value;
                            } else {
                                if drives.len() >= 4 {
                                    return Err("at most four drives are supported".into());
                                }
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
                let _ = reply.send((code, value));
                if stop {
                    return Ok(0);
                }
            }
            Err(e) => {
                let _ = reply.send((400, Some(json!({"fault_message":e.to_string()}))));
            }
        }
    }
}
