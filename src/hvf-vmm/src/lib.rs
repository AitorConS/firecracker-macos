// SPDX-License-Identifier: Apache-2.0
//! Experimental native macOS entry point. The Linux VMM remains a separate target.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod api;
mod block;
mod inherited;
mod limits;
mod loader;
mod resources;
mod security;
mod snapshot;
mod tree;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const RAM_BASE: u64 = 0x4000_0000;
const RAM_SIZE: u64 = 128 << 20;
// Native fatal errors terminate the process; preserve private-file cleanup in that
// path as well as normal Rust unwinding. One VM is allowed per process.
static PRIVATE_DIRECTORY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
extern "C" fn cleanup_private_directory() {
    if let Some(path) = PRIVATE_DIRECTORY.get() {
        let _ = fs::remove_dir_all(path);
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    boot_source: BootSource,
    #[serde(default)]
    machine_config: Machine,
    #[serde(default)]
    drives: Vec<Drive>,
    #[serde(default)]
    firmware: BTreeMap<String, PathBuf>,
    #[serde(default)]
    network_interfaces: Vec<Network>,
    #[serde(default)]
    hvf: Options,
    #[serde(default)]
    security: Option<security::Security>,
    #[serde(default)]
    limits: limits::Limits,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootSource {
    kernel_image_path: PathBuf,
    #[serde(default)]
    boot_protocol: BootProtocol,
    initrd_path: Option<PathBuf>,
    boot_args: Option<String>,
}
#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum BootProtocol {
    #[default]
    Elf,
    LinuxImage,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Network {
    iface_id: String,
    guest_mac: String,
    backend: String,
    #[serde(default)]
    socket_path: Option<PathBuf>,
    #[serde(default)]
    forwards: Vec<Forward>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Forward {
    protocol: String,
    host_addr: std::net::Ipv4Addr,
    host_port: u16,
    guest_addr: std::net::Ipv4Addr,
    guest_port: u16,
}
fn mac_bytes(value: &str) -> Result<[u8; 6]> {
    let bytes: Vec<u8> = value
        .split(':')
        .map(|s| {
            if s.len() != 2 {
                return Err("invalid MAC".into());
            }
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect::<Result<_>>()?;
    let mac: [u8; 6] = bytes.try_into().map_err(|_| "MAC needs six octets")?;
    if mac[0] & 1 != 0 || mac == [0; 6] {
        return Err("MAC must be nonzero and unicast".into());
    }
    Ok(mac)
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Machine {
    #[serde(default = "one")]
    vcpu_count: u32,
    #[serde(default = "memory")]
    mem_size_mib: u32,
    #[serde(default)]
    smt: bool,
    #[serde(default)]
    power_button: bool,
}
fn one() -> u32 {
    1
}
fn memory() -> u32 {
    128
}
impl Default for Machine {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            mem_size_mib: 128,
            smt: false,
            power_button: false,
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Drive {
    drive_id: String,
    path_on_host: PathBuf,
    #[serde(default)]
    is_root_device: bool,
    #[serde(default)]
    copy_on_start: bool,
    #[serde(default)]
    is_read_only: bool,
}
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    max_runtime_ms: u32,
    #[serde(default)]
    trace: bool,
}
impl Config {
    fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        self.validate_files()
    }
    fn validate_shape(&self) -> Result<()> {
        let security = self.security.as_ref().ok_or("SECURITY_MIGRATION_REQUIRED: add security version 1; use --migrate-config to inspect required permissions")?;
        security.validate()?;
        self.limits.validate()?;
        if !(1..=4).contains(&self.machine_config.vcpu_count)
            || !(64..=2048).contains(&self.machine_config.mem_size_mib)
            || self.machine_config.smt
        {
            return Err("HVF currently supports 1..4 vCPUs, 64..2048 MiB and no SMT".into());
        }
        if self.boot_source.boot_protocol == BootProtocol::Elf
            && (self.boot_source.initrd_path.is_some() || self.boot_source.boot_args.is_some())
        {
            return Err("ELF boot does not define initrd or boot_args; select linux-image".into());
        }
        if let Some(args) = &self.boot_source.boot_args
            && (args.len() > 4096 || args.contains('\0'))
        {
            return Err("invalid boot_args".into());
        }
        if self.drives.len() > 4 || self.drives.iter().filter(|d| d.is_root_device).count() > 1 {
            return Err("at most four block devices and one optional root designation".into());
        }
        if self.firmware.len() > 64 {
            return Err("at most 64 firmware files".into());
        }
        for name in self.firmware.keys() {
            if name.is_empty() || name.len() > 55 || name.contains('\0') {
                return Err("invalid firmware name".into());
            }
        }
        if self.network_interfaces.len() > 1 {
            return Err("at most one network interface".into());
        }
        for net in &self.network_interfaces {
            if net.iface_id.is_empty()
                || !["slirp", "unix-stream"].contains(&net.backend.as_str())
                || net.forwards.len() > 64
            {
                return Err("invalid network interface or backend".into());
            }
            if net.backend == "unix-stream" {
                let path = net
                    .socket_path
                    .as_ref()
                    .ok_or("unix-stream requires socket_path")?;
                let value = path.to_str().ok_or("socket_path must be UTF-8")?;
                if !path.is_absolute()
                    || value.len() >= 104
                    || value.chars().any(char::is_control)
                    || path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err("invalid Unix stream socket path".into());
                }
                if security.unix_stream.as_ref() != Some(path)
                    || !net.forwards.is_empty()
                    || !security.egress.is_empty()
                    || !security.listeners.is_empty()
                    || security.dns.is_some()
                {
                    return Err("unix-stream requires matching security.unix_stream; IP policy and forwards belong to the external switch".into());
                }
            } else if net.socket_path.is_some() || security.unix_stream.is_some() {
                return Err("socket_path/security.unix_stream require unix-stream backend".into());
            }
            mac_bytes(&net.guest_mac)?;
            let mut bindings = std::collections::BTreeSet::new();
            for f in &net.forwards {
                if !security.permits_listener(&f.protocol, f.host_addr, f.host_port) {
                    return Err(
                        "forwarding listener is not authorized by security.listeners".into(),
                    );
                }
                if !["tcp", "udp"].contains(&f.protocol.as_str())
                    || f.host_port == 0
                    || f.guest_port == 0
                    || !bindings.insert((&f.protocol, f.host_addr, f.host_port))
                {
                    return Err("invalid or duplicate forwarding rule".into());
                }
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for drive in &self.drives {
            if drive.drive_id.is_empty() || !ids.insert(&drive.drive_id) {
                return Err("drive IDs must be unique and nonempty".into());
            }
        }
        Ok(())
    }
    fn validate_files(&self) -> Result<()> {
        for path in self.firmware.values() {
            let m = fs::metadata(path)?;
            if !m.is_file() || m.len() > 65536 {
                return Err("firmware must be a regular file of at most 64 KiB".into());
            }
        }
        if let Some(path) = &self.boot_source.initrd_path {
            let m = fs::metadata(path)?;
            if !m.is_file()
                || m.len() == 0
                || m.len() > (u64::from(self.machine_config.mem_size_mib) << 20)
            {
                return Err("invalid initrd file".into());
            }
        }
        let kernel = fs::metadata(&self.boot_source.kernel_image_path)?;
        if !kernel.is_file() || kernel.len() > RAM_SIZE {
            return Err("kernel must be a regular file no larger than RAM".into());
        }
        for drive in &self.drives {
            let metadata = fs::metadata(&drive.path_on_host)?;
            if !metadata.is_file() || metadata.len() < 512 || metadata.len() % 512 != 0 {
                return Err(
                    "drives must be regular files with a positive sector-aligned length".into(),
                );
            }
        }
        Ok(())
    }
}
#[repr(C)]
struct NativeDrive {
    fd: i32,
    read_only: u32,
}
#[repr(C)]
struct NativeFirmware {
    name: *const std::ffi::c_char,
    data: *const u8,
    len: u32,
}
#[repr(C)]
struct NativeForward {
    udp: u32,
    host_addr: [u8; 4],
    guest_addr: [u8; 4],
    host_port: u16,
    guest_port: u16,
}
#[repr(C)]
struct NativeOptions {
    cpus: u32,
    memory_mib: u32,
    timeout_ms: u32,
    trace: u32,
    drive_count: u32,
    firmware_count: u32,
    forward_count: u32,
    network_enabled: u32,
    power_button: u32,
    ready_fd: i32,
    mac: [u8; 6],
    drives: *const NativeDrive,
    firmware: *const NativeFirmware,
    forwards: *const NativeForward,
    security: *const security::NativeSecurity,
    snapshot_dir: *const std::ffi::c_char,
    stream_path: *const std::ffi::c_char,
    restore: u32,
    cpu_seconds: u64,
    disk_bytes_per_second: u64,
    disk_operations_per_second: u64,
    network_bytes_per_second: u64,
    network_packets_per_second: u64,
}
unsafe extern "C" {
    fn hvf_run(
        ram_path: *const std::ffi::c_char,
        entry: u64,
        disk: *const std::ffi::c_char,
        options: *const NativeOptions,
    ) -> i32;
}

fn run(config: Config) -> Result<i32> {
    config.validate()?;
    config.limits.apply()?;
    let work = tempfile::tempdir()?;
    PRIVATE_DIRECTORY
        .set(work.path().to_path_buf())
        .map_err(|_| "only one VM may run per process")?;
    // SAFETY: callback has the C ABI, never panics and remains valid until exit.
    if unsafe { libc::atexit(cleanup_private_directory) } != 0 {
        return Err("could not register private-file cleanup".into());
    }
    let ram_path = work.path().join("ram.bin");
    let mut ram = File::create(&ram_path)?;
    let ram_size = u64::from(config.machine_config.mem_size_mib) << 20;
    let (entry, initrd) = match config.boot_source.boot_protocol {
        BootProtocol::Elf => (
            loader::load(&config.boot_source.kernel_image_path, &mut ram, ram_size)?,
            None,
        ),
        BootProtocol::LinuxImage => loader::linux(
            &config.boot_source.kernel_image_path,
            config.boot_source.initrd_path.as_deref(),
            &mut ram,
            ram_size,
        )?,
    };
    let dtb = tree::build(
        config.machine_config.vcpu_count,
        config.machine_config.mem_size_mib,
        config.machine_config.power_button,
        config.boot_source.boot_args.as_deref(),
        initrd,
    )?;
    if dtb.len() > 0x20_0000 {
        return Err("DTB exceeds reserved region".into());
    }
    ram.seek(SeekFrom::Start(0))?;
    ram.write_all(&dtb)?;
    drop(ram);
    use std::os::unix::ffi::OsStrExt;
    let ordered: Vec<_> = config
        .drives
        .iter()
        .filter(|d| d.is_root_device)
        .chain(config.drives.iter().filter(|d| !d.is_root_device))
        .collect();
    use std::os::fd::AsRawFd;
    let files: Vec<File> = if let Ok(inherited) = std::env::var("HVF_DRIVE_FDS") {
        use std::os::fd::FromRawFd;
        let fds: Vec<i32> = if inherited.is_empty() {
            Vec::new()
        } else {
            inherited
                .split(',')
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?
        };
        let unique: std::collections::BTreeSet<_> = fds.iter().copied().collect();
        if fds.len() != ordered.len() || unique.len() != fds.len() || fds.iter().any(|&fd| fd < 3) {
            return Err("invalid supervisor drive descriptors".into());
        }
        fds.into_iter()
            .zip(&ordered)
            .map(|(fd, drive)| {
                // SAFETY: private supervisor handoff; each inherited fd is adopted once.
                block::inherited(unsafe { File::from_raw_fd(fd) }, drive.is_read_only)
            })
            .collect::<Result<_>>()?
    } else {
        ordered
            .iter()
            .enumerate()
            .map(|(i, d)| block::open(d, &work.path().join(format!("disk-{i}.img"))))
            .collect::<Result<_>>()?
    };
    let drives: Vec<_> = files
        .iter()
        .zip(&ordered)
        .map(|(f, d)| NativeDrive {
            fd: f.as_raw_fd(),
            read_only: d.is_read_only.into(),
        })
        .collect();
    let firmware_data: Vec<_> = config
        .firmware
        .values()
        .map(|path| {
            let mut b = Vec::new();
            File::open(path)?.take(65537).read_to_end(&mut b)?;
            if b.len() > 65536 {
                return Err("firmware file exceeds 64 KiB".into());
            }
            Ok(b)
        })
        .collect::<Result<_>>()?;
    let firmware_names: Vec<_> = config
        .firmware
        .keys()
        .map(|name| CString::new(name.as_str()))
        .collect::<std::result::Result<_, _>>()?;
    let firmware: Vec<_> = firmware_names
        .iter()
        .zip(&firmware_data)
        .map(|(n, d)| NativeFirmware {
            name: n.as_ptr(),
            data: d.as_ptr(),
            len: d.len() as u32,
        })
        .collect();
    let net = config.network_interfaces.first();
    let stream_path = net
        .and_then(|n| n.socket_path.as_ref())
        .map(|p| -> Result<CString> {
            let path = fs::canonicalize(p.parent().ok_or("missing socket parent")?)?
                .join(p.file_name().ok_or("missing socket name")?);
            Ok(CString::new(path.as_os_str().as_bytes())?)
        })
        .transpose()?;
    let forwards: Vec<_> = net
        .into_iter()
        .flat_map(|n| &n.forwards)
        .map(|f| NativeForward {
            udp: (f.protocol == "udp").into(),
            host_addr: f.host_addr.octets(),
            guest_addr: f.guest_addr.octets(),
            host_port: f.host_port,
            guest_port: f.guest_port,
        })
        .collect();
    let snapshot_directory = std::env::var_os("HVF_SNAPSHOT_DIR")
        .map(PathBuf::from)
        .ok_or("missing supervised snapshot directory")?;
    let private_root = snapshot_directory
        .parent()
        .ok_or("missing private VM directory")?;
    let snapshot_dir = CString::new(snapshot_directory.as_os_str().as_bytes())?;
    let policy = security::Policy::new(
        config.security.as_ref().unwrap(),
        private_root,
        &config.drives,
    )?;
    let ram_path = CString::new(ram_path.as_os_str().as_bytes())?;
    let native = NativeOptions {
        cpus: config.machine_config.vcpu_count,
        memory_mib: config.machine_config.mem_size_mib,
        timeout_ms: config.hvf.max_runtime_ms,
        trace: config.hvf.trace.into(),
        drive_count: drives.len() as u32,
        firmware_count: firmware.len() as u32,
        forward_count: forwards.len() as u32,
        network_enabled: net.is_some().into(),
        power_button: config.machine_config.power_button.into(),
        ready_fd: std::env::var("HVF_READY_FD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1),
        mac: net
            .map(|n| mac_bytes(&n.guest_mac))
            .transpose()?
            .unwrap_or([0; 6]),
        drives: drives.as_ptr(),
        firmware: firmware.as_ptr(),
        forwards: forwards.as_ptr(),
        security: &policy.native,
        snapshot_dir: snapshot_dir.as_ptr(),
        stream_path: stream_path
            .as_ref()
            .map_or(std::ptr::null(), |p| p.as_ptr()),
        restore: (std::env::var("HVF_RESTORE").as_deref() == Ok("1")).into(),
        cpu_seconds: config.limits.cpu_seconds,
        disk_bytes_per_second: config.limits.disk_bytes_per_second,
        disk_operations_per_second: config.limits.disk_operations_per_second,
        network_bytes_per_second: config.limits.network_bytes_per_second,
        network_packets_per_second: config.limits.network_packets_per_second,
    };
    // SAFETY: C strings/options stay alive throughout this blocking call. The backend
    // owns and joins all vCPU threads before returning; only one VM is run per process.
    let status = unsafe { hvf_run(ram_path.as_ptr(), entry, std::ptr::null(), &native) };
    Ok(status)
}
fn read_config(path: &Path) -> Result<Config> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("configuration exceeds 1 MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn entry(version: &str) -> Result<i32> {
    let mut args = std::env::args().skip(1);
    let mut config = None;
    let mut check = false;
    let mut migrate = false;
    let mut socket = None;
    let mut no_api = false;
    let mut child_mode = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" => {
                println!("Firecracker {} / experimental Darwin HVF backend", version);
                return Ok(0);
            }
            "--help" => {
                println!(
                    "firecracker --no-api --config-file CONFIG [--check-config]\nfirecracker --api-sock SOCKET [--config-file CONFIG]\nfirecracker --migrate-config --config-file CONFIG\nExperimental macOS ARM64 backend; see experiments/hvf/README.md"
                );
                return Ok(0);
            }
            "--no-api" => no_api = true,
            "--hvf-child" => child_mode = true,
            "--api-sock" => {
                socket = Some(PathBuf::from(args.next().ok_or("missing api-sock value")?))
            }
            "--check-config" => check = true,
            "--migrate-config" => migrate = true,
            "--config-file" => {
                config = Some(PathBuf::from(
                    args.next().ok_or("missing config-file value")?,
                ))
            }
            other => return Err(format!("unsupported Darwin option: {other}").into()),
        }
    }
    if no_api && socket.is_some() {
        return Err("--no-api conflicts with --api-sock".into());
    }
    if child_mode {
        if !no_api || check || migrate || socket.is_some() {
            return Err("internal child requires only --no-api and --config-file".into());
        }
        inherited::restrict_child()?;
    }
    let config = config.as_deref().map(read_config).transpose()?;
    if migrate {
        if check || socket.is_some() {
            return Err("--migrate-config conflicts with --check-config and --api-sock".into());
        }
        let mut config = config.ok_or("--config-file is required")?;
        if config.security.is_some() {
            return Err("configuration already declares security".into());
        }
        config.security = Some(security::Security::default());
        let listeners: Vec<_>=config.network_interfaces.iter().flat_map(|n| &n.forwards).map(|f| serde_json::json!({"protocol":f.protocol,"address":f.host_addr,"port":f.host_port})).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "configuration":config,"required_listener_permissions":listeners,
                "review_required":"No listener, outbound or DNS permission has been granted. Add the required exact endpoints before starting; outbound requirements cannot be inferred from the configuration."
            }))?
        );
        return Ok(0);
    }
    if check {
        config
            .as_ref()
            .ok_or("--config-file is required")?
            .validate()?;
        println!("configuration valid");
        return Ok(0);
    }
    if let Some(socket) = socket {
        return api::serve(&socket, config);
    }
    let config = config.ok_or("--config-file or --api-sock is required")?;
    if child_mode {
        if !no_api || std::env::var_os("HVF_READY_FD").is_none() {
            return Err("internal child requires supervisor channel".into());
        }
        run(config)
    } else {
        api::headless(config)
    }
}
/// Execute the Darwin CLI. Unsupported options and configurations fail explicitly.
pub fn main_entry(version: &str) -> ExitCode {
    match entry(version) {
        Ok(status) => ExitCode::from(u8::try_from(status).unwrap_or(1)),
        Err(error) => {
            eprintln!("HVF: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod stream_config_tests {
    use super::*;
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({
            "boot-source":{"kernel_image_path":"/unused"},
            "network-interfaces":[{"iface_id":"eth0","guest_mac":"02:00:00:00:00:01","backend":"unix-stream","socket_path":"/private/tmp/link"}],
            "security":{"version":1,"unix_stream":"/private/tmp/link"}
        })).unwrap()
    }
    #[test]
    fn stream_requires_explicit_matching_capability() {
        let mut c = config();
        c.validate_shape().unwrap();
        c.security.as_mut().unwrap().unix_stream = None;
        assert!(c.validate_shape().is_err());
        c.security.as_mut().unwrap().unix_stream = Some("/other".into());
        assert!(c.validate_shape().is_err());
    }
    #[test]
    fn stream_rejects_ip_policy_and_invalid_paths() {
        let mut c = config();
        c.security.as_mut().unwrap().dns = Some(security::Resolver {
            address: std::net::Ipv4Addr::LOCALHOST,
            port: 53,
        });
        assert!(c.validate_shape().is_err());
        for path in [
            "relative",
            "/tmp/../link",
            "/tmp/\nlink",
            &format!("/tmp/{}", "x".repeat(104)),
        ] {
            let mut c = config();
            c.network_interfaces[0].socket_path = Some(path.into());
            c.security.as_mut().unwrap().unix_stream = Some(path.into());
            assert!(c.validate_shape().is_err());
        }
        let mut c = config();
        c.network_interfaces[0].backend = "slirp".into();
        assert!(c.validate_shape().is_err());
    }
}
