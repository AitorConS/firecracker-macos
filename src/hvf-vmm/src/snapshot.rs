// SPDX-License-Identifier: Apache-2.0
//! Versioned, local snapshots. Native code only sees verified private copies.
use crate::{Config, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
struct Sha256 {
    count: [u32; 2],
    hash: [u32; 8],
    words: [u32; 16],
}
unsafe extern "C" {
    fn CC_SHA256_Init(context: *mut Sha256) -> i32;
    fn CC_SHA256_Update(context: *mut Sha256, bytes: *const u8, length: u32) -> i32;
    fn CC_SHA256_Final(output: *mut u8, context: *mut Sha256) -> i32;
}
impl Sha256 {
    fn new() -> Self {
        let mut value = Self {
            count: [0; 2],
            hash: [0; 8],
            words: [0; 16],
        };
        // SAFETY: repr(C) matches the macOS CommonCrypto SHA-256 context.
        assert_eq!(unsafe { CC_SHA256_Init(&mut value) }, 1);
        value
    }
    fn update(&mut self, bytes: &[u8]) {
        for block in bytes.chunks(131072) {
            // SAFETY: the live slice is readable for this bounded u32 length.
            assert_eq!(
                unsafe { CC_SHA256_Update(self, block.as_ptr(), block.len() as u32) },
                1
            );
        }
    }
    fn finish(mut self) -> String {
        let mut digest = [0u8; 32];
        // SAFETY: output has the required 32 bytes and context was initialized.
        assert_eq!(
            unsafe { CC_SHA256_Final(digest.as_mut_ptr(), &mut self) },
            1
        );
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}
fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err("snapshot operation cancelled".into());
    }
    Ok(())
}
fn regular(path: &Path) -> Result<File> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path.parent().ok_or("missing component parent")?)?;
    let name =
        std::ffi::CString::new(path.file_name().ok_or("invalid component name")?.as_bytes())?;
    // SAFETY: openat is anchored to a live directory FD and a single terminated name.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openat returns a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
        return Err("snapshot component must be an owned regular file without links".into());
    }
    Ok(file)
}
fn copy_hash(
    source: &Path,
    target: Option<&Path>,
    maximum: u64,
    cancel: &AtomicBool,
) -> Result<Component> {
    let mut source = regular(source)?;
    let before = source.metadata()?;
    if before.len() > maximum {
        return Err("snapshot component exceeds size limit".into());
    }
    let mut output = target
        .map(|p| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(p)
        })
        .transpose()?;
    let mut buffer = [0u8; 131072];
    let mut hash = Sha256::new();
    let mut total = 0u64;
    loop {
        cancelled(cancel)?;
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("snapshot size overflow")?;
        if total > maximum || total > before.len() {
            return Err("snapshot component grew during copy".into());
        }
        hash.update(&buffer[..n]);
        if let Some(out) = &mut output {
            out.write_all(&buffer[..n])?;
        }
    }
    let after = source.metadata()?;
    if total != before.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err("snapshot component changed during copy".into());
    }
    if let Some(out) = output {
        out.sync_all()?;
    }
    Ok(Component {
        size: total,
        sha256: hash.finish(),
    })
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Compatibility {
    host: String,
    os_build: String,
    vmm_build_sha256: String,
    device_model: u32,
}
fn sysctl(name: &std::ffi::CStr) -> Result<Vec<u8>> {
    let mut buffer = [0u8; 1024];
    let mut size = buffer.len();
    // SAFETY: bounded writable buffer, terminated name, read-only sysctl.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size > buffer.len()
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(buffer[..size].to_vec())
}
fn compatibility() -> Result<Compatibility> {
    let mut uuid = [0u8; 16];
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: gethostuuid writes precisely 16 bytes and reads a valid timeout.
    if unsafe { libc::gethostuuid(uuid.as_mut_ptr(), &timeout) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Compatibility {
        host: uuid.iter().map(|b| format!("{b:02x}")).collect(),
        os_build: String::from_utf8(sysctl(c"kern.osversion")?)?
            .trim_end_matches('\0')
            .into(),
        vmm_build_sha256: env!("HVF_BUILD_ID").into(),
        device_model: 1,
    })
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Component {
    size: u64,
    sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    compatibility: Compatibility,
    config: Config,
    #[serde(deserialize_with = "unique_components")]
    components: BTreeMap<String, Component>,
}
fn unique_components<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, Component>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, Component>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("at most 80 unique snapshot components")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                if values.len() >= 80 || values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive snapshot components",
                    ));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor)
}
fn names(config: &Config) -> BTreeMap<String, u64> {
    let ram = u64::from(config.machine_config.mem_size_mib) << 20;
    let mut names = BTreeMap::from([
        ("ram.bin".into(), ram),
        ("devices.bin".into(), 65536),
        ("gic.bin".into(), 64 << 20),
        ("kernel".into(), ram),
    ]);
    for i in 0..config.machine_config.vcpu_count {
        names.insert(format!("cpu-{i}.bin"), 131072);
    }
    for i in 0..config.drives.len() {
        names.insert(format!("disk-{i}.bin"), config.limits.file_size_bytes);
    }
    if config.boot_source.initrd_path.is_some() {
        names.insert("initrd".into(), ram);
    }
    for i in 0..config.firmware.len() {
        names.insert(format!("firmware-{i}"), 65536);
    }
    names
}
fn relative_config(config: &mut Config) {
    config.boot_source.kernel_image_path = "kernel".into();
    if config.boot_source.initrd_path.is_some() {
        config.boot_source.initrd_path = Some("initrd".into());
    }
    let indices: Vec<_> = (0..config.drives.len())
        .filter(|&i| config.drives[i].is_root_device)
        .chain((0..config.drives.len()).filter(|&i| !config.drives[i].is_root_device))
        .collect();
    for (ordinal, index) in indices.into_iter().enumerate() {
        config.drives[index].path_on_host = format!("disk-{ordinal}.bin").into();
        config.drives[index].copy_on_start = false;
    }
    for (i, path) in config.firmware.values_mut().enumerate() {
        *path = format!("firmware-{i}").into();
    }
}
fn directory(path: &Path) -> Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let m = dir.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0 {
        return Err("snapshot directory must be owned and private (0700)".into());
    }
    Ok(dir)
}
fn manifest(path: &Path) -> Result<Manifest> {
    let _dir = directory(path)?;
    let mut bytes = Vec::new();
    regular(&path.join("manifest.json"))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("snapshot manifest exceeds 1 MiB".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.format_version != 1 {
        return Err("unsupported snapshot format".into());
    }
    manifest.config.validate_shape()?;
    let mut expected: Config = serde_json::from_value(serde_json::to_value(&manifest.config)?)?;
    relative_config(&mut expected);
    if serde_json::to_value(&expected)? != serde_json::to_value(&manifest.config)? {
        return Err("snapshot contains non-canonical component paths".into());
    }
    let limits = names(&manifest.config);
    if manifest.components.len() != limits.len() {
        return Err("snapshot component set mismatch".into());
    }
    for (name, limit) in limits {
        let component = manifest
            .components
            .get(&name)
            .ok_or("missing snapshot component")?;
        // Empty firmware values are valid (Jerboa uses them for an empty env
        // or mount list) and publish() can create them. Executable/state/RAM
        // and block components must still contain data.
        if (component.size == 0 && !name.starts_with("firmware-"))
            || component.size > limit
            || component.sha256.len() != 64
            || !component
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid snapshot component size or hash".into());
        }
        if name == "ram.bin" && component.size != limit {
            return Err("snapshot RAM length mismatch".into());
        }
        if name.starts_with("disk-") && component.size % 512 != 0 {
            return Err("unaligned snapshot disk".into());
        }
    }
    Ok(manifest)
}

// A unix-stream connection is a host capability, not portable VM state.  Keep
// the guest-visible device (interface ID and MAC) fixed, but require the
// restoring supervisor to provide the current external-switch socket.  This
// makes reconnects explicit and prevents a snapshot from selecting another
// VM's link.  The substituted configuration is validated below, including the
// matching security.unix_stream capability and the absence of IP policy.
fn rebind_unix_stream(config: &mut Config, restore: &serde_json::Value) -> Result<()> {
    let Some(saved) = config
        .network_interfaces
        .iter()
        .find(|network| network.backend == "unix-stream")
    else {
        return Ok(());
    };
    let current: Vec<crate::Network> = serde_json::from_value(
        restore
            .get("network-interfaces")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| "unix-stream snapshot requires compatible restore networking")?;
    if current.len() != 1
        || current[0].backend != "unix-stream"
        || current[0].iface_id != saved.iface_id
        || current[0].guest_mac != saved.guest_mac
    {
        return Err("unix-stream snapshot restore interface is incompatible".into());
    }
    let security: Option<crate::security::Security> = serde_json::from_value(
        restore
            .get("security")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| "unix-stream snapshot requires compatible restore security")?;
    config.network_interfaces = current;
    config.security = security;
    config.validate_shape()?;
    Ok(())
}

/// Cheap synchronous compatibility check used by the API before accepting a
/// restore. Integrity and component copying remain asynchronous.
pub(crate) fn validate_restore_network(source: &Path, restore: &serde_json::Value) -> Result<()> {
    let mut config = manifest(source)?.config;
    rebind_unix_stream(&mut config, restore)
}
/// Publish only after every component and the manifest have been fsynced.
pub(crate) fn publish(
    value: serde_json::Value,
    work: &Path,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut config: Config = serde_json::from_value(value)?;
    config.validate_shape()?;
    relative_config(&mut config);
    let parent = destination
        .parent()
        .ok_or("snapshot requires a parent directory")?;
    let parent = fs::canonicalize(parent)?;
    let name = destination.file_name().ok_or("invalid snapshot name")?;
    let destination = parent.join(name);
    if fs::symlink_metadata(&destination).is_ok() {
        let _ = manifest(&destination)?;
    }
    let temporary = tempfile::Builder::new()
        .prefix(".hvf-snapshot-")
        .tempdir_in(&parent)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let mut components = BTreeMap::new();
    for (name, limit) in names(&config) {
        let source = if name == "kernel" || name == "initrd" || name.starts_with("firmware-") {
            work.join(&name)
        } else {
            work.join("native-snapshot").join(&name)
        };
        components.insert(
            name.clone(),
            copy_hash(&source, Some(&temporary.path().join(&name)), limit, cancel)?,
        );
    }
    let document = Manifest {
        format_version: 1,
        compatibility: compatibility()?,
        config,
        components,
    };
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary.path().join("manifest.json"))?;
    serde_json::to_writer(&mut out, &document)?;
    out.sync_all()?;
    File::open(temporary.path())?.sync_all()?;
    cancelled(cancel)?;
    if fs::symlink_metadata(&destination).is_ok() {
        use std::os::unix::ffi::OsStrExt;
        let from = std::ffi::CString::new(temporary.path().as_os_str().as_bytes())?;
        let to = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
        // SAFETY: live terminated paths. Atomic exchange preserves the old snapshot on failure.
        if unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_SWAP,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    } else {
        let from = std::ffi::CString::new(temporary.path().as_os_str().as_bytes())?;
        let to = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
        // SAFETY: terminated paths, exclusive rename never replaces an intervening entry.
        if unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let _ = temporary.keep();
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}
/// Validate first; copy and hash each opened component into private storage before use.
pub(crate) struct Materialized {
    pub config: serde_json::Value,
    pub public_config: serde_json::Value,
}
pub(crate) fn materialize(
    source: &Path,
    target: &Path,
    cancel: &AtomicBool,
    restore: &serde_json::Value,
) -> Result<Materialized> {
    let mut document = manifest(source)?;
    if document.compatibility != compatibility()? {
        return Err("snapshot host, macOS, VMM build or device model is incompatible".into());
    }
    rebind_unix_stream(&mut document.config, restore)?;
    for (name, limit) in names(&document.config) {
        let observed = copy_hash(
            &source.join(&name),
            Some(&target.join(&name)),
            limit,
            cancel,
        )?;
        if observed != document.components[&name] {
            return Err(format!("snapshot integrity mismatch: {name}").into());
        }
    }
    let mut public: Config = serde_json::from_value(serde_json::to_value(&document.config)?)?;
    let source = fs::canonicalize(source)?;
    public.boot_source.kernel_image_path = source.join("kernel");
    if public.boot_source.initrd_path.is_some() {
        public.boot_source.initrd_path = Some(source.join("initrd"));
    }
    for drive in &mut public.drives {
        drive.path_on_host = source.join(&drive.path_on_host);
        drive.copy_on_start = true;
    }
    for path in public.firmware.values_mut() {
        *path = source.join(&*path);
    }
    let mut config = document.config;
    config.boot_source.kernel_image_path = target.join("kernel");
    if config.boot_source.initrd_path.is_some() {
        config.boot_source.initrd_path = Some(target.join("initrd"));
    }
    for drive in &mut config.drives {
        drive.path_on_host = target.join(&drive.path_on_host);
        drive.copy_on_start = true;
    }
    for path in config.firmware.values_mut() {
        *path = target.join(&*path);
    }
    Ok(Materialized {
        config: serde_json::to_value(config)?,
        public_config: serde_json::to_value(public)?,
    })
}

pub(crate) struct Task {
    pub id: u64,
    pub destination: PathBuf,
    pub cancel: std::sync::Arc<AtomicBool>,
    pub thread: Option<std::thread::JoinHandle<std::result::Result<(), String>>>,
}
impl Drop for Task {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub(crate) fn task(
    id: u64,
    config: serde_json::Value,
    work: PathBuf,
    destination: PathBuf,
) -> Task {
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let published = destination.clone();
    let thread = std::thread::spawn(move || {
        publish(config, &work, &destination, &flag).map_err(|e| e.to_string())
    });
    Task {
        id,
        destination: published,
        cancel,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_standard_vectors_and_chunking() {
        assert_eq!(
            Sha256::new().finish(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut hash = Sha256::new();
        hash.update(b"a");
        hash.update(b"bc");
        assert_eq!(
            hash.finish(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut hash = Sha256::new();
        for _ in 0..1000 {
            hash.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hash.finish(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
    #[test]
    fn snapshot_component_parser_rejects_duplicates() {
        #[derive(Deserialize)]
        struct Sample {
            #[serde(deserialize_with = "unique_components")]
            components: BTreeMap<String, Component>,
        }
        let duplicate =
            r#"{"components":{"x":{"size":1,"sha256":"a"},"x":{"size":2,"sha256":"b"}}}"#;
        assert!(serde_json::from_str::<Sample>(duplicate).is_err());
        assert!(
            serde_json::from_str::<Sample>(r#"{"components":{}}"#)
                .unwrap()
                .components
                .is_empty()
        );
    }
    #[test]
    fn bounded_copy_rejects_links_and_cancellation() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source");
        fs::write(&source, b"data").unwrap();
        let target = work.path().join("target");
        assert!(copy_hash(&source, Some(&target), 3, &AtomicBool::new(false)).is_err());
        assert!(!target.exists());
        assert!(copy_hash(&source, None, 4, &AtomicBool::new(true)).is_err());
        std::os::unix::fs::symlink(&source, &target).unwrap();
        assert!(copy_hash(&target, None, 4, &AtomicBool::new(false)).is_err());
    }

    fn stream_config(path: &str, mac: &str) -> Config {
        serde_json::from_value(serde_json::json!({
            "boot-source": {"kernel_image_path":"/kernel"},
            "network-interfaces": [{
                "iface_id":"eth0", "guest_mac":mac, "backend":"unix-stream",
                "socket_path":path
            }],
            "security": {"version":1, "unix_stream":path},
            "limits": {"version":1}
        }))
        .unwrap()
    }

    #[test]
    fn unix_stream_restore_rebinds_only_compatible_capability() {
        let mut saved = stream_config("/private/tmp/old.sock", "02:00:00:00:00:01");
        let current =
            serde_json::to_value(stream_config("/private/tmp/new.sock", "02:00:00:00:00:01"))
                .unwrap();
        rebind_unix_stream(&mut saved, &current).unwrap();
        assert_eq!(
            saved.network_interfaces[0].socket_path.as_deref(),
            Some(Path::new("/private/tmp/new.sock"))
        );
        assert_eq!(
            saved.security.unwrap().unix_stream.as_deref(),
            Some(Path::new("/private/tmp/new.sock"))
        );

        let mut saved = stream_config("/private/tmp/old.sock", "02:00:00:00:00:01");
        let incompatible =
            serde_json::to_value(stream_config("/private/tmp/new.sock", "02:00:00:00:00:02"))
                .unwrap();
        assert!(
            rebind_unix_stream(&mut saved, &incompatible)
                .unwrap_err()
                .to_string()
                .contains("interface is incompatible")
        );

        let mut policy =
            serde_json::to_value(stream_config("/private/tmp/new.sock", "02:00:00:00:00:01"))
                .unwrap();
        policy["security"]["egress"] = serde_json::json!([{
            "protocol":"tcp", "address":"192.0.2.10", "port":443
        }]);
        assert!(
            rebind_unix_stream(
                &mut stream_config("/private/tmp/old.sock", "02:00:00:00:00:01"),
                &policy,
            )
            .unwrap_err()
            .to_string()
            .contains("IP policy")
        );

        let relative =
            serde_json::to_value(stream_config("relative.sock", "02:00:00:00:00:01")).unwrap();
        assert!(
            rebind_unix_stream(
                &mut stream_config("/private/tmp/old.sock", "02:00:00:00:00:01"),
                &relative,
            )
            .unwrap_err()
            .to_string()
            .contains("invalid Unix stream socket path")
        );

        let mut mismatch =
            serde_json::to_value(stream_config("/private/tmp/new.sock", "02:00:00:00:00:01"))
                .unwrap();
        mismatch["security"]["unix_stream"] = serde_json::json!("/private/tmp/other.sock");
        assert!(
            rebind_unix_stream(
                &mut stream_config("/private/tmp/old.sock", "02:00:00:00:00:01"),
                &mismatch,
            )
            .unwrap_err()
            .to_string()
            .contains("matching security.unix_stream")
        );
    }
}
