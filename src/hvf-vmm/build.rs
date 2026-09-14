// SPDX-License-Identifier: Apache-2.0
fn main() {
    // The workspace includes this crate on Linux too. It is an empty library
    // there; only the Darwin executable selects and links the native backend.
    if std::env::var("TARGET").unwrap() != "aarch64-apple-darwin" {
        return;
    }
    // Stable compatibility identity independent of install path, debug maps and signing.
    // Linux builds do not execute this Darwin-specific build step.
    use std::io::Write;
    fn collect(path: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, files);
            } else if path
                .extension()
                .is_some_and(|e| e == "rs" || e == "c" || e == "h")
            {
                files.push(path);
            }
        }
    }
    let mut sources = Vec::new();
    for directory in ["src", "native", "vendor/libslirp"] {
        collect(std::path::Path::new(directory), &mut sources);
    }
    sources.extend(
        [
            "build.rs",
            "Cargo.toml",
            "../../Cargo.lock",
            "../../experiments/hvf/distribution/sources.json",
        ]
        .map(std::path::PathBuf::from),
    );
    sources.sort();
    let mut identity = Vec::new();
    for path in sources {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(&path).unwrap();
        identity.extend_from_slice(path.to_str().unwrap().as_bytes());
        identity.push(0);
        identity.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        identity.extend_from_slice(&bytes);
    }
    for (command, args) in [
        ("/usr/bin/xcrun", vec!["--show-sdk-version"]),
        ("/usr/bin/clang", vec!["--version"]),
        ("rustc", vec!["--version"]),
    ] {
        let output = std::process::Command::new(command)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        identity.extend_from_slice(&output.stdout);
    }
    let mut hasher = std::process::Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    hasher.stdin.take().unwrap().write_all(&identity).unwrap();
    let output = hasher.wait_with_output().unwrap();
    assert!(output.status.success());
    let digest = String::from_utf8(output.stdout).unwrap();
    let digest = digest.split_whitespace().next().unwrap();
    assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
    println!("cargo:rustc-env=HVF_BUILD_ID={digest}");
    let files = [
        "native/probe.c",
        "native/devices.c",
        "native/net.c",
        "native/net_backend_slirp.c",
        "native/net_backend_ipc.c",
        "native/input.c",
        "native/policy.c",
        "native/sandbox.c",
        "native/socket_gate.c",
    ];
    for f in files.iter().chain(
        [
            "native/hvf.h",
            "native/budget.h",
            "native/control.h",
            "native/cpu_snapshot.h",
            "native/snapshot_io.h",
            "native/devices.h",
            "native/net.h",
            "native/net_backend.h",
            "native/net_backend_stream.h",
            "native/input.h",
        ]
        .iter(),
    ) {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-env-changed=GLIB_PREFIX");
    println!("cargo:rerun-if-changed=vendor/libslirp");
    println!("cargo:rerun-if-changed=native/slirp_policy.h");
    println!("cargo:rerun-if-changed=native/policy.h");
    println!("cargo:rerun-if-changed=native/seatbelt.h");
    println!("cargo:rerun-if-changed=native/socket_gate.h");
    let prefix = std::env::var("GLIB_PREFIX").unwrap_or_else(|_| "/opt/homebrew/opt/glib".into());
    cc::Build::new()
        .files(files)
        .include("vendor/libslirp/src")
        .flag("-std=c11")
        .flag("-D_DARWIN_C_SOURCE")
        .warnings(true)
        .flag("-mmacosx-version-min=26.0")
        .compile("generic_hvf");
    let mut slirp = cc::Build::new();
    let mut sources: Vec<_> = std::fs::read_dir("vendor/libslirp/src")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .collect();
    sources.sort();
    slirp
        .files(sources)
        .include("vendor/libslirp/src")
        .include(format!("{prefix}/include/glib-2.0"))
        .include(format!("{prefix}/lib/glib-2.0/include"))
        .flag("-std=gnu99")
        .flag("-D_DARWIN_C_SOURCE")
        .define("G_LOG_DOMAIN", "\"Slirp\"")
        .define("BUILDING_LIBSLIRP", None)
        .flag("-include")
        .flag("native/slirp_policy.h")
        .extra_warnings(false)
        .flag("-mmacosx-version-min=26.0")
        .compile("hvf_slirp");
    println!("cargo:rustc-link-search=native={prefix}/lib");
    println!("cargo:rustc-link-lib=dylib=glib-2.0");
    println!("cargo:rustc-link-lib=resolv");
    println!("cargo:rustc-link-lib=framework=Hypervisor");
}
