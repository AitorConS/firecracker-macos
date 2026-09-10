// SPDX-License-Identifier: Apache-2.0
fn main() {
    // The workspace includes this crate on Linux too. It is an empty library
    // there; only the Darwin executable selects and links the native backend.
    if std::env::var("TARGET").unwrap() != "aarch64-apple-darwin" {
        return;
    }
    let files = [
        "native/probe.c",
        "native/devices.c",
        "native/net.c",
        "native/net_backend_slirp.c",
        "native/input.c",
    ];
    for f in files.iter().chain(
        [
            "native/hvf.h",
            "native/devices.h",
            "native/net.h",
            "native/net_backend.h",
            "native/input.h",
        ]
        .iter(),
    ) {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-env-changed=SLIRP_PREFIX");
    let prefix = std::env::var("SLIRP_PREFIX").unwrap_or_else(|_| "/opt/homebrew".into());
    cc::Build::new()
        .files(files)
        .include(format!("{prefix}/include"))
        .flag("-std=c11")
        .flag("-D_DARWIN_C_SOURCE")
        .warnings(true)
        .flag("-mmacosx-version-min=15.0")
        .compile("generic_hvf");
    println!("cargo:rustc-link-search=native={prefix}/lib");
    println!("cargo:rustc-link-lib=dylib=slirp");
    println!("cargo:rustc-link-lib=framework=Hypervisor");
}
