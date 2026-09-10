// SPDX-License-Identifier: Apache-2.0
#[cfg(target_os = "linux")]
include!("build_linux.rs");

#[cfg(not(target_os = "linux"))]
fn main() {
    assert_eq!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("macos"),
        "Linux Firecracker seccomp filters must be built on a Linux host");
}
