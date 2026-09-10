// SPDX-License-Identifier: Apache-2.0
#[cfg(target_os = "linux")]
include!("main_linux.rs");

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> std::process::ExitCode {
    hvf_vmm::main_entry(env!("CARGO_PKG_VERSION"))
}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
compile_error!("Firecracker requires Linux or the experimental macOS ARM64 backend");
