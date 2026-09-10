#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
if ! command -v cargo >/dev/null 2>&1; then
    export RUSTUP_HOME="$root/experiments/hvf/build/rustup"
    export CARGO_HOME="$root/experiments/hvf/build/cargo"
    export PATH="$CARGO_HOME/bin:/opt/homebrew/bin:$PATH"
fi
export RUSTUP_TOOLCHAIN=1.97.0
# The currently validated libslirp Homebrew build requires macOS 26.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
cargo build -p firecracker --target aarch64-apple-darwin --release
mkdir -p build/macos-arm64
cp build/cargo_target/aarch64-apple-darwin/release/firecracker build/macos-arm64/firecracker
codesign --force --sign - --entitlements experiments/hvf/entitlements.plist build/macos-arm64/firecracker
file build/macos-arm64/firecracker
