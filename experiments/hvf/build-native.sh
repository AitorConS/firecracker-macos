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
# The HVF backend and pinned native dependencies target macOS 26.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
cargo build --locked -p firecracker --target aarch64-apple-darwin --release
output=${HVF_OUTPUT_DIR:-build/macos-arm64}
target=${CARGO_TARGET_DIR:-build/cargo_target}
mkdir -p "$output"
cp "$target/aarch64-apple-darwin/release/firecracker" "$output/firecracker"
codesign --force --sign - --entitlements experiments/hvf/entitlements.plist "$output/firecracker"
file "$output/firecracker"
