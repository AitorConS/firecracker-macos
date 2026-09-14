#!/bin/sh
# Tests that do not create an HVF VM, suitable for hosted macOS runners.
set -eu
cd "$(dirname "$0")/../../.."
if ! command -v cargo >/dev/null 2>&1; then
    export RUSTUP_HOME="$PWD/experiments/hvf/build/rustup"
    export CARGO_HOME="$PWD/experiments/hvf/build/cargo"
    export PATH="$CARGO_HOME/bin:$PATH"
fi
export RUSTUP_TOOLCHAIN=1.97.0
export MACOSX_DEPLOYMENT_TARGET=26.0
export SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path)}"
export FUZZ_CC="${FUZZ_CC:-$(brew --prefix llvm)/bin/clang}"
sh experiments/hvf/build-native.sh
cargo test --locked -p hvf-vmm --target aarch64-apple-darwin
cargo clippy --locked -p hvf-vmm -p firecracker --target aarch64-apple-darwin -- -D warnings
sh experiments/hvf/test-device-faults.sh
