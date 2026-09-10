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
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"
experiments/hvf/build-native.sh
cargo test -p hvf-vmm --target aarch64-apple-darwin
cargo clippy -p hvf-vmm -p firecracker --target aarch64-apple-darwin -- -D warnings
experiments/hvf/build.sh
python3 -m unittest discover -s experiments/hvf -v
sh experiments/hvf/test-devices.sh
if [ "${1:-}" != "--unit-only" ]; then
    python3 experiments/hvf/guests/linux/prepare.py
    python3 experiments/hvf/test-linux.py
fi
git -c core.whitespace=cr-at-eol diff --check
