#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
mkdir -p experiments/hvf/build/ci
sudo -n python3 experiments/hvf/ci/preflight.py kvm > experiments/hvf/build/ci/availability.json
export RUSTUP_TOOLCHAIN=1.97.0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
cargo test --locked --release --target x86_64-unknown-linux-gnu -p vmm -p firecracker --no-run > experiments/hvf/build/ci/kvm-build.log 2>&1
python3 experiments/hvf/guests/kvm/run-units.py --source "$PWD" --build-log experiments/hvf/build/ci/kvm-build.log --output experiments/hvf/build/ci/kvm-units
