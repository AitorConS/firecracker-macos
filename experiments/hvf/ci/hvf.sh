#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
mkdir -p experiments/hvf/build/ci
python3 experiments/hvf/ci/preflight.py hvf > experiments/hvf/build/ci/availability.json
python3 experiments/hvf/distribution/build-native-deps.py
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
experiments/hvf/test-native.sh --unit-only
if [ "${HVF_USE_CACHED_GUEST:-0}" != 1 ]; then
    python3 experiments/hvf/guests/linux/prepare.py
    python3 experiments/hvf/guests/debian/prepare.py
fi
python3 experiments/hvf/test-linux.py
python3 experiments/hvf/test-linux.py --config build/debian-guest/config.json
python3 experiments/hvf/test-snapshot-linux.py --config build/linux-guest/config.json --output-prefix experiments/hvf/build/ci/alpine-snapshot
python3 experiments/hvf/test-snapshot-linux.py --config build/debian-guest/config.json --output-prefix experiments/hvf/build/ci/debian-snapshot
python3 experiments/hvf/test-security-linux.py
python3 experiments/hvf/test-io-limits.py
python3 experiments/hvf/lifecycle-cycles.py --network --cycles 100 --output experiments/hvf/build/ci/network-cycles.json
sh experiments/hvf/fuzz/run.sh
sh experiments/hvf/fuzz/run-control.sh
sh experiments/hvf/fuzz/run-slirp.sh
# The 24h campaign is explicit, never inferred from short CI smoke results.
if [ "${HVF_RUN_24H:-0}" = 1 ]; then
    python3 experiments/hvf/soak.py --config build/linux-guest/config.json --output experiments/hvf/build/ci/soak-24h
fi
