#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror -O2 \
    -DHVF_STANDALONE ../../src/hvf-vmm/native/probe.c ../../src/hvf-vmm/native/devices.c ../../src/hvf-vmm/native/input.c ../../src/hvf-vmm/native/net.c ../../src/hvf-vmm/native/net_backend_slirp.c -I/opt/homebrew/include -L/opt/homebrew/lib -lslirp -framework Hypervisor -o build/hvf-probe
codesign --force --sign - --entitlements entitlements.plist build/hvf-probe
