#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
output=$(mktemp -d "$root/experiments/hvf/build/net-offload.XXXXXX")
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -g -I src/hvf-vmm/native \
  experiments/hvf/test-net-offload.c src/hvf-vmm/native/net.c src/hvf-vmm/native/net_peer.c src/hvf-vmm/native/net_gso.c -o "$output/test-net-offload"
"$output/test-net-offload"
echo "Offload device test binary: $output/test-net-offload"
