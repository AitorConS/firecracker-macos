#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
output=$(mktemp -d "$root/experiments/hvf/build/net-rx.XXXXXX")
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -g -I src/hvf-vmm/native \
  experiments/hvf/test-net-rx.c -o "$output/test-net-rx"
ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$output/test-net-rx"
echo "Virtio-net RX test binary: $output/test-net-rx"
