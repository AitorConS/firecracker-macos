#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
output=$(mktemp -d "$root/experiments/hvf/build/block-irq.XXXXXX")
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -g -I src/hvf-vmm/native \
  experiments/hvf/test-block-irq.c src/hvf-vmm/native/devices.c -o "$output/test-block-irq"
"$output/test-block-irq"
echo "Virtio-block interrupt test binary: $output/test-block-irq"
