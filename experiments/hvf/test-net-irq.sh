#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
output=$(mktemp -d "$root/experiments/hvf/build/net-irq.XXXXXX")
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -g -I src/hvf-vmm/native \
  experiments/hvf/test-net-irq.c src/hvf-vmm/native/net.c -o "$output/test-net-irq"
"$output/test-net-irq"
echo "Virtio-net interrupt test binary: $output/test-net-irq"
