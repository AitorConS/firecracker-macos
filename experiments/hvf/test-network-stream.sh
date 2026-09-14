#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
output=$(mktemp -d "$root/experiments/hvf/build/stream-tests.XXXXXX")
xcrun clang -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -I src/hvf-vmm/native experiments/hvf/test-network-stream.c -o "$output/transport"
"$output/transport"
xcrun clang -Wall -Wextra -Werror -I src/hvf-vmm/native \
  experiments/hvf/test-security-stream.c src/hvf-vmm/native/sandbox.c -o "$output/security"
"$output/security"
echo "Stream test binaries: $output"
