#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
output=$(mktemp -d "$root/experiments/hvf/build/policy-egress.XXXXXX")
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -g -I src/hvf-vmm/native \
  experiments/hvf/test-policy-egress.c src/hvf-vmm/native/policy.c src/hvf-vmm/native/socket_gate.c \
  src/hvf-vmm/native/sandbox.c -o "$output/test-policy-egress"
"$output/test-policy-egress"
