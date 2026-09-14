#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
xcrun clang -Wall -Wextra -Werror -O2 -mmacosx-version-min=26.0 -Isrc/hvf-vmm/native \
    experiments/hvf/test-security.c src/hvf-vmm/native/policy.c src/hvf-vmm/native/socket_gate.c \
    src/hvf-vmm/native/sandbox.c -o experiments/hvf/build/test-security
experiments/hvf/build/test-security

xcrun clang -Wall -Wextra -Werror -O2 -mmacosx-version-min=26.0 -Isrc/hvf-vmm/native \
    experiments/hvf/test-security-port0.c src/hvf-vmm/native/policy.c src/hvf-vmm/native/socket_gate.c \
    src/hvf-vmm/native/sandbox.c -o experiments/hvf/build/test-security-port0
experiments/hvf/build/test-security-port0
experiments/hvf/build/test-security-port0 --wildcard

xcrun clang -Wall -Wextra -Werror -O2 -Isrc/hvf-vmm/native experiments/hvf/test-budget.c -o experiments/hvf/build/test-budget
experiments/hvf/build/test-budget

GLIB_PREFIX=${GLIB_PREFIX:-/opt/homebrew}
xcrun clang -Wall -Wextra -Werror -O2 \
    -I"$GLIB_PREFIX/include/glib-2.0" -I"$GLIB_PREFIX/lib/glib-2.0/include" \
    -Isrc/hvf-vmm/vendor/libslirp/src -Isrc/hvf-vmm/vendor/libslirp \
    experiments/hvf/test-slirp-align.c -o experiments/hvf/build/test-slirp-align
experiments/hvf/build/test-slirp-align
