#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
mkdir -p experiments/hvf/build
xcrun clang -arch arm64 -mmacosx-version-min=15.0 -Wall -Wextra -Werror -O2 \
    -Isrc/hvf-vmm/native experiments/hvf/device-test.c src/hvf-vmm/native/devices.c \
    -framework Hypervisor -o experiments/hvf/build/device-test
codesign --force --sign - --entitlements experiments/hvf/entitlements.plist experiments/hvf/build/device-test
for test in read write readonly unknown oob cycle short-header malformed-tail firmware; do
    expected=0
    case "$test" in oob|cycle|short-header|malformed-tail) expected=2;; esac
    actual=0
    experiments/hvf/build/device-test "$test" || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        echo "FAIL: $test returned $actual, expected $expected" >&2
        exit 1
    fi
    echo "PASS: block $test"
done
