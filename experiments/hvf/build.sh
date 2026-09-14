#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build/slirp-objects
native=../../src/hvf-vmm/native
slirp=../../src/hvf-vmm/vendor/libslirp/src
glib=${GLIB_PREFIX:-/opt/homebrew/opt/glib}
for source in "$slirp"/*.c; do
    xcrun clang -arch arm64 -mmacosx-version-min=26.0 -O2 -std=gnu99 -D_DARWIN_C_SOURCE -DBUILDING_LIBSLIRP '-DG_LOG_DOMAIN="Slirp"' \
        -I"$slirp" -I"$glib/include/glib-2.0" -I"$glib/lib/glib-2.0/include" -include "$native/slirp_policy.h" \
        -c "$source" -o "build/slirp-objects/$(basename "$source" .c).o"
done
xcrun clang -arch arm64 -mmacosx-version-min=26.0 -Wall -Wextra -Werror -O2 \
    -DHVF_STANDALONE "$native/probe.c" "$native/devices.c" "$native/input.c" "$native/net.c" \
    "$native/net_backend_slirp.c" "$native/net_backend_ipc.c" "$native/policy.c" "$native/socket_gate.c" "$native/sandbox.c" \
    -I"$slirp" build/slirp-objects/*.o -L"$glib/lib" -lglib-2.0 -lresolv -framework Hypervisor -o build/hvf-probe
codesign --force --sign - --entitlements entitlements.plist build/hvf-probe
