#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
clang=${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}
glib=${GLIB_PREFIX:-/opt/homebrew/opt/glib}
slirp=src/hvf-vmm/vendor/libslirp/src
native=src/hvf-vmm/native
out=experiments/hvf/build/fuzz-slirp
mkdir -p "$out/objects" "$out/corpus" "$out/artifacts"
for source in "$slirp"/*.c; do
    "$clang" -g -O1 -std=gnu99 -D_DARWIN_C_SOURCE -DBUILDING_LIBSLIRP '-DG_LOG_DOMAIN="Slirp"' \
        -fsanitize=fuzzer-no-link,address,undefined -I"$slirp" -I"$glib/include/glib-2.0" -I"$glib/lib/glib-2.0/include" \
        -include "$native/slirp_policy.h" -c "$source" -o "$out/objects/$(basename "$source" .c).o"
done
"$clang" -g -O1 -Wall -Wextra -Werror -mmacosx-version-min=26.0 -fsanitize=fuzzer,address,undefined \
    -I"$native" -I"$slirp" experiments/hvf/fuzz/slirp.c "$native/net_backend_slirp.c" "$native/policy.c" \
    "$native/socket_gate.c" "$native/sandbox.c" "$out"/objects/*.o -L"$glib/lib" -lglib-2.0 -lresolv -o "$out/slirp-fuzzer"
cp experiments/hvf/fuzz/slirp-corpus/* "$out/corpus/"
python3 - <<'PY'
from pathlib import Path
p=Path('experiments/hvf/build/fuzz-slirp/corpus')
(p/'arp').write_bytes(bytes.fromhex('ffffffffffff525400123456080600010800060400015254001234560a00020f0000000000000a000202'))
(p/'ipv4').write_bytes(bytes.fromhex('525400123456525400abcdef08004500001c00000000401100000a00020f0a00020204d2003500080000'))
PY
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$out/slirp-fuzzer" "$out/corpus" \
    -artifact_prefix="$out/artifacts/" -max_len=65536 -timeout=5 -rss_limit_mb=0 -malloc_limit_mb=256 \
    -seed=20260911 -max_total_time="${FUZZ_SECONDS:-60}" "$@"
