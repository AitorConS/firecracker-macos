#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
clang=${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}
out=experiments/hvf/build/fuzz-control
mkdir -p "$out/corpus" "$out/artifacts"
"$clang" -g -O1 -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined \
    -Isrc/hvf-vmm/native experiments/hvf/fuzz/control.c -o "$out/control-fuzzer"
python3 - <<'PY'
from pathlib import Path
Path('experiments/hvf/build/fuzz-control/corpus/ready').write_bytes(b'HVFC\x01R\0\0'+(1).to_bytes(8,'little'))
PY
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$out/control-fuzzer" \
    "$out/corpus" -artifact_prefix="$out/artifacts/" -max_len=4096 -timeout=5 \
    -rss_limit_mb=0 -malloc_limit_mb=256 -seed=20260911 -max_total_time="${FUZZ_SECONDS:-60}" "$@"
