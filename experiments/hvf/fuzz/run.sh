#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
clang=${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}
if [ ! -x "$clang" ]; then
    echo "Install LLVM with libFuzzer (brew install llvm), or set FUZZ_CC" >&2
    exit 1
fi
out=experiments/hvf/build/fuzz
mkdir -p "$out/corpus" "$out/artifacts"
for source in devices net input; do
    "$clang" -g -O1 -Wall -Wextra -Werror -fsanitize=fuzzer-no-link,address,undefined \
        -Iexperiments/hvf/fuzz/stubs -Isrc/hvf-vmm/native -include experiments/hvf/fuzz/hooks.h \
        -c "src/hvf-vmm/native/$source.c" -o "$out/$source.o"
done
"$clang" -g -O1 -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined \
    -Isrc/hvf-vmm/native experiments/hvf/fuzz/devices.c "$out/devices.o" "$out/net.o" "$out/input.o" -o "$out/device-fuzzer"
cp experiments/hvf/fuzz/corpus/* "$out/corpus/"
python3 - <<'PY'
from pathlib import Path
p=Path('experiments/hvf/build/fuzz/corpus')
for target in range(5):
    for mode in range(4):
        (p/f'seed-{target}-{mode}').write_bytes(bytes([target,mode]))
PY
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$out/device-fuzzer" \
    "$out/corpus" -artifact_prefix="$out/artifacts/" -max_len=4098 -timeout=5 -rss_limit_mb=0 -malloc_limit_mb=256 -seed=20260911 -max_total_time="${FUZZ_SECONDS:-60}" "$@"
