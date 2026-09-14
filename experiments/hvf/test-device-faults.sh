#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
clang=${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}
build=experiments/hvf/build
mkdir -p "$build/device-fault-mutants"
compile() { # output [extra flags]
    out=$1; shift
    "$clang" -g -O1 -Wall -Wextra -Werror -fsanitize=address,undefined "$@" \
        -Iexperiments/hvf/fuzz/stubs -Isrc/hvf-vmm/native experiments/hvf/device-fault-test.c -o "$out"
}
run_case() { ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$@"; }
cases="short-read short-write write-eintr descriptor-edit io-error no-space eof flush-error
flush-unsupported flush-eintr flush-success flush-sticky ordering flush-readonly
snapshot-latched close-flush close-latched"
compile "$build/device-fault-test"
for test in $cases; do
    run_case "$build/device-fault-test" "$test"
done

# Negative controls: each mutant reintroduces one durability bug; the named
# case must detect it. A surviving mutant means the test lost its power.
mutant() { # name case sed-expression
    name=$1 case=$2 expr=$3
    src=$PWD/$build/device-fault-mutants/$name.c
    sed "$expr" src/hvf-vmm/native/devices.c >"$src"
    if cmp -s src/hvf-vmm/native/devices.c "$src"; then
        echo "FAIL mutant $name did not change devices.c" >&2; exit 1
    fi
    compile "$build/device-fault-mutants/$name" "-DDEVICES_C=\"$src\""
    if run_case "$build/device-fault-mutants/$name" "$case" >"$build/device-fault-mutants/$name.log" 2>&1; then
        echo "FAIL mutant $name survived case $case" >&2; exit 1
    fi
    echo "PASS mutant $name detected by $case"
}
mutant no-latch-flush flush-sticky 's/if(block->storage_errno)result=1;/if(0)result=1;/'
mutant no-latch-write io-error 's/if(block->storage_errno)result=1;/if(0)result=1;/'
mutant fsync-fallback flush-unsupported 's/} while (result == -1 \&\& errno == EINTR);/} while (result == -1 \&\& errno == EINTR); if(result==-1)result=fsync(fd);/'
mutant flush-ignored flush-error 's/else if(flush_disk(block->diskfd)){result=1;latch_storage_error(block,errno);}/else {}/'
mutant publish-before-flush ordering 's/        if(type==4 \&\& !block->read_only){/        if(type==4){*status_byte=0;put(guest(used+2,2),2,(uint16_t)(block->used_idx+1));} if(type==4 \&\& !block->read_only){/'
mutant no-close-flush close-flush 's/else if(flush_disk(b->diskfd))fprintf/else if(0)fprintf/'
