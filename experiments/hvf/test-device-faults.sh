#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
clang=${FUZZ_CC:-/opt/homebrew/opt/llvm/bin/clang}
build=experiments/hvf/build
mkdir -p "$build/device-fault-mutants"
compile() { # output [extra flags]
    out=$1; shift
    "$clang" -g -O1 -Wall -Wextra -Werror -fsanitize=address,undefined -pthread "$@" \
        -Iexperiments/hvf/fuzz/stubs -Isrc/hvf-vmm/native experiments/hvf/device-fault-test.c -o "$out"
}
run_case() { ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$@"; }
cases="advertised-segments short-read short-write vector-read vector-write vector-short-read vector-short-write
vector-range write-eintr descriptor-edit io-error no-space eof flush-error
flush-unsupported flush-eintr flush-success flush-sticky ordering overlap flush-readonly
snapshot-latched close-flush close-latched"
compile "$build/device-fault-test"
for test in $cases; do
    run_case "$build/device-fault-test" "$test"
done
# Randomized ordering stress: many seeds, completions in any order.
for seed in $(seq 1 ${STRESS_SEEDS:-200}); do
    STRESS_SEED=$seed run_case "$build/device-fault-test" stress >/dev/null || { echo "FAIL stress seed $seed" >&2; exit 1; }
done
echo "PASS stress ${STRESS_SEEDS:-200} seeds"
# Host writeback pacing, with a small threshold so a test reaches it.
compile "$build/device-fault-test-pace" -DPACE_BYTES=1024
for test in pace pace-error flush-success io-error; do
    run_case "$build/device-fault-test-pace" "$test"
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
    compile "$build/device-fault-mutants/$name" "-DDEVICES_C=\"$src\"" ${MUTANT_FLAGS:-}
    if run_case "$build/device-fault-mutants/$name" "$case" >"$build/device-fault-mutants/$name.log" 2>&1; then
        echo "FAIL mutant $name survived case $case" >&2; exit 1
    fi
    echo "PASS mutant $name detected by $case"
}
mutant no-latch-flush flush-sticky 's/if(__atomic_load_n(\&block->storage_errno,__ATOMIC_SEQ_CST))q->result=1;/if(0)q->result=1;/'
mutant no-latch-write io-error 's/if(__atomic_load_n(\&block->storage_errno,__ATOMIC_SEQ_CST))q->result=1;/if(0)q->result=1;/'
mutant fsync-fallback flush-unsupported 's/} while (result == -1 \&\& errno == EINTR);/} while (result == -1 \&\& errno == EINTR); if(result==-1)result=fsync(fd);/'
mutant flush-ignored flush-error 's/else if(flush_disk(block->diskfd)){q->result=1;latch_storage_error(block,errno);}/else {}/'
mutant publish-before-flush ordering 's/^        perform(block,q);$/        if(q->type==4){pthread_mutex_lock(\&io_lock);*q->status_byte=0;pthread_mutex_unlock(\&io_lock);} perform(block,q);/'
mutant no-flush-barrier ordering 's/            block->flushing=1;/            block->flushing=0;/'
mutant no-overlap-order overlap 's/while(overlaps(block,q,self))pthread_cond_wait/while(0 \&\& overlaps(block,q,self))pthread_cond_wait/'
mutant no-close-flush close-flush 's/else if(flush_disk(b->diskfd))fprintf/else if(0)fprintf/'
MUTANT_FLAGS=-DPACE_BYTES=1024 mutant pace-error-ignored pace-error 's/if(result)latch_storage_error(block,errno);/if(0)latch_storage_error(block,errno);/'
