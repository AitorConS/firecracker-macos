# Device fuzzing

`experiments/hvf/fuzz/run.sh` builds the real C devices with LLVM/libFuzzer, ASan and UBSan. It requires `brew install llvm`; `FUZZ_CC` accepts another clang with the runtimes. `FUZZ_SECONDS` changes the default 60 s. The growing corpus, logs and crashes remain under `experiments/hvf/build/fuzz`; regression cases are kept in `fuzz/corpus` and are always included.

The harness sets up valid block, TX/RX and input queues, mutates descriptors, rings and buffers, and performs ECAM, BAR and fw_cfg accesses with architectural sizes. It uses production code for DMA, validation and completion. It only replaces HVF/GIC and the host network transport; it does not test libslirp or concurrency with vCPU. Rejections that in production terminate the VM with exit code 2 return to the harness via longjmp. Aborts and sanitizer reports are not intercepted. Each case has clean RAM/device state, a private temporary disk and a maximum of 1024 mutations and 64 MMIO accesses. The real quotas limit the queues.

The first campaign detected an out-of-object intermediate pointer calculation in the input config read (`config + off - 0x100`). It was fixed to `config + (off - 0x100)` and the equivalent expression in the network MAC was fixed. The file `corpus/input-config-pointer` reproduces the original finding. A finite campaign with no new findings does not constitute a security audit or proof of absence of bugs.

LLVM 23/macOS reported 56 bytes when closing libFuzzer's detached RSS monitoring thread, with a stack in `fuzzer::StartRssThread` and no VMM frames. `-rss_limit_mb=0` is used to avoid creating that thread, keeping LeakSanitizer active and the per-allocation limit at 256 MiB. There is no global RSS limit in this campaign. Source: [LLVM StartRssThread implementation](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerDriver.cpp).

Local final campaign (2026-09-11): 4,912,942 cases in 61 s, exit code 0, with no new ASan/UBSan/LeakSanitizer reports. Log: `build/fuzz-final.log` relative to `experiments/hvf`.

## Control protocol

`sh experiments/hvf/fuzz/run-control.sh` tests the real parser and emitter from `native/control.h` via socket pairs: fragmentation, concatenation, invalid version/magic, partial EOF and 64-bit identifiers. The corpus and artifacts remain in `build/fuzz-control`. It uses the same sanitizer configuration and avoids the RSS thread described above; it does not suppress LeakSanitizer. The Rust HTTP parser also has a deterministic mutation campaign: `HVF_FUZZ_CASES=1000000 cargo test --locked -p hvf-vmm mutation_campaign_bounded_requests`. This campaign validates the parser limits; the C sanitizers apply to the other targets, not to the Rust test.

## Vendored libslirp

`sh experiments/hvf/fuzz/run-slirp.sh` builds libslirp 4.9.4 and the adapters with ASan/UBSan/libFuzzer. It uses the same mandatory socket-policy inclusions as the product, with no authorized egress/DNS/listeners. Each input creates, processes and destroys a stack; the local GLib is still not instrumented. This target does not replace IPC authority fuzzing or testing with active permissions.

First campaign: 2,502,154 inputs in 61 seconds with no sanitizer reports; evidence in `build/slirp-fuzz.log`. The device campaign after copying and validating full strings ran 4,798,923 inputs/61 s (`build/resources-fuzz.log`).

## Implementation closure and snapshots

The device target also deserializes block, network and input state via the production snapshot reader, using bounded memory inputs. The manifest, its hashes and the registers/GIC are tested separately with HVF restores and deliberate corruption in `test_snapshot.py`.

600-second campaigns completed on 2026-09-12:
- Devices: 34,717,374 inputs/601 s (`build/final-device-fuzz.log`).
- Control: 25,897,533 inputs/601 s (`build/final-control-fuzz.log`).
- HTTP: one million mutations (`build/final-http-mutation.log`).

The first extended libslirp campaign found arithmetic on NULL in `ip_reass` when the first IPv4 fragment arrived. The patch computes container_of only when a queue already exists; it preserves the new-queue creation flow. `slirp-corpus/ipv4-first-fragment-null-queue` preserves the input and is included on every run. The original file and the UBSan report remain in `build/final-slirp-fuzz.log`; the rerun is in `build/final-slirp-fuzz-fixed.log`. That rerun found a different ASan heap-buffer-overflow in `ncsi_rsp_handler_oem` (`vendor/libslirp/src/ncsi.c:136`): a 31-byte packet declared a truncated OEM payload and the function read four vendor bytes where only one remained. Validation now checks the declared payload, the bytes actually available, and the OEM/Mellanox minimums. `slirp-corpus/ncsi-oem-truncated-payload` preserves the case as a regression.
