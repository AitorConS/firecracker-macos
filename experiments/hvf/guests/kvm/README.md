# Linux x86_64 guest for KVM validation

This smoke test uses the original Linux backend and generic tooling. It does not use HVF,
Jerboa, or QEMU. It requires Linux x86_64 with `/dev/kvm`, GCC, a static BusyBox,
Python 3, `ip`, `unshare`, and a Firecracker-compatible vmlinux kernel with built-in
VirtIO MMIO, block, and networking. `prepare.py` rejects dynamically linked BusyBox.

```sh
python3 experiments/hvf/guests/kvm/prepare.py --output /path/validation/guest
# Place the provided kernel at /path/validation/vmlinux.
sudo unshare --net python3 experiments/hvf/guests/kvm/smoke.py \
  --work /path/validation \
  --binary /path/firecracker/build/cargo_target/release/firecracker
```

The network namespace is mandatory: the script rejects the host namespace.
It creates a temporary TAP and uses 192.0.2.0/30 only inside the namespace; it does not configure
NAT, host routes, or public ports. The TAP and VM processes are removed in
`finally`. Disks, configurations, and logs are kept in the validation
directory for test review. Use a dedicated directory: the script creates
its own `kvm-disk-1.raw` and `kvm-disk-2.raw` from scratch.

The test boots Linux with 1 and 2 vCPUs, twice per disk, checks the counter
persisted with fsync, 4 MiB of HTTP per boot, UDP echo, and guest-requested exit via HTTP (`/exit`). After syncing,
the guest calls reboot with `reboot=k`: Firecracker's i8042 turns the
reset into VM exit. It is not presented as ACPI poweroff support. It saves `logs/smoke-result.json`. The guest C server is a
minimal test fixture, not a production service.

Building Firecracker and running its unit tests are separate checks. A
GNU build may use the empty seccomp filter advertised by upstream: this test
does not validate the jailer, production isolation, or musl distribution. Nor does it
validate KVM ARM64, snapshots, or full parity between KVM and HVF.

With the CI kernel 6.1.102 used in this validation, RB_POWER_OFF leaves the guest at
"System halted" and does not terminate the VMM process. That limitation is preserved; the
upstream backend has not been changed to hide it.

For the upstream tests, first build the executables and then run them in
private namespaces (the build runs as a regular user, the tests require sudo):

```sh
cargo test --release --locked -p vmm -p firecracker --no-run > /path/test-build.log 2>&1
python3 experiments/hvf/guests/kvm/run-units.py --source "$PWD" \
  --build-log /path/test-build.log --output /path/unit-results
```

The runner keeps every result, including failures; it limits each binary to ten
minutes and reaps its process group on timeout. The build requires
the libseccomp development link in addition to Rust and GCC. On the tested host,
the already installed library was used via a link inside the private directory
and `LIBRARY_PATH`, without installing packages or modifying the user's groups.

## Local result from 2026-09-11

Ubuntu 26.04 host, kernel 7.0.0-28, x86_64 virtualized on KVM. KVM API 12.
The fork at commit 9dbd17b05 builds and passes four boots, disk persistence,
16 MiB of total HTTP and UDP. `cc = "1.2"` was fixed to `cc = "1.2.0"` in hvf-vmm
to comply with the dependency policy; the allowed range is unchanged.

Results for the seven test executables, including the dependency-policy retry: **993 passed, 3 failed, none ignored**. The three
failures were reproduced separately and remain open:

- `arch::x86_64::vcpu::tests::test_set_tsc`: the test expects an error when TscControl
  is not advertised, but the SET of the requested frequency returns success.
- `test_build_and_boot_microvm` and `test_build_microvm`: after a call to
  `run_with_timeout(500)`, the exit status is still None, not Some(Ok).

The two upstream files containing these tests are identical to those at
base 16f9023f8; their assertions have not been changed nor have tests been marked as ignored.
That alone does not prove the cause nor substitute for running an independent upstream
build. The whole suite is not declared green nor is KVM ARM64 declared validated.

Logs, kernel URL/SHA256, executable hash, and full results:
`experiments/hvf/build/kvm-validation/verification.json`. The runner's first failure due to a missing CARGO_MANIFEST_DIR was fixed by replicating the working
directory and that Cargo variable when running each test under sudo.

## Independent comparison and closure of the three failures

During implementation, upstream 16f9023f8 was built in its own directory
with Rust 1.97.0, GNU release, and its original lockfile. Its suite reproduced
**993 passed/3 failed/0 ignored**. The fixed fork's suite achieves
**996 passed/0 failed/0 ignored**, without removing tests or exit assertions.
Each fixed case additionally passed three isolated repetitions.

`strace` identifies EPOLLHUP on stdin as the first event in both trees.
The tests now wait for the terminal status during the original total deadline of
500 ms. `tsc-probe.c` shows that the ioctl allows raising the TSC without TscControl
(software catchup); the test requires success and correct readback for the increase and
error for halving it without scaling. See the implementation log
for exact values and the reference to the Linux code.

The compared logs, results, and hashes are in
`experiments/hvf/build/kvm-validation/comparison/comparison.json`. Validation
remains limited to nested KVM x86_64 and does not test jailer/musl or KVM ARM64.
