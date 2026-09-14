# Generic macOS ARM64 VMM / Hypervisor.framework

This local Firecracker fork runs ARM64 guests via HVF. The first
standalone milestone is implemented: ARM64 Linux with initramfs, VirtIO disk and networking,
using exclusively the fork, generic tools and public
Alpine artifacts. No other repositories are needed to build, configure or test
the VMM. Networking supports slirp and a generic Unix Ethernet transport described in
[UNIX_STREAM.md](UNIX_STREAM.md). The full 24-hour campaign, other Macs and
certification via power cuts remain outside local validation.

The Darwin target uses `src/hvf-vmm`: configuration, loaders and API in Rust;
HVF, PCI/VirtIO and slirp transport in C. It remains a new experimental backend,
not a complete abstraction of the upstream Linux VMM. The
security, snapshot and Firecracker Linux API guarantees do not carry over automatically.

## Build and demonstrate the milestone

Tested host: macOS 26.6.2 ARM64. The product requires macOS 26 and Apple Silicon
with Hypervisor available. No chip/version matrix has been certified.

Tools: Xcode Command Line Tools, Rust 1.97.0 and Python 3. Native
dependencies are built into a private prefix from sources with pinned SHA-256.
The package bundles its libraries and does not need Homebrew to run.
Generating Alpine requires the `unsquashfs` extractor pinned in
`guests/linux/tools.json`; Debian uses the macOS `bsdtar` registered there.
Go 1.26.0 is downloaded with checksum and installed into the private build directory.
LLVM with libFuzzer is only needed for fuzzing. QEMU is not a dependency.

```sh
python3 experiments/hvf/distribution/build-native-deps.py
GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native" experiments/hvf/build-native.sh
python3 experiments/hvf/guests/linux/prepare.py
python3 experiments/hvf/guests/debian/prepare.py
build/macos-arm64/firecracker --no-api --config-file build/linux-guest/config.json
```

In another terminal:

```sh
curl http://127.0.0.1:19000/
curl http://127.0.0.1:19000/shutdown
```

The response identifies Linux, ARM64, four CPUs, the configured MAC and a persistent
counter. The guest verifies a disk marker, reads/increments a counter
via `/dev/vda`, fsyncs and serves TCP 9000 and UDP 9001. Host ports
are 19000 and 19001. The VMM does not interpret disk contents nor know
a filesystem. The example preserves `disk.raw` when preparation is repeated.

`prepare.py` downloads Alpine 3.23.5 kernel/initramfs from versioned URLs and
checks the SHA-256 in `guests/linux/assets.json`. It extracts the Image from the
EFI zboot container **in the guest tool**, adds a small Go program and generates
a newc initramfs with normalized ownership, timestamps and inodes. It does not patch the
Linux kernel. Use `--go /path/go` or `GO` to select an external Go.

The build uses Cargo from PATH or the isolated toolchain in `experiments/hvf/build`.
`GLIB_PREFIX` selects the private dependencies; libslirp is vendored
with its authorization patch. The binary is ad-hoc signed with Hypervisor
entitlement. See [distribution and optional notarization](distribution/README.md).
Each preparation records tool and Image/initrd hashes in
`provenance.json`. Changing extractors requires reviewing their provenance and explicitly updating
the lock; another PATH binary is not silently accepted.

## Boot protocols

- `boot_protocol: "linux-image"`: uncompressed Linux AArch64 Image, little endian,
  v3.17+ header with non-zero size. Accepts `boot_args` (4096 bytes maximum) and
  `initrd_path`. Places Image according to `text_offset`, reserves its declared size and
  validates that initrd does not overlap it. Publishes both in the DTB. Does not run EFI.
- `boot_protocol: "elf"` (default value): ELF64 AArch64 EXEC, PT_LOAD inside
  RAM and entry aligned in executable segment with virtual address=physical.
  The first 2 MiB remain reserved for DTB. This protocol does not define
  initrd or Linux arguments and rejects those fields.

Both boot in EL1 with MMU off, masked interrupts, x0=DTB,
x1=x2=x3=0. RAM at `0x40000000`; 1–4 CPUs and 64–2048 MiB of configurable RAM.
VMM capacity does not imply that any guest fits in 64 MiB.
The Linux example is validated with 256 MiB. Output-only PL011 console, GICv3, PSCI,
legacy VirtIO PCI and MMIO fw_cfg. No interactive input console is offered.

## Generic configuration

```json
{
  "boot-source": {
    "boot_protocol": "linux-image",
    "kernel_image_path": "/path/Image",
    "initrd_path": "/path/initrd.gz",
    "boot_args": "console=ttyAMA0 rdinit=/init"
  },
  "machine-config": {"vcpu_count": 4, "mem_size_mib": 256, "power_button": true},
  "drives": [
    {"drive_id": "disk0", "path_on_host": "/path/disk.raw", "copy_on_start": false}
  ],
  "firmware": {"opt/example/data": "/path/payload.bin"},
  "network-interfaces": [{
    "iface_id": "net0", "backend": "slirp", "guest_mac": "02:12:34:56:78:90",
    "forwards": [{
      "protocol": "tcp", "host_addr": "127.0.0.1", "host_port": 19000,
      "guest_addr": "10.0.2.15", "guest_port": 9000
    }]
  }],
  "security": {"version": 1, "listeners": [{"protocol": "tcp", "address": "127.0.0.1", "port": 19000}]},
  "hvf": {"max_runtime_ms": 0, "trace": false}
}
```

Disks: zero to four regular files aligned to 512 bytes, optional `is_read_only`.
`is_root_device` is an optional designation that orders that device
first; it does not select a filesystem nor build mount parameters.
`copy_on_start` copies any disk to a private temporary; by default it is
**false**, so writes persist. Writers take LOCK_EX and
readers LOCK_SH. The copy holds LOCK_SH on the source throughout the copy
and reads from the same locked descriptor, not from a reopening of its path.
These are cooperative locks, not protection against writers that ignore flock.

Firmware: map of names to binary files, maximum 64 files of 64 KiB and
names up to 55 bytes. They are delivered without interpretation via fw_cfg.
Names and content belong to the guest contract. There is no environment,
mounts or filesystem labels interpreted by the VMM.

Network: optional interface independent of `forwards`, configurable unicast MAC,
up to 64 explicit TCP/UDP IPv4 rules with addresses/ports. An interface without
forwarding rules can only egress to destinations authorized in `security`;
egress and DNS are denied by default. slirp provides NAT/DHCP/DNS on
`10.0.2.0/24` (gateway `.2`, DNS `.3`, DHCP from `.15`). The transport is behind
`net_backend.h`, separate from VirtIO; it supports slirp and the generic
`unix-stream` transport described in [UNIX_STREAM.md](UNIX_STREAM.md).
The guest configures its own address and routes. There is no gVisor dependency.

## macOS API 1.0

```sh
build/macos-arm64/firecracker --api-sock /private/path/vmm.sock
```

Unix socket 0600; use private directory. HTTP/1.1 with connection close, without
chunked encoding. Headers up to 8 KiB, body up to 1 MiB. There is no TCP API.

| Operation | Contract |
| --- | --- |
| GET `/` | Version, state, `operation_id`, `exit_code`, `last_error`, `shutdown_delivered` |
| GET `/capabilities` | Implemented protocols and limits; explicitly absent capabilities |
| GET `/vm/config` | Current configuration |
| GET `/operations`, `/operations/{id}` | Up to 64 recent operations, state, diagnostics and result |
| GET `/metrics` | JSON; `Accept: text/plain` selects Prometheus |
| PUT `/security`, `/limits` | Versioned configuration sections, with the VM stopped |
| PUT `/actions`, `Pause` / `Resume` | 202; full barrier and frozen virtual clock |
| PUT `/snapshot/create`, `/snapshot/load` | 202; absolute `snapshot_path`, capture from Paused and restore to Paused |
| PUT `/boot-source`, `/machine-config`, `/drives/{id}` | Upstream name/structure subset; unsupported fields are rejected |
| PUT `/firmware`, `/network-interfaces`, `/hvf` | macOS extensions; map, list and options respectively |
| PUT `/actions`, `InstanceStart` | 202 with `Starting` and `operation_id`; initialization in worker |
| PUT `/actions`, `ForceStop` | 202 with `Stopping`; cancels boot or kills VM, preserves supervisor/API; `Stop` is alias |
| PUT `/actions`, `Shutdown` | 202 with `Stopping`; requires `machine-config.power_button: true` |

States: `Not started`, `Starting`, `Running`, `Pausing`, `Paused`, `Resuming`,
`Snapshotting`, `Restoring`, `Stopping`, `Failed`, `Exited`.
`InstanceStart` accepts one operation, does not confirm its success. Query GET `/`:
`Failed` includes `last_error.fault_code=BOOT_FAILED` and the real child diagnostics
(invalid ELF, locks, busy ports). Initialization has a 30 s maximum and
can be cancelled with ForceStop or supervisor signal. `Running` means
HVF/devices ready, not that the OS or application has finished booting.
Configuring or restarting while an operation/VM is active returns 409.
After exit, `Exited` preserves the code and allows configuring and starting again.
`--api-sock --config-file` also starts asynchronously.

VMM-requested shutdown:

```json
{"action_type":"Shutdown","timeout_ms":5000,"force_on_timeout":false}
```

The optional VirtIO MMIO input device publishes standard EV_KEY/KEY_POWER.
Linux needs virtio_mmio, virtio_input and a userspace policy that
handles the button (the test uses evdev). The guest decides whether to sync and shut down.
`shutdown_delivered` only confirms
that events were written to the queue, not that the OS processed them.
The timeout allows 1–300000 ms (default 5000). On expiry `SHUTDOWN_TIMEOUT` remains;
without escalation it returns to Running, with `force_on_timeout:true` the VM is killed.
Cancelling the pending event does not withdraw already delivered events: the guest could still
shut down after the deadline. Without `power_button`, Shutdown returns 409.
The `/shutdown` HTTP function belongs solely to the test guest.
SIGTERM/Ctrl-C to the supervisor gives the child process 2 s before SIGKILL; it does not guarantee
guest fsync. Signals and ForceStop are forced stops.
PSCI SYSTEM_OFF returns 0; pvpanic 1; unimplemented exit 2; requested reset
3; watchdog 124; direct signal 128+signal. Reset does not yet restart the VM.
The child monitors a private connection to the supervisor and stops if it
dies, even via SIGKILL. SIGKILL or host crash do not run parent destructors:
temporary socket/configuration may remain, although the VM is no longer
running.

API 1.0 keeps the upstream names shown in the table and adds macOS extensions.
It does not support metadata/MMDS or KVM snapshots. To import 0.3 configuration,
use the explicit migration described below: network permissions are not granted
implicitly. The upstream Linux contract remains separate per target.

## Tests

```sh
experiments/hvf/test-native.sh              # includes Linux; needs Go and downloads pinned assets
experiments/hvf/test-native.sh --unit-only  # Rust, synthetic HVF, API and devices
python3 experiments/hvf/test-linux.py       # uses already prepared build/linux-guest/config.json
experiments/hvf/fuzz/run.sh                  # 60s, ASan/UBSan and incremental corpus
```

The generic suite tests ELF/Linux loaders and limits, copy/locks,
HTTP parser, real boot errors with retry, supervisor exit and cleanup,
synthetic HVF guest, block/firmware and Linux with 1/4 CPUs. Linux performs
two boots per configuration, fsync and persistence, checks MAC, transfers
16 MiB of HTTP per boot, uses UDP and receives Shutdown from the VMM API;
checks the marker written/fsynced by the button handler before shutting down. Another boot tests
outbound networking without publishing ports. Local logs in `experiments/hvf/build`.
The [CI](ci/README.md) distinguishes tests without virtualization from tests that
boot real guests on dedicated hardware.

VirtIO validates indexes, DMA ranges, addresses and cycles; it does not support indirect/event_idx
or offloads. Block limits requests to 4 MiB and work per turn to 32 requests
with an 8 MiB budget (may finish the in-progress request); pending work
resumes on poll. TX limits each turn to 256 packets. I/O errors are reported
via VirtIO status; invalid descriptors terminate the VM. This is not equivalent to an
audit or exhaustive fuzzing.

Original entry/build code and Linux dependencies are preserved per target.
Linux/KVM x86_64 has been tested on an Ubuntu 26.04 host with kernel 7.0.0-28,
KVM API 12 and sudo access. The host is virtualized: the test uses nested KVM.
GNU release build and four real Linux 6.1.102 boots
(1/2 vCPU) pass with persistence, 16 MiB total HTTP, UDP and exit via i8042.
That kernel's poweroff leaves the VM halted; ACPI poweroff support is not claimed.
The [KVM suite](guests/kvm/README.md) uses a private network namespace and keeps
results in `experiments/hvf/build/kvm-validation`.

The independent upstream base 16f9023f8 reproduced 993 passes and three failures.
The comparison identified a TSC expectation incompatible with KVM-admitted software catchup
and two polls observing non-terminal events. The tests were fixed
preserving assertions and the total 500 ms deadline. The fork passes
996 tests, zero ignored; the three affected cases pass three repetitions.
Evidence in `build/kvm-validation/comparison/comparison.json` in this
lab. KVM ARM64, bare metal, jailer/musl and other hosts remain unvalidated.
The GNU build uses the empty seccomp filter announced by upstream.

Protocol sources: [ARM64 Linux boot](https://docs.kernel.org/arch/arm64/booting.html),
[Alpine netboot 3.23.5](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot-3.23.5/),
[Hypervisor.framework](https://developer.apple.com/documentation/hypervisor),
[VirtIO](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html).

## Security and configuration migration

Reproducible network tests are described in
[NETWORK_REGRESSIONS.md](NETWORK_REGRESSIONS.md).

Old configurations require explicit migration:

```sh
build/macos-arm64/firecracker --migrate-config --config-file old.json > migration-report.json
```

The report shows `configuration` and `required_listener_permissions`. Review and
extract the configuration, adding only the necessary permissions: it is not an
automatically granted executable file. A boot without network access uses
`"security": {"version": 1}`. Example with specific listener and TCP egress:

```json
{
  "security": {
    "version": 1,
    "listeners": [{"protocol": "tcp", "address": "127.0.0.1", "port": 19000}],
    "egress": [{"protocol": "tcp", "address": "192.0.2.10", "port": 443}]
  },
  "limits": {
    "version": 1,
    "open_files": 1024,
    "file_size_bytes": 17179869184,
    "rss_mib": 3072,
    "cpu_seconds": 86400,
    "nice": 5,
    "disk_bytes_per_second": 268435456,
    "disk_operations_per_second": 20000,
    "network_bytes_per_second": 67108864,
    "network_packets_per_second": 100000
  }
}
```

In `security.listeners`, `0.0.0.0` authorizes an INADDR_ANY bind on all
host IPv4 interfaces, only for that protocol and non-zero port. It must match
`forwards[].host_addr` exactly: it does not substitute a specific bind permission
like `127.0.0.1`. It does not grant egress or DNS; `egress` and `dns` still reject
wildcard addresses. Socket gate preserves exact comparison and Seatbelt.
On Darwin, SO_REUSEADDR allows TCP coexistence between wildcard and specific
address on the same port; the specific bind takes precedence. Identical
endpoints collide.

These sections are added to the boot, disk and interface configuration.
The example IP must be replaced with the real destination. Permissions apply
to host addresses after slirp translation: for example, accessing
the host via `10.0.2.2` requires authorizing the effective loopback destination.
DNS needs `"dns": {"address": "RESOLVER_IP", "port": 53}`; it does not use
the host resolver implicitly. Development without Seatbelt/policy requires
explicit `"security": {"version": 1, "mode": "development"}`.

`PUT /security` and `PUT /limits` change configuration only with the VM stopped.
`GET /capabilities` distinguishes effective isolation and available limits.
Aggregate group RSS and CPU are reactive, sampled every 100 ms. RLIMIT_CPU
is not supported with HVF on the validated host; it only applies to network processes.
I/O limiters act on devices, with disk bursts of 4 MiB/32
operations and network bursts of 256 KiB/256 packets. They are not equivalent to cgroups or kernel network
quotas. `--no-api` also keeps a private supervisor.

Input files must be regular; final symlinks are rejected.
The supervisor locks and prepares the files, and passes the open disks.
Socket authority and its trust boundary are described in
[README.hvf.md](../../src/hvf-vmm/vendor/README.hvf.md). The standalone package
includes GLib and libintl with paths relative to the executable.

## Pause and resume

`PUT /actions` accepts `{"action_type":"Pause"}` from Running and
`{"action_type":"Resume"}` from Paused. It returns 202 with operation
identifier; query `/operations/{id}` or the `/` state. The intermediate
states are Pausing and Resuming. Incompatible actions return 409;
ForceStop remains available during both transitions and while paused.
Shutdown requires Running: resume before delivering the button to the guest.

Paused confirms that all vCPUs, including secondaries that have not yet
started, are at the barrier. Already published disk/TX requests are completed,
respecting quotas, and broker processing stops.
Already broker-delivered RX packets are consumed before acknowledging.
Interrupts remain pending in the GIC; their state is not cleared. On
resume, all vCPUs adjust their CNTVCT offset before releasing the barrier.
The PL031 clock and libslirp clock pause is also discounted.

Metrics queries, resource monitoring and broker death detection
remain active. Pause may take a while if there is quota-deferred I/O.
A failure or exceeded internal deadline terminates the VM with diagnostics: 300 s to
pause and 5 s to resume. The VM's explicit watchdog still uses host
time. External sockets may expire during a prolonged pause;
preserving connections against remote-end timeouts is not guaranteed.

## Local snapshots, format 1

From Paused, `PUT /snapshot/create` with `{"snapshot_path":"/private/path/snapshot"}`
starts capture. From a stopped VM, `/snapshot/load` with the same body
restores to **Paused**; `Resume` allows running. Both return 202 and
`operation_id`: the definitive result is in `/operations/{id}`. Capture
preserves Paused even on failure; ForceStop cancels in-progress operations.

The directory contains versioned manifest, full RAM, per-CPU state
(general/SIMD/system registers and SME when active), timers, GIC blob,
devices, firmware, kernel/initrd and copies of all disks, including RO.
It contains no host pointers or descriptors. It is written to a private temporary,
files and directory are synced and published via atomic rename.
A failure preserves the previous snapshot. The per-file size quota also
limits captured RAM and disks; configure sufficient space before booting.

Restore first validates schema, names, limits and compatibility;
then copies components verifying size/SHA-256, ownership and regular type.
It rejects symlinks, missing components, external paths and corruption.
Compatibility requires the same Mac UUID, macOS build, VMM build
identifier and device model. The identifier derives from sources and toolchain;
relocating or re-signing the same build does not change it. Hashes check
integrity, they do not authenticate the creator: keep snapshots private.

Restored disks are independent copies. The network backend restarts;
applications must reconnect. For `unix-stream`, the current configuration
must declare a compatible interface and the authorized switch socket;
see [the restore contract](UNIX_STREAM.md).
Manifests with invalid format, paths or sizes are rejected with HTTP 400
before accepting the operation; component integrity is checked
during async restore. No application transactional consistency,
migration between Macs, compatibility after system updates
or KVM snapshots are offered. Capturing a paused VM preserves its block
and RAM state, but does not turn application buffers into transactions.

## Metrics and stability

The supervisor publishes JSON/Prometheus via its Unix socket. Includes process CPU/RSS,
per-vCPU exits, disk bytes/operations/errors, network packets/bytes,
VirtIO and IPC queues, IPC drops and telemetry sample losses. CPU is
expressed in host ticks. Operation result and duration counters
are preserved even if an operation is evicted from the 64-entry history.
Current state duration and accumulated time per state are also published.
The private metrics channel uses version 2 with 26 bounded fields; truncated
or unknown-version frames are rejected.

```sh
python3 experiments/hvf/test-snapshot-linux.py --config build/linux-guest/config.json
python3 experiments/hvf/test-snapshot-linux.py --config build/debian-guest/config.json --output-prefix experiments/hvf/build/debian-snapshot
FUZZ_SECONDS=600 sh experiments/hvf/fuzz/run.sh
python3 experiments/hvf/soak.py --config build/linux-guest/config.json --output experiments/hvf/build/soak-24h
```

The stability campaign performs disk with fsync, TCP/UDP and periodic snapshots
without restarting the VM. It records RSS, errors, API latency and cleanup. It only declares
`acceptance_24h_passed` if the target is at least 86400 seconds and 86400
effective seconds complete; a short test does not meet that criterion. The
`sample_label` field identifies the target duration: `--seconds 28800 --interval 5`
produces an `8h` sample, which never accredits 24h acceptance.
It prevents idle sleep only while running.
