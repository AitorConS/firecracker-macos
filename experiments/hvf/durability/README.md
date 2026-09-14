# Durability of guest storage on the macOS HVF VMM

This directory holds the test-only tooling for host-crash and power-loss
durability of virtio-blk volumes. None of it is linked into release builds.

## Storage chain

1. Application: `fsync()`/`fdatasync()` (PostgreSQL: `wal_sync_method=fdatasync`,
   PANIC on data-file fsync failure in the fixture patch).
2. Nanos: `fsync_internal` → `fsfile_flush`/`filesystem_flush` →
   `pagecache_sync_node`/`pagecache_sync_volume` (waits for page writes) → TFS
   `log_flush` (metadata) → `STORAGE_OP_FLUSH`. The syscall returns `-EIO` if any
   step reports an error.
3. Nanos virtio-blk negotiates `VIRTIO_BLK_F_FLUSH` and sends `VIRTIO_BLK_T_FLUSH`.
4. VMM (`src/hvf-vmm/native/devices.c`): requests are handled strictly in ring
   order; each write is `pwrite()` to the original host volume file (Jerboa
   never sets `copy_on_start`); FLUSH completes only after `fcntl(F_FULLFSYNC)`
   returns. `EINTR` is retried; any other error is returned to the guest. There is
   no fallback to `fsync()`.

## Hardening in devices.c

- **Latched storage errors.** The first failed write or F_FULLFSYNC is latched per
  drive, and every later FLUSH returns `VIRTIO_BLK_S_IOERR` until the VMM restarts.
  Without this, a later successful F_FULLFSYNC could acknowledge data lost after an
  earlier error. The error could come from the host page cache, or from Nanos TFS,
  whose `log_flush_complete` clears `dirty` even when the flush failed and whose
  `fsfile_flush` clears `FSF_DIRTY*` before completion. Read errors do not latch.
- **Snapshots refuse a latched device**, because the latch is not serialized and a
  restore must not clear it.
- **Final flush on clean VMM exit.** `devices_close()` issues F_FULLFSYNC on
  writable drives, or logs that it skipped it after a latched error. The guest is
  gone by then, so failures are only logged.

## Test layers

| Layer | What it proves | What it cannot prove |
| --- | --- | --- |
| `test-device-faults.sh` (ASan/UBSan) | Syscall-level ordering, error propagation, latching, read-only drives, snapshot refusal, close flush, no fsync fallback. Six mutants re-introduce bugs, and each must be detected. | Guest or real-storage behaviour |
| `crash_journal.h` + `crash_replay.py` + `scripts/test-power-loss-sim.py` and `scripts/test-postgres-power-loss-sim.py` (Jerboa repo) | On real HVF with real Nanos, TFS and PostgreSQL: data acknowledged to the application survives when all (or any ordered subset of) writes after the last successful F_FULLFSYNC are lost. Negative controls `nosync`/`fsync=off` and `flush-lie` must be detected. | That macOS, APFS and the SSD actually persist what F_FULLFSYNC acknowledged |
| `powercut-probe.py` on dedicated hardware | Whether the physical host keeps F_FULLFSYNC-acknowledged blocks across a real power cut | Nothing about the guest stack; combine with the layer above |

### Crash journal build

```sh
F=$PWD   # firecracker-macos
CFLAGS="-DHVF_CRASH_JOURNAL -I$F/experiments/hvf/durability" \
CARGO_TARGET_DIR=/private/tmp/target-journal HVF_OUTPUT_DIR=/private/tmp/journal-vmm \
sh experiments/hvf/build-native.sh
```

The build prints `HVF CRASH JOURNAL TEST BUILD` on every start and exits with 98
if the journal cannot be written. Never distribute it: it copies all guest writes
to `HVF_CRASH_JOURNAL_DIR`. The journal is opened from `devices_init()`, because
the exec'd VMM closes ambient descriptors (`inherited.rs`) and the Seatbelt
profile installed afterwards forbids opening files outside the work root.

Replay models, for the volume inode:

- `full`: every journaled write. This must equal the disk left by the VMM kill,
  which proves the journal is complete.
- `durable`: only writes before the last F_FULLFSYNC, as if the host cache is fully lost.
- `subset`: durable writes plus a seeded, order-preserving random subset of later
  writes, as with partial writeback.
- `boundary --flush k`: writes before the k-th F_FULLFSYNC plus a subset of the
  writes issued before flush k+1, a cut while an earlier sync was in flight.
  - ACK lines cannot be mapped to flushes, so the guest verifies with `DURA_ACK=-1`.
    Every record named by `/data/meta` must be intact; meta is fsynced only after
    that record's fdatasync.
  - PostgreSQL uses `PGACK=0`, so only crash consistency is checked: recovery,
    checksums, heap/index agreement and amcheck.

Why `boundary` is needed: the guest syncs after every record, so at the kill there
are usually no unflushed writes. Then `durable` and `subset` equal `full`. The
boundary cuts are what actually drop writes in positive rounds.

Harness pitfall: `jerboad` formats an unformatted volume on the host at its first
`run` (`volume.EnsureFormatted`). That write is outside the VMM journal, so the
baseline image is taken after a first VM has run. The harness checks `full` against
the killed disk; any difference outside the final in-flight intent fails the run.

Each recorded write buffer is replayed or dropped as a whole, in the order the
VMM issued the writes. This is coarser than sector-level atomicity. Partial/torn
writes, torn sectors and reordering inside the SSD are outside the model.

## Physical power-cut protocol (dedicated hardware only)

Never run this on a machine holding data you care about. It requires physically
removing power, and it was **not** executed during development.

1. **Hardware.** Use a dedicated Apple Silicon Mac under test (MUT) with the same
   macOS and storage class as the target. A desktop is preferable, because a laptop
   battery defeats a wall-power cut. You also need a second machine as observer on
   wired Ethernet, and a switched PDU or relay that cuts MUT mains power. Record
   the model, macOS build, SSD model, FileVault state and the free space on the
   test volume.
2. **Host storage probe, at least 20 cuts per configuration.**
   - On the observer: `powercut-probe.py observer --listen 0.0.0.0:7788 --log acks-N.log`
   - On the MUT: `powercut-probe.py writer --file /Users/Shared/probe.bin --size-mib 2048 --observer OBSERVER:7788`
   - After at least 10 s of writing, cut power at a random offset. Restore power
     and let the MUT boot.
   - Copy `acks-N.log` over, then `powercut-probe.py verify --file /Users/Shared/probe.bin --acks acks-N.log`.
     This must report `missing_or_corrupt=0`.
   - **Negative control.** Repeat 5 cuts with `--sync none`. At least one run must
     lose acknowledged blocks. If none do, the cut is not removing volatile state
     (e.g. power is not really removed) and the positive runs prove nothing.
3. **Guest stack.**
   - Run the PostgreSQL fixture from a release-recipe bundle with the server port
     published on the LAN.
   - Run the fixture client in `ack` mode on the observer (a Linux build of
     `client.go`), logging ACK lines to the observer's disk.
   - Cut MUT power at a random time, 20 times, with checkpoints landing inside
     some windows.
   - After each reboot, start the server on the same volume and run the client in
     `recover` mode with `PGACK` from the observer log and `PGAMCHECK=1`. It must
     pass: all acknowledged rows present, checksums, heap/index agreement, amcheck.
   - **Negative control.** Repeat with `fsync=off`. Loss or failed recovery is expected.
4. **Retain.**
   - Observer logs, verify outputs, recovery logs and PDU timestamps.
   - The unified log from boot (`log show --last boot`) and SHA256 of every binary.
5. **Acceptance scope.** A passing campaign covers only that hardware, macOS build
   and storage type. It qualifies neither other Macs, external/USB/Thunderbolt or
   network storage, nor third-party filesystems. Filesystems that reject
   F_FULLFSYNC fail FLUSH by design.
