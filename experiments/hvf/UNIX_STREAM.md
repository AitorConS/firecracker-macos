# Unix Ethernet Transport for HVF

`unix-stream` is a generic Ethernet client compatible with the framing of
[QEMU netdev stream](https://www.qemu.org/docs/master/system/qemu-manpage.html).
It does not need to run QEMU. The VMM does not manage IPAM or service DNS.
The external switch configures and authorizes the network. `slirp` retains its
configuration and its independent socket authority.

```json
{
  "network-interfaces": [{
    "iface_id": "eth0",
    "backend": "unix-stream",
    "guest_mac": "02:00:00:00:00:01",
    "socket_path": "/private/tmp/my-private-network/link.sock"
  }],
  "security": {
    "version": 1,
    "unix_stream": "/private/tmp/my-private-network/link.sock"
  }
}
```

Those sections are added to a normal boot/machine/drives configuration.
The `security.unix_stream` authorization must exactly match the backend
socket. `forwards`, `security.egress`, `security.listeners` and
`security.dns` are rejected with this transport: the external switch is the IP authority and must
enforce those permissions. Granting the socket grants connectivity to the switch serving
it; the VMM does not promise to filter its IP destinations.

The parent directory must be user-owned and private (0700); the socket
must belong to the same user and be 0600. The parent is resolved before
installing Seatbelt. The broker receives only connection and metadata
permission for that canonical path, checks `getpeereid`, and obtains no Internet connection
permission, host file opening, or access to other Unix sockets. The VMM
keeps its usual sandbox. The protection does not aim to isolate malicious
processes with the same UID capable of modifying the authorized directory.
The client never creates, deletes, or replaces the server socket.

## Transport contract

- A **u32 big endian** length, followed by the Ethernet frame with no
  VirtIO prefixes or offload headers. Supported size: 14–65536 bytes.
- RX uses a fixed 65540-byte buffer; TX uses a fixed 1 MiB queue. Offsets are
  preserved across partial operations. The length is validated before reading
  the payload, and new arrivals do not extend a stalled writer's timeout.
- The broker stops draining guest IPC when the TX queue cannot accept a maximum
  sized frame. The VMM retains its VirtIO descriptor when IPC is full. RX also
  retains one complete frame until the VMM accepts it. An empty guest RX ring
  defers that frame until descriptors return; RX kicks retry immediately.
  Both the broker and VMM wake on input readiness instead of waiting for a
  periodic device poll. The broker stops polling guest input while its bounded
  stream TX queue is full, and polls writable readiness only for pending output.
  These paths apply
  backpressure without blocking device processing or allocating unbounded memory.
- Whole-frame drops remain possible at queue saturation and disconnect, and are
  included in the API TX counters. Frames never interleave or lose partial bytes.
- Startup requires being able to initiate the connection. Once started, EOF, errors,
  invalid framing, or five seconds without progress on a pending frame/connection
  close the link, discard its partial state, and retry every second.
  Pending frames are not retransmitted to the new peer. Applications must
  tolerate loss and reconnect; TCP sessions of the restarted switch are not preserved.
- Existing aggregate VirtIO byte/packet quotas apply.
  Pause/Resume maintains the broker barrier; it does not process frames while
  paused. Once every vCPU has parked, an exhausted RX ring causes a counted
  drop during the finite drain: parked CPUs cannot replenish it. Normal running
  operation retains backpressure. Transport deadlines use host monotonic time.
- Snapshots preserve the device, but not the external switch state.
  Before restoring, configure a `unix-stream` interface with the same
  `iface_id` and MAC, a current socket, and its `security.unix_stream` authorization.
  Restoration validates that compatibility and reconnects to the authorized socket;
  it never implicitly reuses the authority saved in the snapshot.
  Slirp also reinitializes networking on restore.

`GET /capabilities` advertises both backends, framing, maximum size, reconnection
interval, snapshot restore contract, and
`network_policy: external-switch-unix-capability` when applicable. The
macOS API remains 1.0; these are additive fields. Linux/KVM uses its separate backend.

## Build and validation without replacing other work

```sh
export CARGO_TARGET_DIR="$PWD/experiments/hvf/build/my-network-cargo"
export HVF_OUTPUT_DIR="$PWD/experiments/hvf/build/my-network-bin"
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
sh experiments/hvf/build-native.sh
export HVF_BINARY="$HVF_OUTPUT_DIR/firecracker"
sh experiments/hvf/test-network-stream.sh
python3 -m unittest discover -s experiments/hvf -p test_network_stream.py -v
```

The C helper uses ASan/UBSan and tests fragmented/coalesced framing, adversarial
lengths, partial writes, saturation, timeout, EOF, permissions, and
reconnection. A second ASan/UBSan helper exercises the production VirtIO receive
path: an empty ring preserves the frame, an RX refill kick retries it, and
quiescent draining accounts drops without waiting for parked guest CPUs.
The Seatbelt helper verifies allowed and denied connections.
The API test boots a real HVF VM and checks reconnection, capabilities,
Pause/Resume, and snapshot capture. The Rust tests check interface
compatibility and explicit replacement of the authorization on restore.

`distribution/verify-reproducible.py --reuse-native --output NEW_DIRECTORY`
rebuilds the VMM for two targets and packages the already installed dependencies,
without replacing dylibs used by another campaign. Its report distinguishes that scope
from a full dependency rebuild. The packages preserve ad-hoc
signature, Hypervisor entitlement, relative dependencies, licenses, and checksums.

## Sustained Jerboa validation (2026-09-24)

The companion Jerboa regression runner measured VM-to-VM TCP and UDP without
changing default quotas (64 MiB/s aggregate Ethernet bytes, 100,000 packets/s).
Replacing empty-ring drops improved 20-second TCP from 91.48 to 210.41 Mbit/s;
readiness-driven receive processing raised it to 507.34 Mbit/s. The 60-second
matrix completed in both directions at about 507 Mbit/s TCP without zero-progress
intervals, and at 100/400 Mbit/s UDP with zero observed loss. At an offered
1 Gbit/s, UDP received about 521.4 Mbit/s with 47.8% loss. A 1420-byte UDP
payload in a 1462-byte frame has a quota ceiling of about 521.45 Mbit/s.
This is expected overload loss, not a claim that a successful iperf process
received the offered rate. No unbounded queues or installed runtime replacements
were used. Exact raw results, final build hashes and Linux controls are tracked
in Jerboa's `docs/benchmarks/remediation-results.json`.
