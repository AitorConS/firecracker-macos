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
- RX and TX each use a fixed 65540-byte buffer. Offsets are preserved
  across partial operations; the length is validated before reading the payload.
- The broker holds a single pending TX frame. If saturated, it drops the
  next complete frame; it never interleaves bytes nor truncates the pending frame.
  Drops are added to the API TX counters. Broker/VMM IPC and
  poll-based processing are also bounded.
- Startup requires being able to initiate the connection. Once started, EOF, errors,
  invalid framing, or five seconds without progress on a pending frame/connection
  close the link, discard its partial state, and retry every second.
  Pending frames are not retransmitted to the new peer. Applications must
  tolerate loss and reconnect; TCP sessions of the restarted switch are not preserved.
- Existing aggregate VirtIO byte/packet quotas apply.
  Pause/Resume maintains the broker barrier; it does not process frames while
  paused. Transport deadlines use host monotonic time.
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
reconnection. The Seatbelt helper verifies allowed and denied connections.
The API test boots a real HVF VM and checks reconnection, capabilities,
Pause/Resume, and snapshot capture. The Rust tests check interface
compatibility and explicit replacement of the authorization on restore.

`distribution/verify-reproducible.py --reuse-native --output NEW_DIRECTORY`
rebuilds the VMM for two targets and packages the already installed dependencies,
without replacing dylibs used by another campaign. Its report distinguishes that scope
from a full dependency rebuild. The packages preserve ad-hoc
signature, Hypervisor entitlement, relative dependencies, licenses, and checksums.
