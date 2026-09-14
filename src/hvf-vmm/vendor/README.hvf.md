# HVF network dependency

libslirp 4.9.4 comes from the upstream archive identified in `libslirp.json`.
Its tree and license notices are preserved (`libslirp/COPYRIGHT`). The patch
`libslirp-hvf.patch` selects only the declared IPv4 resolver in hardened
mode; explicit development mode retains upstream resolution. It also fixes
response translation from IPv4 resolvers on ports other than 53: the
original destination is compared before replacing it with the virtual DNS IP.
It also avoids container_of(NULL) when creating an IPv4 reassembly queue,
a UBSan finding reproduced by the final campaign's fragment corpus.
It validates the declared and available length of NC-SI packets before reading
OEM payloads, including Mellanox-specific fields. The permanent corpus
`ncsi-oem-truncated-payload` reproduces the original out-of-bounds read.
`libslirp-version.h` is derived from the upstream template with the version pinned
in `libslirp.json` and is checked into Git so that direct builds do not depend
on a prior Meson configuration. When updating libslirp, also update
this header.

Both local builds compile **all** C units with the forced include
`native/slirp_policy.h`: socket, connect, bind, listen, sendto, recvfrom,
getsockname and close go through the shims. No Homebrew libslirp is linked.
The development build accepts `GLIB_PREFIX` (Homebrew by default). The
`experiments/hvf/distribution/` flow builds GLib 2.88.3 and verified dependencies
in a private prefix and packages relative dylibs; its relocated execution has
already been tested without access to Homebrew. The public distribution is still pending.

In hardened mode, Seatbelt denies file access, execution, and direct network
in the broker that parses the frames. A separate authority, without libslirp,
receives fixed-size requests via IPC and authorizes the **translated**
IPv4/port/protocol destination before opening TCP or sending UDP. There are no exceptions for
loopback, gateway, or LAN. DNS requires an explicit resolver. Listeners require
its authorization; UDP only replies to an observed peer on a declared listener
(for 60 seconds, maximum 32 peers per socket).

The authority is part of the trust base: its Seatbelt profile allows network,
but denies files and execution. This is deliberate because Seatbelt on macOS 26
does not support filters for arbitrary IPv4 literals. Exact authorization is
implemented by `socket_gate.c`; the broker receives already-open connected TCP sockets/listeners
and Unix proxies for UDP, never Internet UDP sockets. The authority
retains neither guest RAM nor disk descriptors. It has at most 256
UDP proxies and processes at most 128 datagrams per iteration, with rotation.
This is not equivalent to an audit. DNS, UDP proxy, TCP, and
descriptor-passing regressions are described in
[NETWORK_REGRESSIONS.md](../../../experiments/hvf/NETWORK_REGRESSIONS.md).
