# HVF Network Regressions

Controls change a single mechanism in temporary copies: production is never reverted
nor is HEAD used as baseline of this shared checkout.

- `python3 experiments/hvf/test-network-transfer.py --repeat 3`: real authority,
  SCM_RIGHTS transfer, TCP and two echoes via UDP proxy. The control closes the
  sender reference before the ACK. The stimulus creates/frees Unix sockets and may
  trigger GC across the host; run without other concurrent network campaigns.
  The script requires reproduction on each protocol and complete delivery on fixed.
  `--churn 0` checks natural traffic, without guaranteeing discrimination.
- `python3 experiments/hvf/test-network-recovery.py --repeat 2`: real gate, authority,
  policy and libslirp; control disables only listener recovery.
  Covers isolated failure, persistent failure, budget, recovery with traffic between
  failures, DNS under pressure, ephemeral mappings and down authority.
- `python3 experiments/hvf/test-network-rpc.py`: injects timeout, wrong-ID response,
  ACK failure and EINTR; checks fatal state, descriptor close and
  rejection of requests before the ACK. `--control PATH` allows comparing with the
  previous version of that mechanism.
- `test-network-{gate,fd,port}.py` retain the previous ICMP discriminants,
  TCP release and port collisions.

Use a fresh `--output` to preserve evidence. `--sanitize --fixed-only` is
supported in transfer and recovery. Induced cases are distinguished from
spontaneous failures. Listener injection is equivalent to closing its read side:
it does not alter permissions nor pretend that already-lost datagrams are recovered.

VMM validation uses `test-network-closure.py` (exact HTTP content and status,
DNS and UDP), plus `test-linux.py` (forwarding, bidirectional traffic, disk and
pause cycles). Run socket-pressure campaigns sequentially to avoid interference between tests. Results correspond
to the binary and host recorded by each run, not to later builds.
