<!-- SPDX-License-Identifier: Apache-2.0 -->
# Jerboa Linux Firecracker 1.10.1 backport

These patches apply to upstream Firecracker commit
`1fcdaec088da9e30c2c111f9feb2649118488361` (v1.10.1), not to the
1.18 development sources in this repository. They preserve the Linux deployment
version while correcting Jerboa guest failure reporting. Apply them in a separate
checkout; do not replace an installed VMM until its deployment has been reviewed.

See [BUILD.md](BUILD.md) for the pinned checkout, scoped toolchain, exact host
compatibility flags, dependency fetch, build commands and validation record.

## Behavior

Jerboa writes one raw exit byte to x86 I/O port 0x501 before its fallback reset.
Patch 0001 handles zero as a successful stop and nonzero as a VMM failure. Other
ports and malformed widths retain their previous behavior. It queues the vCPU
exit response before notifying the eventfd, preventing the main loop from seeing
an event before its status. The CLI preserves success/failure (0/1), not the
original numeric guest exit code. Simultaneous unrelated vCPU failures are not a
new arbitration protocol; Jerboa quiesces other CPUs before its shutdown write.

Patch 0002 is build compatibility for the tested Ubuntu 26 toolchain: use the
bundled AWS-LC musl bindings instead of regenerating them with Clang 21, which
omitted five required functions. It removes the inactive aws-lc-fips-sys package
and optional dependency edge from Cargo.lock; active versions/checksums do not
change. This is the upstream default non-FIPS build, not a FIPS configuration.

## Validation on the Linux host

Rust 1.79.0, x86_64-unknown-linux-musl, release build with two build jobs:

- New port unit test passes (zero, nonzero, malformed widths and other port).
- Relevant vCPU suite: 25/26 pass. test_set_tsc fails with unwrap_err on Ok in
  both the patched and unpatched source under the same build configuration.
  No assertion was removed or disabled.
- Forty marker-validated guest runs pass: ten normal and ten exit7 at each of
  one and two vCPUs. The actual guest marker must appear; timeout and startup
  failure cannot count as an expected nonzero exit.
- A guest self-SIGSEGV produces the guest signal 11 diagnostic and CLI1.
- Killing the identified test VMM with SIGKILL separately produces a CLI error.

Evidence resides in the task archive `jerboa-bench/evidence/linux-vmm-v1.10.1/`.
`root-verification.json` independently checks the forty raw logs, guest SIGSEGV,
and artifact hashes. Both patches applied to a fresh upstream checkout exactly
reproduce the tested final-source.diff and Cargo.lock.

## Recorded SHA-256

| Artifact | SHA-256 |
| --- | --- |
| 0001-guest-exit.patch | 3d451d5138be33c256e442132b710e633c74339e6af401f4ec91c489ebf5b04a |
| 0002-bundled-bindings.patch | 9c455dea8bc3ed35fad332f2e1da3bcd0df6717df48479a487b9c00f7ee321c1 |
| Resulting Cargo.lock | 36729e70990ec4162a2d655d5991f91ed4a61c8f42ffadf2df02ff62819d522f |
| Tested release binary | 227166b96079804fc897646a4a83603005ce08f19726b4598cfeb9ef6276e22b |

The binary hash identifies the measured artifact, not a promise that different
build paths or host toolchains produce a bit-identical executable.
