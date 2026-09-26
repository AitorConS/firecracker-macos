<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reproduce the Linux Firecracker 1.10.1 guest-exit candidate

Source: upstream Firecracker tag `v1.10.1`, commit `1fcdaec088da9e30c2c111f9feb2649118488361`. The runtime patch is `0001-guest-exit.patch` (SHA256 `3d451d5138be33c256e442132b710e633c74339e6af401f4ec91c489ebf5b04a`) and changes only `src/vmm/src/vstate/vcpu/mod.rs` and `x86_64.rs`. The task-owned build checkout also uses `0002-bundled-bindings.patch` (SHA256 `9c455dea8bc3ed35fad332f2e1da3bcd0df6717df48479a487b9c00f7ee321c1`): it removes `aws-lc-rs`'s explicit `bindgen` feature in `src/vmm/Cargo.toml` so its bundled x86_64 musl bindings are used. This was required because on this host Clang 21 generated bindings omitted several functions including `ERR_GET_LIB_RUST`, `BIO_ctrl`, and `CRYPTO_library_init`; the initial failed attempts are archived as `firecracker-test-guest-exit*.log`.

The compatibility patch also updates `Cargo.lock`: it removes the inactive optional `aws-lc-fips-sys 0.12.13` entry and that optional dependency edge from `aws-lc-rs`. No active package versions or checksums changed in the lock diff. The original active dependency tree (checked with `cargo tree --locked -i aws-lc-sys -e features`) used `aws-lc-sys 0.22.0` via `aws-lc-rs` and did not activate `aws-lc-fips-sys`; the resulting build is non-FIPS as before. The frozen resulting `Cargo.lock` is included here, SHA256 `36729e70990ec4162a2d655d5991f91ed4a61c8f42ffadf2df02ff62819d522f`. `final-source.diff` contains the exact combined source and lock diff after the baseline TSC control and is byte-identical to the pre-control `build-checkout.diff` (SHA256 `003f72138dd6c0acf7ab07ab5ce9180df9c9972bdb14a027507621c836c2f30b`).

## Prepare a separate checkout

Keep this repository unchanged; use a fresh task-owned directory for the pinned
Linux source. The archive paths below record the measured host, and may be
replaced with a different dedicated build directory. From this patch directory,
record its absolute path, then clone upstream and verify the exact revision:

```sh
patch_dir="$PWD"
base=/home/aitorcons/jbench-linux-dev
# The destination must not already contain another checkout.
git clone --branch v1.10.1 --depth 1 https://github.com/firecracker-microvm/firecracker.git "$base/firecracker-v1.10.1"
cd "$base/firecracker-v1.10.1"
test "$(git rev-parse HEAD)" = 1fcdaec088da9e30c2c111f9feb2649118488361
git apply "$patch_dir/0001-guest-exit.patch"
git apply "$patch_dir/0002-bundled-bindings.patch"
sha256sum Cargo.lock
```

Check Cargo.lock against the hash below before building. Once the scoped Rust
environment below is set, populate a fresh cache with
`cargo fetch --locked --target x86_64-unknown-linux-musl`; the recorded offline
commands assume those dependencies are already present. No dependency update is
needed. Evidence logs and runtime test scripts referenced below live in the
external task archive `jerboa-bench/evidence/linux-vmm-v1.10.1/`, not this source
directory.

## Host and scoped prerequisites

The build host was Ubuntu 26.04 x86_64, Linux `7.0.0-28-generic`, two vCPUs, 4 GiB RAM. The initially absent packages were installed with:

```sh
sudo apt-get install -y --no-install-recommends musl-tools libclang-dev cmake pkg-config
```

APT installed 18 new packages, zero upgrades/removals. Versions used: `musl-tools` and `musl-dev` 1.2.5-3build1, `libclang-dev` 1:21.1.6-71, `libclang-21-dev` 1:21.1.8-6ubuntu1, `cmake` 4.2.3-2ubuntu2, `pkg-config` 2.5.1-4. Full package transaction is in the host's `/var/log/apt/history.log` at 2026-09-26 19:54 UTC. `/usr/bin/musl-gcc` and `/usr/lib/llvm-21/lib/libclang.so` were available afterward.

Official `rustup-init` for x86_64 Linux GNU was downloaded from `https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init` and checked against its adjacent `.sha256`: `dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71`. It was installed **only under task-owned paths** by setting `RUSTUP_HOME=/home/aitorcons/jbench-linux-dev/rustup-home`, `CARGO_HOME=/home/aitorcons/jbench-linux-dev/cargo-home` and running `rustup-init -y --no-modify-path --default-toolchain 1.79.0 --profile minimal --target x86_64-unknown-linux-musl`. The direct toolchain binaries reported `rustc 1.79.0 (129f3b996 2024-06-10)` and `cargo 1.79.0 (ffa9cf99a 2024-06-03)`. No global PATH/toolchain installation was required.

The scoped Linux UAPI include directory was created exactly as follows, because `userfaultfd-sys` could not find `linux/types.h` under the musl include search path:

```sh
base=/home/aitorcons/jbench-linux-dev
mkdir -p "$base/linux-uapi-headers"
ln -s /usr/include/linux "$base/linux-uapi-headers/linux"
ln -s /usr/include/x86_64-linux-gnu/asm "$base/linux-uapi-headers/asm"
ln -s /usr/include/asm-generic "$base/linux-uapi-headers/asm-generic"
```

The successful **focused test and release build** used these variables (the test additionally set `CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0`; the first successful focused test set `LIBCLANG_PATH=/usr/lib/llvm-21/lib`, which is unnecessary once bundled bindings are selected):

```sh
base=/home/aitorcons/jbench-linux-dev
export RUSTUP_HOME="$base/rustup-home" CARGO_HOME="$base/cargo-home"
export RUSTUP_TOOLCHAIN=1.79.0 CARGO_TARGET_DIR="$base/firecracker-target"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
export CMAKE_POLICY_VERSION_MINIMUM=3.5
export CFLAGS_x86_64_unknown_linux_musl="-I$base/linux-uapi-headers -Wno-error=unterminated-string-initialization"
export AWS_LC_SYS_CFLAGS=-Wno-error=unterminated-string-initialization
export PATH="$CARGO_HOME/bin:$PATH"
cd "$base/firecracker-v1.10.1"
cargo test --locked --offline --target x86_64-unknown-linux-musl -j2 -p vmm test_guest_exit_port -- --nocapture
cargo build --locked --offline --release --target x86_64-unknown-linux-musl -j2 -p firecracker
```

The `CMAKE_POLICY_VERSION_MINIMUM=3.5` variable is needed for this older AWS-LC CMake project under host CMake 4.2; the scoped CFLAGS also suppress the GCC 15 `-Werror=unterminated-string-initialization` failure in AWS-LC. Earlier attempts were kept as failed logs rather than counted as passing builds. The release log reports `Finished release profile [optimized]` in 3m18s and yielded a static PIE Firecracker 1.10.1 executable, SHA256 `227166b96079804fc897646a4a83603005ce08f19726b4598cfeb9ef6276e22b` (`firecracker-v1.10.1-guest-exit`). It was copied outside Cargo's target directory before deleting build intermediates. The installed `/usr/local/bin/firecracker` stayed at SHA256 `96d25e000e5fcbf5b11dca0e1275b5d7dc0922ff8b8206aeaed98e515a8468dc`.

## Tests and controls

- Focused `test_guest_exit_port`: 1 passed. Broader vCPU tests as root: 25 passed, 1 failed (`test_set_tsc` expected an error but KVM returned success on this VPS). Temporarily restoring only the two patched vCPU files to upstream while retaining the same Cargo.toml/lock/env reproduced the exact same TSC assertion failure; see `vmm-tsc-baseline/run.log`, `test-rc.txt=101`. The guest-exit patch was reapplied and its SHA256 verified exactly.
- Original 40 guest runs are in `vmm-exit-v1.10.1/`. A second 40 guest run matrix in `vmm-exit-marker-v1.10.1/` required a unique guest output marker before exit. At each 1 and 2 vCPUs, all ten `exit 0` cases had CLI status 0 and no Firecracker error; all ten `exit 7` cases had CLI status 1 and the exact Firecracker failed-exit line. Every run showed its guest marker; no timeout or startup error was accepted.
- A guest BusyBox shell printed a marker, sent SIGSEGV to itself, printed `*** signal 11 received`, and returned CLI status 1 with Firecracker failed-exit output (`vmm-guest-sigsegv-v1.10.1/`). Separately, a running guest's **host Firecracker process** was SIGKILLed and logged `signal: killed` (`vmm-signal-v1.10.1/`). The first host-signal attempt used `sh -c sleep 30`, which exited immediately because fork is unavailable; it is preserved in the same directory and was corrected to invoke BusyBox `sleep` directly.
- On the VPS, root `perf stat -e cycles,instructions -- true` reported unsupported hardware events, while `perf stat -e task-clock,context-switches -- true` and `perf record -e cpu-clock -- true` worked. `perf-probe.log` records the software sampling probe. A separate network profile is planned after scored suites.

After archiving the executable, logs, source diff, and lockfile, only the task-owned Cargo target, scoped Rustup/Cargo homes, and rustup download were removed; the source checkout and stable candidate executable remain under `~/jbench-linux-dev`. A mistaken version query through the rustup shim without `RUSTUP_HOME` created `/home/aitorcons/.rustup` at 20:30 UTC (~1.2 GiB); that newly created directory was identified and removed immediately, restoring disk space, and later version checks used direct scoped toolchain binaries. The installed Jerboa service and Firecracker binary were unchanged. Thirteen task-created image tags were removed through the dev daemon after zero VM/volume checks (`dev-image-cleanup/`), leaving 5.4 GiB free before final scoring.
