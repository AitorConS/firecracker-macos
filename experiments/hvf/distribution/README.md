# Experimental local macOS ARM64 package

The package includes the macOS 1.0 API and the network and storage regressions.
The final 24-hour test, other Macs, and publicly signed distribution
are not certified. See the [available tests](../ci/README.md).

Requires macOS 26 and Apple Silicon with Hypervisor available. The
`bin/firecracker` executable uses the libraries in `lib/` relative to its location.
Keep both folders together. Does not require Homebrew to run.

`bin/firecracker --api-sock /private/path/vmm.sock` starts the supervisor.
Guests and disks are provided by the user. The configuration requires
`security: {"version": 1}` and denies networking by default; IPv4/port/protocol authorizations
must be declared explicitly. The macOS 1.0 API includes
Pause/Resume and local format-1 snapshots. Capture from Paused with
`PUT /snapshot/create {"snapshot_path":"/private/path/snapshot"}` and restore
with `/snapshot/load` using the same body. See `/operations/{id}`; the
restore ends in Paused. Requires the same Mac, macOS build and VMM build.
Disks are copied and network connections must be re-established.

To rebuild from the repository:

```sh
/usr/bin/python3 experiments/hvf/distribution/build-native-deps.py
GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native" experiments/hvf/build-native.sh
/usr/bin/python3 experiments/hvf/distribution/package.py /path/new/package
```

Rust is pinned to 1.97.0; Rust dependencies are recorded in Cargo.lock.
Native sources and Meson/Ninja tools are pinned by SHA-256 in
sources.json. The Apple SDK/compiler is recorded in the manifest: it is not
downloaded nor considered interchangeable with another version. Native sources
are included in sources/, with the libslirp patch. GLib licenses are
included in licenses/ and their original notices remain in the source file.

The package has an ad-hoc signature, without notarization. The manifest distinguishes pre-signing Mach-O hashes
and final checksums. Comparing two builds with clean native objects and separate Cargo targets
confirmed equality of the three unsigned Mach-Os on this host/SDK.
`verify-reproducible.py` repeats the check; it does not cover provenance metadata
or signatures/notarization. Notices for Rust dependencies and their standard library are included
in licenses/rust/. It is not a finished commercial release.

The `test-relocated.py PACKAGE --linux-config CONFIG` test runs the regressions
with the package copied to a temporary directory. It also boots a real synthetic guest
under an external profile that denies the repository, /opt/homebrew and /usr/local.
This additional check uses explicit development mode: macOS rejects installing
the internal Seatbelt profile inside another inherited sandbox. The
main suite does retain hardened mode and its internal profiles.

`sign-notarize.sh PACKAGE NEW.pkg` optionally prepares a signed installer,
submits it to Apple and requests stapling. Requires APPLICATION_IDENTITY,
INSTALLER_IDENTITY and NOTARY_PROFILE already configured. It does not run as part
of the local build, requires credentials and performs an external transmission.
It has not yet been validated with commercial identities. The package would install
to /usr/local/libexec/firecracker-hvf; the local build installs nothing there.

For a functional review limited to packaging, run
`test-relocated.py PACKAGE --packaging-only`. This option selects explicit
control and synthetic snapshot tests, plus the relocated boot
with repository/Homebrew access denied. It excludes network,
security, stress and stability tests, and does not accept Linux configuration. Running
without this option does include network/security cases from the full suites.

The original Firecracker notices (`NOTICE` and `THIRD-PARTY`) are retained
and those for proxy-libintl, PCRE2 and libffi are exposed in `licenses/`, in addition to
their original sources. The original NOTICE contains references to the Linux/libseccomp bundle; the inventory for this macOS package is in the manifest
and in its Mach-O dependencies.
