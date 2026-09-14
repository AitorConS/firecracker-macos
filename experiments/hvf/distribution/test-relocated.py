#!/usr/bin/env python3
"""Run real HVF regressions after relocation, denying source/Homebrew access."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]

# Explicit allowlist: additions to the full suites cannot silently enable network,
# security, stress or stability tests in a packaging-only review.
PACKAGING_TESTS = [
    'test_control.ControlTests.' + name for name in (
        'test_pause_freezes_virtual_counter',
        'test_elf_error_is_returned_and_can_retry',
        'test_locked_source_cannot_be_copied',
        'test_vm_exit_preserves_api_and_exit_state',
        'test_start_can_be_cancelled_without_closing_api',
        'test_shutdown_requires_capability',
        'test_shutdown_timeout_requires_explicit_escalation',
        'test_metrics_json_and_prometheus',
        'test_operation_result_survives_restart',
        'test_force_stop_preserves_api_and_allows_restart',
    )
] + [
    'test_snapshot.SnapshotTests.' + name for name in (
        'test_capture_restore_paused_ram_and_offline_cpus',
        'test_restore_cancellation_keeps_supervisor_responsive',
        'test_all_disks_readonly_and_firmware_are_self_contained',
    )
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--linux-config', type=Path)
    # The snapshot regression needs its own guest: the plain Linux initrd does not
    # serve the disk round trip it asserts, so reusing --linux-config for both
    # failed on the fixture, not on the package.
    parser.add_argument('--snapshot-config', type=Path,
                        default=ROOT / 'build/linux-snapshot-guest/config.json')
    parser.add_argument('--packaging-only', action='store_true',
                        help='Only offline functional tests; no network/security/stress/stability tests')
    args = parser.parse_args()
    if args.packaging_only and args.linux_config:
        parser.error('--packaging-only cannot be combined with --linux-config')
    with tempfile.TemporaryDirectory(prefix='hvf-relocated-') as temporary:
        work = Path(temporary).resolve()
        package = work / 'package'
        shutil.copytree(args.package, package)
        profile = work / 'isolation.sb'
        # Only the executable is sandboxed; the external test driver reads tests.
        profile.write_text('(version 1)\n(allow default)\n' + ''.join(
            f'(deny file-read* file-write* (subpath {json.dumps(str(path))}))\n'
            for path in (ROOT, Path('/opt/homebrew'), Path('/usr/local'))))
        wrapper = work / 'firecracker'
        # Paths contain no user-provided shell text.
        import shlex
        wrapper.write_text('#!/bin/sh\nexec /usr/bin/sandbox-exec -f ' + shlex.quote(str(profile))
                           + ' ' + shlex.quote(str(package / 'bin/firecracker')) + ' "$@"\n')
        wrapper.chmod(0o700)
        env = {**os.environ, 'HVF_BINARY': str(package / 'bin/firecracker'), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
        for key in list(env):
            if key.startswith('DYLD_'):
                env.pop(key)
        tests = PACKAGING_TESTS if args.packaging_only else ['test_control', 'test_snapshot']
        subprocess.run(['/usr/bin/python3', '-m', 'unittest', '-v', *tests],
                       cwd=ROOT / 'experiments/hvf', env=env, check=True)
        def relocate(source, name):
            # Copy the guest assets out of the repository so the run does not read
            # anything the isolation profile denies to the packaged executable.
            config = json.loads(Path(source).read_text())
            boot = config['boot-source']
            for key in ('kernel_image_path', 'initrd_path'):
                if key in boot:
                    target = work / f'{name}-{key}'
                    shutil.copyfile(boot[key], target)
                    boot[key] = str(target)
            local = work / f'{name}.json'
            local.write_text(json.dumps(config))
            return local
        if args.linux_config:
            subprocess.run(['/usr/bin/python3', ROOT / 'experiments/hvf/test-linux.py',
                            '--config', relocate(args.linux_config, 'linux')], env=env, check=True)
            subprocess.run(['/usr/bin/python3', ROOT / 'experiments/hvf/test-snapshot-linux.py',
                            '--config', relocate(args.snapshot_config, 'snapshot'),
                            '--output-prefix', ROOT / 'experiments/hvf/build/relocated-snapshot'], env=env, check=True)
        # macOS rejects sandbox_init inside an inherited sandbox. Validate dependency
        # independence with explicit development mode under the external deny profile.
        import sys
        sys.path.insert(0, str(ROOT / 'experiments/hvf'))
        from test_control import elf
        kernel = work / 'exit.elf'
        kernel.write_bytes(elf([0xd2800100, 0xf2b08000, 0xd4000002]))  # PSCI SYSTEM_OFF
        config = work / 'external-sandbox.json'
        config.write_text(json.dumps({'boot-source': {'kernel_image_path': str(kernel)},
                                     'security': {'version': 1, 'mode': 'development'}}))
        subprocess.run([str(wrapper), '--no-api', '--config-file', str(config)],
                       cwd=work, env=env, check=True, timeout=10)
        print('Relocated hardened regressions passed; separate real HVF boot passed '
              'with repository/Homebrew denied (explicit development mode, external Seatbelt)')


if __name__ == '__main__':
    main()
