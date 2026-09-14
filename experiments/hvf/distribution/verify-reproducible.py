#!/usr/bin/env python3
"""Rebuild native objects and Rust twice, then compare unsigned packaged Mach-O."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'experiments/hvf/build/distribution'


def run(args, env):
    subprocess.run([str(a) for a in args], cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New evidence directory')
    parser.add_argument('--reuse-native', action='store_true', help='Read installed native dependencies without rebuilding or replacing shared dylibs')
    args = parser.parse_args()
    # Keep both builds and logs as evidence; never clean the user's ordinary target.
    work = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='repro-', dir=BASE))
    if args.output: work.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, RUSTUP_HOME=str(ROOT / 'experiments/hvf/build/rustup'),
               CARGO_HOME=str(ROOT / 'experiments/hvf/build/cargo'), RUSTUP_TOOLCHAIN='1.97.0',
               GLIB_PREFIX=str(BASE / 'native'), MACOSX_DEPLOYMENT_TARGET='26.0')
    env['PATH'] = f"{env['CARGO_HOME']}/bin:{BASE}/tools/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    for key in ('CPATH', 'LIBRARY_PATH', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS',
                'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'PKG_CONFIG_PATH', 'RUSTC_WRAPPER'):
        env.pop(key, None)
    manifests = []
    for iteration in (1, 2):
        target = work / f'target-{iteration}'
        env['RUSTFLAGS'] = f'-Ccodegen-units=1 --remap-path-prefix={target}=/build --remap-path-prefix={ROOT}=/firecracker'
        if not args.reuse_native:
            run(['meson', 'compile', '-C', BASE / 'glib-build', '--clean'], env)
            run(['meson', 'compile', '-C', BASE / 'glib-build', '-j', '4'], env)
            run(['meson', 'install', '-C', BASE / 'glib-build', '--no-rebuild'], env)
        run(['cargo', 'build', '--locked', '--offline', '-p', 'firecracker', '--release',
             '--target', 'aarch64-apple-darwin', '--target-dir', target], env)
        package = work / f'package-{iteration}'
        run([sys.executable, Path(__file__).with_name('package.py'), '--binary',
             target / 'aarch64-apple-darwin/release/firecracker', package], env)
        manifests.append(json.loads((package / 'manifest.json').read_text()))
    first, second = [m['unsigned_macho_sha256'] for m in manifests]
    report = {'scope': 'unsigned Mach-O; same source, SDK, compiler and native prefix; separate Rust target directories',
              'native_dependencies_rebuilt': not args.reuse_native,
              'build_directories': [str(work / f'package-{i}') for i in (1, 2)],
              'first': first, 'second': second, 'equal': first == second}
    (work / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    if first != second:
        raise SystemExit('Unsigned Mach-O reproducibility mismatch')


if __name__ == '__main__':
    main()
