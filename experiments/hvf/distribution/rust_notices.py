#!/usr/bin/env python3
"""Collect actual macOS dependency notices from Cargo's locked dependency graph."""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def collect(destination):
    env = dict(os.environ, RUSTUP_TOOLCHAIN='1.97.0')
    cargo = shutil.which('cargo')
    if not cargo:
        env['RUSTUP_HOME'] = str(ROOT / 'experiments/hvf/build/rustup')
        env['CARGO_HOME'] = str(ROOT / 'experiments/hvf/build/cargo')
        cargo = str(Path(env['CARGO_HOME']) / 'bin/cargo')
    metadata = json.loads(subprocess.check_output([cargo, 'metadata', '--locked', '--offline',
        '--format-version', '1', '--filter-platform', 'aarch64-apple-darwin'], cwd=ROOT, env=env))
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    packages = {p['id']: p for p in metadata['packages']}
    stack = [p['id'] for p in packages.values() if p['name'] == 'firecracker']
    seen = set()
    while stack:
        identity = stack.pop()
        if identity in seen:
            continue
        seen.add(identity)
        stack.extend(d['pkg'] for d in nodes[identity]['deps']
                     if any(k['kind'] != 'dev' for k in d['dep_kinds']))
    result = []
    for identity in sorted(seen):
        package = packages[identity]
        directory = Path(package['manifest_path']).parent
        notices = sorted(p for p in directory.iterdir() if p.is_file() and
                         p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT')))
        if package.get('license_file'):
            notices.append(directory / package['license_file'])
        if not notices and directory.is_relative_to(ROOT):
            notices = [ROOT / 'LICENSE']
        if not notices:
            raise RuntimeError(f'Missing original license notices: {identity}')
        target = destination / f"{package['name']}-{package['version']}"
        target.mkdir(parents=True)
        for notice in notices:
            shutil.copyfile(notice, target / notice.name)
        result.append({'name': package['name'], 'version': package['version'],
                       'license_expression': package['license'], 'source': package['source'],
                       'notices': [str((target / p.name).relative_to(destination)) for p in notices]})
    rustc = str(Path(cargo).with_name('rustc'))
    sysroot = Path(subprocess.check_output([rustc, '--print', 'sysroot'], env=env, text=True).strip())
    standard = sysroot / 'share/doc/rust/COPYRIGHT-library.html'
    if not standard.is_file():
        raise RuntimeError('Rust standard-library copyright bundle is missing')
    shutil.copyfile(standard, destination / 'rust-standard-library-COPYRIGHT.html')
    (destination / 'dependencies.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
