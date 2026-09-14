#!/usr/bin/env python3
"""Build locked native dependencies without Homebrew or implicit wrap downloads."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'experiments/hvf/build/distribution'
LOCK = Path(__file__).with_name('sources.json')


def run(*args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, **kwargs)


def main():
    BASE.mkdir(parents=True, exist_ok=True)
    locked = json.loads(LOCK.read_text())
    cache = BASE / 'downloads'
    cache.mkdir(exist_ok=True)
    for name, source in locked.items():
        target = cache / name
        # Reuse existing verified downloads from exploratory builds.
        candidates = [BASE / name, BASE / 'glib-2.88.3/subprojects/packagecache' / name]
        if not target.exists():
            existing = next((p for p in candidates if p.is_file()), None)
            temporary = target.with_suffix(target.suffix + '.partial')
            if existing:
                shutil.copyfile(existing, temporary)
            else:
                with urllib.request.urlopen(source['url'], timeout=60) as response, temporary.open('wb') as out:
                    shutil.copyfileobj(response, out)
            temporary.replace(target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != source['sha256']:
            raise SystemExit(f'Checksum mismatch: {target}')
    source = BASE / 'glib-2.88.3'
    if not source.exists():
        with tarfile.open(cache / 'glib-2.88.3.tar.xz') as archive:
            # Source archive is authenticated above, never a guest-provided archive.
            archive.extractall(BASE)
    wraps = source / 'subprojects/packagecache'
    wraps.mkdir(exist_ok=True)
    for name in locked:
        if not name.endswith('.whl') and not name.startswith('glib-'):
            shutil.copyfile(cache / name, wraps / name)
    venv = BASE / 'tools'
    if not (venv / 'bin/python3').exists():
        run('/usr/bin/python3', '-m', 'venv', venv)
    run(venv / 'bin/python3', '-m', 'pip', 'install', '--no-index', '--no-deps',
        *[cache / name for name in locked if name.endswith('.whl')])
    env = dict(os.environ, PATH=f'{venv}/bin:/usr/bin:/bin:/usr/sbin:/sbin',
               CC='/usr/bin/clang', CXX='/usr/bin/clang++', MACOSX_DEPLOYMENT_TARGET='26.0',
               PKG_CONFIG_LIBDIR=str(BASE / 'empty-pkgconfig'))
    # Do not let caller search paths silently import Homebrew dependencies.
    for key in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
                'PKG_CONFIG_PATH', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS'):
        env.pop(key, None)
    build = BASE / 'glib-build'
    if not (build / 'build.ninja').exists():
        run('meson', 'setup', build, source, f'--prefix={BASE}/native', '--libdir=lib',
            '--buildtype=release', '--wrap-mode=nodownload',
            '--force-fallback-for=libpcre2-8,libffi,intl', '-Dtests=false',
            '-Dinstalled_tests=false', '-Ddocumentation=false', '-Dman-pages=disabled',
            '-Dintrospection=disabled', '-Dnls=disabled', '-Dsysprof=disabled',
            '-Ddtrace=disabled', '-Dsystemtap=disabled', '-Dselinux=disabled',
            '-Dlibmount=disabled', env=env)
    run('meson', 'compile', '-C', build, '-j', '4', env=env)
    run('meson', 'install', '-C', build, '--no-rebuild', env=env)
    print(f'GLIB_PREFIX={BASE}/native')


if __name__ == '__main__':
    main()
