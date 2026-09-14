#!/usr/bin/env python3
"""Stage a relocatable ad-hoc ARM64 package; reject non-system external dylibs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from rust_notices import collect

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / 'experiments/hvf/build/distribution/native'


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True).strip()


def dependencies(path):
    return [line.strip().split(' (compatibility version')[0]
            for line in run('/usr/bin/otool', '-L', path).splitlines()[1:]]


def system(path):
    return path.startswith(('/usr/lib/', '/System/Library/'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/macos-arm64/firecracker')
    parser.add_argument('output', type=Path, help='New destination directory (must not exist)')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    executable = output / 'bin/firecracker'
    executable.parent.mkdir()
    (output / 'lib').mkdir()
    shutil.copy2(args.binary, executable)
    # Remove linker debug-map entries containing absolute object/target paths.
    run('/usr/bin/strip', '-S', executable)
    pending = [executable]
    binaries = []
    while pending:
        binary = pending.pop()
        binaries.append(binary)
        for dependency in dependencies(binary):
            if system(dependency):
                continue
            original = Path(dependency)
            if not original.is_absolute() or not original.resolve().is_relative_to(NATIVE.resolve()):
                raise SystemExit(f'Unexpected dependency in {binary}: {dependency}')
            library = output / 'lib' / original.name
            if not library.exists():
                shutil.copy2(original, library)
                pending.append(library)
            replacement = ('@loader_path/../lib/' if binary == executable else '@loader_path/') + library.name
            run('/usr/bin/install_name_tool', '-change', dependency, replacement, binary)
        if binary != executable:
            run('/usr/bin/install_name_tool', '-id', '@loader_path/' + binary.name, binary)
    # Record content before distribution signing; reproducibility still requires two clean builds.
    unsigned = {}
    for binary in binaries:
        subprocess.run(['/usr/bin/codesign', '--remove-signature', str(binary)],
                       check=True, capture_output=True)
        unsigned[str(binary.relative_to(output))] = digest(binary)
    for binary in binaries:
        command = ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none']
        if binary == executable:
            command += ['--entitlements', str(ROOT / 'experiments/hvf/entitlements.plist')]
        run(*command, binary)
        run('/usr/bin/codesign', '--verify', '--strict', binary)
        for dependency in dependencies(binary):
            if not system(dependency) and not dependency.startswith('@loader_path/'):
                raise SystemExit(f'Non-relocatable dependency: {dependency}')
    licenses = output / 'licenses'
    licenses.mkdir()
    rust_dependencies=collect(licenses / 'rust')
    shutil.copy2(ROOT / 'LICENSE', licenses / 'firecracker-Apache-2.0.txt')
    for notice in ('NOTICE', 'THIRD-PARTY'):
        shutil.copy2(ROOT / notice, licenses / ('firecracker-' + notice))
    shutil.copy2(ROOT / 'src/hvf-vmm/vendor/libslirp/COPYRIGHT', licenses / 'libslirp-COPYRIGHT')
    source = ROOT / 'experiments/hvf/build/distribution/glib-2.88.3'
    shutil.copytree(source / 'LICENSES', licenses / 'glib')
    # Include dependency source archives and local network patch for source availability.
    sources = output / 'sources'
    shutil.copytree(ROOT / 'experiments/hvf/build/distribution/downloads', sources)
    # Expose the original native notices alongside the binaries' other licenses.
    for archive, member, name in (
        ('proxy-libintl-0.5.tar.gz', 'proxy-libintl-0.5/COPYING', 'proxy-libintl-COPYING'),
        ('pcre2-10.46.tar.bz2', 'pcre2-10.46/COPYING', 'pcre2-COPYING'),
        ('libffi-3.5.2.tar.gz', 'libffi-3.5.2/LICENSE', 'libffi-LICENSE'),
    ):
        with tarfile.open(sources / archive) as source_archive:
            with source_archive.extractfile(member) as notice:
                (licenses / name).write_bytes(notice.read())
    shutil.copytree(ROOT / 'src/hvf-vmm/vendor', sources / 'network')
    shutil.copy2(Path(__file__).with_name('sources.json'), output / 'native-sources.json')
    shutil.copy2(ROOT / 'Cargo.lock', output / 'Cargo.lock')
    shutil.copy2(Path(__file__).with_name('README.md'), output / 'README.md')
    manifest = {'format_version': 1, 'architecture': 'arm64', 'minimum_macos': '26.0',
                'api': '1.0', 'signing': 'ad-hoc', 'notarized': False,
                'rust': '1.97.0', 'rust_dependencies': rust_dependencies, 'sdk': run('/usr/bin/xcrun', '--show-sdk-version'),
                'compiler': run('/usr/bin/clang', '--version'),
                'git_commit': run('git', '-C', ROOT, 'rev-parse', 'HEAD'),
                'dirty': bool(run('git', '-C', ROOT, 'status', '--porcelain')),
                'unsigned_macho_sha256': unsigned, 'reproducibility_verified': False}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    files = sorted(p for p in output.rglob('*') if p.is_file())
    (output / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(output)}\n' for p in files))
    print(output)


if __name__ == '__main__':
    main()
