#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Discriminate SCM_RIGHTS lifetime protection with real TCP and UDP gates.

Control closes only the sender's reference early and accepts the resulting ACK.
The default host churn schedules Darwin's Unix-socket GC without modifying any
transferred descriptor. Serialize this test with other network load campaigns.
"""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--count', type=int, default=4000)
    p.add_argument('--churn', type=int, choices=(0, 1), default=1)
    p.add_argument('--sanitize', action='store_true')
    p.add_argument('--fixed-only', action='store_true')
    p.add_argument('--output', type=Path, default=HERE / 'build/network-transfer')
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    native = ROOT / 'src/hvf-vmm/native'
    fixed = native / 'socket_gate.c'
    text = fixed.read_text()
    replacements = {
        'held=descriptor;held_id=request->id;': 'close(descriptor); /* early-close control */',
        'if(held<0||request->id!=held_id)return -1;': 'if(held<0)return 0; /* ignore control ACK */\n        if(request->id!=held_id)return -1;',
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise SystemExit('Transfer control anchor changed; review mutation: ' + old)
        text = text.replace(old, new)
    control = out / 'control-gate.c'
    control.write_text(text)
    sources = {'fixed': fixed} if a.fixed_only else {'control': control, 'fixed': fixed}
    flags = ['-g', '-O1', '-std=gnu11', '-D_DARWIN_C_SOURCE',
             '-mmacosx-version-min=26.0', '-I' + str(native)]
    if a.sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    for protocol in ('tcp', 'udp'):
        for variant, gate in sources.items():
            args = ['xcrun', 'clang', *flags]
            if protocol == 'udp':
                args += ['-DGATE_SOURCE="' + str(gate) + '"']
            args += [HERE / f'test-network-transfer-{protocol}.c']
            if protocol == 'tcp':
                args += [gate]
            args += [native / 'policy.c', native / 'sandbox.c', '-o', out / f'{protocol}-{variant}']
            subprocess.run(args, check=True)
    rows = []
    for i in range(a.repeat):
        for protocol in ('tcp', 'udp'):
            for variant in sources:
                args = [str(a.count), str(a.churn)] if protocol == 'tcp' else [str(a.churn), str(a.count)]
                r = subprocess.run([out / f'{protocol}-{variant}', *args], capture_output=True, text=True, timeout=180)
                (out / f'{protocol}-{variant}-{i}.log').write_text(r.stdout + r.stderr)
                if protocol == 'tcp':
                    row = json.loads(r.stdout.strip().splitlines()[-1])
                    ok = row['ok'] == a.count and r.returncode == 0
                    discriminates = row['eof_before_byte'] > 0
                else:
                    line = next(s for s in r.stdout.splitlines() if s.startswith('RESULT '))
                    row = {k: int(v) for k, v in (s.split('=') for s in line.split()[1:])}
                    ok = r.returncode == 0 and row['queries_ok'] == 2 * a.count
                    discriminates = row['dead_channels'] > 0
                sanitizer = 'ERROR: AddressSanitizer' in r.stderr or 'runtime error:' in r.stderr
                row.update(protocol=protocol, variant=variant, repeat=i, exit=r.returncode,
                           sanitizer=sanitizer, passed=ok, discriminates=discriminates)
                rows.append(row)
                print(json.dumps(row), flush=True)
                (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    if any(r['sanitizer'] or (r['variant'] == 'fixed' and not r['passed']) for r in rows):
        raise SystemExit('Corrected transfer regression failed; see results.json')
    if a.churn and not a.fixed_only:
        for protocol in ('tcp', 'udp'):
            if not any(r['variant'] == 'control' and r['protocol'] == protocol and r['discriminates'] for r in rows):
                raise SystemExit('Control did not reproduce ' + protocol + '; no discriminant established')


if __name__ == '__main__':
    main()
