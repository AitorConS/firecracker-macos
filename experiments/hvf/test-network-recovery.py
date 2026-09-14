#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and run the UDP listener recovery regression: control vs patched gate.

Both variants compile current production sources. Control disables only the
listener-recovery branch; the transfer ACK and RPC failure handling are preserved.
Everything is written below --output.
"""
import argparse, json, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
W = Path(__file__).resolve().parent
GATES = {'fixed': ROOT / 'src/hvf-vmm/native/socket_gate.c'}
# (control exit, fixed exit). 1 = contract violated. Non-discriminating
# scenarios check that the patch keeps the behaviour that was already right.
EXPECT = {'isolated': (0, 0), 'recover': (1, 0), 'repeat': (1, 0), 'budget': (1, 0), 'alternating': (1, 0),
          'ephemeral': (0, 0), 'pressure': (1, 0), 'authority-down': (0, 0)}
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repeat', type=int, default=5)
    p.add_argument('--sanitize', action='store_true')
    p.add_argument('--fixed-only', action='store_true')
    p.add_argument('--scenario', action='append', choices=sorted(EXPECT))
    p.add_argument('--output', type=Path, default=W / 'build/network-recovery')
    p.add_argument('--gate', action='append', default=[], help='VARIANT=PATH override (diagnostic copies)')
    a = p.parse_args(); out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    for override in a.gate:
        name, path = override.split('=', 1); GATES[name] = Path(path).resolve()
    if 'control' not in GATES:
        text = GATES['fixed'].read_text()
        marker = 'if(client_binds[fd].sin_port){'
        if text.count(marker) != 1: raise SystemExit('Recovery control anchor changed; review mutation')
        control = out / 'control-gate.c'
        control.write_text(text.replace(marker, 'if(0){ /* regression: disable listener recovery only */'))
        GATES['control'] = control
    native = ROOT / 'src/hvf-vmm/native'; src = ROOT / 'src/hvf-vmm/vendor/libslirp/src'; glib = ROOT / 'experiments/hvf/build/distribution/native'
    flags = ['-g', '-O1', '-std=gnu99', '-D_DARWIN_C_SOURCE', '-DBUILDING_LIBSLIRP', '-mmacosx-version-min=26.0',
             *['-I' + str(f) for f in (native, src, glib / 'include/glib-2.0', glib / 'lib/glib-2.0/include')]]
    if a.sanitize: flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    objs = []; (out / 'obj').mkdir(exist_ok=True)
    for f in sorted(src.glob('*.c')):
        o = out / 'obj' / (f.stem + '.o')
        subprocess.run(['xcrun', 'clang', *flags, '-include', str(native / 'slirp_policy.h'), '-c', str(f), '-o', str(o)], check=True)
        objs.append(o)
    results = []; failures = []
    variants = ('fixed',) if a.fixed_only else ('control', 'fixed')
    for variant in variants:
        binary = out / variant
        subprocess.run(['xcrun', 'clang', *flags, '-DGATE_SOURCE="%s"' % GATES[variant], str(W / 'test-network-recovery.c'),
                        str(native / 'policy.c'), str(native / 'sandbox.c'), *map(str, objs), '-L' + str(glib / 'lib'),
                        '-lglib-2.0', '-lresolv', '-o', str(binary)], check=True)
        for scenario in a.scenario or sorted(EXPECT):
            expected = EXPECT[scenario][variants.index(variant) if not a.fixed_only else 1] if not a.fixed_only else EXPECT[scenario][1]
            for i in range(a.repeat):
                t0 = time.monotonic()
                try:
                    r = subprocess.run([str(binary), scenario], capture_output=True, timeout=60)
                    code, stdout, stderr = r.returncode, r.stdout, r.stderr
                except subprocess.TimeoutExpired as e:
                    code, stdout, stderr = 'timeout', e.stdout or b'', e.stderr or b''
                log = out / f'{variant}-{scenario}-{i}.log'; log.write_bytes(stdout + b'\n--- stderr ---\n' + stderr)
                text = stdout.decode(errors='replace')
                line = next((s for s in text.splitlines() if s.startswith('RESULT ')), None)
                fail = next((s for s in text.splitlines() if s.startswith('FAIL ')), None)
                sanitizer = b'ERROR: AddressSanitizer' in stderr or b'runtime error:' in stderr
                ok = code == expected and not sanitizer
                entry = {'variant': variant, 'scenario': scenario, 'run': i, 'exit': code, 'expected_exit': expected,
                         'as_expected': ok, 'seconds': round(time.monotonic() - t0, 3), 'result': line, 'fail': fail,
                         'sanitizer_report': sanitizer,
                         'gate_diagnostics': [s for s in stderr.decode(errors='replace').splitlines() if s.startswith('hvf gate:')][:12]}
                diag = [s for s in stderr.decode(errors='replace').splitlines() if 'consecutive receives' in s]
                injected = next((int(s.split('=')[1]) for s in text.splitlines() if s.startswith('INJECTED breaks=')), None)
                entry['fault_runs'] = len(diag); entry['injected_breaks'] = injected
                # Every injected break yields exactly one 16-read run; any excess is a
                # channel that broke on its own (the in-flight descriptor race).
                entry['spontaneous_fault_runs'] = None if injected is None else max(0, len(diag) - injected)
                results.append(entry); print(json.dumps(entry), flush=True)
                if not ok: failures.append(entry)
    (out / 'results.json').write_text(json.dumps({'sanitize': a.sanitize, 'results': results,
        'unexpected': len(failures), 'gates': {k: str(v) for k, v in GATES.items()}}, indent=2))
    if failures: raise SystemExit(f'{len(failures)} unexpected outcomes')
if __name__ == '__main__':
    main()
