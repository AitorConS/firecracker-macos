#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build/run gate regressions and a control removing only the retry fix."""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RETRY='''            /* Readiness can become stale, and the HVF UDP gate reports a
             * consumed invalid envelope as EAGAIN. Neither is a remote port
             * error: retain the socket and let UDP/application timers run. */
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                m_free(m);
                return;
            }
'''
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repeat',type=int,default=20);p.add_argument('--sanitize',action='store_true');p.add_argument('--fixed-only',action='store_true');p.add_argument('--output',default=None);a=p.parse_args()
    out=ROOT/(a.output or ('experiments/hvf/build/astra-network-evidence/gate-asan' if a.sanitize else 'experiments/hvf/build/astra-network-evidence/gate'));out.mkdir(parents=True,exist_ok=True)
    native=ROOT/'src/hvf-vmm/native';src=ROOT/'src/hvf-vmm/vendor/libslirp/src';glib=ROOT/'experiments/hvf/build/distribution/native'
    flags=['-g','-O1','-std=gnu99','-D_DARWIN_C_SOURCE','-DBUILDING_LIBSLIRP','-mmacosx-version-min=26.0',*['-I'+str(f) for f in (native,src,glib/'include/glib-2.0',glib/'lib/glib-2.0/include')]]
    if a.sanitize:flags.extend(['-fsanitize=address,undefined','-fno-omit-frame-pointer'])
    objs=[]
    for f in sorted(src.glob('*.c')):
        o=out/(f.stem+'.o');subprocess.run(['xcrun','clang',*flags,'-include',str(native/'slirp_policy.h'),'-c',str(f),'-o',str(o)],check=True);objs.append(o)
    source=(src/'socket.c').read_text();assert source.count(RETRY)==1
    control=out/'socket-control.c';control.write_text(source.replace(RETRY,''));control_obj=out/'socket-control.o'
    subprocess.run(['xcrun','clang',*flags,'-include',str(native/'slirp_policy.h'),'-c',control,'-o',control_obj],check=True)
    results=[]
    for variant in (('fixed',) if a.fixed_only else ('control','fixed')):
        binary=out/variant;objects=[control_obj if variant=='control' and o.name=='socket.o' else o for o in objs]
        subprocess.run(['xcrun','clang',*flags,ROOT/'experiments/hvf/test-network-gate.c',native/'policy.c',native/'sandbox.c',*objects,'-L'+str(glib/'lib'),'-lglib-2.0','-lresolv','-o',binary],check=True)
        for i in range(a.repeat):
            r=subprocess.run([binary],capture_output=True,timeout=10);(out/f'{variant}-{i}.log').write_bytes(r.stdout+r.stderr)
            assert r.returncode==(1 if variant=='control' else 0),(variant,r.stdout,r.stderr)
            assert b'RESULT icmp=' in r.stdout and b'ERROR: AddressSanitizer' not in r.stderr and b'runtime error:' not in r.stderr,(r.stdout,r.stderr)
            results.append({'variant':variant,'run':i,'exit':r.returncode,'result':r.stdout.decode().splitlines()[-1]})
    (out/'results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
if __name__=='__main__':main()
