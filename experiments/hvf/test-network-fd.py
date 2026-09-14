#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build/run the descriptor lifetime regression and a control removing only the release."""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RELEASE='\n        sorelease(so);'
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repeat',type=int,default=5)
    p.add_argument('--connections',type=int,default=64)
    p.add_argument('--queries',type=int,default=64)
    p.add_argument('--sanitize',action='store_true')
    p.add_argument('--fixed-only',action='store_true')
    p.add_argument('--output',default='experiments/hvf/build/claude-network-fix/fd')
    a=p.parse_args()
    out=ROOT/a.output;out.mkdir(parents=True,exist_ok=True)
    native=ROOT/'src/hvf-vmm/native';src=ROOT/'src/hvf-vmm/vendor/libslirp/src';glib=ROOT/'experiments/hvf/build/distribution/native'
    flags=['-g','-O1','-std=gnu99','-D_DARWIN_C_SOURCE','-DBUILDING_LIBSLIRP','-mmacosx-version-min=26.0',*['-I'+str(f) for f in (native,src,glib/'include/glib-2.0',glib/'lib/glib-2.0/include')]]
    if a.sanitize:flags.extend(['-fsanitize=address,undefined','-fno-omit-frame-pointer'])
    objs=[]
    for f in sorted(src.glob('*.c')):
        o=out/(f.stem+'.o');subprocess.run(['xcrun','clang',*flags,'-include',str(native/'slirp_policy.h'),'-c',str(f),'-o',str(o)],check=True);objs.append(o)
    # The control differs from production by exactly the two release calls.
    source=(src/'socket.c').read_text();assert source.count(RELEASE)==2,source.count(RELEASE)
    control=out/'socket-control.c';control.write_text(source.replace(RELEASE,''));control_obj=out/'socket-control.o'
    subprocess.run(['xcrun','clang',*flags,'-include',str(native/'slirp_policy.h'),'-c',control,'-o',control_obj],check=True)
    results=[]
    for variant in (('fixed',) if a.fixed_only else ('control','fixed')):
        binary=out/variant;objects=[control_obj if variant=='control' and o.name=='socket.o' else o for o in objs]
        subprocess.run(['xcrun','clang',*flags,ROOT/'experiments/hvf/test-network-fd.c',native/'policy.c',native/'sandbox.c',*objects,'-L'+str(glib/'lib'),'-lglib-2.0','-lresolv','-o',binary],check=True)
        for i in range(a.repeat):
            r=subprocess.run([binary,str(a.connections),str(a.queries)],capture_output=True,timeout=900)
            (out/f'{variant}-{i}.log').write_bytes(r.stdout+r.stderr)
            lines=[l for l in r.stdout.decode().splitlines() if l.startswith(('RESULT','LEAK','STATES','FAIL','PASS'))]
            # UndefinedBehaviorSanitizer reports pre-existing misaligned accesses
            # in libslirp's TCP reassembly queue. They are recorded, not hidden,
            # and not silently turned into a pass: see the report.
            undefined=sorted({l.split(' runtime error: ')[0].split('/')[-1] for l in r.stderr.decode(errors='replace').splitlines() if ' runtime error: ' in l})
            results.append({'variant':variant,'run':i,'exit':r.returncode,'result':lines,'undefined':undefined})
            print(json.dumps(results[-1]))
            assert b'ERROR: AddressSanitizer' not in r.stderr,r.stderr
            assert r.returncode==(1 if variant=='control' else 0),(variant,r.stdout,r.stderr)
    (out/'results.json').write_text(json.dumps(results,indent=2))
    print(f'{len(results)} runs recorded in {out/"results.json"}')
if __name__=='__main__':main()
