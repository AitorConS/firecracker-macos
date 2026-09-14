#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the proxy source-port regression and a control restoring only SO_REUSEADDR.

The control differs from production by the one option that made the kernel stop
excluding ports already held on the host, and nothing else.
"""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FIXED='''static int make_socket(int type){int fd=socket(AF_INET,type,0);if(fd>=0)nonblock(fd);return fd;}'''
CONTROL='''static int make_socket(int type){int fd=socket(AF_INET,type,0);if(fd>=0){nonblock(fd);int one=1;(void)setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));}return fd;}'''
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repeat',type=int,default=5);p.add_argument('--sanitize',action='store_true')
    p.add_argument('--fixed-only',action='store_true')
    p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/claude-dns-fix/port')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    native=ROOT/'src/hvf-vmm/native';gate=(native/'socket_gate.c').read_text()
    assert gate.count(FIXED)==1,'production make_socket changed; update this control'
    (out/'socket_gate_control.c').write_text(gate.replace(FIXED,CONTROL))
    flags=['-g','-O1','-std=gnu99','-D_DARWIN_C_SOURCE','-mmacosx-version-min=26.0','-I'+str(native)]
    if a.sanitize:flags.extend(['-fsanitize=address,undefined','-fno-omit-frame-pointer'])
    results=[]
    for variant in (('fixed',) if a.fixed_only else ('control','fixed')):
        source=str(out/'socket_gate_control.c') if variant=='control' else str(native/'socket_gate.c')
        binary=out/variant
        subprocess.run(['xcrun','clang',*flags,'-DGATE_SOURCE="%s"'%source,
                        str(ROOT/'experiments/hvf/test-network-port.c'),str(native/'policy.c'),
                        str(native/'sandbox.c'),'-o',str(binary)],check=True)
        for i in range(a.repeat):
            r=subprocess.run([binary],capture_output=True,timeout=300)
            (out/f'{variant}-{i}.log').write_bytes(r.stdout+r.stderr)
            line=next(s for s in r.stdout.decode().splitlines() if s.startswith('RESULT '))
            fields=dict(kv.split('=') for kv in line.split()[1:])
            assert b'ERROR: AddressSanitizer' not in r.stderr and b'runtime error:' not in r.stderr,r.stderr
            assert r.returncode==(1 if variant=='control' else 0),(variant,line,r.stderr)
            assert int(fields['delivered'])>=int(fields['proxies'])*0.9,('lost traffic',line)
            results.append({'variant':variant,'run':i,'exit':r.returncode,**{k:int(v) for k,v in fields.items()}})
            print(json.dumps(results[-1]),flush=True)
    (out/'results.json').write_text(json.dumps(results,indent=2))
if __name__=='__main__':main()
