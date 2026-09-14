# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Discriminant RPC fail-stop checks. Failure injection changes syscall outcomes,
never production source. Control must fail all five invariants; fixed must pass.
"""
from pathlib import Path
import argparse,subprocess,fcntl,json
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'src/hvf-vmm/native/policy.c').exists())
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--control',type=Path,help='Optional pre-fix gate source for a discriminant control')
 p.add_argument('--fixed',type=Path,default=ROOT/'src/hvf-vmm/native/socket_gate.c')
 p.add_argument('--output',type=Path,default=HERE/'build/network-rpc')
 p.add_argument('--lock',type=Path,help='Optional shared load lock path')
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True);native=ROOT/'src/hvf-vmm/native';rows=[]
 with (a.lock or a.output/'host-load.lock').open('a+') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  for arm,source in ([('control',a.control.resolve())] if a.control else []) + [('fixed',a.fixed.resolve())]:
   binary=a.output.resolve()/f'rpc-{arm}'
   subprocess.run(['xcrun','clang','-O1','-D_DARWIN_C_SOURCE','-I'+str(native),'-DGATE_SOURCE="'+str(source)+'"',str(HERE/'test-network-rpc.c'),str(native/'policy.c'),str(native/'sandbox.c'),'-o',str(binary)],check=True)
   for scenario in ['timeout','malformed','ack','eintr','authority']:
    r=subprocess.run([binary,scenario],capture_output=True,text=True,timeout=5);rows.append(dict(arm=arm,scenario=scenario,exit=r.returncode,output=r.stdout+r.stderr));print(rows[-1],flush=True)
 (a.output/'results.json').write_text(json.dumps(rows,indent=2))
 assert all(r['exit']==0 for r in rows if r['arm']=='fixed')
 assert all(r['exit']==1 for r in rows if r['arm']=='control')
if __name__=='__main__':main()
