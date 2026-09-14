#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a control VMM that differs from production only by the network fixes.

The control is generated in the evidence directory with a compiler wrapper and a
separate Cargo target; production sources are never edited. Use it to show that a
guest-visible failure is caused by the removed lines and not by the workload.
"""
import argparse,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
# Each entry removes exactly one production fix, nothing else.
REMOVALS={
 'descriptor-release':{'socket.c':('src/hvf-vmm/vendor/libslirp/src/socket.c',[('\n        sorelease(so);','',2)])},
 'transfer-check':{'socket_gate.c':('src/hvf-vmm/native/socket_gate.c',[(
   '        if(received>=0&&!listener&&!attempt&&!transfer_usable(fd)){\n'
   '            fprintf(stderr,"hvf gate: transferred socket for fd %d was unreadable on arrival; retrying once\\n",fd);\n'
   '            continue;\n'
   '        }\n','',1)])},
 'proxy-port-exclusion':{'socket_gate.c':('src/hvf-vmm/native/socket_gate.c',[(
   'static int make_socket(int type){int fd=socket(AF_INET,type,0);if(fd>=0)nonblock(fd);return fd;}',
   'static int make_socket(int type){int fd=socket(AF_INET,type,0);if(fd>=0){nonblock(fd);int one=1;(void)setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));}return fd;}',1),(
   '        if(request->op==2)setsockopt(descriptor,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));\n','',1)])},
 'proxy-recycle':{'udp.c':('src/hvf-vmm/vendor/libslirp/src/udp.c',[(
   '    if (!have_valid_socket(so->s) && (errno == EMFILE || errno == ENFILE) &&\n'
   '        udp_reclaim(so->slirp)) {\n'
   '        so->s = slirp_socket(af, SOCK_DGRAM, 0);\n'
   '    }\n','',1)])},
}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--remove',action='append',choices=sorted(REMOVALS),required=True)
    p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/claude-network-fix/control')
    a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    changes={}
    for name in a.remove:changes.update(REMOVALS[name])
    for name,(path,replacements) in changes.items():
        source=(ROOT/path).read_text()
        for before,after,count in replacements:
            assert source.count(before)==count,(name,before,source.count(before))
            source=source.replace(before,after)
        (out/name).write_text(source)
    wrapper=out/'cc.py';wrapper.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
root=Path(__file__).resolve().parent
args=sys.argv[1:]
for i,arg in enumerate(args):
    p=Path(arg)
    if p.suffix=='.c' and p.name in '''+repr(list(changes))+''':
        args[i]=str(root/p.name);args.extend(['-I'+str(p.resolve().parent)])
os.execv('/usr/bin/clang',['clang',*args])
''');wrapper.chmod(0o755)
    env={**os.environ,'RUSTUP_HOME':str(ROOT/'experiments/hvf/build/rustup'),'CARGO_HOME':str(ROOT/'experiments/hvf/build/cargo'),'RUSTUP_TOOLCHAIN':'1.97.0','GLIB_PREFIX':str(ROOT/'experiments/hvf/build/distribution/native'),'CARGO_TARGET_DIR':str(out/'target'),'CC':str(wrapper)}
    env['PATH']=env['CARGO_HOME']+'/bin:/opt/homebrew/bin:'+env['PATH']
    with (out/'build.log').open('w') as log:
        subprocess.run(['cargo','build','--locked','-p','firecracker','--target','aarch64-apple-darwin','--release'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    binary=out/'target/aarch64-apple-darwin/release/firecracker'
    subprocess.run(['codesign','--force','--sign','-','--entitlements',ROOT/'experiments/hvf/entitlements.plist',binary],check=True)
    print(binary)
if __name__=='__main__':main()
