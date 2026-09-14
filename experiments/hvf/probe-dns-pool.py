#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a VMM that reports the proxy pool census at every refused UDP socket.

The recycle added under pressure retires one answered DNS mapping per failed
attempt. Whether that is enough depends on what the pool is full of at that
instant, which was never measured. This build logs nothing while sockets are
granted; on each refusal it walks libslirp's UDP list and classifies every
mapping, then reports whether the retry succeeded. Production is never edited.
"""
import argparse,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HEADER='''
#include <stdio.h>
#include <errno.h>
static unsigned pool_events;
static void pool_census(Slirp *slirp,const char *stage,int retried)
{
    struct socket *so;
    unsigned total=0,hostfwd=0,no_expiry=0,dns_ready=0,dns_queued=0,dns_pending=0,other=0;
    int saved=errno;
    for (so = slirp->udb.so_next; so && so != &slirp->udb; so = so->so_next) {
        total++;
        if (so->so_state & SS_HOSTFWD) { hostfwd++; continue; }
        if (so->so_expire == 0) { no_expiry++; continue; }
        if (so->so_fport != htons(53)) { other++; continue; }
        if (so->so_expire > curtime + SO_EXPIREFAST) { dns_pending++; continue; }
        if (so->so_queued) { dns_queued++; continue; }
        dns_ready++;
    }
    char text[256];
    snprintf(text,sizeof(text),
             "POOLPROBE %s seq=%u errno=%d retried=%d total=%u hostfwd=%u no_expiry=%u "
             "dns_ready=%u dns_queued=%u dns_pending=%u other=%u\\n",
             stage,++pool_events,saved,retried,total,hostfwd,no_expiry,
             dns_ready,dns_queued,dns_pending,other);
    fputs(text,stderr);fflush(stderr);errno=saved;
}
'''
CHANGES={
 'udp.c':('src/hvf-vmm/vendor/libslirp/src/udp.c',[(
  '''    so->s = slirp_socket(af, SOCK_DGRAM, 0);
    if (!have_valid_socket(so->s) && (errno == EMFILE || errno == ENFILE) &&
        udp_reclaim(so->slirp)) {
        so->s = slirp_socket(af, SOCK_DGRAM, 0);
    }''',
  '''    so->s = slirp_socket(af, SOCK_DGRAM, 0);
    if (!have_valid_socket(so->s)) {
        pool_census(so->slirp, "refused", 0);
    }
    if (!have_valid_socket(so->s) && (errno == EMFILE || errno == ENFILE) &&
        udp_reclaim(so->slirp)) {
        so->s = slirp_socket(af, SOCK_DGRAM, 0);
        pool_census(so->slirp, "after_reclaim", have_valid_socket(so->s) ? 1 : -1);
    }''')]),
}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/claude-dns-fix/pool')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    (out/'probe.h').write_text(HEADER)
    for name,(path,replacements) in CHANGES.items():
        source=(ROOT/path).read_text()
        for before,after in replacements:
            assert source.count(before)==1,(name,source.count(before))
            source=source.replace(before,after)
        marker='#include "slirp.h"'
        assert source.count(marker)>=1
        source=source.replace(marker,marker+'\n#include "probe.h"',1)
        (out/name).write_text(source)
    wrapper=out/'cc.py';wrapper.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
root=Path(__file__).resolve().parent
args=sys.argv[1:]
for i,arg in enumerate(args):
    p=Path(arg)
    if p.suffix=='.c' and p.name in '''+repr(list(CHANGES))+''':
        args[i]=str(root/p.name);args.extend(['-I'+str(p.resolve().parent),'-I'+str(root)])
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
