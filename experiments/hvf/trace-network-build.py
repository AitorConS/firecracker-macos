#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate diagnostic-only C copies; never edit production for byte tracing."""
import argparse,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/astra-network-fix/trace');args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
header=r'''
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
static void trace_bytes(const char *tag,int fd,const void *data,ssize_t n){
    static unsigned event;unsigned id=++event;int saved=errno;
    const unsigned char *p=data;size_t count=n>0?(size_t)n:0;
    char *line=malloc(count*2+128);if(!line)abort();
    int used=snprintf(line,count*2+128,"NETTRACE %d %s %u %d %zd 0 ",getpid(),tag,id,fd,n);
    const char hex[]="0123456789abcdef";
    for(size_t i=0;i<count;i++){line[used++]=hex[p[i]>>4];line[used++]=hex[p[i]&15];}
    line[used++]='\n';if(write(2,line,used)!=used)abort();free(line);errno=saved;
}
static ssize_t trace_recv(int fd,void *data,size_t n,int flags){
    ssize_t result=recv(fd,data,n,flags);int saved=errno;
    struct sockaddr_in local={0};socklen_t len=sizeof(local);getsockname(fd,(void *)&local,&len);
    fprintf(stderr,"TCP_READ fd=%d port=%u requested=%zu result=%zd error=%d\n",fd,ntohs(local.sin_port),n,result,result<0?saved:0);
    trace_bytes("TCP_RECV",fd,data,result);errno=saved;return result;
}
'''
(out/'trace.h').write_text(header)
changes={
 'socket.c':('src/hvf-vmm/vendor/libslirp/src/socket.c', [('nn = recv(so->s,','nn = trace_recv(so->s,'),('ret = recv(so->s,','ret = trace_recv(so->s,')]),
 'socket_gate.c':('src/hvf-vmm/native/socket_gate.c', [('if(!slot){reply.error=EMFILE;goto respond;}', 'if(!slot){fprintf(stderr,"UDP_CAPACITY max=%d\\n",MAX_UDP);reply.error=EMFILE;goto respond;}'), ('slot->token=++*next_token;', 'fprintf(stderr,"UDP_OPEN slot=%ld token=%u\\n",(long)(slot-sockets),*next_token+1);slot->token=++*next_token;'), ('static void dispose(struct udp *socket){','static void dispose(struct udp *socket){fprintf(stderr,"UDP_CLOSE token=%u\\n",socket->token);'),('client_listeners[fd]=listener && result==0;', 'trace_bytes("SCM_TCP",fd,&received,sizeof(received));\n    client_listeners[fd]=listener && result==0;')]),
 'net_backend_ipc.c':('src/hvf-vmm/native/net_backend_ipc.c', [('ssize_t n=send(frames,data,size,MSG_DONTWAIT);','ssize_t n=send(frames,data,size,MSG_DONTWAIT);\n    if(n==(ssize_t)size)trace_bytes("BROKER_RX",frames,data,size);')]),
 'net.c':('src/hvf-vmm/native/net.c', [('memcpy(dma(d.addr,n),frame+done,n);done+=n;','memcpy(dma(d.addr,n),frame+done,n);if(memcmp(dma(d.addr,n),frame+done,n))abort();done+=n;'),('complete(q,h,total);rx++;','trace_bytes("VIRTIO_RX",h,buf,len);complete(q,h,total);rx++;')])}
for name,(path,replacements) in changes.items():
    source=(ROOT/path).read_text()
    for before,after in replacements:
        assert source.count(before)==1,(name,before);source=source.replace(before,after)
    (out/name).write_text('#include "trace.h"\n'+source)
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
with (out/'build.log').open('w') as log:subprocess.run(['cargo','build','--locked','-p','firecracker','--target','aarch64-apple-darwin','--release'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
binary=out/'target/aarch64-apple-darwin/release/firecracker'
subprocess.run(['codesign','--force','--sign','-','--entitlements',ROOT/'experiments/hvf/entitlements.plist',binary],check=True)
print(binary)
