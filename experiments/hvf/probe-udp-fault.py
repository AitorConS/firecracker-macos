#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a VMM that reports why a UDP proxy channel starts faulting.

The bounded fault counter tears a mapping down after sixteen consecutive invalid
receives, and that teardown is now the only remaining cause of a lost guest
datagram. This build logs nothing on a healthy exchange: it reports each faulting
receive with the bytes and state that produced it, and every slot the authority
disposes, so the two can be lined up. Production is never edited.
"""
import argparse,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HEADER='''
#include <stdio.h>
static unsigned fault_events,dispose_events;
static void probe_line(const char *text){int saved=errno;fputs(text,stderr);fflush(stderr);errno=saved;}
'''
CHANGES={
 'socket_gate.c':('src/hvf-vmm/native/socket_gate.c',[(
  '''    if(n<0&&(errno==EMSGSIZE||errno==EPROTOTYPE))return gate_fault(fd,"host receive error");
    if(n<0)return -1;
    if(n<(ssize_t)sizeof(header)||header.magic!=UDP_MAGIC||header.address.sin_family!=AF_INET)return gate_fault(fd,"invalid envelope");''',
  '''    if(n<0&&(errno==EMSGSIZE||errno==EPROTOTYPE))return gate_fault(fd,"host receive error");
    if(n<0)return -1;
    if(n<(ssize_t)sizeof(header)||header.magic!=UDP_MAGIC||header.address.sin_family!=AF_INET){
        if(fault_events<64){
            int saved=errno,readable=-1;socklen_t rl=sizeof(readable);
            (void)getsockopt(fd,SOL_SOCKET,SO_NREAD,&readable,&rl);
            struct pollfd ready={fd,POLLIN,0};int pollres=poll(&ready,1,0);
            char text[256];
            snprintf(text,sizeof(text),
                     "UDPFAULT seq=%u fd=%d token=%u n=%zd flags=%x magic=%08x family=%u "
                     "port=%u faults=%u nread=%d poll=%d/%x errno=%d\\n",
                     ++fault_events,fd,client_tokens[fd],n,(unsigned)message.msg_flags,
                     header.magic,(unsigned)header.address.sin_family,
                     ntohs(header.address.sin_port),(unsigned)client_faults[fd],readable,
                     pollres,(unsigned)ready.revents,saved);
            errno=saved;probe_line(text);
        }
        return gate_fault(fd,"invalid envelope");
    }'''),(
  'static void dispose(struct udp *socket){if(socket->net>=0)close(socket->net);if(socket->ipc>=0)close(socket->ipc);memset(socket,0,sizeof(*socket));socket->net=socket->ipc=-1;}',
  '''static void dispose(struct udp *socket){
    if(dispose_events<256){char text[128];snprintf(text,sizeof(text),"UDPDISPOSE seq=%u slot=%ld token=%u net=%d ipc=%d\\n",++dispose_events,(long)(socket-sockets),socket->token,socket->net,socket->ipc);probe_line(text);}
    if(socket->net>=0)close(socket->net);if(socket->ipc>=0)close(socket->ipc);memset(socket,0,sizeof(*socket));socket->net=socket->ipc=-1;}'''),(
  '''    }else if(request->op==5){struct udp *slot=lookup(request->token);if(slot)dispose(slot);}''',
  '''    }else if(request->op==5){struct udp *slot=lookup(request->token);
        if(dispose_events<256){char text[96];snprintf(text,sizeof(text),"UDPRELEASE token=%u found=%d\\n",request->token,slot?1:0);probe_line(text);}
        if(slot)dispose(slot);}'''),(
  '    client_tokens[received]=reply.token;client_faults[received]=0;',
  '''    {
        /* Is the channel already hung up the moment the authority hands it over,
         * or does something close the other end later? */
        struct pollfd fresh={received,POLLIN,0};int fr=poll(&fresh,1,0);
        if(fresh.revents&(POLLHUP|POLLERR)){char text[160];snprintf(text,sizeof(text),"UDPBORN fd=%d token=%u poll=%d/%x\\n",received,reply.token,fr,(unsigned)fresh.revents);probe_line(text);}
    }
    client_tokens[received]=reply.token;client_faults[received]=0;'''),(
  'void hvf_gate_close(int fd){if(fd>=0&&fd<MAX_FD){client_listeners[fd]=0;client_faults[fd]=0;}',
  '''void hvf_gate_close(int fd){
    if(fd>=0&&fd<MAX_FD&&client_tokens[fd]&&dispose_events<256){char text[128];snprintf(text,sizeof(text),"UDPGATECLOSE fd=%d token=%u\\n",fd,client_tokens[fd]);probe_line(text);}
    if(fd>=0&&fd<MAX_FD){client_listeners[fd]=0;client_faults[fd]=0;}''')]),
}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/claude-dns-fix/fault')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    (out/'probe.h').write_text(HEADER)
    for name,(path,replacements) in CHANGES.items():
        source=(ROOT/path).read_text()
        for before,after in replacements:
            assert source.count(before)==1,(name,source.count(before))
            source=source.replace(before,after)
        (out/name).write_text('#include "socket_gate.h"\n#include <errno.h>\n#include <poll.h>\n'+HEADER+source)
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
