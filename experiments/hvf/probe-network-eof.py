#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a VMM that logs only the EOF anomaly and the silent RX drops.

Full byte tracing changes timing by two orders of magnitude and the intermittent
EOF stops appearing. This build logs nothing on a healthy exchange: it reports a
TCP connection closed towards the guest without ever delivering a byte, plus each
frame dropped on the two paths that discard silently. Production is never edited.
"""
import argparse,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HEADER='''
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
static unsigned probe_event;
static void probe_line(const char *text){int saved=errno;fputs(text,stderr);fflush(stderr);errno=saved;}
static void probe_fd(const char *tag,int fd,const void *owner,unsigned extra){
    int saved=errno;char text[128];
    snprintf(text,sizeof(text),"EOFPROBE %s seq=%u fd=%d so=%p extra=%u\\n",tag,++probe_event,fd,owner,extra);
    fputs(text,stderr);fflush(stderr);errno=saved;
}
'''
CHANGES={
 'socket.c':('src/hvf-vmm/vendor/libslirp/src/socket.c',[(
  '            DEBUG_MISC(" --- soread() disconnected, nn = %d, errno = %d-%s", nn,',
  '''            {
                struct tcpcb *probe = sototcpcb(so);
                unsigned delivered = probe ? (unsigned)(probe->snd_nxt - probe->iss) : 0;
                if (nn < 0 || delivered <= 1 || so->so_rcv.sb_cc) {
                    char text[640];int saved = errno;
                    struct sockaddr_in hlocal = {0}, hremote = {0};
                    socklen_t hl = sizeof(hlocal), hr = sizeof(hremote);
                    int lok = getsockname(so->s, (struct sockaddr *)&hlocal, &hl);
                    int rok = getpeername(so->s, (struct sockaddr *)&hremote, &hr);
                    /* The host stack knows how many bytes actually arrived on
                     * this socket: it separates "the peer never sent them" from
                     * "they arrived and were discarded locally". */
                    struct tcp_connection_info tci;memset(&tci, 0, sizeof(tci));
                    socklen_t tl = sizeof(tci);
                    int tok = getsockopt(so->s, IPPROTO_TCP, TCP_CONNECTION_INFO, &tci, &tl);
                    /* A second, non-destructive read separates a real end of
                     * stream from a zero that the first call produced on its own. */
                    int again = (int)recv(so->s, iov[0].iov_base, iov[0].iov_len, MSG_PEEK);
                    int again_errno = errno;
                    int readable = -1;
                    ioctl(so->s, FIONREAD, &readable);
                    int atmark = -1;
                    ioctl(so->s, SIOCATMARK, &atmark);
                    snprintf(text, sizeof(text),
                             "EOFPROBE soread fd=%d lport=%u fport=%u nn=%d errno=%d soerr=%d "
                             "rcv_cc=%u snd_cc=%u delivered=%u state=%x tstate=%d "
                             "hostlocal=%u/%d hostpeer=%u/%d tcpi=%d/%u rx=%llu tx=%llu "
                             "iov0=%u iov1=%u n=%d buflen=%zu datalen=%u sndcc=%u "
                             "wptr=%td rptr=%td mss=%d again=%d/%d fionread=%d atmark=%d\\n",
                             (int)so->s, ntohs(so->so_lport), ntohs(so->so_fport), (int)nn,
                             saved, err, (unsigned)so->so_rcv.sb_cc, (unsigned)so->so_snd.sb_cc,
                             delivered, (unsigned)so->so_state, probe ? (int)probe->t_state : -1,
                             ntohs(hlocal.sin_port), lok, ntohs(hremote.sin_port), rok,
                             tok, (unsigned)tci.tcpi_state,
                             (unsigned long long)tci.tcpi_rxbytes,
                             (unsigned long long)tci.tcpi_txbytes,
                             (unsigned)iov[0].iov_len, (unsigned)iov[1].iov_len, n, buf_len,
                             (unsigned)sb->sb_datalen, (unsigned)sb->sb_cc,
                             (ptrdiff_t)(sb->sb_wptr - sb->sb_data),
                             (ptrdiff_t)(sb->sb_rptr - sb->sb_data),
                             so->so_tcpcb ? so->so_tcpcb->t_maxseg : -1,
                             again, again_errno, readable, atmark);
                    errno = saved;probe_line(text);
                }
            }
            DEBUG_MISC(" --- soread() disconnected, nn = %d, errno = %d-%s", nn,'''),
  ('''static void sofcantrcvmore(struct socket *so)
{
    if ((so->so_state & SS_NOFDREF) == 0) {
        shutdown(so->s, 0);
    }''','''static void sofcantrcvmore(struct socket *so)
{
    if ((so->so_state & SS_NOFDREF) == 0) {
        probe_fd("shutrd", (int)so->s, so, (unsigned)so->so_state);
        shutdown(so->s, 0);
    }'''),
  ('''static void sofcantsendmore(struct socket *so)
{
    if ((so->so_state & SS_NOFDREF) == 0) {
        shutdown(so->s, 1); /* send FIN to fhost */
    }''','''static void sofcantsendmore(struct socket *so)
{
    if ((so->so_state & SS_NOFDREF) == 0) {
        probe_fd("shutwr", (int)so->s, so, (unsigned)so->so_state);
        shutdown(so->s, 1); /* send FIN to fhost */
    }''')]),
 'policy.c':('src/hvf-vmm/native/policy.c',[(
  'int hvf_policy_close(int fd){\n    hvf_gate_close(fd);',
  'int hvf_policy_close(int fd){\n    probe_fd("close",fd,0,0);\n    hvf_gate_close(fd);')]),
 'socket_gate.c':('src/hvf-vmm/native/socket_gate.c',[(
  'client_listeners[fd]=listener && result==0;',
  '''{
        /* Split the problem in half: does the descriptor already refuse to read
         * the moment it is installed, or does something break it afterwards? */
        char peek;int saved_probe=errno;
        ssize_t immediate=recv(fd,&peek,1,MSG_PEEK|MSG_DONTWAIT);
        if(immediate==0||received==fd||(result&&errno!=EINPROGRESS))
            probe_fd("gate_install",fd,0,(unsigned)((immediate==0?1u:0u)|(received==fd?2u:0u)|(result?4u:0u)));
        errno=saved_probe;
    }
    probe_fd("gate_tcp",fd,0,(unsigned)received);
    client_listeners[fd]=listener && result==0;''')]),
 'net_backend_ipc.c':('src/hvf-vmm/native/net_backend_ipc.c',[(
  '    if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){rx_drops++;rx_drop_bytes+=size;return (ssize_t)size;}return n;',
  '''    if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){
        rx_drops++;rx_drop_bytes+=size;
        if(rx_drops<=64){char text[128];snprintf(text,sizeof(text),"EOFPROBE ipc_drop n=%llu size=%zu errno=%d\\n",(unsigned long long)rx_drops,size,errno);probe_line(text);}
        return (ssize_t)size;
    }return n;''')]),
 'net.c':('src/hvf-vmm/native/net.c',[(
  '    if(!pending(q)){drop_packets++;drop_bytes+=len;return len;} // allow protocol retransmission when RX ring is empty',
  '''    if(!pending(q)){
        drop_packets++;drop_bytes+=len;
        if(drop_packets<=64){char text[128];snprintf(text,sizeof(text),"EOFPROBE ring_drop n=%llu size=%zu\\n",(unsigned long long)drop_packets,len);probe_line(text);}
        return len;
    } // allow protocol retransmission when RX ring is empty''')]),
}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/claude-network-fix/probe')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    (out/'probe.h').write_text(HEADER)
    for name,(path,replacements) in CHANGES.items():
        source=(ROOT/path).read_text()
        for before,after in replacements:
            assert source.count(before)==1,(name,source.count(before))
            source=source.replace(before,after)
        (out/name).write_text('#include "probe.h"\n'+source)
    wrapper=out/'cc.py';wrapper.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
root=Path(__file__).resolve().parent
args=sys.argv[1:]
for i,arg in enumerate(args):
    p=Path(arg)
    if p.suffix=='.c' and p.name in '''+repr(list(CHANGES))+''':
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
