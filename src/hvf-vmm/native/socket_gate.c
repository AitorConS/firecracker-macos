// SPDX-License-Identifier: Apache-2.0
// Small socket authority. It never parses guest Ethernet/IP/TCP packets.
// The slirp process has deny-all network Seatbelt and receives connected TCP
// descriptors or Unix UDP proxies. All new IPv4 endpoints are authorized here.
#include "socket_gate.h"
#include "policy.h"
#include "seatbelt.h"
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MAX_UDP 256
#define MAX_FD 4096
// A lost datagram is retryable, but a channel that only ever faults must not be
// reported as "no data yet" forever: without an expiry (forwarding listeners)
// nothing would ever notice, and the descriptor stays permanently readable.
#define MAX_FAULTS 16
// A persistent UDP listener has no guest traffic that would re-create it after a
// detach, so a dead channel is replaced in place. The replacement also travels by
// SCM_RIGHTS and can arrive dead too, so only this many consecutive replacements
// without a delivered datagram are attempted before the gate fails.
#define MAX_RECOVERIES 8
#define MAGIC 0x31564148U
#define UDP_MAGIC 0x31445648U
// Local ABI version 1, fixed values only, never pointers or guest-provided FDs.
struct request {uint32_t magic,op,id,token;struct sockaddr_in address;};
struct reply {uint32_t magic,id,token;int32_t error;struct sockaddr_in address;};
struct datagram {uint32_t magic;struct sockaddr_in address;};
_Static_assert(sizeof(struct request)==32,"gate request ABI");
_Static_assert(sizeof(struct reply)==32,"gate reply ABI");
struct peer {struct sockaddr_in address;uint64_t expires;};
struct udp {int net,ipc;uint32_t token;struct sockaddr_in local;struct peer peers[32];unsigned next_peer;};
static struct udp sockets[MAX_UDP];
static uint32_t client_tokens[MAX_FD];
static unsigned char client_listeners[MAX_FD];
static unsigned char client_faults[MAX_FD];
static struct sockaddr_in client_names[MAX_FD];
static struct sockaddr_in client_binds[MAX_FD];
static unsigned char client_streak[MAX_FD];
static uint32_t client_recoveries[MAX_FD];
static int gate_failed;
static int channel=-1;
static pid_t authority_pid=-1;
static uint32_t sequence;
static uint64_t now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec;}
static void nonblock(int fd){int flags=fcntl(fd,F_GETFL);if(flags>=0)(void)fcntl(fd,F_SETFL,flags|O_NONBLOCK);}
static int same(const struct sockaddr_in *a,const struct sockaddr_in *b){return a->sin_addr.s_addr==b->sin_addr.s_addr&&a->sin_port==b->sin_port;}
static int send_reply(int fd,const struct reply *reply,int descriptor){
    struct iovec iov={(void *)reply,sizeof(*reply)};char ancillary[CMSG_SPACE(sizeof(int))]={0};
    struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;
    if(descriptor>=0){message.msg_control=ancillary;message.msg_controllen=sizeof(ancillary);struct cmsghdr *c=CMSG_FIRSTHDR(&message);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&descriptor,sizeof(descriptor));}
    return sendmsg(fd,&message,MSG_DONTWAIT)==sizeof(*reply)?0:-1;
}
static void dispose(struct udp *socket){if(socket->net>=0)close(socket->net);if(socket->ipc>=0)close(socket->ipc);memset(socket,0,sizeof(*socket));socket->net=socket->ipc=-1;}
static struct udp *lookup(uint32_t token){for(unsigned i=0;i<MAX_UDP;i++)if(sockets[i].token==token&&sockets[i].net>=0)return &sockets[i];return NULL;}
// SO_REUSEADDR belongs on a TCP listener, which binds a chosen port and has to
// come back after the previous instance's TIME_WAIT. Anywhere else it is unsafe
// here: proxies are never bound and never connected, so the kernel assigns their
// source port with a wildcard local address, and the option drops the check that
// excludes ports already held on a specific address. A proxy then gets the port
// of a live host service, which starts receiving guest traffic addressed to
// itself and answering its own address in a loop that outlives the VM.
static int make_socket(int type){int fd=socket(AF_INET,type,0);if(fd>=0)nonblock(fd);return fd;}
// A socket referenced only by an SCM_RIGHTS message can be flushed by XNU
// unp_gc while in flight. Keep an authority reference until the broker ACKs
// recvmsg, for both TCP sockets and the UDP proxy endpoint.
static int held=-1;static uint32_t held_id;
static int handle(int fd,const struct request *request,uint32_t *next_token){
    struct reply reply={.magic=MAGIC,.id=request->id};int descriptor=-1;
    if(request->magic!=MAGIC)return -1;
    // Keep the external reference until the receiver explicitly acknowledges it.
    // Another request cannot prove receipt: the preceding RPC may have timed out.
    if(request->op==6){
        if(held<0||request->id!=held_id)return -1;
        close(held);held=-1;return 0;
    }
    if(held>=0)return -1;
    if(request->op==1||request->op==2){
        if(!hvf_policy_allows(SOCK_STREAM,&request->address,request->op==2)){reply.error=EPERM;goto respond;}
        descriptor=make_socket(SOCK_STREAM);
        if(descriptor<0){reply.error=errno;goto respond;}
        int one=1;setsockopt(descriptor,SOL_SOCKET,SO_OOBINLINE,&one,sizeof(one));setsockopt(descriptor,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
        if(request->op==2)setsockopt(descriptor,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        int result=request->op==1?connect(descriptor,(const void *)&request->address,sizeof(request->address)):bind(descriptor,(const void *)&request->address,sizeof(request->address));
        if(result<0 && !(request->op==1&&errno==EINPROGRESS)){reply.error=errno;close(descriptor);descriptor=-1;goto respond;}
        if(request->op==1 && result<0)reply.error=EINPROGRESS;
        if(request->op==2 && listen(descriptor,16)<0){reply.error=errno;close(descriptor);descriptor=-1;}
    }else if(request->op==3){
        struct udp *slot=NULL;for(unsigned i=0;i<MAX_UDP;i++)if(sockets[i].net<0){slot=&sockets[i];break;}
        if(!slot){reply.error=EMFILE;goto respond;}
        int pair[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)){reply.error=errno;goto respond;}
        slot->net=make_socket(SOCK_DGRAM);if(slot->net<0){reply.error=errno;close(pair[0]);close(pair[1]);goto respond;}
        slot->ipc=pair[0];nonblock(pair[0]);nonblock(pair[1]);
        int buffer=262144;setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));setsockopt(pair[1],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));
        slot->token=++*next_token;if(!slot->token){dispose(slot);close(pair[1]);return -1;}
        slot->local.sin_family=AF_INET;slot->local.sin_len=sizeof(slot->local);
        reply.token=slot->token;descriptor=pair[1];
    }else if(request->op==4){
        struct udp *slot=lookup(request->token);
        if(!slot){reply.error=EBADF;goto respond;}
        if(request->address.sin_port && !hvf_policy_allows(SOCK_DGRAM,&request->address,1)){reply.error=EPERM;goto respond;}
        if(request->address.sin_family!=AF_INET){reply.error=EINVAL;goto respond;}
        if(bind(slot->net,(const void *)&request->address,sizeof(request->address))){reply.error=errno;goto respond;}
        socklen_t length=sizeof(slot->local);getsockname(slot->net,(void *)&slot->local,&length);reply.address=slot->local;
    }else if(request->op==5){struct udp *slot=lookup(request->token);if(slot)dispose(slot);}
    else return -1;
respond:;
    int result=send_reply(fd,&reply,descriptor);
    if(descriptor>=0&&!result&&(request->op==1||request->op==2||request->op==3)){held=descriptor;held_id=request->id;}
    else if(descriptor>=0)close(descriptor);
    return result;
}
static void udp_poll(struct udp *slot,int outgoing,int incoming,unsigned *remaining){
    uint8_t bytes[65536];struct datagram header={.magic=UDP_MAGIC};
    if(outgoing)for(unsigned budget=0;budget<16 && *remaining;budget++,--*remaining){
        struct iovec iov[2]={{&header,sizeof(header)},{bytes,65507}};struct msghdr message={.msg_iov=iov,.msg_iovlen=2};
        ssize_t n=recvmsg(slot->ipc,&message,MSG_DONTWAIT);
        if(n<0)break;
        if(n<(ssize_t)sizeof(header)||(message.msg_flags&MSG_TRUNC)||header.magic!=UDP_MAGIC||header.address.sin_family!=AF_INET)continue;
        int allowed=hvf_policy_allows(SOCK_DGRAM,&header.address,0);
        if(!allowed)for(unsigned i=0;i<32;i++)if(slot->peers[i].expires>now()&&same(&slot->peers[i].address,&header.address)){allowed=1;break;}
        if(allowed)(void)sendto(slot->net,bytes,n-sizeof(header),MSG_DONTWAIT,(const void *)&header.address,sizeof(header.address));
    }
    if(incoming)for(unsigned budget=0;budget<16 && *remaining;budget++,--*remaining){
        socklen_t length=sizeof(header.address);ssize_t n=recvfrom(slot->net,bytes,65507,MSG_DONTWAIT,(void *)&header.address,&length);if(n<0)break;
        socklen_t local_length=sizeof(slot->local);getsockname(slot->net,(void *)&slot->local,&local_length);
        // An ephemeral outbound bind is not a listener: only deliver datagrams
        // from an explicitly authorized UDP egress/DNS endpoint. A declared
        // listener keeps receiving from any peer and records it for replies.
        if(hvf_policy_allows(SOCK_DGRAM,&slot->local,1)){struct peer *peer=&slot->peers[slot->next_peer++%32];peer->address=header.address;peer->expires=now()+60;}
        else if(!hvf_policy_allows(SOCK_DGRAM,&header.address,0))continue;
        struct iovec iov[2]={{&header,sizeof(header)},{bytes,(size_t)n}};struct msghdr message={.msg_iov=iov,.msg_iovlen=2};
        // A transient sendmsg failure on the proxy channel must not close the
        // slot; the datagram is lost and the protocol retransmits instead.
        (void)sendmsg(slot->ipc,&message,MSG_DONTWAIT);
    }
}
static void authority(int fd,pid_t parent){
    signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);
    const char *lease_env=getenv("HVF_LEASE_FD");int lease=lease_env?atoi(lease_env):-1;
    long maximum=sysconf(_SC_OPEN_MAX);if(maximum<0||maximum>1048576)maximum=1048576;
    for(int candidate=0;candidate<maximum;candidate++)if(candidate!=fd&&candidate!=2&&candidate!=lease)close(candidate);
    for(unsigned i=0;i<MAX_UDP;i++)sockets[i].net=sockets[i].ipc=-1;
    // This tiny authority is the trusted network permission boundary. It has no
    // libslirp callbacks, file access or ability to execute further processes.
    if(hvf_sandbox_install("(version 1)(deny default)(allow network*)"))_exit(2);
    struct reply ready={.magic=MAGIC};
    if(send_reply(fd,&ready,-1))_exit(2);
    uint32_t next_token=0;
    while(getppid()==parent){
        struct pollfd fds[1+MAX_UDP*2];fds[0]=(struct pollfd){fd,POLLIN,0};
        for(unsigned i=0;i<MAX_UDP;i++){fds[1+2*i]=(struct pollfd){sockets[i].ipc,POLLIN,0};fds[2+2*i]=(struct pollfd){sockets[i].net,POLLIN,0};}
        int result=poll(fds,1+MAX_UDP*2,10);if(result<0&&errno!=EINTR)break;
        if(fds[0].revents){struct request request;struct iovec iov={&request,sizeof(request)};struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};ssize_t n=recvmsg(fd,&message,MSG_DONTWAIT);if(n!=sizeof(request)||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||handle(fd,&request,&next_token))break;}
        unsigned remaining=128;
        static unsigned first;
        for(unsigned j=0;j<MAX_UDP && remaining;j++){unsigned i=(first+j)%MAX_UDP;if(sockets[i].net>=0)udp_poll(&sockets[i],fds[1+2*i].revents&POLLIN,fds[2+2*i].revents&POLLIN,&remaining);}
        first=(first+1)%MAX_UDP;
    }
    _exit(0);
}
int hvf_gate_start(void){
    int pair[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,pair))return -1;
    pid_t parent=getpid(),child=fork();if(child<0){close(pair[0]);close(pair[1]);return -1;}
    if(!child){close(pair[0]);authority(pair[1],parent);}
    close(pair[1]);
    struct pollfd ready={pair[0],POLLIN,0};struct reply reply;
    if(poll(&ready,1,2000)<=0 || recv(pair[0],&reply,sizeof(reply),MSG_DONTWAIT)!=sizeof(reply) || reply.magic!=MAGIC || reply.id || reply.error){
        close(pair[0]);kill(child,SIGKILL);while(waitpid(child,NULL,0)<0&&errno==EINTR){}errno=EPROTO;return -1;
    }
    channel=pair[0];authority_pid=child;return 0;
}
int hvf_gate_check(void){if(gate_failed)return -1;if(authority_pid<=0)return 0;int status;pid_t result=waitpid(authority_pid,&status,WNOHANG);return result==0 || (result<0&&errno==EINTR)?0:-1;}
int hvf_gate_active(void){return channel>=0;}
// A transport/protocol failure makes the synchronous channel unusable: a late
// reply must never be mistaken for the next RPC. Keep the gate active (no direct
// socket fallback); hvf_gate_check makes the backend report the failure and exit.
static int rpc_failed(int error,int *descriptor){
    if(*descriptor>=0)close(*descriptor);
    *descriptor=-1;gate_failed=1;errno=error;return -1;
}
static int rpc(uint32_t op,uint32_t token,const struct sockaddr_in *address,struct reply *reply,int *descriptor){
    *descriptor=-1;
    if(gate_failed){errno=ENOTCONN;return -1;}
    struct request request={.magic=MAGIC,.op=op,.id=++sequence,.token=token};if(address)request.address=*address;
    ssize_t sent;
    do{sent=send(channel,&request,sizeof(request),MSG_DONTWAIT);}while(sent<0&&errno==EINTR);
    if(sent!=sizeof(request))return rpc_failed(sent<0?errno:EPROTO,descriptor);
    struct timespec began,current;clock_gettime(CLOCK_MONOTONIC,&began);
    struct pollfd ready={channel,POLLIN,0};int result,remaining=2000;
    for(;;){
        result=poll(&ready,1,remaining);
        if(result>=0||errno!=EINTR)break;
        clock_gettime(CLOCK_MONOTONIC,&current);
        int64_t elapsed=(current.tv_sec-began.tv_sec)*1000+(current.tv_nsec-began.tv_nsec)/1000000;
        if(elapsed>=2000){result=0;break;}
        remaining=2000-(int)elapsed;
    }
    if(result<=0)return rpc_failed(result==0?ETIMEDOUT:errno,descriptor);
    char ancillary[CMSG_SPACE(sizeof(int))]={0};struct iovec iov={reply,sizeof(*reply)};struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof(ancillary)};
    ssize_t n;
    do{n=recvmsg(channel,&message,MSG_DONTWAIT);}while(n<0&&errno==EINTR);
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS&&c->cmsg_len==CMSG_LEN(sizeof(int)))memcpy(descriptor,CMSG_DATA(c),sizeof(int));
    if(n!=sizeof(*reply)||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||reply->magic!=MAGIC||reply->id!=request.id)return rpc_failed(n<0?errno:EPROTO,descriptor);
    // ACK failure is fatal: the authority must not retain an unacknowledged
    // socket while the broker continues using the synchronous channel.
    if(*descriptor>=0&&(op==1||op==2||op==3)){
        struct request ack={.magic=MAGIC,.op=6,.id=request.id};
        do{sent=send(channel,&ack,sizeof(ack),MSG_DONTWAIT);}while(sent<0&&errno==EINTR);
        if(sent!=sizeof(ack))return rpc_failed(sent<0?errno:EPROTO,descriptor);
    }
    if(reply->error){errno=reply->error;return -1;}return 0;
}
// Retain the earlier pre-data EOF mitigation as a diagnostic fallback. The
// acknowledged transfer above prevents the measured in-flight flush; this
// probe alone cannot distinguish every legitimate peer close or a later flush.
static int transfer_usable(int fd){
    char probe;
    if(recv(fd,&probe,1,MSG_PEEK|MSG_DONTWAIT))return 1;
    struct tcp_connection_info info;socklen_t length=sizeof(info);
    if(getsockopt(fd,IPPROTO_TCP,TCP_CONNECTION_INFO,&info,&length))return 1;
    return info.tcpi_rxbytes||info.tcpi_txbytes;
}
int hvf_gate_tcp(int fd,const struct sockaddr_in *address,int listener){
    if(fd<0||fd>=MAX_FD){errno=EMFILE;return -1;}
    for(unsigned attempt=0;;attempt++){
        struct reply reply;int received=-1;int result=rpc(listener?2:1,0,address,&reply,&received);int error=errno;
        if(received>=0){if(dup2(received,fd)<0){close(received);return -1;}close(received);nonblock(fd);}
        // Ask once for another socket; the retry replaces this one through dup2.
        if(received>=0&&!listener&&!attempt&&!transfer_usable(fd)){
            fprintf(stderr,"hvf gate: transferred socket for fd %d was unreadable on arrival; retrying once\n",fd);
            continue;
        }
        client_listeners[fd]=listener && result==0;
        errno=error;return result;
    }
}
int hvf_gate_udp(void){
    struct reply reply;int received=-1;if(rpc(3,0,NULL,&reply,&received))return -1;
    if(received<0||received>=MAX_FD){if(received>=0)close(received);struct reply ignored;int extra;(void)rpc(5,reply.token,NULL,&ignored,&extra);if(extra>=0)close(extra);errno=EMFILE;return -1;}
    client_tokens[received]=reply.token;client_faults[received]=0;client_streak[received]=0;client_recoveries[received]=0;memset(&client_binds[received],0,sizeof(client_binds[received]));memset(&client_names[received],0,sizeof(client_names[received]));client_names[received].sin_family=AF_INET;client_names[received].sin_len=sizeof(struct sockaddr_in);return received;
}
int hvf_gate_is_listener(int fd){return fd>=0&&fd<MAX_FD&&client_listeners[fd];}
int hvf_gate_is_udp(int fd){return fd>=0&&fd<MAX_FD&&client_tokens[fd];}
int hvf_gate_bind(int fd,const struct sockaddr_in *address){struct reply reply;int received;int result=rpc(4,client_tokens[fd],address,&reply,&received);if(!result){client_names[fd]=reply.address;if(address->sin_port)client_binds[fd]=*address;}return result;}
int hvf_gate_name(int fd,struct sockaddr *address,socklen_t *length){if(!address||!length){errno=EINVAL;return -1;}size_t n=*length<sizeof(struct sockaddr_in)?*length:sizeof(struct sockaddr_in);memcpy(address,&client_names[fd],n);*length=sizeof(struct sockaddr_in);return 0;}
ssize_t hvf_gate_send(int fd,const void *data,size_t size,int flags,const struct sockaddr *address,socklen_t length){
    if(!address||length!=sizeof(struct sockaddr_in)||address->sa_family!=AF_INET||size>65507){errno=EINVAL;return -1;}
    struct datagram header={.magic=UDP_MAGIC,.address=*(const struct sockaddr_in *)address};struct iovec iov[2]={{&header,sizeof(header)},{(void *)data,size}};struct msghdr message={.msg_iov=iov,.msg_iovlen=2};
    ssize_t n=sendmsg(fd,&message,flags|MSG_DONTWAIT);return n<0?-1:n-(ssize_t)sizeof(header);
}
// Replace a listener's dead proxy through the same descriptor number, so the
// libslirp socket and its poll registration stay valid, and bind the address the
// policy authorized before; the authority checks that authorization again. The
// old slot is released first, which also frees the port and one pool entry.
// Datagrams queued on the old channel and remote peers learned by it are lost.
static const char *gate_recover(int fd){
    if(client_streak[fd]>=MAX_RECOVERIES)return "every consecutive replacement failed before carrying a datagram";
    struct sockaddr_in bound=client_binds[fd];struct reply reply;int extra;
    if(rpc(5,client_tokens[fd],NULL,&reply,&extra))return "authority unavailable";
    int fresh=hvf_gate_udp();if(fresh<0)return "no replacement proxy";
    if(dup2(fresh,fd)<0){hvf_gate_close(fresh);close(fresh);return "descriptor replacement failed";}
    client_tokens[fd]=client_tokens[fresh];client_tokens[fresh]=0;close(fresh);client_faults[fd]=0;
    if(hvf_gate_bind(fd,&bound))return "authorized address could not be bound again";
    client_binds[fd]=bound;client_streak[fd]++;client_recoveries[fd]++;return NULL;
}
// One faulty receive loses a datagram and stays retryable; a run of consecutive
// faults means the proxy channel no longer carries data, so report it once and
// return a hard error. libslirp then detaches the mapping and lets the guest
// create a new one, instead of polling a permanently readable dead descriptor.
// A listener cannot be re-created by the guest: it is recovered in place, and
// when that is impossible the gate fails, so hvf_gate_check stops the backend
// explicitly instead of the forward disappearing without notice.
static ssize_t gate_fault(int fd,const char *reason){
    if(fd<0||fd>=MAX_FD){errno=EAGAIN;return -1;}
    if(client_faults[fd]<MAX_FAULTS)client_faults[fd]++;
    if(client_faults[fd]<MAX_FAULTS){errno=EAGAIN;return -1;}
    if(client_binds[fd].sin_port){
        uint32_t token=client_tokens[fd];const char *failure=gate_recover(fd);
        if(!failure){
            fprintf(stderr,"hvf gate: UDP listener fd %d token %u failed %d consecutive receives (%s); "
                           "replaced its proxy as token %u (recovery %u, %u consecutive of %d)\n",fd,token,MAX_FAULTS,reason,client_tokens[fd],client_recoveries[fd],client_streak[fd],MAX_RECOVERIES);
            errno=EAGAIN;return -1;
        }
        gate_failed=1;
        fprintf(stderr,"hvf gate: UDP listener fd %d token %u failed %d consecutive receives (%s) and was not recovered: %s; "
                       "failing the network backend\n",fd,token,MAX_FAULTS,reason,failure);
        errno=ENOTCONN;return -1;
    }
    fprintf(stderr,"hvf gate: UDP proxy fd %d token %u failed %d consecutive receives (%s); "
                   "reporting it instead of masking the channel\n",fd,client_tokens[fd],MAX_FAULTS,reason);
    errno=ENOTCONN;return -1;
}
ssize_t hvf_gate_recv(int fd,void *data,size_t size,int flags,struct sockaddr *address,socklen_t *length){
    struct datagram header={0};struct iovec iov[2]={{&header,sizeof(header)},{data,size}};struct msghdr message={.msg_iov=iov,.msg_iovlen=2};ssize_t n=recvmsg(fd,&message,flags|MSG_DONTWAIT);
    // Compatibility mitigation for observed receive errors. UDP data envelopes
    // carry no SCM_RIGHTS; transient FD-transfer probes do not establish the
    // cause here. libslirp must handle EAGAIN without emitting an ICMP error.
    if(n<0&&(errno==EMSGSIZE||errno==EPROTOTYPE))return gate_fault(fd,"host receive error");
    if(n<0)return -1;
    if(n<(ssize_t)sizeof(header)||header.magic!=UDP_MAGIC||header.address.sin_family!=AF_INET)return gate_fault(fd,"invalid envelope");
    if(fd>=0&&fd<MAX_FD)client_faults[fd]=client_streak[fd]=0;
    if(address&&length){size_t copy=*length<sizeof(header.address)?*length:sizeof(header.address);memcpy(address,&header.address,copy);*length=sizeof(header.address);}return n-sizeof(header);
}
void hvf_gate_close(int fd){if(fd>=0&&fd<MAX_FD){client_listeners[fd]=0;client_faults[fd]=client_streak[fd]=0;client_recoveries[fd]=0;memset(&client_binds[fd],0,sizeof(client_binds[fd]));}if(hvf_gate_is_udp(fd)){struct reply reply;int received;(void)rpc(5,client_tokens[fd],NULL,&reply,&received);client_tokens[fd]=0;}}
