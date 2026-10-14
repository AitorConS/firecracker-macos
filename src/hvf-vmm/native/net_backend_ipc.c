// SPDX-License-Identifier: Apache-2.0
// Spawned before HVF/vCPU threads: only the broker invokes libslirp/Internet sockets.
#include "net_backend.h"
#include "control.h"
#include "seatbelt.h"
#include "net.h"
#include <sys/resource.h>
#include "policy.h"
#include "socket_gate.h"
#include <poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "net_backend_stream.h"
#include "net_peer.h"
#include "net_peer_relay.h"

static int frames=-1,health=-1,stats=-1,peer_channel=-1,link_channel=-1;
static uint64_t stream_drops,stream_drop_bytes;
static uint64_t tx_drops,tx_drop_bytes,rx_drops,rx_drop_bytes,stats_drops;
static uint8_t deferred_frame[65536];
static size_t deferred_size;
static pid_t broker=-1;
static struct control_reader health_reader;
static uint64_t pause_operation, pause_ack;
static net_receive_fn receive_frame;
static int broker_stream;
// Direct link: the broker connects to the host switch as before, checks the
// socket, and hands the connected descriptor to the VMM, which then exchanges
// frames with the switch itself instead of through the broker (one process
// hop and two copies fewer per frame). The broker keeps authority: it alone
// connects, and the VMM asks it for a new link when one fails. Each handoff
// carries a generation; the broker keeps its reference until the VMM
// acknowledges it, as XNU can collect a socket that is only in flight.
#define LINK_MESSAGE 16
enum {LINK_OFFER='S',LINK_ACK='A',LINK_LOST='R'};
static uint64_t link_generation;   // VMM: generation of the adopted link (0: none)
static int link_lost;              // VMM: LINK_LOST sent for link_generation
// VMM: polls that ended inside a frame. A switch whose socket buffer is smaller
// than a frame (older jerboad: 8 KiB) leaves one there every time.
static unsigned link_partial_polls;
#define LINK_PARTIAL_POLLS 32
static int link_message(int fd,uint8_t kind,uint64_t generation,int descriptor){
    uint8_t wire[LINK_MESSAGE]={'H','V','L','K',kind};
    for(unsigned i=0;i<8;i++)wire[8+i]=(uint8_t)(generation>>(8*i));
    char space[CMSG_SPACE(sizeof(int))];
    struct iovec io={wire,sizeof(wire)};
    struct msghdr h={.msg_iov=&io,.msg_iovlen=1};
    if(descriptor>=0){
        memset(space,0,sizeof(space));h.msg_control=space;h.msg_controllen=sizeof(space);
        struct cmsghdr *c=CMSG_FIRSTHDR(&h);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&descriptor,sizeof(descriptor));
    }
    return sendmsg(fd,&h,MSG_DONTWAIT)==(ssize_t)sizeof(wire)?0:-1;
}
// Returns 1 with a message (and *descriptor, or -1), 0 when none is queued.
static int link_receive(int fd,uint8_t *kind,uint64_t *generation,int *descriptor){
    for(;;){
        uint8_t wire[LINK_MESSAGE+1];char space[CMSG_SPACE(sizeof(int))];
        struct iovec io={wire,sizeof(wire)};
        struct msghdr h={.msg_iov=&io,.msg_iovlen=1,.msg_control=space,.msg_controllen=sizeof(space)};
        ssize_t n=recvmsg(fd,&h,MSG_DONTWAIT);
        if(n<0)return 0;
        *descriptor=-1;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&h);c;c=CMSG_NXTHDR(&h,c)){
            if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS)continue;
            size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
            for(size_t i=0;i<count;i++){
                int received;memcpy(&received,CMSG_DATA(c)+i*sizeof(int),sizeof(received));
                if(*descriptor<0)*descriptor=received;else close(received);
            }
        }
        if(n!=LINK_MESSAGE||(h.msg_flags&MSG_CTRUNC)||memcmp(wire,"HVLK",4)){if(*descriptor>=0)close(*descriptor);continue;}
        *kind=wire[4];*generation=0;
        for(unsigned i=0;i<8;i++)*generation|=(uint64_t)wire[8+i]<<(8*i);
        return 1;
    }
}
static void fail(const char *message){fprintf(stderr,"network IPC: %s\n",message);exit(2);}
static ssize_t broker_deliver(const void *data,size_t size,void *opaque){
    (void)opaque;
    ssize_t n=send(frames,data,size,MSG_DONTWAIT);
    if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){
        // Unix-stream transport can retry its retained frame. libslirp has
        // no equivalent backpressure contract, so preserve its drop policy.
        if(broker_stream){errno=EAGAIN;return -1;}
        rx_drops++;rx_drop_bytes+=size;return (ssize_t)size;
    }
    return n;
}
static void broker_main(const struct hvf_options *options){
    if(net_forget_guest_memory())_exit(2);
    if(options->cpu_seconds){struct rlimit limit={options->cpu_seconds,options->cpu_seconds};if(setrlimit(RLIMIT_CPU,&limit))_exit(2); }
    signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);
    // Retain only IPC, stderr, and the inherited workspace lease. No disk FDs.
    const char *lease_env=getenv("HVF_LEASE_FD");
    int lease=lease_env?atoi(lease_env):-1;
    long maximum=sysconf(_SC_OPEN_MAX);
    if(maximum<0||maximum>1048576)maximum=1048576;
    for(int fd=0;fd<maximum;fd++)if(fd!=frames&&fd!=health&&fd!=stats&&fd!=peer_channel&&fd!=link_channel&&fd!=STDERR_FILENO&&fd!=lease)close(fd);
    // Keep stdout occupied: GLib diagnostics must never write into a reused socket FD.
    if(dup2(STDERR_FILENO,STDOUT_FILENO)<0)_exit(2);
    hvf_policy_set(options->security);
    int is_stream=options->stream_path!=NULL;
    broker_stream=is_stream;
    if(options->security && !options->security->development &&
       ((!is_stream && hvf_gate_start()) || hvf_sandbox_install(options->security->broker_profile))){
        (void)control_send(health,'E',0);_exit(2);
    }
    if(is_stream?stream_open(options,broker_deliver):slirp_backend_open(options,broker_deliver)){
        (void)control_send(health,'E',0);_exit(2);
    }
    if(is_stream&&options->control_path&&peer_channel>=0)relay_open(options->control_path,peer_channel,options->mac);
    if(control_send(health,'B',0))_exit(2);
    uint8_t packet[65537];
    struct control_reader commands={0};
    int paused=0;uint64_t last_operation=0;
    // direct: the VMM owns the current link; held: our reference to it until acknowledged.
    int direct=0,held=-1;uint64_t offered=0;
    uint64_t next_stats=0;
    for(;;){
        struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);uint64_t ms=(uint64_t)now.tv_sec*1000+now.tv_nsec/1000000;
        if(ms>=next_stats){
            uint8_t packet[48]={'H','V','D','P',1,5,0,0};uint64_t values[5]={rx_drops,rx_drop_bytes,stats_drops,stream.drops,stream.drop_bytes};
            for(unsigned i=0;i<5;i++)for(unsigned j=0;j<8;j++)packet[8+i*8+j]=(uint8_t)(values[i]>>(8*j));
            if(send(stats,packet,sizeof(packet),MSG_DONTWAIT)!=(ssize_t)sizeof(packet))stats_drops++;next_stats=ms+100;
        }
        if(!is_stream && hvf_gate_check()){fprintf(stderr,"socket authority disconnected\n");_exit(2);}
        // Wake for Unix-stream traffic directly. Polling only the supervisor
        // sockets added a fixed 1 ms delay to every guest/host exchange.
        short stream_events=0;
        if(is_stream && stream.fd>=0){
            if(stream.used<stream.need)stream_events|=POLLIN;
            if(stream.queued)stream_events|=POLLOUT;
        }
        struct pollfd fds[6]={{health,POLLIN,0},{frames,POLLIN,0},{stream.fd,stream_events,0}};
        unsigned nfds=is_stream && stream.fd>=0?3:2;
        if(link_channel>=0)fds[nfds++]=(struct pollfd){link_channel,POLLIN,0};
        nfds+=relay_poll_fds(fds+nfds);
        int result=poll(fds,nfds,1);
        if(result<0&&errno!=EINTR)break;
        if(fds[0].revents){
            uint8_t kind;uint64_t operation;
            int n=control_receive(health,&commands,&kind,&operation);
            if(n<0)break;
            if(n==1){
                if(operation<=last_operation || (kind!='P' && kind!='U'))break;
                last_operation=operation;
                // Sender has stopped guest TX before P; drain its finite IPC queue.
                if(kind=='P'){
                    for(;;){ssize_t bytes=recv(frames,packet,sizeof(packet),MSG_DONTWAIT);
                        if(bytes<0){if(errno==EINTR)continue;if(errno!=EAGAIN&&errno!=EWOULDBLOCK)goto done;break;}
                        if(bytes<14||bytes>65536)goto done;
                        if(is_stream)stream_send(packet,(size_t)bytes);else slirp_backend_send(packet,(size_t)bytes);
                    }
                }
                paused=(kind=='P');if(is_stream)stream.paused=paused;else slirp_backend_pause(paused);
                if(control_send(health,'A',operation))break;
            }
        }
        // Peer control carries no guest memory or frames; it continues while paused.
        relay_service();
        if(link_channel>=0){
            uint8_t kind;uint64_t generation;int descriptor;
            while(link_receive(link_channel,&kind,&generation,&descriptor)){
                if(descriptor>=0)close(descriptor);
                if(generation!=offered||!direct)continue;
                if(kind==LINK_ACK&&held>=0){close(held);held=-1;}
                // The VMM closed a failed link: reconnect after the usual delay.
                if(kind==LINK_LOST){direct=0;if(held>=0){close(held);held=-1;}stream.fd=-1;stream_disconnect();}
            }
            // Hand each new connection to the VMM, at a frame boundary in both
            // directions (bytes the broker already holds cannot follow the
            // descriptor). A failed handoff leaves the link with the broker,
            // which then carries frames as before.
            if(!direct&&stream.fd>=0&&!stream.connecting&&!stream.queued&&!stream.rx_used&&
               !link_message(link_channel,LINK_OFFER,offered+1,stream.fd)){
                offered++;direct=1;held=stream.fd;
                stream.fd=-1;stream.used=0;stream.need=4;stream.rx_start=stream.rx_used=0;stream.queued=stream.sent=0;
            }
        }
        if(paused){usleep(1000);continue;}
        for(unsigned budget=0;budget<256;budget++){
            // While the VMM owns the link it sends nothing here; drain stragglers.
            if(is_stream&&!direct){stream_flush();if(stream.queued)break;}
            ssize_t n=recv(frames,packet,sizeof(packet),MSG_DONTWAIT);
            if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)goto done;break;}
            if(n<14||n>65536)goto done;
            if(is_stream&&direct){stream.drops++;stream.drop_bytes+=(uint64_t)n;}
            else if(is_stream)stream_send(packet,(size_t)n);else slirp_backend_send(packet,(size_t)n);
        }
        if(is_stream&&!direct)stream_poll();else if(!is_stream)slirp_backend_poll();
    }
done:
    if(held>=0)close(held);
    if(is_stream)stream_disconnect();else slirp_backend_close();close(frames);close(health);_exit(0);
}
int net_backend_open(const struct hvf_options *options,net_receive_fn receive){
    int data[2],control[2],telemetry[2],peers[2]={-1,-1};
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,data))return -1;
    if(socketpair(AF_UNIX,SOCK_STREAM,0,control)){close(data[0]);close(data[1]);return -1;}
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,telemetry)){close(data[0]);close(data[1]);close(control[0]);close(control[1]);return -1;}
    int buffer=262144;
    for(unsigned i=0;i<2;i++){
        if(setsockopt(data[i],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer)) || setsockopt(data[i],SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer))){
            close(data[0]);close(data[1]);close(control[0]);close(control[1]);close(telemetry[0]);close(telemetry[1]);return -1;
        }
    }
    if(options->stream_path&&options->control_path&&socketpair(AF_UNIX,SOCK_DGRAM,0,peers)){
        close(data[0]);close(data[1]);close(control[0]);close(control[1]);close(telemetry[0]);close(telemetry[1]);return -1;
    }
    // HVF_NET_DIRECT_STREAM=0 keeps every frame on the broker (comparison and fallback).
    const char *direct_env=getenv("HVF_NET_DIRECT_STREAM");
    int links[2]={-1,-1};
    if(options->stream_path&&!(direct_env&&!strcmp(direct_env,"0"))&&socketpair(AF_UNIX,SOCK_DGRAM,0,links))links[0]=links[1]=-1;
    broker=fork();
    if(broker<0){close(data[0]);close(data[1]);close(control[0]);close(control[1]);close(telemetry[0]);close(telemetry[1]);if(peers[0]>=0){close(peers[0]);close(peers[1]);}if(links[0]>=0){close(links[0]);close(links[1]);}return -1;}
    if(!broker){close(data[0]);close(control[0]);close(telemetry[0]);if(peers[0]>=0)close(peers[0]);if(links[0]>=0)close(links[0]);frames=data[1];health=control[1];stats=telemetry[1];peer_channel=peers[1];link_channel=links[1];broker_main(options);}
    close(data[1]);close(control[1]);close(telemetry[1]);if(peers[1]>=0)close(peers[1]);if(links[1]>=0)close(links[1]);frames=data[0];health=control[0];stats=telemetry[0];receive_frame=receive;
    link_channel=links[0];link_generation=0;link_lost=0;stream.fd=-1;stream.receive=receive;
    if(link_channel>=0){
        int flags=fcntl(link_channel,F_GETFL);
        if(flags<0||fcntl(link_channel,F_SETFL,flags|O_NONBLOCK)||fcntl(link_channel,F_SETFD,FD_CLOEXEC)){close(link_channel);link_channel=-1;}
    }
    if(peers[0]>=0){
        int flags=fcntl(peers[0],F_GETFL);
        if(flags<0||fcntl(peers[0],F_SETFL,flags|O_NONBLOCK)||fcntl(peers[0],F_SETFD,FD_CLOEXEC)){close(peers[0]);peers[0]=-1;}
    }
    net_peer_open(peers[0],options->mac,receive);
    struct pollfd ready={health,POLLIN,0};
    struct control_reader reader={0};uint8_t kind=0;uint64_t operation=0;
    // Startup runs on the supervisor's asynchronous worker; runtime never blocks.
    if(poll(&ready,1,3000)>0 && control_receive(health,&reader,&kind,&operation)==1 && kind=='B' && operation==0)return 0;
    net_backend_close();return -1;
}
int net_backend_send(const void *data,size_t size){
    if(link_generation&&!link_lost)return stream_offer(data,size);
    ssize_t sent;
    do {sent=send(frames,data,size,MSG_DONTWAIT);} while(sent<0&&errno==EINTR);
    if(sent==(ssize_t)size)return 1;
    if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS))return 0;
    fail("broker send failed");
    return 0;
}
// Adopts links the broker hands over and reports a failed one so it reconnects.
static void link_service(void){
    if(link_channel<0)return;
    uint8_t kind;uint64_t generation;int descriptor;
    while(link_receive(link_channel,&kind,&generation,&descriptor)){
        if(kind!=LINK_OFFER||descriptor<0||generation<=link_generation){if(descriptor>=0)close(descriptor);continue;}
        if(fcntl(descriptor,F_SETFD,FD_CLOEXEC)){close(descriptor);continue;}
        if(stream.fd>=0)close(stream.fd);
        int paused=stream.paused;
        stream.fd=descriptor;stream.connecting=0;stream.used=0;stream.need=4;stream.rx_start=stream.rx_used=0;
        stream.queued=stream.sent=0;stream.progress=stream.tx_progress=stream_ms();stream.paused=paused;
        if(!link_generation)fprintf(stderr,"network: direct link to the switch\n");
        link_generation=generation;link_lost=0;link_partial_polls=0;
        if(link_message(link_channel,LINK_ACK,generation,-1))fail("link acknowledgement");
    }
    if(link_generation&&!link_lost&&stream.fd<0){
        link_lost=1;
        if(link_message(link_channel,LINK_LOST,link_generation,-1))fail("link loss report");
    }
}
void net_backend_poll(void){
    uint8_t packet[65537];
    net_backend_health();
    if(link_generation&&!link_lost){
        stream_poll();
        if(stream.used>0&&stream.used<stream.need&&link_partial_polls<LINK_PARTIAL_POLLS)link_partial_polls++;
        link_service();
    }
    if(deferred_size){if(receive_frame(deferred_frame,deferred_size,NULL)<0)return;deferred_size=0;}
    for(unsigned budget=0;budget<256;budget++){
        ssize_t n=recv(frames,packet,sizeof(packet),MSG_DONTWAIT);
        if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)fail("broker receive failed");break;}
        if(n<14||n>65536)fail("invalid broker frame");
        if(receive_frame(packet,(size_t)n,NULL)<0){memcpy(deferred_frame,packet,(size_t)n);deferred_size=(size_t)n;break;}
    }
}
void net_backend_close(void){
    deferred_size=0;
    if(link_channel>=0){close(link_channel);link_channel=-1;}
    if(stream.fd>=0)stream_disconnect();
    link_generation=0;link_lost=0;
    if(stats>=0){close(stats);stats=-1;}
    if(frames>=0){close(frames);frames=-1;}if(health>=0){close(health);health=-1;}
    if(broker>0){
        int status;pid_t result=waitpid(broker,&status,WNOHANG);
        if(!result){kill(broker,SIGKILL);while(waitpid(broker,&status,0)<0&&errno==EINTR){}}
        broker=-1;
    }
}

int net_backend_pid(void){return broker>0?(int)broker:0;}

void net_backend_health(void){
    if(health<0)return;
    link_service();
    uint8_t kind;uint64_t operation;
    int n=control_receive(health,&health_reader,&kind,&operation);
    if(n<0)fail("broker disconnected");
    if(n==1){if(kind!='A'||operation!=pause_operation)fail("unexpected broker acknowledgement");pause_ack=operation;}
}
void net_backend_pause(int paused,uint64_t operation){
    pause_operation=operation;
    stream.paused=paused; // the VMM's own link, when it has one
    if(health<0){pause_ack=operation;return;}
    if(control_send(health,paused?'P':'U',operation))fail("pause control send");
}
int net_backend_pause_ready(uint64_t operation){net_backend_health();return pause_ack==operation;}
int net_backend_wait_fd(void){
    // Whole frames arrive in batches the poll interval collects cheaply. Only a
    // switch that hands over a frame in pieces needs a wakeup for each piece.
    if(link_partial_polls<LINK_PARTIAL_POLLS)return -1;
    if(!link_generation||link_lost||stream.fd<0||stream.connecting||stream.paused)return -1;
    // A frame held back by guest backpressure keeps the link readable: only the poll interval retries it.
    if(stream.need>4&&stream.used==stream.need)return -1;
    return stream.fd;
}
int net_backend_pending_rx(void){
    if(frames<0)return 0;
    if(deferred_size)return 1;
    char byte;ssize_t n=recv(frames,&byte,1,MSG_PEEK|MSG_DONTWAIT);
    if(n<0 && errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)fail("RX queue inspection");
    return n>=0;
}

void net_backend_metrics(uint64_t out[7]){
    if(stats>=0)for(unsigned budget=0;budget<8;budget++){
        uint8_t packet[49];ssize_t n=recv(stats,packet,sizeof(packet),MSG_DONTWAIT);if(n<0)break;
        if(n!=48 || memcmp(packet,"HVDP\1\5\0\0",8))continue;
        uint64_t values[5]={0};for(unsigned i=0;i<5;i++)for(unsigned j=0;j<8;j++)values[i]|=(uint64_t)packet[8+i*8+j]<<(8*j);
        rx_drops=values[0];rx_drop_bytes=values[1];stats_drops=values[2];stream_drops=values[3];stream_drop_bytes=values[4];
    }
    int next=0;if(frames>=0 && ioctl(frames,FIONREAD,&next))next=-1;
    out[0]=next>=0?(uint64_t)next:UINT64_MAX;out[1]=deferred_size;out[2]=tx_drops+stream_drops+(broker>0?stream.drops:0);out[3]=tx_drop_bytes+stream_drop_bytes+(broker>0?stream.drop_bytes:0);out[4]=rx_drops;out[5]=rx_drop_bytes;out[6]=stats_drops;
}
