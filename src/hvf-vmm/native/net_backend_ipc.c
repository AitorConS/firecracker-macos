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

static int frames=-1,health=-1,stats=-1;
static uint64_t stream_drops,stream_drop_bytes;
static uint64_t tx_drops,tx_drop_bytes,rx_drops,rx_drop_bytes,stats_drops;
static uint8_t deferred_frame[65536];
static size_t deferred_size;
static pid_t broker=-1;
static struct control_reader health_reader;
static uint64_t pause_operation, pause_ack;
static net_receive_fn receive_frame;
static void fail(const char *message){fprintf(stderr,"network IPC: %s\n",message);exit(2);}
static ssize_t broker_deliver(const void *data,size_t size,void *opaque){
    (void)opaque;
    ssize_t n=send(frames,data,size,MSG_DONTWAIT);
    // Bounded datagram queues may drop under load; protocols can retransmit.
    if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){rx_drops++;rx_drop_bytes+=size;return (ssize_t)size;}return n;
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
    for(int fd=0;fd<maximum;fd++)if(fd!=frames&&fd!=health&&fd!=stats&&fd!=STDERR_FILENO&&fd!=lease)close(fd);
    // Keep stdout occupied: GLib diagnostics must never write into a reused socket FD.
    if(dup2(STDERR_FILENO,STDOUT_FILENO)<0)_exit(2);
    hvf_policy_set(options->security);
    int is_stream=options->stream_path!=NULL;
    if(options->security && !options->security->development &&
       ((!is_stream && hvf_gate_start()) || hvf_sandbox_install(options->security->broker_profile))){
        (void)control_send(health,'E',0);_exit(2);
    }
    if(is_stream?stream_open(options,broker_deliver):slirp_backend_open(options,broker_deliver)){
        (void)control_send(health,'E',0);_exit(2);
    }
    if(control_send(health,'B',0))_exit(2);
    uint8_t packet[65537];
    struct control_reader commands={0};
    int paused=0;uint64_t last_operation=0;
    uint64_t next_stats=0;
    for(;;){
        struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);uint64_t ms=(uint64_t)now.tv_sec*1000+now.tv_nsec/1000000;
        if(ms>=next_stats){
            uint8_t packet[48]={'H','V','D','P',1,5,0,0};uint64_t values[5]={rx_drops,rx_drop_bytes,stats_drops,stream.drops,stream.drop_bytes};
            for(unsigned i=0;i<5;i++)for(unsigned j=0;j<8;j++)packet[8+i*8+j]=(uint8_t)(values[i]>>(8*j));
            if(send(stats,packet,sizeof(packet),MSG_DONTWAIT)!=(ssize_t)sizeof(packet))stats_drops++;next_stats=ms+100;
        }
        if(!is_stream && hvf_gate_check()){fprintf(stderr,"socket authority disconnected\n");_exit(2);}
        struct pollfd fds[2]={{health,POLLIN,0},{frames,POLLIN,0}};
        int result=poll(fds,2,1);
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
        if(paused){usleep(1000);continue;}
        for(unsigned budget=0;budget<256;budget++){
            ssize_t n=recv(frames,packet,sizeof(packet),MSG_DONTWAIT);
            if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)goto done;break;}
            if(n<14||n>65536)goto done;
            if(is_stream)stream_send(packet,(size_t)n);else slirp_backend_send(packet,(size_t)n);
        }
        if(is_stream)stream_poll();else slirp_backend_poll();
    }
done:
    if(is_stream)stream_disconnect();else slirp_backend_close();close(frames);close(health);_exit(0);
}
int net_backend_open(const struct hvf_options *options,net_receive_fn receive){
    int data[2],control[2],telemetry[2];
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,data))return -1;
    if(socketpair(AF_UNIX,SOCK_STREAM,0,control)){close(data[0]);close(data[1]);return -1;}
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,telemetry)){close(data[0]);close(data[1]);close(control[0]);close(control[1]);return -1;}
    int buffer=262144;
    for(unsigned i=0;i<2;i++){
        if(setsockopt(data[i],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer)) || setsockopt(data[i],SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer))){
            close(data[0]);close(data[1]);close(control[0]);close(control[1]);close(telemetry[0]);close(telemetry[1]);return -1;
        }
    }
    broker=fork();
    if(broker<0){close(data[0]);close(data[1]);close(control[0]);close(control[1]);close(telemetry[0]);close(telemetry[1]);return -1;}
    if(!broker){close(data[0]);close(control[0]);close(telemetry[0]);frames=data[1];health=control[1];stats=telemetry[1];broker_main(options);}
    close(data[1]);close(control[1]);close(telemetry[1]);frames=data[0];health=control[0];stats=telemetry[0];receive_frame=receive;
    struct pollfd ready={health,POLLIN,0};
    struct control_reader reader={0};uint8_t kind=0;uint64_t operation=0;
    // Startup runs on the supervisor's asynchronous worker; runtime never blocks.
    if(poll(&ready,1,3000)>0 && control_receive(health,&reader,&kind,&operation)==1 && kind=='B' && operation==0)return 0;
    net_backend_close();return -1;
}
void net_backend_send(const void *data,size_t size){
    if(send(frames,data,size,MSG_DONTWAIT)<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=ENOBUFS)fail("broker send failed");tx_drops++;tx_drop_bytes+=size;}
}
void net_backend_poll(void){
    uint8_t packet[65537];
    net_backend_health();
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
    uint8_t kind;uint64_t operation;
    int n=control_receive(health,&health_reader,&kind,&operation);
    if(n<0)fail("broker disconnected");
    if(n==1){if(kind!='A'||operation!=pause_operation)fail("unexpected broker acknowledgement");pause_ack=operation;}
}
void net_backend_pause(int paused,uint64_t operation){
    pause_operation=operation;
    if(health<0){pause_ack=operation;return;}
    if(control_send(health,paused?'P':'U',operation))fail("pause control send");
}
int net_backend_pause_ready(uint64_t operation){net_backend_health();return pause_ack==operation;}
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
    out[0]=next>=0?(uint64_t)next:UINT64_MAX;out[1]=deferred_size;out[2]=tx_drops+stream_drops;out[3]=tx_drop_bytes+stream_drop_bytes;out[4]=rx_drops;out[5]=rx_drop_bytes;out[6]=stats_drops;
}
