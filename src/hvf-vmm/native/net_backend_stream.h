// SPDX-License-Identifier: Apache-2.0
// QEMU stream Ethernet client. Fixed memory, nonblocking I/O, reconnect on EOF.
#pragma once
#include <sys/socket.h>
#include <sys/uio.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "net_backend.h"
#define STREAM_FRAME 65536u
#define STREAM_RX_CAPACITY (2u * (STREAM_FRAME + 4u))
// macOS gives Unix stream sockets 8 KiB buffers, less than one 9000-byte frame,
// so each frame took several partial sends and wakeups on both sides.
#define STREAM_SOCKET_BUFFER (1 << 20)
#define STREAM_TX_CAPACITY (1024u * 1024u)
static struct {
    int fd, connecting, paused;
    const char *path;
    net_receive_fn receive;
    uint8_t rx[STREAM_RX_CAPACITY], tx[STREAM_TX_CAPACITY];
    // used/need describe the current frame for the broker's blocked_rx check.
    // rx_start/rx_used delimit buffered bytes; later frames remain in place.
    size_t used, need, rx_start, rx_used, sent, queued, tx_head;
    uint64_t retry, progress, tx_progress, drops, drop_bytes;
} stream = {.fd=-1};
static uint64_t stream_ms(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void stream_disconnect(void) {
    if(stream.fd>=0)close(stream.fd);
    stream.fd=-1;stream.connecting=0;stream.used=0;stream.need=4;stream.rx_start=stream.rx_used=0;
    for(size_t offset=stream.tx_head;offset<stream.queued;){
        uint32_t size=0;
        for(unsigned i=0;i<4;i++)size=(size<<8)|stream.tx[offset+i];
        stream.drops++;stream.drop_bytes+=size;offset+=size+4;
    }
    stream.queued=stream.sent=stream.tx_head=0;stream.retry=stream_ms()+1000;
}
static int stream_peer(void) {
    uid_t uid;gid_t gid;
    return getpeereid(stream.fd,&uid,&gid)==0 && uid==geteuid();
}
static void stream_connect(void) {
    // A stream adopted from the broker has no path: only the broker connects.
    if(!stream.path || stream.fd>=0 || stream_ms()<stream.retry)return;
    struct stat st;
    if(lstat(stream.path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077)){
        stream.retry=stream_ms()+1000;return;
    }
    stream.fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(stream.fd<0){stream_disconnect();return;}
    int one=1,buffer=STREAM_SOCKET_BUFFER;
    // Best effort: the kernel caps buffers at kern.ipc.maxsockbuf.
    (void)setsockopt(stream.fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));
    (void)setsockopt(stream.fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer));
    if(fcntl(stream.fd,F_SETFL,O_NONBLOCK)||fcntl(stream.fd,F_SETFD,FD_CLOEXEC)||
       setsockopt(stream.fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))){stream_disconnect();return;}
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    strlcpy(addr.sun_path,stream.path,sizeof(addr.sun_path));
    stream.progress=stream_ms();
    if(connect(stream.fd,(struct sockaddr *)&addr,sizeof(addr))){
        if(errno==EINPROGRESS)stream.connecting=1;else stream_disconnect();
    }else if(!stream_peer())stream_disconnect();
}
static int stream_open(const struct hvf_options *options,net_receive_fn receive) {
    stream.path=options->stream_path;stream.receive=receive;stream.need=4;stream.used=0;stream.rx_start=stream.rx_used=0;
    stream_connect();return stream.fd<0?-1:0;
}
static void stream_flush(void) {
    while(stream.fd>=0 && !stream.connecting && stream.sent<stream.queued){
        uint32_t size=0;
        for(unsigned i=0;i<4;i++)size=(size<<8)|stream.tx[stream.tx_head+i];
        size_t end=stream.tx_head+size+4;
        ssize_t n=send(stream.fd,stream.tx+stream.sent,end-stream.sent,0);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
        if(n<=0){stream_disconnect();return;}
        stream.sent+=(size_t)n;stream.tx_progress=stream_ms();
        if(stream.sent==end)stream.tx_head=end;
    }
    if(stream.sent==stream.queued)stream.sent=stream.queued=stream.tx_head=0;
}
// A bounded byte queue absorbs ordinary VirtIO bursts. Saturation still drops
// whole new frames; a partially transmitted frame is retained until completion.
static void stream_send(const void *data,size_t size) {
    if(size<14||size>STREAM_FRAME)return;
    stream_flush();
    if(stream.fd<0 || size+4>sizeof(stream.tx)-(stream.queued-stream.tx_head)){
        stream.drops++;stream.drop_bytes+=size;return;
    }
    if(size+4>sizeof(stream.tx)-stream.queued){
        memmove(stream.tx,stream.tx+stream.tx_head,stream.queued-stream.tx_head);
        stream.queued-=stream.tx_head;stream.sent-=stream.tx_head;stream.tx_head=0;
    }
    // New arrivals must not extend a stalled writer's timeout indefinitely.
    if(!stream.queued)stream.tx_progress=stream_ms();
    for(unsigned i=0;i<4;i++)stream.tx[stream.queued+i]=(uint8_t)(size>>(24-8*i));
    memcpy(stream.tx+stream.queued+4,data,size);stream.queued+=size+4;
    stream_flush();
}
static int stream_can_send(void) {
    return stream.fd>=0 && STREAM_FRAME+4<=sizeof(stream.tx)-(stream.queued-stream.tx_head);
}
// Sender that owns the link directly (the VMM): a full socket is
// backpressure, never loss. Returns 1 once the frame is written, or queued
// behind a partial write, and 0 while an earlier frame is still queued or
// nothing could be written (the caller retains the frame and retries).
static int stream_offer(const void *data,size_t size) {
    if(size<14||size>STREAM_FRAME||stream.fd<0){stream.drops++;stream.drop_bytes+=size;return 1;}
    stream_flush();
    if(stream.fd<0){stream.drops++;stream.drop_bytes+=size;return 1;}
    if(stream.queued)return 0;
    uint8_t length[4];for(unsigned i=0;i<4;i++)length[i]=(uint8_t)(size>>(24-8*i));
    struct iovec parts[2]={{length,4},{(void *)data,size}};
    ssize_t n=writev(stream.fd,parts,2);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<=0){stream_disconnect();stream.drops++;stream.drop_bytes+=size;return 1;}
    stream.tx_progress=stream_ms();
    if((size_t)n==size+4)return 1;
    // Keep the unsent tail so the stream never carries part of a frame.
    memcpy(stream.tx,length,4);memcpy(stream.tx+4,data,size);
    stream.queued=size+4;stream.sent=(size_t)n;
    return 1;
}
static void stream_poll(void) {
    if(stream.paused)return;
    stream_connect();if(stream.fd<0)return;
    if((stream.used || stream.connecting) && stream_ms()-stream.progress>5000){stream_disconnect();return;}
    if(stream.queued && stream_ms()-stream.tx_progress>5000){stream_disconnect();return;}
    if(stream.connecting){
        struct pollfd p={stream.fd,POLLOUT,0};
        if(poll(&p,1,0)<=0)return;
        int error=0;socklen_t size=sizeof(error);
        if(getsockopt(stream.fd,SOL_SOCKET,SO_ERROR,&error,&size)||error||!stream_peer()){
            stream_disconnect();return;
        }stream.connecting=0;
    }
    stream_flush();
    for(unsigned budget=0;budget<256 && stream.fd>=0;budget++){
        if(stream.need==4 && stream.rx_used>=4){
            uint32_t size=0;for(unsigned i=0;i<4;i++)size=(size<<8)|stream.rx[stream.rx_start+i];
            if(size<14||size>STREAM_FRAME){stream_disconnect();return;}
            stream.need=size+4;
        }
        stream.used=stream.rx_used<stream.need?stream.rx_used:stream.need;
        if(stream.used==stream.need){
            // Keep used==need if the callback applies backpressure: the broker
            // uses that condition to stop polling the stream socket for RX.
            // Temporary backpressure retries later; other failures reconnect.
            if(stream.receive(stream.rx+stream.rx_start+4,stream.need-4,NULL)<0){
                if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=ENOBUFS&&errno!=EINTR)
                    stream_disconnect();
                return;
            }
            stream.rx_start+=stream.need;
            stream.rx_used-=stream.need;
            if(!stream.rx_used)stream.rx_start=0;
            stream.need=4;stream.used=0;
            continue;
        }
        size_t tail_free=sizeof(stream.rx)-(stream.rx_start+stream.rx_used);
        if(stream.rx_start && tail_free<STREAM_FRAME+4){
            // Compact only when another maximum-sized frame will not fit.
            // Normal draining of coalesced frames advances an offset only.
            memmove(stream.rx,stream.rx+stream.rx_start,stream.rx_used);
            stream.rx_start=0;tail_free=sizeof(stream.rx)-stream.rx_used;
        }
        if(!tail_free){stream_disconnect();return;}
        ssize_t n=recv(stream.fd,stream.rx+stream.rx_start+stream.rx_used,tail_free,0);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
        if(n<=0){stream_disconnect();return;}
        stream.rx_used+=(size_t)n;stream.progress=stream_ms();
    }
}
