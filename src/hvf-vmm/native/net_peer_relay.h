// SPDX-License-Identifier: Apache-2.0
// Broker side of the peer control protocol (peer_proto.h). The broker owns the
// connection to the switch's control socket; the VMM never connects anywhere.
// Messages and descriptors cross the broker/VMM channel as single datagrams.
#pragma once
#include "peer_proto.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define RELAY_HELD 64
static struct {
    int ctl,channel,connecting,pending_fd;
    const char *path;
    uint8_t mac[6],in[PEER_MESSAGE];
    size_t used;
    uint64_t retry;
    // PEER_ADD descriptors stay referenced here until the VMM acknowledges them.
    struct {uint64_t id;int fd;} held[RELAY_HELD];
    unsigned nheld;
} relay={.ctl=-1,.channel=-1,.pending_fd=-1};
static uint64_t relay_ms(void){
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static int relay_to_vmm(const struct peer_message *m,int fd){
    uint8_t wire[PEER_MESSAGE];peer_encode(wire,m);
    char space[CMSG_SPACE(sizeof(int))];
    struct iovec io={wire,sizeof(wire)};
    struct msghdr h={.msg_iov=&io,.msg_iovlen=1};
    if(fd>=0){
        memset(space,0,sizeof(space));h.msg_control=space;h.msg_controllen=sizeof(space);
        struct cmsghdr *c=CMSG_FIRSTHDR(&h);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    }
    return sendmsg(relay.channel,&h,MSG_DONTWAIT)==(ssize_t)sizeof(wire)?0:-1;
}
static void relay_disconnect(void){
    int had=relay.ctl>=0;
    if(relay.ctl>=0)close(relay.ctl);
    if(relay.pending_fd>=0)close(relay.pending_fd);
    for(unsigned i=0;i<relay.nheld;i++)close(relay.held[i].fd);
    relay.ctl=relay.pending_fd=-1;relay.connecting=0;relay.used=0;relay.nheld=0;relay.retry=relay_ms()+1000;
    // Fail closed: without the switch, no peer may stay authorized.
    if(had)(void)relay_to_vmm(&(struct peer_message){.type=PEER_RESET},-1);
}
// A short message on a Unix stream either fits or the connection is unusable.
static int relay_to_switch(const struct peer_message *m){
    uint8_t wire[PEER_MESSAGE];peer_encode(wire,m);
    if(send(relay.ctl,wire,sizeof(wire),MSG_DONTWAIT)==(ssize_t)sizeof(wire))return 0;
    relay_disconnect();return -1;
}
static void relay_connected(void){
    uid_t uid;gid_t gid;
    if(getpeereid(relay.ctl,&uid,&gid)||uid!=geteuid()){relay_disconnect();return;}
    struct peer_message hello={.type=PEER_HELLO,.value=PEER_FEATURE_DGRAM};memcpy(hello.mac,relay.mac,6);
    (void)relay_to_switch(&hello);
}
static void relay_connect(void){
    if(!relay.path||relay.ctl>=0||relay_ms()<relay.retry)return;
    struct stat st;
    if(lstat(relay.path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077)){relay.retry=relay_ms()+1000;return;}
    relay.ctl=socket(AF_UNIX,SOCK_STREAM,0);
    int one=1;
    if(relay.ctl<0||fcntl(relay.ctl,F_SETFL,O_NONBLOCK)||fcntl(relay.ctl,F_SETFD,FD_CLOEXEC)||
       setsockopt(relay.ctl,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))){relay_disconnect();return;}
    struct sockaddr_un address={.sun_family=AF_UNIX};
    strlcpy(address.sun_path,relay.path,sizeof(address.sun_path));
    if(!connect(relay.ctl,(struct sockaddr *)&address,sizeof(address)))relay_connected();
    else if(errno==EINPROGRESS)relay.connecting=1;
    else relay_disconnect();
}
static void relay_open(const char *path,int channel,const uint8_t mac[6]){
    relay.path=path;relay.channel=channel;memcpy(relay.mac,mac,6);relay_connect();
}
static void relay_release(uint64_t id){
    for(unsigned i=0;i<relay.nheld;i++)if(relay.held[i].id==id){
        close(relay.held[i].fd);relay.held[i]=relay.held[--relay.nheld];return;
    }
}
static void relay_from_switch(void){
    for(;;){
        char space[CMSG_SPACE(4*sizeof(int))];
        struct iovec io={relay.in+relay.used,PEER_MESSAGE-relay.used};
        struct msghdr h={.msg_iov=&io,.msg_iovlen=1,.msg_control=space,.msg_controllen=sizeof(space)};
        ssize_t n=recvmsg(relay.ctl,&h,MSG_DONTWAIT);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
        int invalid=n<=0||(h.msg_flags&MSG_CTRUNC);
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&h);c;c=CMSG_NXTHDR(&h,c)){
            if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS)continue;
            size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
            for(size_t i=0;i<count;i++){
                int fd;memcpy(&fd,CMSG_DATA(c)+i*sizeof(int),sizeof(fd));
                if(relay.pending_fd<0)relay.pending_fd=fd;else{close(fd);invalid=1;}
            }
        }
        if(invalid){relay_disconnect();return;}
        relay.used+=(size_t)n;
        if(relay.used<PEER_MESSAGE)continue;
        relay.used=0;
        struct peer_message m;int fd=relay.pending_fd;relay.pending_fd=-1;
        if(peer_decode(relay.in,&m)||(m.type!=PEER_WELCOME&&m.type!=PEER_ADD&&m.type!=PEER_DEL)||
           (m.type==PEER_ADD)!=(fd>=0)){
            if(fd>=0)close(fd);
            relay_disconnect();return;
        }
        if(m.type!=PEER_ADD){(void)relay_to_vmm(&m,-1);continue;}
        if(relay.nheld==RELAY_HELD||relay_to_vmm(&m,fd)){
            close(fd);
            if(relay_to_switch(&(struct peer_message){.type=PEER_ACK,.epoch=m.epoch,.value=m.value}))return;
            continue;
        }
        relay.held[relay.nheld].id=m.value;relay.held[relay.nheld++].fd=fd;
    }
}
static void relay_from_vmm(void){
    for(unsigned budget=0;budget<64;budget++){
        uint8_t wire[PEER_MESSAGE+1];
        ssize_t n=recv(relay.channel,wire,sizeof(wire),MSG_DONTWAIT);
        if(n<0)return;
        struct peer_message m;
        if(n!=PEER_MESSAGE||peer_decode(wire,&m)||(m.type!=PEER_ACK&&m.type!=PEER_DEAD&&m.type!=PEER_STATS))continue;
        if(m.type==PEER_ACK)relay_release(m.value);
        if(relay.ctl>=0&&!relay.connecting&&relay_to_switch(&m))return;
    }
}
// Adds the relay's descriptors to a poll set; returns how many were added.
static unsigned relay_poll_fds(struct pollfd *fds){
    unsigned count=0;
    if(relay.channel<0)return 0;
    fds[count++]=(struct pollfd){relay.channel,POLLIN,0};
    if(relay.ctl>=0)fds[count++]=(struct pollfd){relay.ctl,relay.connecting?POLLOUT:POLLIN,0};
    return count;
}
static void relay_service(void){
    if(relay.channel<0)return;
    relay_connect();
    if(relay.ctl>=0&&relay.connecting){
        struct pollfd p={relay.ctl,POLLOUT,0};
        if(poll(&p,1,0)>0){
            int error=0;socklen_t length=sizeof(error);
            relay.connecting=0;
            if(getsockopt(relay.ctl,SOL_SOCKET,SO_ERROR,&error,&length)||error)relay_disconnect();
            else relay_connected();
        }
    }
    if(relay.ctl>=0&&!relay.connecting)relay_from_switch();
    relay_from_vmm();
}
