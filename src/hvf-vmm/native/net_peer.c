// SPDX-License-Identifier: Apache-2.0
#include "net_peer.h"
#include "peer_proto.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define PEER_MAX 64
#define PEER_FRAME 65536
#define PEER_RX_BUDGET 64
// A peer that cannot take frames for this long is a stalled link: drop its
// frames, as the switch's bounded writer does, so it never blocks the TX ring.
#define PEER_STALL_MS 100
#define PEER_STATS_MS 1000
struct peer {
    uint64_t id;int fd,dead;uint8_t mac[6],ip[4];
    uint64_t blocked;size_t deferred;uint8_t *buf;
};
static struct peer peers[PEER_MAX];
static unsigned npeers,next_rx;
static int channel=-1;
static uint8_t self_mac[6],self_ip[4];
static uint64_t epoch,next_stats,sent_tx,sent_rx;
static net_peer_receive_fn deliver;
static uint64_t tx_frames,rx_frames,tx_bytes,rx_bytes,invalid_drops,stalled_drops;

static uint64_t now_ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
static uint16_t be16(const uint8_t *p){return (uint16_t)(p[0]<<8|p[1]);}
int net_frame_source_valid(const uint8_t *f,size_t len,const uint8_t mac[6],const uint8_t ip[4]){
    static const uint8_t zero[4];
    if(len<14||memcmp(f+6,mac,6))return 0;
    switch(be16(f+12)){
    case 0x0800:{
        size_t header=(size_t)(f[14]&15)*4;
        return len>=34&&f[14]>>4==4&&header>=20&&len>=14+header&&!memcmp(f+26,ip,4);
    }
    case 0x0806:
        return len>=42&&be16(f+14)==1&&be16(f+16)==0x0800&&f[18]==6&&f[19]==4&&
            !memcmp(f+22,mac,6)&&(!memcmp(f+28,ip,4)||!memcmp(f+28,zero,4));
    default:return 0; // IPv6 and VLAN trunks are not part of this IPv4 contract.
    }
}
static void channel_send(const struct peer_message *m){
    uint8_t wire[PEER_MESSAGE];peer_encode(wire,m);
    if(channel>=0)(void)send(channel,wire,sizeof(wire),MSG_DONTWAIT);
}
static void peer_release(struct peer *p){if(p->fd>=0)close(p->fd);free(p->buf);p->fd=-1;p->buf=NULL;}
static void compact(void){
    unsigned kept=0;
    for(unsigned i=0;i<npeers;i++){if(peers[i].dead)peer_release(&peers[i]);else peers[kept++]=peers[i];}
    npeers=kept;if(next_rx>=npeers)next_rx=0;
}
static void peer_dead(struct peer *p){
    if(p->dead)return;
    p->dead=1;channel_send(&(struct peer_message){.type=PEER_DEAD,.epoch=epoch,.value=p->id});
}
static void drop_all(void){for(unsigned i=0;i<npeers;i++)peers[i].dead=1;compact();}
static int configure(int fd){
    int one=1,size=2<<20,type=0;socklen_t length=sizeof(type);
    struct sockaddr_storage address;socklen_t address_length=sizeof(address);
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length)||type!=SOCK_DGRAM||
       getsockname(fd,(struct sockaddr *)&address,&address_length)||address.ss_family!=AF_UNIX)return -1;
    return fcntl(fd,F_SETFL,O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)||
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))||
        setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size))||
        setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size))?-1:0;
}
static int peer_add(const struct peer_message *m,int fd){
    static const uint8_t zero[4];
    if(!epoch||m->epoch!=epoch||(m->mac[0]&1)||!memcmp(m->mac,self_mac,6)||!memcmp(m->ip,zero,4)||configure(fd))return 0;
    for(unsigned i=0;i<npeers;i++)if(peers[i].id==m->value||!memcmp(peers[i].mac,m->mac,6))peers[i].dead=1;
    compact();
    uint8_t *buf=npeers<PEER_MAX?malloc(PEER_FRAME):NULL;
    if(!buf)return 0;
    struct peer *p=&peers[npeers++];
    *p=(struct peer){.id=m->value,.fd=fd,.buf=buf};memcpy(p->mac,m->mac,6);memcpy(p->ip,m->ip,4);
    return 1;
}
static void control(const struct peer_message *m,int fd){
    switch(m->type){
    case PEER_WELCOME:
        if(fd<0&&m->epoch&&!memcmp(m->mac,self_mac,6)){
            drop_all();epoch=m->epoch;memcpy(self_ip,m->ip,4);
            // A new switch session starts with no statistics: report any at once.
            if(tx_bytes||rx_bytes){sent_tx=sent_rx=UINT64_MAX;next_stats=0;}
        }
        break;
    case PEER_ADD:{
        int accepted=fd>=0&&peer_add(m,fd);
        if(fd>=0&&!accepted)close(fd);
        channel_send(&(struct peer_message){.type=PEER_ACK,.flags=(uint8_t)accepted,.epoch=m->epoch,.value=m->value});
        return;
    }
    case PEER_DEL:
        if(m->epoch==epoch)for(unsigned i=0;i<npeers;i++)if(peers[i].id==m->value)peers[i].dead=1;
        compact();break;
    case PEER_RESET:drop_all();epoch=0;memset(self_ip,0,4);break;
    default:break;
    }
    if(fd>=0)close(fd);
}
static void channel_poll(void){
    for(unsigned budget=0;channel>=0&&budget<64;budget++){
        uint8_t wire[PEER_MESSAGE+1];char space[CMSG_SPACE(4*sizeof(int))];
        struct iovec io={wire,sizeof(wire)};
        struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=space,.msg_controllen=sizeof(space)};
        ssize_t n=recvmsg(channel,&m,MSG_DONTWAIT);
        if(n<0)return;
        int fd=-1,extra=0;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
            if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS)continue;
            size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
            for(size_t i=0;i<count;i++){int d;memcpy(&d,CMSG_DATA(c)+i*sizeof(int),sizeof(d));if(fd<0)fd=d;else{close(d);extra=1;}}
        }
        struct peer_message message;
        if(n!=PEER_MESSAGE||extra||(m.msg_flags&MSG_CTRUNC)||peer_decode(wire,&message)){if(fd>=0)close(fd);continue;}
        control(&message,fd);
    }
}
void net_peer_open(int fd,const uint8_t mac[6],net_peer_receive_fn receive){
    net_peer_close();
    channel=fd;deliver=receive;memcpy(self_mac,mac,6);
    tx_frames=rx_frames=tx_bytes=rx_bytes=invalid_drops=stalled_drops=sent_tx=sent_rx=0;
}
int net_peer_send(const uint8_t *f,size_t len){
    if(!npeers||len<14||(f[0]&1))return -1;
    struct peer *p=NULL;
    for(unsigned i=0;i<npeers&&!p;i++)if(!memcmp(peers[i].mac,f,6))p=&peers[i];
    // Frames the switch would reject go to the switch, which drops and counts them.
    if(!p||!net_frame_source_valid(f,len,self_mac,self_ip))return -1;
    ssize_t n=send(p->fd,f,len,MSG_DONTWAIT);
    if(n==(ssize_t)len){p->blocked=0;tx_frames++;tx_bytes+=len;return 1;}
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==ENOBUFS)){
        uint64_t now=now_ms();
        if(!p->blocked)p->blocked=now;
        if(now-p->blocked<PEER_STALL_MS)return 0;
        stalled_drops++;return 1;
    }
    peer_dead(p);compact();return -1;
}
int net_peer_poll(void){
    channel_poll();
    int moved=0;
    unsigned count=npeers,start=next_rx;
    for(unsigned k=0;k<count;k++){
        struct peer *p=&peers[(start+k)%count];
        if(p->dead)continue;
        if(p->deferred){
            if(deliver(p->buf,p->deferred,NULL)<0){next_rx=(start+k)%count;goto done;}
            p->deferred=0;moved++;
        }
        for(unsigned budget=0;budget<PEER_RX_BUDGET;budget++){
            ssize_t n=recv(p->fd,p->buf,PEER_FRAME,MSG_DONTWAIT);
            if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)peer_dead(p);break;}
            if(!net_frame_source_valid(p->buf,(size_t)n,p->mac,p->ip)){invalid_drops++;continue;}
            rx_frames++;rx_bytes+=(uint64_t)n;
            // The guest RX ring is shared by every source: stop when it is full
            // and resume with this peer, so no peer starves another.
            if(deliver(p->buf,(size_t)n,NULL)<0){p->deferred=(size_t)n;next_rx=(start+k)%count;goto done;}
            moved++;
        }
    }
    if(count)next_rx=(start+1)%count;
done:
    compact();
    uint64_t now=now_ms();
    if(channel>=0&&now>=next_stats&&(tx_bytes!=sent_tx||rx_bytes!=sent_rx)){
        channel_send(&(struct peer_message){.type=PEER_STATS,.epoch=tx_bytes,.value=rx_bytes});
        sent_tx=tx_bytes;sent_rx=rx_bytes;next_stats=now+PEER_STATS_MS;
    }
    return moved;
}
void net_peer_close(void){
    drop_all();epoch=0;memset(self_ip,0,4);
    if(channel>=0){close(channel);channel=-1;}
}
void net_peer_metrics(uint64_t out[7]){
    out[0]=tx_frames;out[1]=rx_frames;out[2]=tx_bytes;out[3]=rx_bytes;
    out[4]=invalid_drops;out[5]=stalled_drops;out[6]=npeers;
}
