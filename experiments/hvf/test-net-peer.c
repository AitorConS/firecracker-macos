// SPDX-License-Identifier: Apache-2.0
// Direct VM-to-VM links: source contract, wire protocol, VMM data plane and
// the broker relay, against real Unix sockets and a fake switch.
#include "net_peer.h"
#include "net_peer_relay.h"
#include "seatbelt.h"
#include <sys/wait.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const uint8_t self_mac[6]={2,0,0,0,0,1},self_ip[4]={10,0,0,1};
static const uint8_t peer_mac[6]={2,0,0,0,0,2},peer_ip[4]={10,0,0,2};
static uint8_t delivered[65536];
static size_t delivered_size;
static unsigned deliveries;
static int ring_full;

static ssize_t deliver(const void *frame,size_t size,void *opaque){
    (void)opaque;
    if(ring_full)return -1;
    memcpy(delivered,frame,size);delivered_size=size;deliveries++;return (ssize_t)size;
}
static size_t ipv4(uint8_t *f,const uint8_t dst[6],const uint8_t src[6],const uint8_t ip[4],size_t size){
    memset(f,0,size);memcpy(f,dst,6);memcpy(f+6,src,6);f[12]=8;f[13]=0;f[14]=0x45;memcpy(f+26,ip,4);return size;
}
static size_t arp(uint8_t *f,const uint8_t dst[6],const uint8_t src[6],const uint8_t ip[4]){
    memset(f,0,42);memcpy(f,dst,6);memcpy(f+6,src,6);f[12]=8;f[13]=6;
    f[15]=1;f[16]=8;f[18]=6;f[19]=4;f[21]=2;memcpy(f+22,src,6);memcpy(f+28,ip,4);return 42;
}
static void send_message_at(int line,int fd,const struct peer_message *m,int descriptor){
    uint8_t wire[PEER_MESSAGE];peer_encode(wire,m);
    char space[CMSG_SPACE(sizeof(int))];memset(space,0,sizeof(space));
    struct iovec io={wire,sizeof(wire)};
    struct msghdr h={.msg_iov=&io,.msg_iovlen=1};
    if(descriptor>=0){
        h.msg_control=space;h.msg_controllen=sizeof(space);
        struct cmsghdr *c=CMSG_FIRSTHDR(&h);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&descriptor,sizeof(int));
    }
    if(sendmsg(fd,&h,0)!=(ssize_t)sizeof(wire)){fprintf(stderr,"send_message line %d: %s\n",line,strerror(errno));abort();}
}
#define send_message(...) send_message_at(__LINE__,__VA_ARGS__)
// Reads one message; returns the descriptor attached to it, or -1.
static int read_message_at(int line,int fd,struct peer_message *m){
    uint8_t wire[PEER_MESSAGE];size_t used=0;int descriptor=-1;
    while(used<sizeof(wire)){
        char space[CMSG_SPACE(sizeof(int))];
        struct iovec io={wire+used,sizeof(wire)-used};
        struct msghdr h={.msg_iov=&io,.msg_iovlen=1,.msg_control=space,.msg_controllen=sizeof(space)};
        ssize_t n=recvmsg(fd,&h,0);
        if(n<=0){fprintf(stderr,"read_message line %d: %s\n",line,n<0?strerror(errno):"EOF");abort();}
        used+=(size_t)n;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&h);c;c=CMSG_NXTHDR(&h,c))memcpy(&descriptor,CMSG_DATA(c),sizeof(int));
    }
    assert(peer_decode(wire,m)==0);
    return descriptor;
}
#define read_message(...) read_message_at(__LINE__,__VA_ARGS__)
static void set_timeout(int fd){struct timeval t={2,0};assert(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t)));}
// The other VMM sizes its end the same way (unix datagram buffers default to a few KB).
static void size_link(int fd){int size=2<<20;assert(!setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size))&&!setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size)));}

static void test_source_contract(void){
    uint8_t f[64];
    assert(net_frame_source_valid(f,ipv4(f,peer_mac,self_mac,self_ip,60),self_mac,self_ip));
    assert(!net_frame_source_valid(f,ipv4(f,peer_mac,self_mac,peer_ip,60),self_mac,self_ip));   // spoofed IP
    assert(!net_frame_source_valid(f,ipv4(f,peer_mac,peer_mac,self_ip,60),self_mac,self_ip));   // spoofed MAC
    assert(!net_frame_source_valid(f,ipv4(f,peer_mac,self_mac,self_ip,30),self_mac,self_ip));   // truncated
    ipv4(f,peer_mac,self_mac,self_ip,60);f[14]=0x44;
    assert(!net_frame_source_valid(f,60,self_mac,self_ip));                                     // bad IHL
    assert(net_frame_source_valid(f,arp(f,peer_mac,self_mac,self_ip),self_mac,self_ip));
    static const uint8_t zero[4];
    assert(net_frame_source_valid(f,arp(f,peer_mac,self_mac,zero),self_mac,self_ip));           // probe
    assert(!net_frame_source_valid(f,arp(f,peer_mac,self_mac,peer_ip),self_mac,self_ip));
    ipv4(f,peer_mac,self_mac,self_ip,60);f[12]=0x86;f[13]=0xdd;
    assert(!net_frame_source_valid(f,60,self_mac,self_ip));                                     // IPv6
}
static void test_protocol(void){
    uint8_t wire[PEER_MESSAGE];struct peer_message in={.type=PEER_ADD,.flags=1,.epoch=0x1122334455667788ULL,.value=0xa0b0c0d0},out;
    memcpy(in.mac,peer_mac,6);memcpy(in.ip,peer_ip,4);
    peer_encode(wire,&in);
    assert(!memcmp(wire,"JPC1",4)&&wire[4]==PEER_ADD&&wire[8]==0x88&&wire[16]==0xd0&&wire[26]==10);
    assert(!peer_decode(wire,&out)&&out.epoch==in.epoch&&out.value==in.value&&!memcmp(out.mac,peer_mac,6)&&!memcmp(out.ip,peer_ip,4));
    struct peer_message stats={.type=PEER_STATS,.epoch=1ULL<<40,.value=(1ULL<<40)+5};
    peer_encode(wire,&stats);assert(!peer_decode(wire,&out)&&out.epoch==stats.epoch&&out.value==stats.value);
    peer_encode(wire,&in);wire[0]='X';assert(peer_decode(wire,&out));
    peer_encode(wire,&in);wire[4]=99;assert(peer_decode(wire,&out));
    peer_encode(wire,&in);wire[6]=1;assert(peer_decode(wire,&out));
    peer_encode(wire,&in);wire[31]=1;assert(peer_decode(wire,&out));
}
static void test_data_plane(void){
    int channel[2],link[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,channel));set_timeout(channel[1]);
    net_peer_open(channel[0],self_mac,deliver);
    uint8_t f[9000];struct peer_message m;
    // No peers yet: everything uses the switch.
    assert(net_peer_send(f,ipv4(f,peer_mac,self_mac,self_ip,100))==-1);

    struct peer_message welcome={.type=PEER_WELCOME,.epoch=7};memcpy(welcome.mac,self_mac,6);memcpy(welcome.ip,self_ip,4);
    send_message(channel[1],&welcome,-1);
    struct peer_message add={.type=PEER_ADD,.epoch=7,.value=42};memcpy(add.mac,peer_mac,6);memcpy(add.ip,peer_ip,4);

    // A stale epoch is refused, but still acknowledged so references are released.
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    struct peer_message stale=add;stale.epoch=6;
    send_message(channel[1],&stale,link[0]);close(link[0]);close(link[1]);
    net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==0&&m.value==42);

    // A stream socket is not an Ethernet link.
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,link));
    send_message(channel[1],&add,link[0]);close(link[0]);close(link[1]);
    net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==0);

    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));size_link(link[1]);
    send_message(channel[1],&add,link[0]);close(link[0]);
    net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==1&&m.epoch==7&&m.value==42);
    uint64_t metrics[7];net_peer_metrics(metrics);assert(metrics[6]==1);

    // TX: unicast to the peer goes direct; broadcast, unknown and spoofed frames do not.
    size_t size=ipv4(f,peer_mac,self_mac,self_ip,9000);
    assert(net_peer_send(f,size)==1);
    uint8_t got[65536];assert(recv(link[1],got,sizeof(got),0)==(ssize_t)size&&!memcmp(got,f,size));
    static const uint8_t broadcast[6]={255,255,255,255,255,255},other[6]={2,0,0,0,0,9};
    assert(net_peer_send(f,ipv4(f,broadcast,self_mac,self_ip,60))==-1);
    assert(net_peer_send(f,ipv4(f,other,self_mac,self_ip,60))==-1);
    assert(net_peer_send(f,ipv4(f,peer_mac,self_mac,peer_ip,60))==-1);

    // RX: valid frames reach the guest; frames that break the peer's source contract do not.
    size=ipv4(f,self_mac,peer_mac,peer_ip,1500);
    assert(send(link[1],f,size,0)==(ssize_t)size);
    assert(net_peer_poll()==1&&deliveries==1&&delivered_size==size);
    ipv4(f,self_mac,peer_mac,self_ip,100);assert(send(link[1],f,100,0)==100);
    assert(net_peer_poll()==0&&deliveries==1);
    net_peer_metrics(metrics);assert(metrics[4]==1);

    // A full guest ring retains the frame for that peer and delivers it later.
    ring_full=1;assert(send(link[1],f,ipv4(f,self_mac,peer_mac,peer_ip,200),0)==200);
    assert(net_peer_poll()==0&&deliveries==1);
    ring_full=0;assert(net_peer_poll()==1&&deliveries==2&&delivered_size==200);

    // A peer that stops reading first applies backpressure, then is dropped after the stall bound.
    size=ipv4(f,peer_mac,self_mac,self_ip,9000);
    int result;unsigned sent=0;
    while((result=net_peer_send(f,size))==1)sent++;
    assert(result==0&&sent>0);
    usleep(150000);
    assert(net_peer_send(f,size)==1);
    net_peer_metrics(metrics);assert(metrics[5]>=1);
    while(recv(link[1],got,sizeof(got),MSG_DONTWAIT)>0){}
    assert(net_peer_send(f,size)==1);

    // STATS reports direct bytes to the switch.
    int found=0;
    for(int i=0;i<4&&!found;i++){net_peer_poll();if(read_message(channel[1],&m)<0&&m.type==PEER_STATS)found=1;}
    assert(found&&m.epoch>0&&m.value>0);

    // A new switch session gets the cumulative statistics without waiting for new traffic.
    send_message(channel[1],&welcome,-1);
    found=0;
    for(int i=0;i<4&&!found;i++){net_peer_poll();if(read_message(channel[1],&m)<0&&m.type==PEER_STATS)found=1;}
    assert(found&&m.epoch>0);
    assert(net_peer_send(f,size)==-1); // the new session dropped the old link
    close(link[1]);
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));size_link(link[1]);
    send_message(channel[1],&add,link[0]);close(link[0]);net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==1);

    // PEER_DEL and RESET return the destination to the switch.
    struct peer_message del={.type=PEER_DEL,.epoch=7,.value=42};
    send_message(channel[1],&del,-1);net_peer_poll();
    assert(net_peer_send(f,size)==-1);
    close(link[1]);

    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    send_message(channel[1],&add,link[0]);close(link[0]);net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.flags==1);
    send_message(channel[1],&(struct peer_message){.type=PEER_RESET},-1);net_peer_poll();
    assert(net_peer_send(f,size)==-1);

    // A peer whose other end is gone is reported dead and falls back to the switch.
    close(link[1]);
    send_message(channel[1],&welcome,-1);
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    send_message(channel[1],&add,link[0]);close(link[0]);net_peer_poll();
    assert(read_message(channel[1],&m)<0&&m.flags==1);
    close(link[1]);
    assert(net_peer_send(f,size)==-1);
    net_peer_poll();
    do assert(read_message(channel[1],&m)<0); while(m.type==PEER_STATS); // the session start reports statistics
    assert(m.type==PEER_DEAD&&m.value==42);
    net_peer_close();close(channel[1]);
}
static void test_relay(void){
    char directory[]="/tmp/hvf-peer.XXXXXX";assert(mkdtemp(directory));
    char path[128];snprintf(path,sizeof(path),"%s/net.ctl",directory);
    int listener=socket(AF_UNIX,SOCK_STREAM,0);
    struct sockaddr_un address={.sun_family=AF_UNIX};strlcpy(address.sun_path,path,sizeof(address.sun_path));
    assert(!bind(listener,(struct sockaddr *)&address,sizeof(address))&&!chmod(path,0600)&&!listen(listener,4));
    int channel[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,channel));set_timeout(channel[1]);
    relay_open(path,channel[0],self_mac);
    struct pollfd fds[2];assert(relay_poll_fds(fds)>=1&&fds[0].fd==channel[0]);
    for(int i=0;i<100&&relay.connecting;i++){relay_service();usleep(1000);}
    int sw=accept(listener,NULL,NULL);assert(sw>=0);set_timeout(sw);
    struct peer_message m;
    assert(read_message(sw,&m)<0&&m.type==PEER_HELLO&&m.value==PEER_FEATURE_DGRAM&&!memcmp(m.mac,self_mac,6));

    struct peer_message welcome={.type=PEER_WELCOME,.epoch=3};memcpy(welcome.mac,self_mac,6);
    send_message(sw,&welcome,-1);
    int link[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    struct peer_message add={.type=PEER_ADD,.epoch=3,.value=5};memcpy(add.mac,peer_mac,6);memcpy(add.ip,peer_ip,4);
    send_message(sw,&add,link[0]);close(link[0]);
    usleep(10000);relay_service();
    assert(read_message(channel[1],&m)<0&&m.type==PEER_WELCOME&&m.epoch==3);
    int received=read_message(channel[1],&m);
    assert(received>=0&&m.type==PEER_ADD&&m.value==5&&relay.nheld==1);
    // The descriptor that reached the VMM is the switch's socketpair end.
    assert(send(received,"x",1,0)==1);char byte;assert(recv(link[1],&byte,1,0)==1&&byte=='x');

    // The broker releases its reference only on PEER_ACK, which it forwards.
    send_message(channel[1],&(struct peer_message){.type=PEER_ACK,.flags=1,.epoch=3,.value=5},-1);
    relay_service();
    assert(relay.nheld==0);
    assert(read_message(sw,&m)<0&&m.type==PEER_ACK&&m.flags==1&&m.value==5);

    // VMM-originated messages other than ACK/DEAD/STATS are not forwarded.
    send_message(channel[1],&welcome,-1);
    send_message(channel[1],&(struct peer_message){.type=PEER_DEAD,.epoch=3,.value=5},-1);
    send_message(channel[1],&(struct peer_message){.type=PEER_IDLE,.epoch=3,.value=5},-1);
    relay_service();
    assert(read_message(sw,&m)<0&&m.type==PEER_DEAD);
    assert(read_message(sw,&m)<0&&m.type==PEER_IDLE);

    // A PEER_ADD without a descriptor is a protocol violation: fail closed.
    send_message(sw,&add,-1);usleep(10000);relay_service();
    assert(relay.ctl<0&&read_message(channel[1],&m)<0&&m.type==PEER_RESET);
    close(sw);close(received);close(link[1]);

    // Switch restart: the broker reconnects and introduces itself again.
    relay.retry=0;relay_service();
    for(int i=0;i<100&&relay.connecting;i++){relay_service();usleep(1000);}
    sw=accept(listener,NULL,NULL);assert(sw>=0);set_timeout(sw);
    assert(read_message(sw,&m)<0&&m.type==PEER_HELLO);
    close(sw);usleep(10000);relay_service();
    assert(relay.ctl<0&&read_message(channel[1],&m)<0&&m.type==PEER_RESET);
    close(listener);unlink(path);rmdir(directory);close(channel[0]);close(channel[1]);
}
// Built with PEER_IDLE_MS=400: a quiet link is reported idle exactly once,
// and traffic makes it active again.
static void test_idle(void){
    int channel[2],link[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,channel)&&!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    set_timeout(channel[1]);size_link(link[1]);
    net_peer_open(channel[0],self_mac,deliver);
    struct peer_message welcome={.type=PEER_WELCOME,.epoch=11};memcpy(welcome.mac,self_mac,6);memcpy(welcome.ip,self_ip,4);
    struct peer_message add={.type=PEER_ADD,.epoch=11,.value=3};memcpy(add.mac,peer_mac,6);memcpy(add.ip,peer_ip,4);
    send_message(channel[1],&welcome,-1);send_message(channel[1],&add,link[0]);close(link[0]);
    net_peer_poll();
    struct peer_message m;assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==1);
    uint8_t f[100];size_t size=ipv4(f,peer_mac,self_mac,self_ip,100);
    usleep(250000);assert(net_peer_send(f,size)==1); // activity before the threshold
    usleep(250000);net_peer_poll();
    char byte;assert(recv(channel[1],&byte,1,MSG_DONTWAIT|MSG_PEEK)<0); // not idle yet
    usleep(450000);net_peer_poll();
    do assert(read_message(channel[1],&m)<0); while(m.type==PEER_STATS);
    assert(m.type==PEER_IDLE&&m.epoch==11&&m.value==3);
    usleep(450000);net_peer_poll();
    while(recv(channel[1],&byte,1,MSG_DONTWAIT|MSG_PEEK)>0){read_message(channel[1],&m);assert(m.type!=PEER_IDLE);} // once only
    assert(net_peer_send(f,size)==1); // still usable until the switch withdraws it
    usleep(450000);net_peer_poll();
    do assert(read_message(channel[1],&m)<0); while(m.type==PEER_STATS);
    assert(m.type==PEER_IDLE);
    net_peer_close();close(channel[1]);close(link[1]);
}
// The VMM receives peer descriptors after its Seatbelt profile is installed.
// Check that the hardened profile (no network rules at all) still permits
// datagram I/O on a socketpair end received by SCM_RIGHTS.
static void test_sandboxed_vmm(void){
    int channel[2],link[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,channel)&&!socketpair(AF_UNIX,SOCK_DGRAM,0,link));
    size_link(link[1]);set_timeout(channel[1]);set_timeout(link[1]);
    pid_t child=fork();assert(child>=0);
    if(!child){
        close(channel[1]);close(link[0]);close(link[1]);
        if(hvf_sandbox_install("(version 1)(deny default)(allow file-read* file-write* (subpath \"/private/var/empty\"))"))_exit(10);
        deliveries=0;ring_full=0;
        net_peer_open(channel[0],self_mac,deliver);
        uint64_t metrics[7]={0};
        for(int i=0;i<2000&&metrics[6]==0;i++){net_peer_poll();net_peer_metrics(metrics);usleep(1000);}
        if(metrics[6]!=1)_exit(11);
        uint8_t f[1500];size_t size=ipv4(f,peer_mac,self_mac,self_ip,1500);
        if(net_peer_send(f,size)!=1)_exit(12);
        for(int i=0;i<2000&&!deliveries;i++){net_peer_poll();usleep(1000);}
        _exit(deliveries==1&&delivered_size==200?0:13);
    }
    close(channel[0]);
    struct peer_message welcome={.type=PEER_WELCOME,.epoch=9};memcpy(welcome.mac,self_mac,6);memcpy(welcome.ip,self_ip,4);
    struct peer_message add={.type=PEER_ADD,.epoch=9,.value=1};memcpy(add.mac,peer_mac,6);memcpy(add.ip,peer_ip,4);
    send_message(channel[1],&welcome,-1);send_message(channel[1],&add,link[0]);
    struct peer_message m;assert(read_message(channel[1],&m)<0&&m.type==PEER_ACK&&m.flags==1);
    close(link[0]);
    uint8_t got[2000];assert(recv(link[1],got,sizeof(got),0)==1500);
    uint8_t f[200];assert(send(link[1],f,ipv4(f,self_mac,peer_mac,peer_ip,200),0)==200);
    int status;assert(waitpid(child,&status,0)==child);
    if(!WIFEXITED(status)||WEXITSTATUS(status)){fprintf(stderr,"sandboxed VMM child status %d\n",status);abort();}
    close(channel[1]);close(link[1]);
}
int main(void){
    test_source_contract();
    test_protocol();
    test_data_plane();
    test_relay();
    test_idle();
    test_sandboxed_vmm();
    puts("net-peer: ok");
    return 0;
}
