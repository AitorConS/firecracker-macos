// SPDX-License-Identifier: Apache-2.0
// White-box protocol regression: real Unix datagrams, production gate + libslirp.
#include "slirp.h"
#include "../../src/hvf-vmm/native/socket_gate.c"
#include <assert.h>
#include <stdio.h>
static unsigned icmp, udp_frames;
static int64_t milliseconds=1000;
static ssize_t output(const void *data,size_t len,void *opaque){
    (void)opaque;const uint8_t *p=data;
    if(len>=34&&p[12]==8&&p[13]==0){if(p[23]==1)icmp++;if(p[23]==17)udp_frames++;}
    return len;
}
static int64_t clock_ns(void *p){(void)p;return milliseconds*1000000;}
static int poll_add(int fd,int events,void *p){(void)fd;(void)events;(void)p;return 0;}
static int poll_events(int i,void *p){(void)i;(void)p;return 0;}
static void notify(void *p){(void)p;}
static void register_fd(int fd,void *p){(void)fd;(void)p;}
int main(void){
    struct hvf_security policy={.development=1};hvf_policy_set(&policy);
    SlirpConfig cfg={.version=6,.in_enabled=true,.if_mtu=1500,.if_mru=1500};
    inet_pton(AF_INET,"10.0.2.0",&cfg.vnetwork);inet_pton(AF_INET,"255.255.255.0",&cfg.vnetmask);
    inet_pton(AF_INET,"10.0.2.2",&cfg.vhost);inet_pton(AF_INET,"10.0.2.3",&cfg.vnameserver);
    SlirpCb cb={.send_packet=output,.clock_get_ns=clock_ns,.notify=notify,.register_poll_socket=register_fd,.unregister_poll_socket=register_fd};
    Slirp *s=slirp_new(&cfg,&cb,NULL);assert(s);
    struct socket *so=socreate(s,IPPROTO_UDP);assert(udp_attach(so,AF_INET)>=0);close(so->s);
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_DGRAM,0,pair));so->s=pair[0];client_tokens[pair[0]]=1;
    so->so_lfamily=so->so_ffamily=AF_INET;inet_pton(AF_INET,"10.0.2.15",&so->so_laddr);so->so_faddr=cfg.vnameserver;
    so->so_lport=htons(12345);so->so_fport=htons(53);
    uint8_t mac[6]={2,1,2,3,4,5};arp_table_add(s,so->so_laddr.s_addr,mac);
    so->so_m=m_get(s);so->so_m->m_len=28;memset(so->so_m->m_data,0,28);
    struct ip *ip=mtod(so->so_m,struct ip *);ip->ip_v=4;ip->ip_hl=5;ip->ip_len=28;ip->ip_ttl=64;ip->ip_p=17;ip->ip_src=so->so_laddr;ip->ip_dst=so->so_faddr;
    // No SCM_RIGHTS on data channel. A malformed envelope is consumed, then a
    // valid response must remain available. Repeated faults must be bounded.
    struct datagram good={.magic=UDP_MAGIC,.address={.sin_len=sizeof(struct sockaddr_in),.sin_family=AF_INET,.sin_port=htons(53)}};good.address.sin_addr=cfg.vnameserver;
    char wire[sizeof(good)+4];memcpy(wire,&good,sizeof(good));memcpy(wire+sizeof(good),"DNS!",4);
    // Isolated losses stay retryable indefinitely: a valid datagram in between
    // clears the fault run, so the mapping is never torn down and no ICMP flows.
    for(unsigned i=0;i<64;i++){
        unsigned before=icmp;
        struct datagram bad=good;
        if(i%4==0)assert(send(pair[1],"",0,0)==0);
        if(i%4==1)assert(send(pair[1],"short",5,0)==5);
        if(i%4==2){bad.magic=0;assert(send(pair[1],&bad,sizeof(bad),0)==sizeof(bad));}
        if(i%4==3){bad.address.sin_family=AF_UNIX;assert(send(pair[1],&bad,sizeof(bad),0)==sizeof(bad));}
        sorecvfrom(so);
        printf("empty %u icmp=%u\n",i,icmp-before);
        struct pollfd p={pair[0],POLLIN,0};assert(poll(&p,1,0)==0);
        assert(s->udb.so_next==so);
        assert(send(pair[1],wire,sizeof(wire),0)==sizeof(wire));sorecvfrom(so);
        assert(udp_frames==i+1);
    }
    // A run shorter than the bound is tolerated and never refreshes the expiry.
    unsigned expires=so->so_expire;
    for(unsigned i=0;i+1<MAX_FAULTS;i++){assert(send(pair[1],"",0,0)==0);sorecvfrom(so);assert(so->so_expire==expires);}
    assert(s->udb.so_next==so);
    assert(send(pair[1],wire,sizeof(wire),0)==sizeof(wire));sorecvfrom(so);assert(s->udb.so_next==so);
    // A closed receive half is permanently readable on Darwin, so every read
    // returns zero bytes. Forwarding sockets have no expiry: if the gate kept
    // reporting EAGAIN nothing would ever notice the channel is gone.
    assert(!shutdown(pair[0],SHUT_RD));
    struct pollfd readable={pair[0],POLLIN,0};assert(poll(&readable,1,0)==1);
    so->so_expire=0;
    unsigned reads=0;
    while(s->udb.so_next==so&&reads<MAX_FAULTS*8){sorecvfrom(so);reads++;}
    assert(s->udb.so_next==&s->udb);assert(reads<=MAX_FAULTS);
    printf("RESULT icmp=%u valid_udp=%u isolated_tolerated=%d persistent_reads=%u torn_down=1\n",
           icmp,udp_frames,MAX_FAULTS-1,reads);
    client_tokens[pair[0]]=0;close(pair[1]);slirp_cleanup(s);
    return icmp?1:0;
}
