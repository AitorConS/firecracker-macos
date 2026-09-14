// SPDX-License-Identifier: Apache-2.0
// White-box regression over the real socket authority: a UDP proxy must never
// be given a source port that another process already holds on the host.
//
// The authority leaves its proxies unbound and unconnected, so the kernel picks
// the source port on the first send. With SO_REUSEADDR the ephemeral search
// stops excluding ports held by sockets bound to a specific address, so a proxy
// can be handed the port of a live service. That service then receives guest
// traffic addressed to itself, and anything it answers comes straight back to
// it: a packet loop that survives the VM. This exercises exactly that path with
// the production gate and reports what the services observed.
#ifndef GATE_SOURCE
#define GATE_SOURCE "../../src/hvf-vmm/native/socket_gate.c"
#endif
#include GATE_SOURCE
#include "policy.h"
#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>

#define SERVICES 64
#define BATCH 64
#define BATCHES 128

static int services[SERVICES];
static uint16_t service_ports[SERVICES];

static int is_service_port(uint16_t port)
{
    for(unsigned i=0;i<SERVICES;i++)if(service_ports[i]==port)return 1;
    return 0;
}

int main(void)
{
    struct hvf_security policy={.development=1};hvf_policy_set(&policy);
    struct sockaddr_in loopback={.sin_len=sizeof(struct sockaddr_in),.sin_family=AF_INET};
    loopback.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    for(unsigned i=0;i<SERVICES;i++){
        services[i]=socket(AF_INET,SOCK_DGRAM,0);assert(services[i]>=0);
        assert(!bind(services[i],(const void *)&loopback,sizeof(loopback)));
        nonblock(services[i]);
        struct sockaddr_in name;socklen_t length=sizeof(name);
        assert(!getsockname(services[i],(void *)&name,&length));
        service_ports[i]=ntohs(name.sin_port);
    }
    assert(!hvf_gate_start());

    unsigned proxies=0,delivered=0,collisions=0,self_addressed=0,foreign=0;
    for(unsigned batch=0;batch<BATCHES;batch++){
        int fds[BATCH];unsigned made=0;
        for(unsigned i=0;i<BATCH;i++){
            int fd=hvf_gate_udp();
            if(fd<0)break;
            fds[made++]=fd;proxies++;
            struct sockaddr_in target=loopback;
            target.sin_port=htons(service_ports[(batch*BATCH+i)%SERVICES]);
            char payload[16];snprintf(payload,sizeof(payload),"probe-%05u",proxies);
            assert(hvf_gate_send(fd,payload,sizeof(payload),0,(const void *)&target,sizeof(target))==(ssize_t)sizeof(payload));
        }
        // The authority forwards on its own poll loop; give it room to drain.
        for(unsigned wait=0;wait<20;wait++){
            struct pollfd idle={services[0],POLLIN,0};(void)poll(&idle,1,1);
        }
        for(unsigned i=0;i<SERVICES;i++)for(;;){
            char buffer[128];struct sockaddr_in from;socklen_t length=sizeof(from);
            if(recvfrom(services[i],buffer,sizeof(buffer),MSG_DONTWAIT,(void *)&from,&length)<0)break;
            delivered++;
            uint16_t source=ntohs(from.sin_port);
            if(source==service_ports[i]){collisions++;self_addressed++;}
            else if(is_service_port(source)){collisions++;foreign++;}
        }
        for(unsigned i=0;i<made;i++){hvf_gate_close(fds[i]);close(fds[i]);}
    }
    printf("RESULT proxies=%u delivered=%u collisions=%u self_addressed=%u foreign=%u\n",
           proxies,delivered,collisions,self_addressed,foreign);
    return collisions?1:0;
}
