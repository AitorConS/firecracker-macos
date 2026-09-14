// SPDX-License-Identifier: Apache-2.0
// White-box regression over the real socket authority: a UDP proxy channel
// handed to the broker must carry datagrams, never arrive with its receive side
// already shut down.
//
// The broker side runs in this process exactly as libslirp drives it:
// hvf_gate_udp, hvf_gate_send, hvf_gate_recv, hvf_gate_close + close. The
// authority is the real forked one. A loopback echo service answers each query.
// Every proxy sends QUERIES datagrams; each must come back through the same
// channel. Receives go through hvf_gate_recv only, so a dead channel shows up
// exactly as in production: n=0 envelopes counted as faults and ENOTCONN after
// sixteen. Nothing is retried and no loss threshold is applied.
//
// Optional host activity (argv[1] = churn processes): unrelated processes that
// create and free Unix socketpairs. Every free schedules XNU's unp_gc, which is
// what any busy host does; it changes no byte of the protocol.
#ifndef GATE_SOURCE
#define GATE_SOURCE "socket_gate.c"
#endif
#include GATE_SOURCE
#include "policy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>

#define PROXIES 20000
#define QUERIES 2

static void churn(void){
    for(;;){int t[2];if(!socketpair(AF_UNIX,SOCK_DGRAM,0,t)){close(t[0]);close(t[1]);}}
}

int main(int argc,char **argv){
    int churners=argc>1?atoi(argv[1]):0;unsigned proxies=argc>2?(unsigned)atoi(argv[2]):PROXIES;
    struct hvf_security policy={.development=1};hvf_policy_set(&policy);
    struct sockaddr_in loopback={.sin_len=sizeof(struct sockaddr_in),.sin_family=AF_INET};
    loopback.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    int echo=socket(AF_INET,SOCK_DGRAM,0);assert(echo>=0);
    assert(!bind(echo,(const void *)&loopback,sizeof(loopback)));
    socklen_t elen=sizeof(loopback);assert(!getsockname(echo,(void *)&loopback,&elen));
    pid_t echo_pid=fork();assert(echo_pid>=0);
    if(!echo_pid){
        for(;;){char b[256];struct sockaddr_in from;socklen_t l=sizeof(from);ssize_t n=recvfrom(echo,b,sizeof(b),0,(void *)&from,&l);if(n>0)(void)sendto(echo,b,(size_t)n,0,(void *)&from,l);}
    }
    close(echo);
    pid_t churn_pids[16];if(churners>16)churners=16;
    for(int i=0;i<churners;i++){churn_pids[i]=fork();assert(churn_pids[i]>=0);if(!churn_pids[i])churn();}
    assert(!hvf_gate_start());

    unsigned opened=0,dead_channels=0,teardowns=0,queries_ok=0,queries_lost=0,after_dead_ok=0,after_dead_total=0,errors=0,faults_total=0;
    int saw_dead_recently=0;
    for(unsigned p=0;p<proxies;p++){
        int fd=hvf_gate_udp();
        if(fd<0){errors++;continue;}
        opened++;
        int dead=0,torn=0;unsigned ok=0;
        for(unsigned q=0;q<QUERIES && !torn;q++){
            char payload[32];int plen=snprintf(payload,sizeof(payload),"q-%u-%u",p,q)+1;
            if(hvf_gate_send(fd,payload,(size_t)plen,0,(const void *)&loopback,sizeof(loopback))!=plen){errors++;break;}
            int got=0;
            for(unsigned attempt=0;attempt<200 && !got && !torn;attempt++){
                struct pollfd ready={fd,POLLIN,0};(void)poll(&ready,1,5);
                char buffer[64];struct sockaddr_in from;socklen_t length=sizeof(from);
                ssize_t n=hvf_gate_recv(fd,buffer,sizeof(buffer),0,(void *)&from,&length);
                if(n==plen&&!memcmp(buffer,payload,(size_t)plen))got=1;
                else if(n<0&&errno==ENOTCONN){torn=1;dead=1;}
                else if(n<0&&errno==EAGAIN&&client_faults[fd])dead=1;
            }
            if(got)ok++;
        }
        faults_total+=client_faults[fd];
        if(dead)dead_channels++;
        if(torn)teardowns++;
        queries_ok+=ok;queries_lost+=QUERIES-ok;
        // Recovery: after a dead channel, the next proxy must work (counted below).
        if(saw_dead_recently){after_dead_total++;if(ok==QUERIES)after_dead_ok++;saw_dead_recently=0;}
        if(dead)saw_dead_recently=1;
        hvf_gate_close(fd);close(fd);
    }
    for(int i=0;i<churners;i++){kill(churn_pids[i],SIGKILL);waitpid(churn_pids[i],NULL,0);}
    kill(echo_pid,SIGKILL);waitpid(echo_pid,NULL,0);
    printf("RESULT churners=%d proxies=%u opened=%u dead_channels=%u teardowns=%u queries_ok=%u queries_lost=%u "
           "after_dead_ok=%u after_dead_total=%u errors=%u\n",
           churners,proxies,opened,dead_channels,teardowns,queries_ok,queries_lost,after_dead_ok,after_dead_total,errors);
    (void)faults_total;
    return (dead_channels||queries_lost||errors)?1:0;
}
