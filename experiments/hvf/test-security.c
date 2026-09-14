// SPDX-License-Identifier: Apache-2.0
// Real Seatbelt + socket authority regression, runs only on macOS 26.
#include "policy.h"
#include "socket_gate.h"
#include "seatbelt.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <spawn.h>
extern char **environ;
int hvf_policy_socket(int,int,int);
int hvf_policy_connect(int,const struct sockaddr *,socklen_t);
ssize_t hvf_policy_sendto(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
int hvf_policy_close(int);
int hvf_policy_dns(struct in_addr *,uint16_t *);
ssize_t hvf_policy_recvfrom(int,void *,size_t,int,struct sockaddr *,socklen_t *);
static struct sockaddr_in address(unsigned port){struct sockaddr_in a={.sin_len=sizeof(a),.sin_family=AF_INET,.sin_port=htons(port)};a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);return a;}
int main(int argc,char **argv){
    unsigned stress=argc==2 && !strcmp(argv[1],"--udp-stress")?32:0;
    // Set up real host endpoints before applying the broker profile.
    int tcp=socket(AF_INET,SOCK_STREAM,0),udp=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in t=address(0),u=address(0);socklen_t len=sizeof(t);
    assert(!bind(tcp,(void *)&t,sizeof(t)));assert(!listen(tcp,4));assert(!getsockname(tcp,(void *)&t,&len));
    u.sin_addr.s_addr=htonl(INADDR_ANY);
    assert(!bind(udp,(void *)&u,sizeof(u)));assert(!getsockname(udp,(void *)&u,&len));
    u.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    pid_t child=fork();assert(child>=0);
    if(child){
        struct pollfd ready={tcp,POLLIN,0};assert(poll(&ready,1,3000)==1);
        int accepted=accept(tcp,NULL,NULL);assert(accepted>=0);char byte;assert(read(accepted,&byte,1)==1&&byte=='t');close(accepted);
        ready=(struct pollfd){udp,POLLIN,0};assert(poll(&ready,1,3000)==1);
        struct sockaddr_in peer;socklen_t length=sizeof(peer);assert(recvfrom(udp,&byte,1,0,(void *)&peer,&length)==1&&byte=='u');
        assert(sendto(udp,"r",1,0,(void *)&peer,length)==1);
        for(unsigned i=0;i<stress;i++){
            ready=(struct pollfd){udp,POLLIN,0};assert(poll(&ready,1,3000)==1);
            length=sizeof(peer);assert(recvfrom(udp,&byte,1,0,(void *)&peer,&length)==1&&byte=='b');
            assert(sendto(udp,"s",1,0,(void *)&peer,length)==1);
        }
        ready=(struct pollfd){udp,POLLIN,0};assert(poll(&ready,1,200)==0);
        int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
        close(tcp);close(udp);puts("Seatbelt file/socket denial, exact TCP authorization and UDP roundtrip: PASS");return 0;
    }
    close(tcp);close(udp);if(stress){close(0);assert(dup2(2,1)==1);}
    struct hvf_endpoint rules[2]={{.port=ntohs(t.sin_port),.address={127,0,0,1}},{.udp=1,.port=ntohs(u.sin_port),.address={127,0,0,1}}};
    struct hvf_security policy={.egress_count=2,.egress=rules};hvf_policy_set(&policy);
    assert(!hvf_gate_start());assert(!hvf_sandbox_install("(version 1)(deny default)"));
    assert(open("/etc/passwd",O_RDONLY)<0);
    pid_t executable;char *args[]={"/usr/bin/true",NULL};assert(posix_spawn(&executable,args[0],NULL,NULL,args,environ)!=0);
    struct in_addr dns;uint16_t dns_port;assert(hvf_policy_dns(&dns,&dns_port)==-1);
    int client=hvf_policy_socket(AF_INET,SOCK_STREAM,0);assert(client>=0);
    struct sockaddr_in forbidden=t;forbidden.sin_addr.s_addr=htonl(0x7f000002);
    assert(hvf_policy_connect(client,(void *)&forbidden,sizeof(forbidden))<0&&errno==EPERM);
    assert(hvf_gate_tcp(client,&forbidden,0)<0&&errno==EPERM);
    int result=hvf_policy_connect(client,(void *)&t,sizeof(t));assert(!result||errno==EINPROGRESS);
    struct pollfd ready={client,POLLOUT,0};assert(poll(&ready,1,1000)==1);
    assert(write(client,"t",1)==1);char byte;
    int raw=socket(AF_INET,SOCK_STREAM,0);assert(raw>=0);assert(connect(raw,(void *)&t,sizeof(t))<0&&errno==EPERM);close(raw);
    int proxy=hvf_policy_socket(AF_INET,SOCK_DGRAM,0);assert(proxy>=0);
    assert(hvf_policy_sendto(proxy,"u",1,0,(void *)&u,sizeof(u))==1);
    ready=(struct pollfd){proxy,POLLIN,0};assert(poll(&ready,1,1000)==1);
    // Existing host endpoint remains usable for receiving in the restricted helper.
    struct sockaddr_in peer;len=sizeof(peer);assert(hvf_policy_recvfrom(proxy,&byte,1,0,(void *)&peer,&len)==1&&byte=='r');
    int many[32];
    for(unsigned i=0;i<stress;i++){
        many[i]=hvf_policy_socket(AF_INET,SOCK_DGRAM,0);assert(many[i]>=0);
        assert(hvf_policy_sendto(many[i],"b",1,0,(void *)&u,sizeof(u))==1);
    }
    for(unsigned i=0;i<stress;i++){
        ready=(struct pollfd){many[i],POLLIN,0};assert(poll(&ready,1,3000)==1);
        len=sizeof(peer);assert(hvf_policy_recvfrom(many[i],&byte,1,0,(void *)&peer,&len)==1&&byte=='s');
        hvf_policy_close(many[i]);
    }
    forbidden=u;forbidden.sin_addr.s_addr=htonl(0x7f000002);
    assert(hvf_policy_sendto(proxy,"x",1,0,(void *)&forbidden,sizeof(forbidden))==1);
    hvf_policy_close(proxy);close(client);_exit(0);
}
