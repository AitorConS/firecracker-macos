// SPDX-License-Identifier: Apache-2.0
// Unit regression on the real socket authority (socket_gate.c + policy.c).
// hvf_gate_start() forks the real authority; each connection goes through the
// real hvf_gate_tcp() (RPC, SCM_RIGHTS, dup2, transfer_usable retry) exactly as
// libslirp's tcp_fconnect does. A loopback server writes one byte and closes.
// Reading EOF before that byte is the guest-visible EOF. With trigger=1 a thread
// frees AF_UNIX sockets to schedule XNU unp_gc() often; the gate is untouched.
// Built against baseline socket_gate.c (control) or the patched copy (fixed).
// usage: gate-unit <connections> <trigger 0|1>
#include "hvf.h"
#include "policy.h"
#include "socket_gate.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static atomic_int running=1;static atomic_ulong frees;static int listener=-1;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void *server(void *u){(void)u;while(atomic_load(&running)){struct pollfd p={listener,POLLIN,0};if(poll(&p,1,50)<=0)continue;int c=accept(listener,NULL,NULL);if(c<0)continue;(void)write(c,"x",1);close(c);}return NULL;}
static void *trigger(void *u){(void)u;while(atomic_load(&running)){int p[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,p))continue;close(p[0]);close(p[1]);atomic_fetch_add(&frees,1);}return NULL;}
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: %s connections trigger\n",argv[0]);return 2;}
    unsigned long n=strtoul(argv[1],NULL,10);int use_trigger=atoi(argv[2]);signal(SIGPIPE,SIG_IGN);
    static struct hvf_security security={.development=1};hvf_policy_set(&security);
    listener=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in address={.sin_len=sizeof(address),.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if(bind(listener,(void *)&address,sizeof(address))||listen(listener,1024)){perror("listen");return 2;}
    socklen_t l=sizeof(address);getsockname(listener,(void *)&address,&l);
    if(hvf_gate_start()){perror("hvf_gate_start");return 2;}   // fork before any thread
    pthread_t s,t;pthread_create(&s,NULL,server,NULL);if(use_trigger)pthread_create(&t,NULL,trigger,NULL);
    unsigned long ok=0,eof=0,connect_error=0,read_error=0,timeouts=0;double start=now();
    for(unsigned long i=0;i<n;i++){
        int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0){connect_error++;continue;}
        int r=hvf_gate_tcp(fd,&address,0);
        if(r<0&&errno!=EINPROGRESS){connect_error++;hvf_gate_close(fd);close(fd);continue;}
        char b;ssize_t got=-1;int e=0;double deadline=now()+2;
        for(;;){got=recv(fd,&b,1,0);e=errno;if(got>=0||(e!=EAGAIN&&e!=ENOTCONN))break;if(now()>deadline)break;struct pollfd q={fd,POLLIN,0};(void)poll(&q,1,20);}
        if(got==1&&b=='x')ok++;else if(got==1)read_error++;else if(got==0)eof++;else if(e==EAGAIN||e==ENOTCONN)timeouts++;else read_error++;
        hvf_gate_close(fd);close(fd);
        if(hvf_gate_check()){fprintf(stderr,"authority died\n");break;}
    }
    double seconds=now()-start;atomic_store(&running,0);pthread_join(s,NULL);if(use_trigger)pthread_join(t,NULL);
    printf("{\"connections\":%lu,\"trigger\":%d,\"ok\":%lu,\"eof_before_byte\":%lu,\"connect_error\":%lu,\"read_error\":%lu,\"timeouts\":%lu,\"trigger_frees\":%lu,\"seconds\":%.3f}\n",n,use_trigger,ok,eof,connect_error,read_error,timeouts,(unsigned long)atomic_load(&frees),seconds);
    return ok==n && !eof && !connect_error && !read_error && !timeouts ? 0 : 1;
}
