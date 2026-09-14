// SPDX-License-Identifier: Apache-2.0
// Compiled separately from libslirp, without the socket interception macros.
#include "policy.h"
#include "socket_gate.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
struct peer { int fd; struct sockaddr_in address; time_t expires; };
static struct peer peers[1024];
static unsigned next_peer;
static const struct hvf_security deny_all={0};
static const struct hvf_security *policy=&deny_all;
void hvf_policy_set(const struct hvf_security *value){policy=value?value:&deny_all;}
static int denied(void){errno=EPERM;return -1;}
static int socket_type(int fd){int value=0;socklen_t n=sizeof(value);return getsockopt(fd,SOL_SOCKET,SO_TYPE,&value,&n)?-1:value;}
// Listener 0.0.0.0 authorizes that exact INADDR_ANY bind only. Never
// interpret it as a wildcard match for concrete endpoints or egress.
static int match(const struct hvf_endpoint *rules,unsigned count,int type,const struct sockaddr_in *address){
    for(unsigned i=0;i<count;i++)if(rules[i].udp==(type==SOCK_DGRAM) && rules[i].port==ntohs(address->sin_port) && !memcmp(rules[i].address,&address->sin_addr,4))return 1;
    return 0;
}
int hvf_policy_allows(int type,const struct sockaddr_in *v4,int listener){
    if(policy->development)return 1;
    if(!v4||v4->sin_family!=AF_INET||(type!=SOCK_DGRAM&&type!=SOCK_STREAM))return 0;
    if(listener)return match(policy->listeners,policy->listener_count,type,v4);
    if(policy->dns_port && policy->dns_port==ntohs(v4->sin_port) && !memcmp(policy->dns_address,&v4->sin_addr,4))return 1;
    return match(policy->egress,policy->egress_count,type,v4);
}
static int authorized(int fd,const struct sockaddr *address,socklen_t length,int listener){
    return address && length==sizeof(struct sockaddr_in) && hvf_policy_allows(socket_type(fd),(const void *)address,listener);
}
int hvf_policy_socket(int domain,int type,int protocol){
    if(!policy->development && !(domain==AF_INET && ((type==SOCK_STREAM&&(protocol==0||protocol==IPPROTO_TCP)) || (type==SOCK_DGRAM&&(protocol==0||protocol==IPPROTO_UDP)))))return denied();
    if(hvf_gate_active() && type==SOCK_DGRAM)return hvf_gate_udp();
    return socket(domain,type,protocol);
}
int hvf_policy_connect(int fd,const struct sockaddr *address,socklen_t length){
    if(!authorized(fd,address,length,0))return denied();
    if(hvf_gate_active()){
        if(socket_type(fd)!=SOCK_STREAM)return denied();
        return hvf_gate_tcp(fd,(const void *)address,0);
    }
    return connect(fd,address,length);
}
int hvf_policy_bind(int fd,const struct sockaddr *address,socklen_t length){
    // An ephemeral outbound source bind confers no destination authorization.
    int ephemeral=address && length==sizeof(struct sockaddr_in) && address->sa_family==AF_INET && ((const struct sockaddr_in *)address)->sin_port==0;
    if(!ephemeral&&!authorized(fd,address,length,1))return denied();
    if(hvf_gate_active()){
        if(hvf_gate_is_udp(fd))return hvf_gate_bind(fd,(const void *)address);
        if(ephemeral)return denied();
        return hvf_gate_tcp(fd,(const void *)address,1);
    }
    return bind(fd,address,length);
}
int hvf_policy_listen(int fd,int backlog){
    struct sockaddr_storage address;socklen_t length=sizeof(address);
    if(getsockname(fd,(void *)&address,&length)||!authorized(fd,(void *)&address,length,1))return denied();
    if(hvf_gate_active())return hvf_gate_is_listener(fd)?0:denied();
    return listen(fd,backlog);
}
ssize_t hvf_policy_sendto(int fd,const void *data,size_t size,int flags,const struct sockaddr *address,socklen_t length){
    if(hvf_gate_is_udp(fd))return hvf_gate_send(fd,data,size,flags,address,length);
    if(!authorized(fd,address,length,0)){
        // Only reply to peers actually observed on a declared UDP listener.
        int reply=0;
        if(address && address->sa_family==AF_INET && length==sizeof(struct sockaddr_in)){
            const struct sockaddr_in *v4=(const void *)address;
            for(unsigned i=0;i<1024;i++)if(peers[i].fd==fd && peers[i].expires>time(NULL) && peers[i].address.sin_port==v4->sin_port && peers[i].address.sin_addr.s_addr==v4->sin_addr.s_addr){reply=1;break;}
        }
        if(!reply)return denied();
    }
    return sendto(fd,data,size,flags,address,length);
}
int hvf_policy_dns(struct in_addr *address,uint16_t *port){
    if(policy->development)return 0; // explicit development mode uses host resolution
    if(!policy->dns_port)return -1;
    memcpy(address,policy->dns_address,4);*port=htons(policy->dns_port);return 1;
}

ssize_t hvf_policy_recvfrom(int fd,void *data,size_t size,int flags,struct sockaddr *address,socklen_t *length){
    if(hvf_gate_is_udp(fd))return hvf_gate_recv(fd,data,size,flags,address,length);
    ssize_t n=recvfrom(fd,data,size,flags,address,length);
    if(n>=0 && address && length && *length==sizeof(struct sockaddr_in) && address->sa_family==AF_INET){
        struct sockaddr_storage local;socklen_t local_length=sizeof(local);
        if(!getsockname(fd,(void *)&local,&local_length) && authorized(fd,(void *)&local,local_length,1)){
            struct peer *p=&peers[next_peer++%1024];p->fd=fd;p->address=*(struct sockaddr_in *)address;p->expires=time(NULL)+60;
        }
    }
    return n;
}
int hvf_policy_close(int fd){
    hvf_gate_close(fd);
    for(unsigned i=0;i<1024;i++)if(peers[i].fd==fd)peers[i].expires=0;
    return close(fd);
}

int hvf_policy_getsockname(int fd,struct sockaddr *address,socklen_t *length){return hvf_gate_is_udp(fd)?hvf_gate_name(fd,address,length):getsockname(fd,address,length);}
