// SPDX-License-Identifier: Apache-2.0
// User-mode network transport; independent of the VirtIO PCI device.
#include "net_backend.h"
#include "libslirp.h"
#include "policy.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static Slirp *slirp;
static net_receive_fn receive_packet;
static ssize_t deliver(const void *data,size_t size,void *opaque){return receive_packet(data,size,opaque);}
static void die(const char *why){fprintf(stderr,"slirp backend error: %s\n",why);exit(2);}
static int64_t paused_at, clock_offset;
static int64_t host_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int64_t now(void *opaque){(void)opaque;return (paused_at?paused_at:host_now())-clock_offset;}
void slirp_backend_pause(int paused){if(paused){if(!paused_at)paused_at=host_now();}else if(paused_at){clock_offset+=host_now()-paused_at;paused_at=0;}}
static void error(const char *msg,void *o){(void)o;fprintf(stderr,"slirp: %s\n",msg);}
static void noop(void *o){(void)o;}
static void socknoop(slirp_os_socket fd,void *o){(void)fd;(void)o;}
struct timer {SlirpTimerCb cb;void *arg;int64_t at;struct timer *next;};
static struct timer *timers;
static void *timer_new(SlirpTimerCb cb,void *arg,void *o){(void)o;struct timer *t=calloc(1,sizeof(*t));if(!t)die("timer allocation");t->cb=cb;t->arg=arg;t->at=-1;t->next=timers;timers=t;return t;}
static void timer_free(void *p,void *o){(void)o;struct timer **t=&timers;while(*t && *t!=p)t=&(*t)->next;if(*t){*t=(*t)->next;free(p);}}
static void timer_mod(void *p,int64_t at,void *o){(void)o;((struct timer*)p)->at=at;}
static struct pollfd polls[4096];static unsigned npoll;
static int add_poll(slirp_os_socket fd,int events,void *o){
    (void)o;if(npoll>=4096)die("poll limit");short ev=0;
    if(events&SLIRP_POLL_IN)ev|=POLLIN;if(events&SLIRP_POLL_OUT)ev|=POLLOUT;if(events&SLIRP_POLL_PRI)ev|=POLLPRI;
    polls[npoll]=(struct pollfd){fd,ev,0};return npoll++;
}
static int revents(int i,void *o){(void)o;if(i<0||(unsigned)i>=npoll)die("poll index");short r=polls[i].revents;return ((r&POLLIN)?SLIRP_POLL_IN:0)|((r&POLLOUT)?SLIRP_POLL_OUT:0)|((r&POLLPRI)?SLIRP_POLL_PRI:0)|((r&POLLERR)?SLIRP_POLL_ERR:0)|((r&POLLHUP)?SLIRP_POLL_HUP:0);}
void slirp_backend_poll(void){
    if(!slirp)return;
    npoll=0;uint32_t timeout=0;slirp_pollfds_fill_socket(slirp,&timeout,add_poll,NULL);
    int n=poll(polls,npoll,0);slirp_pollfds_poll(slirp,n<0,revents,NULL);
    for(struct timer *t=timers;t;){struct timer *next=t->next;if(t->at>=0&&t->at<=now(NULL)/1000000){t->at=-1;t->cb(t->arg);}t=next;}
}
int slirp_backend_open(const struct hvf_options *options,net_receive_fn receive){
    receive_packet=receive;paused_at=clock_offset=0;
    hvf_policy_set(options->security);
    SlirpConfig c={.version=6,.in_enabled=true,.if_mtu=1500,.if_mru=1500,.disable_host_loopback=false};
    c.disable_dns=!(options->security && (options->security->development || options->security->dns_port));
    inet_pton(AF_INET,"10.0.2.0",&c.vnetwork);inet_pton(AF_INET,"255.255.255.0",&c.vnetmask);
    inet_pton(AF_INET,"10.0.2.2",&c.vhost);inet_pton(AF_INET,"10.0.2.15",&c.vdhcp_start);inet_pton(AF_INET,"10.0.2.3",&c.vnameserver);
    static const SlirpCb cb={.send_packet=deliver,.guest_error=error,.clock_get_ns=now,.timer_new=timer_new,.timer_free=timer_free,.timer_mod=timer_mod,.notify=noop,.register_poll_socket=socknoop,.unregister_poll_socket=socknoop};
    slirp=slirp_new(&c,&cb,NULL);if(!slirp)return -1;
    for(unsigned i=0;i<options->forward_count;i++){
        const struct hvf_forward *f=&options->forwards[i];struct in_addr host,guest;
        memcpy(&host,f->host_addr,4);memcpy(&guest,f->guest_addr,4);
        if(slirp_add_hostfwd(slirp,f->udp,host,f->host_port,guest,f->guest_port)){perror(f->udp?"UDP forwarding listener":"TCP forwarding listener");return -1;}
    }
    return 0;
}
void slirp_backend_send(const void *data,size_t size){slirp_input(slirp,data,(int)size);}
void slirp_backend_close(void){if(slirp){slirp_cleanup(slirp);slirp=NULL;}}
