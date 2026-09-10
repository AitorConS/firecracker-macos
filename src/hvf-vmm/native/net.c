// SPDX-License-Identifier: Apache-2.0
#include "net.h"
#include <Hypervisor/Hypervisor.h>
#include "net_backend.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#define BASE 0x40000000ULL
#define BAR 0x10010000ULL
#define ECAM 0x3f008000ULL
#define QSZ 256
static int enabled;
static uint8_t *ram;
static size_t ram_size;
static uint8_t cfg[256],status,isr;
static uint32_t bar=BAR,features;
static uint16_t selectq;
struct queue {uint32_t pfn;uint16_t avail,used;};
static struct queue queues[2];
static unsigned long rx,tx;
static uint8_t mac[6];
static void die(const char *why) {fprintf(stderr,"net error: %s\n",why);exit(2);}
static uint64_t get(const void *p,unsigned n){uint64_t v=0;memcpy(&v,p,n);return v;}
static void put(void *p,unsigned n,uint64_t v){memcpy(p,&v,n);}
static uint8_t *dma(uint64_t pa,uint64_t n){if(pa<BASE||n>ram_size||pa-BASE>ram_size-n)die("DMA outside RAM");return ram+pa-BASE;}
static void irq(int level){if(hv_gic_set_spi(36,level)!=HV_SUCCESS)die("SPI");}
struct desc {uint64_t addr;uint32_t len;uint16_t flags,next;};
static struct desc desc(struct queue *q,uint16_t i){
    if(i>=QSZ)die("descriptor index");
    struct desc d;memcpy(&d,dma(((uint64_t)q->pfn<<12)+16*i,16),16);
    if(d.flags&~3U)die("descriptor flags");dma(d.addr,d.len);return d;
}
static uint64_t avail_addr(struct queue *q){return ((uint64_t)q->pfn<<12)+16*QSZ;}
static int pending(struct queue *q){
    if(!q->pfn||!(status&4))return 0;
    uint16_t n=get(dma(avail_addr(q)+2,2),2);
    atomic_thread_fence(memory_order_acquire);
    if((uint16_t)(n-q->avail)>QSZ)die("ring overrun");
    return n!=q->avail;
}
static uint16_t head(struct queue *q){return get(dma(avail_addr(q)+4+2*(q->avail%QSZ),2),2);}
static void complete(struct queue *q,uint16_t h,uint32_t n){
    uint64_t used=(avail_addr(q)+4+2*QSZ+2+4095)&~4095ULL;
    put(dma(used+4+8*(q->used%QSZ),8),4,h);put(dma(used+8+8*(q->used%QSZ),4),4,n);
    atomic_thread_fence(memory_order_release);put(dma(used+2,2),2,++q->used);q->avail++;
    isr=1;irq(1);
}
static ssize_t receive(const void *buf,size_t len,void *opaque){
    (void)opaque;
    struct queue *q=&queues[0];
    if(!pending(q))return len; // allow protocol retransmission when RX ring is empty
    if(len>65536-10)die("oversized frame");
    uint8_t frame[65536]={0};memcpy(frame+10,buf,len);size_t total=len+10,done=0;
    uint16_t h=head(q),i=h;unsigned count=0;
    while(done<total){
        if(++count>QSZ)die("RX cycle");struct desc d=desc(q,i);
        if(!(d.flags&2))die("RX direction");
        size_t n=d.len<total-done?d.len:total-done;
        memcpy(dma(d.addr,n),frame+done,n);done+=n;
        if(done<total && !(d.flags&1))die("RX buffer too small");i=d.next;
    }
    complete(q,h,total);rx++;return len;
}
static void transmit(void){
    struct queue *q=&queues[1];
    for(unsigned budget=0;budget<256 && pending(q);budget++){
        uint16_t h=head(q),i=h;unsigned count=0;size_t len=0;uint8_t frame[65536];
        for(;;){
            if(++count>QSZ)die("TX cycle");struct desc d=desc(q,i);
            if(d.flags&2 || d.len>sizeof(frame)-len)die("TX buffer");
            memcpy(frame+len,dma(d.addr,d.len),d.len);len+=d.len;
            if(!(d.flags&1))break;i=d.next;
        }
        if(len<24 || frame[0] || frame[1])die("TX header/offload unsupported");
        complete(q,h,0);net_backend_send(frame+10,len-10);tx++;
    }
}
int net_init(void *memory,size_t size,const struct hvf_options *options){
    memset(cfg,0,sizeof(cfg));memset(queues,0,sizeof(queues));
    status=isr=features=selectq=rx=tx=0;bar=BAR;
    ram=memory;ram_size=size;enabled=options->network_enabled;if(!enabled)return 0;
    memcpy(mac,options->mac,6);
    if(net_backend_open(options,receive))return -1;
    put(cfg,2,0x1af4);put(cfg+2,2,0x1000);cfg[0xb]=2;
    put(cfg+0x10,4,BAR);put(cfg+0x2c,2,0x1af4);put(cfg+0x2e,2,1);cfg[0x3d]=1;
    fprintf(stderr,"network: slirp enabled, %u forwarding rules\n",options->forward_count);return 0;
}
int net_mmio(uint64_t addr,unsigned size,int write,uint64_t *v){
    if(!enabled)return 0;
    if(addr>=ECAM && addr<ECAM+256){
        unsigned off=addr-ECAM;if(size>4||off+size>256)return 0;
        if(write){if(off==0x10&&size==4){bar=*v;put(cfg+off,4,bar==0xffffffff?0xfffff000:bar&~15U);}else if(off==4&&size==2)put(cfg+off,size,*v);}
        else *v=get(cfg+off,size);return 1;
    }
    uint64_t base=bar&~15U;if(addr<base||addr>=base+4096)return 0;
    unsigned off=addr-base;struct queue *q=selectq<2?&queues[selectq]:NULL;
    if(write){switch(off){
        case 4:if(size!=4||(*v&~(1U<<5)))return 0;features=*v;break;
        case 8:if(size!=4||!q)return 0;*q=(struct queue){.pfn=*v};break;
        case 14:if(size!=2)return 0;selectq=*v;break;
        case 16:if(size!=2||*v>1)return 0;if(*v==1)transmit();break;
        case 18:if(size!=1)return 0;status=*v;if(!status){memset(queues,0,sizeof(queues));features=0;isr=0;irq(0);}break;
        default:return 0;
    }}else{switch(off){
        case 0:*v=1U<<5;break;
        case 4:*v=features;break;
        case 8:*v=q?q->pfn:0;break;
        case 12:*v=q?QSZ:0;break;
        case 14:*v=selectq;break;
        case 18:*v=status;break;
        case 19:*v=isr;isr=0;irq(0);break;
        default:{if(off<20||off+size>26)return 0;*v=get(mac+(off-20),size);}
    }}return 1;
}
void net_poll(void){if(enabled){transmit();net_backend_poll();}}
void net_close(void){if(enabled){fprintf(stderr,"network: TX=%lu RX=%lu\n",tx,rx);net_backend_close();enabled=0;}}
