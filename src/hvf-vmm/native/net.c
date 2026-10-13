// SPDX-License-Identifier: Apache-2.0
#include "net.h"
#include "budget.h"
static struct budget network_budget;
#include <Hypervisor/Hypervisor.h>
#include "net_backend.h"
#include "net_peer.h"
#include "net_gso.h"
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#define BASE 0x40000000ULL
#define BAR 0x10010000ULL
#define ECAM 0x3f008000ULL
#define QSZ 256
#define VRING_AVAIL_F_NO_INTERRUPT 1u
static int enabled;
static uint8_t *ram;
static size_t ram_size;
static uint8_t cfg[256],status,isr;
static uint32_t bar=BAR,features;
static uint16_t selectq;
struct queue {uint32_t pfn;uint16_t avail,used;};
static struct queue queues[2];
static unsigned long rx,tx;
static uint64_t rx_bytes,tx_bytes,drop_packets,drop_bytes;
static uint8_t mac[6];
// Offloads. The guest batches TCP segments into one TSO frame with a partial
// checksum (HOST_TSO4, CSUM) and accepts such frames (GUEST_TSO4, GUEST_CSUM).
// They cross direct peer links whole; the switch only ever sees MSS-sized
// frames with complete checksums, segmented here.
#define NET_F_CSUM (1U<<0)
#define NET_F_GUEST_CSUM (1U<<1)
#define NET_F_MAC (1U<<5)
#define NET_F_GUEST_TSO4 (1U<<7)
#define NET_F_HOST_TSO4 (1U<<11)
#define NET_FEATURES (NET_F_MAC|NET_F_CSUM|NET_F_GUEST_CSUM|NET_F_GUEST_TSO4|NET_F_HOST_TSO4)
// Segments of the TX head already handed to the switch when its socket
// filled mid-frame; a retry continues from there instead of repeating them.
static unsigned tx_resume;
static uint8_t staging[65536]; // segments and completed checksums; io_lock held
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
static unsigned queued(struct queue *q){
    if(!q->pfn||!(status&4))return 0;
    uint16_t n=get(dma(avail_addr(q)+2,2),2);
    atomic_thread_fence(memory_order_acquire);
    if((uint16_t)(n-q->avail)>QSZ)die("ring overrun");
    return (uint16_t)(n-q->avail);
}
static int pending(struct queue *q){return queued(q)!=0;}
static uint16_t head(struct queue *q){return get(dma(avail_addr(q)+4+2*(q->avail%QSZ),2),2);}
static void complete(struct queue *q,uint16_t h,uint32_t n){
    uint64_t used=(avail_addr(q)+4+2*QSZ+2+4095)&~4095ULL;
    put(dma(used+4+8*(q->used%QSZ),8),4,h);put(dma(used+8+8*(q->used%QSZ),4),4,n);
    atomic_thread_fence(memory_order_release);put(dma(used+2,2),2,++q->used);q->avail++;
    // EVENT_IDX is not offered by this device. A polling guest suppresses TX
    // interrupts with avail.flags; it checks used.idx after re-enabling them.
    // Order the used index before reading flags to preserve that handshake.
    atomic_thread_fence(memory_order_seq_cst);
    if(!(get(dma(avail_addr(q),2),2)&VRING_AVAIL_F_NO_INTERRUPT) && !isr){
        isr=1;irq(1);
    }
}
// Writes header and frame into the next RX chain as one virtio packet.
static void deliver(const uint8_t header[10],const uint8_t *frame,size_t len){
    struct queue *q=&queues[0];
    size_t total=len+10,done=0;
    uint16_t h=head(q),i=h;unsigned count=0;
    while(done<total){
        if(++count>QSZ)die("RX cycle");struct desc d=desc(q,i);
        if(!(d.flags&2))die("RX direction");
        size_t n=d.len<total-done?d.len:total-done;uint8_t *to=dma(d.addr,n);
        for(size_t copied=0;copied<n;){
            size_t at=done+copied,k;
            if(at<10){k=10-at<n-copied?10-at:n-copied;memcpy(to+copied,header+at,k);}
            else{k=n-copied;memcpy(to+copied,frame+(at-10),k);}
            copied+=k;
        }
        done+=n;
        if(done<total && !(d.flags&1))die("RX buffer too small");i=d.next;
    }
    complete(q,h,total);rx++;rx_bytes+=len;
}
// opaque is the frame's virtio_net_hdr when it came from a direct peer
// (another guest: malformed offloads are dropped, never fatal); NULL for
// the switch, whose frames are always complete.
static ssize_t receive(const void *buf,size_t len,void *opaque){
    static const uint8_t plain[10];
    struct queue *q=&queues[0];
    if(!pending(q)){errno=EAGAIN;return -1;} // IPC retains one frame until the guest replenishes RX
    struct vnet_hdr hd={0};
    if(opaque){
        vnet_hdr_decode(opaque,&hd);
        if(len>65536-10||(hd.flags&~(VNET_F_NEEDS_CSUM|VNET_F_DATA_VALID))||
           (hd.gso_type&&vnet_gso_count(buf,len,&hd)<0)||
           ((hd.flags&VNET_F_NEEDS_CSUM)&&(size_t)hd.csum_start+hd.csum_offset+2>len)){
            drop_packets++;drop_bytes+=len;return (ssize_t)len;
        }
    }else if(len>65536-10)die("oversized frame");
    int tso=(features&NET_F_GUEST_TSO4)&&(features&NET_F_GUEST_CSUM);
    if(hd.gso_type&&!tso){
        // A guest without TSO receives the segments it would have seen on a wire.
        int count=vnet_gso_count(buf,len,&hd);
        if(queued(q)<(unsigned)count){errno=EAGAIN;return -1;}
        if(!budget_take(&network_budget,len,(unsigned)count)){errno=EAGAIN;return -1;}
        for(int s=0;s<count;s++){
            long n=vnet_gso_segment(buf,len,&hd,(unsigned)s,staging,sizeof(staging));
            if(n<0)die("RX segmentation");
            deliver(plain,staging,(size_t)n);
        }
        return (ssize_t)len;
    }
    if(!budget_take(&network_budget,len,1)){errno=EAGAIN;return -1;}
    if((hd.flags&VNET_F_NEEDS_CSUM)&&!(features&NET_F_GUEST_CSUM)){
        memcpy(staging,buf,len);
        if(vnet_complete_csum(staging,len,&hd))die("RX checksum offsets");
        deliver(plain,staging,len);return (ssize_t)len;
    }
    deliver(opaque?opaque:plain,buf,len);return (ssize_t)len;
}
// The switch takes MSS-sized frames with complete checksums. Returns 1 when
// the whole frame was handed over, 0 when its socket is full (tx_resume
// remembers how many segments already went).
static int to_switch(uint8_t *frame,size_t len,const struct vnet_hdr *hd){
    if(hd->gso_type){
        int count=vnet_gso_count(frame,len,hd);
        if(count<0)die("TX TSO frame");
        for(unsigned s=tx_resume;s<(unsigned)count;s++){
            long n=vnet_gso_segment(frame,len,hd,s,staging,sizeof(staging));
            if(n<0)die("TX TSO frame");
            if(!net_backend_send(staging,(size_t)n)){tx_resume=s;return 0;}
        }
        tx_resume=0;return 1;
    }
    if((hd->flags&VNET_F_NEEDS_CSUM)&&vnet_complete_csum(frame,len,hd))die("TX checksum offsets");
    return net_backend_send(frame,len);
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
        if(len<24)die("TX header");
        struct vnet_hdr hd;vnet_hdr_decode(frame,&hd);
        if((hd.flags&~VNET_F_NEEDS_CSUM)||((hd.flags&VNET_F_NEEDS_CSUM)&&!(features&NET_F_CSUM))||
           (hd.gso_type&&(hd.gso_type!=VNET_GSO_TCPV4||!(features&NET_F_HOST_TSO4))))die("TX header/offload unsupported");
        if(!tx_resume&&!budget_take(&network_budget,len-10,1))break;
        // A full socket is backpressure, not packet loss. Leave this
        // descriptor available and retry it on the next supervisor poll.
        // Direct peers take the frame whole; everything else (and anything
        // they refuse) uses the switch.
        int sent=tx_resume?-1:net_peer_send(frame,len);
        if(sent<0)sent=to_switch(frame+10,len-10,&hd);
        if(!sent)break;
        complete(q,h,0);tx++;tx_bytes+=len-10;
    }
}
int net_init(void *memory,size_t size,const struct hvf_options *options){
    budget_init(&network_budget,options->network_bytes_per_second,options->network_packets_per_second,256ULL<<10,256);
    memset(cfg,0,sizeof(cfg));memset(queues,0,sizeof(queues));
    status=isr=features=selectq=rx=tx=0;bar=BAR;tx_resume=0;
    rx_bytes=tx_bytes=drop_packets=drop_bytes=0;
    ram=memory;ram_size=size;enabled=options->network_enabled;if(!enabled)return 0;
    memcpy(mac,options->mac,6);
    if(net_backend_open(options,receive))return -1;
    put(cfg,2,0x1af4);put(cfg+2,2,0x1000);cfg[0xb]=2;
    put(cfg+0x10,4,BAR);put(cfg+0x2c,2,0x1af4);put(cfg+0x2e,2,1);cfg[0x3d]=1;
    fprintf(stderr,"network: %s enabled, %u forwarding rules\n",options->stream_path?"unix-stream":"slirp",options->forward_count);return 0;
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
        case 4:if(size!=4||(*v&~NET_FEATURES))return 0;features=*v;break;
        case 8:if(size!=4||!q)return 0;*q=(struct queue){.pfn=*v};break;
        case 14:if(size!=2)return 0;selectq=*v;break;
        case 16:if(size!=2||*v>1)return 0;if(*v==1)transmit();break;
        case 18:if(size!=1)return 0;status=*v;if(!status){memset(queues,0,sizeof(queues));features=0;isr=0;tx_resume=0;irq(0);}break;
        default:return 0;
    }}else{switch(off){
        case 0:*v=NET_FEATURES;break;
        case 4:*v=features;break;
        case 8:*v=q?q->pfn:0;break;
        case 12:*v=q?QSZ:0;break;
        case 14:*v=selectq;break;
        case 18:*v=status;break;
        case 19:*v=isr;if(isr){isr=0;irq(0);}break;
        default:{if(off<20||off+size>26)return 0;*v=get(mac+(off-20),size);}
    }}return 1;
}
int net_pending_tx(void){return enabled && pending(&queues[1]);}
int net_poll(void){
    if(!enabled)return 0;
    unsigned long before_tx=tx,before_rx=rx;
    transmit();net_backend_poll();net_peer_poll();
    return tx!=before_tx||rx!=before_rx;
}
void net_close(void){if(enabled){fprintf(stderr,"network: TX=%lu RX=%lu\n",tx,rx);net_peer_close();net_backend_close();enabled=0;}}

// Caller holds the device I/O lock. RX drops count empty rings; rate limiting defers one bounded IPC frame.
void net_metrics(uint64_t out[6]) {
    out[0]=tx;out[1]=rx;out[2]=tx_bytes;out[3]=rx_bytes;
    out[4]=drop_packets;out[5]=drop_bytes;
}

// Called only in the freshly forked transport process, before parsing packets.
int net_forget_guest_memory(void){if(ram && munmap(ram,ram_size))return -1;ram=NULL;ram_size=0;return 0;}

void net_snapshot(struct snapshot_io *s){
    snapshot_bytes(s,cfg,sizeof(cfg));SNAP(s,status);SNAP(s,isr);SNAP(s,bar);SNAP(s,features);SNAP(s,selectq);
    for(unsigned i=0;i<2;i++){SNAP(s,queues[i].pfn);SNAP(s,queues[i].avail);SNAP(s,queues[i].used);}
    SNAP(s,rx);SNAP(s,tx);SNAP(s,rx_bytes);SNAP(s,tx_bytes);SNAP(s,drop_packets);SNAP(s,drop_bytes);
}

void net_queue_depths(uint64_t out[2]){out[0]=enabled?queued(&queues[1]):0;out[1]=enabled?queued(&queues[0]):0;}
