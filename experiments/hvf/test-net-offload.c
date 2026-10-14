// SPDX-License-Identifier: Apache-2.0
// virtio-net offloads through the real device model, without a guest: TSO
// frames reach the switch as checksummed segments (resuming after a full
// socket without repeating any), and frames from direct peers are adapted to
// what the guest negotiated.
#include "net.h"
#include "net_backend.h"
#include "net_gso.h"
#include <Hypervisor/Hypervisor.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 0x40000000ULL
#define BAR 0x10010000ULL
#define SIZE (8u<<20)
#define RX_RING 0x10000
#define TX_RING 0x20000
#define TX_BUF 0x100000
#define RX_BUF 0x200000
#define ETH 14
#define FEATURES 0x8a3u // MAC, CSUM, GUEST_CSUM, GUEST_TSO4, HOST_TSO4
struct descriptor { uint64_t addr; uint32_t len; uint16_t flags,next; };
static uint8_t *memory;
static net_receive_fn receive;
static uint8_t sent[64][65536];
static size_t sent_len[64];
static unsigned sends,fail_at=~0u;

hv_return_t hv_gic_set_spi(uint32_t intid,bool asserted){(void)intid;(void)asserted;return HV_SUCCESS;}
int net_backend_open(const struct hvf_options *options,net_receive_fn fn){(void)options;receive=fn;return 0;}
int net_backend_send(const void *data,size_t size){
    if(sends==fail_at){fail_at=~0u;return 0;} // the broker socket is full once
    assert(sends<64&&size<=sizeof(sent[0]));
    memcpy(sent[sends],data,size);sent_len[sends++]=size;return 1;
}
void net_backend_poll(void){}
void net_backend_close(void){receive=NULL;}
void net_backend_health(void){}
int net_backend_wait_fd(void){return -1;}

static void write_reg(unsigned offset,unsigned width,uint64_t value){assert(net_mmio(BAR+offset,width,1,&value));}
static uint64_t read_reg(unsigned offset,unsigned width){uint64_t value=0;assert(net_mmio(BAR+offset,width,0,&value));return value;}
static uint16_t *avail(unsigned ring){return (uint16_t *)(memory+ring+4096);}
static uint16_t *used_idx(unsigned ring){return (uint16_t *)(memory+ring+8192+2);}
static uint32_t *used_len(unsigned ring,unsigned slot){return (uint32_t *)(memory+ring+8192+4+8*slot+4);}
static void setup(uint32_t features){
    write_reg(18,1,0);
    assert(read_reg(0,4)==FEATURES);
    write_reg(4,4,features);assert(read_reg(4,4)==features);
    write_reg(14,2,0);write_reg(8,4,(BASE+RX_RING)>>12);
    write_reg(14,2,1);write_reg(8,4,(BASE+TX_RING)>>12);
    memset(memory+RX_RING,0,3*4096);memset(memory+TX_RING,0,3*4096);
    write_reg(18,1,4);
}
static unsigned tx_slot,rx_slot;
static void reset_slots(void){tx_slot=rx_slot=0;}
static void tx(const uint8_t *packet,size_t len){
    struct descriptor *d=(void *)(memory+TX_RING);
    unsigned slot=tx_slot++;
    memcpy(memory+TX_BUF+slot*65536,packet,len);
    d[slot]=(struct descriptor){BASE+TX_BUF+slot*65536,(uint32_t)len,0,0};
    avail(TX_RING)[2+slot]=(uint16_t)slot;avail(TX_RING)[1]++;
    write_reg(16,2,1);
}
static void post_rx(unsigned count,uint32_t size){
    struct descriptor *d=(void *)(memory+RX_RING);
    for(unsigned k=0;k<count;k++){
        unsigned slot=rx_slot++;
        d[slot]=(struct descriptor){BASE+RX_BUF+slot*65536,size,2,0};
        avail(RX_RING)[2+slot]=(uint16_t)slot;avail(RX_RING)[1]++;
    }
}
static const uint8_t *rx_packet(unsigned slot){return memory+RX_BUF+slot*65536;}

static uint32_t ref_sum(uint32_t sum,const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)sum+=i&1?p[i]:(uint32_t)p[i]<<8;return sum;}
static uint16_t ref_fold(uint32_t sum){while(sum>>16)sum=(sum&0xffff)+(sum>>16);return (uint16_t)sum;}
static int tcp_valid(const uint8_t *f,size_t len){
    const uint8_t *ip=f+ETH;size_t l4=len-ETH-20;
    return ref_fold(ref_sum(0,ip,20))==0xffff&&ref_fold(ref_sum(ref_sum(0,ip+12,8)+6+(uint32_t)l4,ip+20,l4))==0xffff;
}
static uint32_t seq(const uint8_t *f){const uint8_t *p=f+ETH+24;return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
// virtio_net_hdr + IPv4/TCP frame with the pseudo-header seed a guest writes.
static size_t tso_packet(uint8_t *v,size_t payload,uint16_t mss){
    memset(v,0,10+ETH+40);
    uint8_t *f=v+10;memcpy(f,"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00",ETH);
    uint8_t *ip=f+ETH;ip[0]=0x45;ip[8]=64;ip[9]=6;memcpy(ip+12,"\x0a\0\0\x01\x0a\0\0\x02",8);
    uint8_t *tcp=ip+20;tcp[12]=0x50;tcp[13]=0x18;memcpy(tcp+4,"\0\0\x10\0",4);
    for(size_t i=0;i<payload;i++)f[ETH+40+i]=(uint8_t)(i*13+1);
    // The guest completes the IPv4 header itself; only L4 is offloaded.
    ip[2]=(uint8_t)((40+payload)>>8);ip[3]=(uint8_t)(40+payload);
    uint16_t ipsum=(uint16_t)~ref_fold(ref_sum(0,ip,20));ip[10]=(uint8_t)(ipsum>>8);ip[11]=(uint8_t)ipsum;
    uint16_t seed=ref_fold(ref_sum(0,ip+12,8)+6+(uint32_t)(20+payload));
    tcp[16]=(uint8_t)(seed>>8);tcp[17]=(uint8_t)seed;
    struct vnet_hdr h={.flags=VNET_F_NEEDS_CSUM,.gso_type=mss?VNET_GSO_TCPV4:VNET_GSO_NONE,.hdr_len=ETH+40,.gso_size=mss,.csum_start=ETH+20,.csum_offset=16};
    vnet_hdr_encode(v,&h);
    return 10+ETH+40+payload;
}

static void test_tx_to_switch(void){
    static uint8_t packet[65536];
    setup(FEATURES);reset_slots();sends=0;
    // A 5-segment TSO frame; the switch socket fills after two segments.
    size_t len=tso_packet(packet,5000,1000);
    fail_at=2;
    tx(packet,len);
    assert(sends==2&&*used_idx(TX_RING)==0); // descriptor retained
    net_poll();
    assert(sends==5&&*used_idx(TX_RING)==1);
    for(unsigned i=0;i<5;i++){
        assert(sent_len[i]==ETH+40+1000&&tcp_valid(sent[i],sent_len[i]));
        assert(seq(sent[i])==0x1000+i*1000);           // each segment exactly once
        assert(!memcmp(sent[i]+ETH+40,packet+10+ETH+40+i*1000,1000));
    }
    // A partial checksum without TSO is completed for the switch.
    sends=0;len=tso_packet(packet,777,0);
    tx(packet,len);
    assert(sends==1&&sent_len[0]==len-10&&tcp_valid(sent[0],sent_len[0]));
}
static void test_rx_from_peer(void){
    static uint8_t packet[65536];
    size_t len=tso_packet(packet,30000,8960);
    uint64_t metrics[6];

    // A TSO guest gets the frame whole, with the sender's header.
    setup(FEATURES);reset_slots();
    post_rx(1,65536);
    assert(receive(packet+10,len-10,packet)==(ssize_t)(len-10));
    assert(*used_idx(RX_RING)==1&&*used_len(RX_RING,0)==len&&!memcmp(rx_packet(0),packet,len));

    // A guest without offloads gets complete MSS segments, all or nothing.
    setup(0x20);reset_slots();
    post_rx(3,9100); // MTU-sized buffers, as a guest without TSO posts
    errno=0;assert(receive(packet+10,len-10,packet)<0&&errno==EAGAIN&&*used_idx(RX_RING)==0);
    post_rx(1,9100); // four slots for four segments
    assert(receive(packet+10,len-10,packet)==(ssize_t)(len-10));
    assert(*used_idx(RX_RING)==4);
    for(unsigned i=0;i<4;i++){
        const uint8_t *p=rx_packet(i);size_t n=*used_len(RX_RING,i)-10;
        static const uint8_t zero[10];
        assert(!memcmp(p,zero,10)&&n==ETH+40+(i<3?8960:30000-3*8960)&&tcp_valid(p+10,n));
    }

    // CSUM without GUEST_CSUM: completed, header cleared.
    setup(0x20);reset_slots();post_rx(1,2048);
    len=tso_packet(packet,500,0);
    assert(receive(packet+10,len-10,packet)==(ssize_t)(len-10));
    assert(rx_packet(0)[0]==0&&tcp_valid(rx_packet(0)+10,len-10));

    // Malformed offloads from another guest are dropped, never fatal.
    setup(FEATURES);reset_slots();post_rx(1,65536);
    net_metrics(metrics);uint64_t drops=metrics[4];
    len=tso_packet(packet,3000,1000);packet[1]=3; // TCPv6 GSO
    assert(receive(packet+10,len-10,packet)==(ssize_t)(len-10));
    len=tso_packet(packet,3000,0);packet[6]=0xff;packet[7]=0xff; // checksum outside the frame
    assert(receive(packet+10,len-10,packet)==(ssize_t)(len-10));
    net_metrics(metrics);assert(metrics[4]==drops+2&&*used_idx(RX_RING)==0);

    // Switch frames (no header) are delivered with a zero header, as before.
    uint8_t plain[60]={0};
    assert(receive(plain,sizeof(plain),NULL)==sizeof(plain)&&*used_idx(RX_RING)==1&&rx_packet(0)[0]==0);
}
int main(void){
    memory=calloc(1,SIZE);assert(memory);
    struct hvf_options options={.network_enabled=1};
    assert(net_init(memory,SIZE,&options)==0);
    test_tx_to_switch();
    test_rx_from_peer();
    net_close();free(memory);
    puts("net-offload: ok");
    return 0;
}
