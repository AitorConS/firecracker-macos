// SPDX-License-Identifier: Apache-2.0
// TCPv4 segmentation and checksum completion, checked against an independent
// checksum verifier and by reassembling the payload.
#include "net_gso.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH 14
static uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static uint16_t rd16(const uint8_t *p){return (uint16_t)(p[0]<<8|p[1]);}
// Reference one's-complement sum, one byte pair at a time.
static uint32_t ref_sum(uint32_t sum,const uint8_t *p,size_t n){
    for(size_t i=0;i<n;i++)sum+=i&1?p[i]:(uint32_t)p[i]<<8;
    return sum;
}
static uint16_t ref_fold(uint32_t sum){while(sum>>16)sum=(sum&0xffff)+(sum>>16);return (uint16_t)sum;}
static int ip_valid(const uint8_t *ip){return ref_fold(ref_sum(0,ip,(size_t)(ip[0]&15)*4))==0xffff;}
static int l4_valid(const uint8_t *f,size_t len,uint8_t proto){
    const uint8_t *ip=f+ETH;size_t ihl=(size_t)(ip[0]&15)*4,l4=len-ETH-ihl;
    uint32_t sum=ref_sum(0,ip+12,8)+proto+(uint32_t)l4;
    return ref_fold(ref_sum(sum,ip+ihl,l4))==0xffff;
}
// An IPv4/TCP frame with options-free headers and a patterned payload.
static size_t tcp_frame(uint8_t *f,size_t payload,uint8_t flags){
    memset(f,0,ETH+40);
    memcpy(f,"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00",ETH);
    uint8_t *ip=f+ETH;ip[0]=0x45;ip[2]=(uint8_t)((40+payload)>>8);ip[3]=(uint8_t)(40+payload);
    ip[4]=0x12;ip[5]=0x34;ip[8]=64;ip[9]=6;memcpy(ip+12,"\x0a\0\0\x01\x0a\0\0\x02",8);
    uint8_t *tcp=ip+20;tcp[0]=0x30;tcp[1]=0x39;tcp[2]=0x14;tcp[3]=0x51;
    memcpy(tcp+4,"\xff\xff\xff\xf0",4); // sequence wraps inside the frame
    tcp[12]=0x50;tcp[13]=flags;tcp[14]=0xff;tcp[15]=0xff;
    for(size_t i=0;i<payload;i++)f[ETH+40+i]=(uint8_t)(i*7+3);
    return ETH+40+payload;
}
static void test_segmentation(void){
    static uint8_t f[65536],seg[65536],joined[65536];
    const size_t payload=60000,mss=8960;
    size_t len=tcp_frame(f,payload,0x80|0x08|0x01|0x10); // CWR, PSH, FIN, ACK
    // As a guest sends it: partial checksum seeded with the pseudo-header.
    struct vnet_hdr h={.flags=VNET_F_NEEDS_CSUM,.gso_type=VNET_GSO_TCPV4,.hdr_len=ETH+40,.gso_size=(uint16_t)mss,.csum_start=ETH+20,.csum_offset=16};
    uint8_t wire[VNET_HDR];struct vnet_hdr back;vnet_hdr_encode(wire,&h);vnet_hdr_decode(wire,&back);
    assert(!memcmp(&back,&h,sizeof(h))&&wire[4]==(uint8_t)mss&&wire[5]==(uint8_t)(mss>>8));
    int count=vnet_gso_count(f,len,&h);
    assert(count==7);
    size_t got=0;
    for(int i=0;i<count;i++){
        long n=vnet_gso_segment(f,len,&h,(unsigned)i,seg,sizeof(seg));
        size_t expect=i<count-1?mss:payload-6*mss;
        assert(n==(long)(ETH+40+expect));
        uint8_t *ip=seg+ETH,*tcp=ip+20;
        assert(rd16(ip+2)==40+expect&&rd16(ip+4)==0x1234+i);
        assert(ip_valid(ip)&&l4_valid(seg,(size_t)n,6));
        assert(rd32(tcp+4)==0xfffffff0u+(uint32_t)(i*mss));
        uint8_t flags=tcp[13];
        assert(flags&0x10);                                  // ACK everywhere
        assert(!!(flags&0x80)==(i==0));                      // CWR on the first
        assert(!!(flags&0x09)==(i==count-1)&&(i<count-1||(flags&0x09)==0x09)); // PSH|FIN on the last
        memcpy(joined+got,seg+ETH+40,expect);got+=expect;
    }
    assert(got==payload&&!memcmp(joined,f+ETH+40,payload));
    assert(vnet_gso_segment(f,len,&h,(unsigned)count,seg,sizeof(seg))<0);
    assert(vnet_gso_segment(f,len,&h,0,seg,100)<0); // too small for the output

    // An odd payload ends in a padded checksum word.
    len=tcp_frame(f,1001,0x10);h.gso_size=500;
    assert(vnet_gso_count(f,len,&h)==3);
    long n=vnet_gso_segment(f,len,&h,2,seg,sizeof(seg));
    assert(n==ETH+40+1&&l4_valid(seg,(size_t)n,6));
}
static void test_rejects(void){
    static uint8_t f[2000];
    size_t len=tcp_frame(f,1000,0x10);
    struct vnet_hdr h={.gso_type=VNET_GSO_TCPV4,.gso_size=100};
    assert(vnet_gso_count(f,len,&h)==10);
    struct vnet_hdr bad=h;bad.gso_size=0;assert(vnet_gso_count(f,len,&bad)<0);
    bad=h;bad.gso_type=3;assert(vnet_gso_count(f,len,&bad)<0);              // TCPv6
    bad=h;bad.gso_size=1;assert(vnet_gso_count(f,len,&bad)<0);              // too many segments
    f[ETH+9]=17;assert(vnet_gso_count(f,len,&h)<0);f[ETH+9]=6;              // not TCP
    f[12]=0x86;assert(vnet_gso_count(f,len,&h)<0);f[12]=0x08;               // not IPv4
    f[ETH]=0x44;assert(vnet_gso_count(f,len,&h)<0);f[ETH]=0x45;             // IHL
    f[ETH+32]=0xf0;assert(vnet_gso_count(f,ETH+40+20,&h)<0);f[ETH+32]=0x50; // TCP header beyond frame
    assert(vnet_gso_count(f,ETH+40,&h)<0);                                  // no payload
}
static void test_checksum_completion(void){
    static uint8_t f[2000];
    size_t len=tcp_frame(f,777,0x18);
    uint8_t *ip=f+ETH,*tcp=ip+20;
    // Guest seed: folded pseudo-header sum, not complemented.
    uint16_t seed=ref_fold(ref_sum(0,ip+12,8)+6+(uint32_t)(len-ETH-20));
    tcp[16]=(uint8_t)(seed>>8);tcp[17]=(uint8_t)seed;
    struct vnet_hdr h={.flags=VNET_F_NEEDS_CSUM,.csum_start=ETH+20,.csum_offset=16};
    assert(!vnet_complete_csum(f,len,&h)&&l4_valid(f,len,6));
    struct vnet_hdr bad=h;bad.csum_start=(uint16_t)len;bad.csum_offset=0;
    assert(vnet_complete_csum(f,len,&bad)<0);
    bad=h;bad.csum_offset=(uint16_t)(len-ETH-20-1);assert(vnet_complete_csum(f,len,&bad)<0);

    // UDP: a computed zero is transmitted as 0xffff.
    memset(f,0,64);memcpy(f+12,"\x08\x00",2);ip[0]=0x45;ip[9]=17;
    uint8_t *udp=ip+20;udp[5]=8+2;f[ETH+28]=0;f[ETH+29]=0;
    // The guest seeds the checksum field with the pseudo-header sum; choose
    // data so the full sum is 0xffff and the checksum computes to zero.
    uint16_t useed=ref_fold(ref_sum(0,ip+12,8)+17+10);
    udp[6]=(uint8_t)(useed>>8);udp[7]=(uint8_t)useed;
    uint16_t need=(uint16_t)(0xffff-ref_fold(ref_sum(0,udp,8)));
    f[ETH+28]=(uint8_t)(need>>8);f[ETH+29]=(uint8_t)need;
    struct vnet_hdr u={.flags=VNET_F_NEEDS_CSUM,.csum_start=ETH+20,.csum_offset=6};
    assert(!vnet_complete_csum(f,ETH+30,&u)&&udp[6]==0xff&&udp[7]==0xff);
}
int main(void){
    test_segmentation();
    test_rejects();
    test_checksum_completion();
    puts("net-gso: ok");
    return 0;
}
