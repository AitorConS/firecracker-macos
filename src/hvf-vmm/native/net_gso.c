// SPDX-License-Identifier: Apache-2.0
#include "net_gso.h"
#include <string.h>
#define ETH 14u
#define GSO_MAX_SEGMENTS 256
static uint16_t le16(const uint8_t *p){return (uint16_t)(p[0]|p[1]<<8);}
static void put_le16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static uint16_t be16(const uint8_t *p){return (uint16_t)(p[0]<<8|p[1]);}
static void put_be16(uint8_t *p,uint16_t v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static uint32_t be32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void put_be32(uint8_t *p,uint32_t v){p[0]=(uint8_t)(v>>24);p[1]=(uint8_t)(v>>16);p[2]=(uint8_t)(v>>8);p[3]=(uint8_t)v;}
// One's-complement sum of big-endian 16-bit words; an odd tail is padded.
static uint64_t sum16(uint64_t sum,const uint8_t *p,size_t n){
    while(n>=8){sum+=(uint64_t)be16(p)+be16(p+2)+be16(p+4)+be16(p+6);p+=8;n-=8;}
    while(n>=2){sum+=be16(p);p+=2;n-=2;}
    if(n)sum+=(uint64_t)p[0]<<8;
    return sum;
}
static uint16_t fold(uint64_t sum){while(sum>>16)sum=(sum&0xffff)+(sum>>16);return (uint16_t)sum;}

void vnet_hdr_decode(const uint8_t in[VNET_HDR],struct vnet_hdr *h){
    h->flags=in[0];h->gso_type=in[1];h->hdr_len=le16(in+2);h->gso_size=le16(in+4);
    h->csum_start=le16(in+6);h->csum_offset=le16(in+8);
}
void vnet_hdr_encode(uint8_t out[VNET_HDR],const struct vnet_hdr *h){
    out[0]=h->flags;out[1]=h->gso_type;put_le16(out+2,h->hdr_len);put_le16(out+4,h->gso_size);
    put_le16(out+6,h->csum_start);put_le16(out+8,h->csum_offset);
}
int vnet_complete_csum(uint8_t *f,size_t len,const struct vnet_hdr *h){
    size_t start=h->csum_start,at=start+h->csum_offset;
    if(start>len||at+2>len||at<start)return -1;
    // The field holds the pseudo-header sum seeded by the guest.
    uint16_t c=(uint16_t)~fold(sum16(0,f+start,len-start));
    // UDP transmits a zero checksum as all ones (RFC 768).
    if(!c&&len>=ETH+20&&be16(f+12)==0x0800&&f[ETH+9]==17&&start==ETH+(size_t)(f[ETH]&15)*4)c=0xffff;
    put_be16(f+at,c);
    return 0;
}
// Validates an IPv4/TCP TSO frame; returns the header length and payload length.
static int tcp4(const uint8_t *f,size_t len,const struct vnet_hdr *h,size_t *headers,size_t *payload){
    if(h->gso_type!=VNET_GSO_TCPV4||!h->gso_size||len<ETH+40||be16(f+12)!=0x0800||f[ETH]>>4!=4)return -1;
    size_t ihl=(size_t)(f[ETH]&15)*4;
    if(ihl<20||f[ETH+9]!=6||len<ETH+ihl+20)return -1;
    size_t doff=(size_t)(f[ETH+ihl+12]>>4)*4;
    if(doff<20||len<ETH+ihl+doff)return -1;
    *headers=ETH+ihl+doff;*payload=len-*headers;
    return *payload?0:-1;
}
int vnet_gso_count(const uint8_t *f,size_t len,const struct vnet_hdr *h){
    size_t headers,payload;
    if(tcp4(f,len,h,&headers,&payload))return -1;
    size_t count=(payload+h->gso_size-1)/h->gso_size;
    return count>GSO_MAX_SEGMENTS?-1:(int)count;
}
int vnet_gso_whole(uint8_t *f,size_t len,const struct vnet_hdr *h){
    size_t headers,payload;
    if(tcp4(f,len,h,&headers,&payload)||len-ETH>65535)return -1;
    uint8_t *ip=f+ETH;size_t ihl=(size_t)(ip[0]&15)*4;
    put_be16(ip+2,(uint16_t)(len-ETH));
    put_be16(ip+10,0);put_be16(ip+10,(uint16_t)~fold(sum16(0,ip,ihl)));
    return 0;
}
int vnet_gso_describe(const uint8_t *f,size_t len,unsigned mtu,struct vnet_hdr *h){
    struct vnet_hdr probe={.gso_type=VNET_GSO_TCPV4,.gso_size=1};
    size_t headers,payload;
    if(tcp4(f,len,&probe,&headers,&payload)||be16(f+ETH+2)!=len-ETH||headers-ETH>=mtu)return -1;
    size_t ihl=(size_t)(f[ETH]&15)*4;
    *h=(struct vnet_hdr){.flags=VNET_F_NEEDS_CSUM,.gso_type=VNET_GSO_TCPV4,.hdr_len=(uint16_t)headers,
        .gso_size=(uint16_t)(mtu-(headers-ETH)),.csum_start=(uint16_t)(ETH+ihl),.csum_offset=16};
    return 0;
}
long vnet_gso_segment(const uint8_t *f,size_t len,const struct vnet_hdr *h,unsigned index,uint8_t *out,size_t cap){
    size_t headers,payload;
    if(tcp4(f,len,h,&headers,&payload))return -1;
    size_t mss=h->gso_size,offset=(size_t)index*mss;
    if(offset>=payload)return -1;
    size_t n=payload-offset<mss?payload-offset:mss,total=headers+n;
    if(total>cap)return -1;
    int last=offset+n==payload;
    memcpy(out,f,headers);memcpy(out+headers,f+headers+offset,n);
    uint8_t *ip=out+ETH;size_t ihl=(size_t)(ip[0]&15)*4;uint8_t *tcp=ip+ihl;
    put_be16(ip+2,(uint16_t)(total-ETH));
    put_be16(ip+4,(uint16_t)(be16(f+ETH+4)+index));
    put_be16(ip+10,0);put_be16(ip+10,(uint16_t)~fold(sum16(0,ip,ihl)));
    put_be32(tcp+4,be32(f+ETH+ihl+4)+(uint32_t)offset);
    if(!last)tcp[13]&=(uint8_t)~0x09;   // FIN and PSH only on the last segment
    if(index)tcp[13]&=(uint8_t)~0x80;   // CWR only on the first
    size_t tcp_len=total-ETH-ihl;
    uint64_t sum=sum16(0,ip+12,8)+6+tcp_len;
    put_be16(tcp+16,0);put_be16(tcp+16,(uint16_t)~fold(sum16(sum,tcp,tcp_len)));
    return (long)total;
}
