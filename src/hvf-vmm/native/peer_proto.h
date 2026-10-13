// SPDX-License-Identifier: Apache-2.0
// Peer control protocol between the external switch (jerboad), the network
// broker and the VMM. The switch remains the control plane: it decides which
// VMs on one network exchange unicast frames directly and hands both ends of a
// SOCK_DGRAM socketpair to their VMMs. Every message is 32 wire bytes, little
// endian, never a native struct:
//
//   0  magic "JPC1"      8  u64 epoch (STATS: TX bytes)
//   4  u8 type           16 u32 peer id (HELLO: features; STATS: RX bytes, u64)
//   5  u8 flags          20 MAC[6]
//   6  u16 reserved (0)  26 IPv4[4]   30 u16 reserved (0)
//
// switch -> VMM: WELCOME{epoch, own MAC, own IP}, PEER_ADD{epoch, id, MAC, IP}
//   with exactly one SCM_RIGHTS descriptor, PEER_DEL{epoch, id}.
// VMM -> switch: HELLO{features, own MAC}, PEER_ACK{epoch, id, flags=accepted},
//   PEER_DEAD{epoch, id}, STATS{TX bytes, RX bytes}, PEER_IDLE{epoch, id}
//   (no frames either way for a while: the switch may withdraw the link).
// broker -> VMM only: RESET (the switch connection was lost; drop every peer).
//
// The sender keeps its reference to a descriptor until PEER_ACK: XNU unp_gc
// can flush a socket referenced only by an in-flight SCM_RIGHTS message.
#pragma once
#include <stdint.h>
#include <string.h>
#define PEER_MESSAGE 32u
#define PEER_FEATURE_DGRAM 1u
enum peer_type {
    PEER_HELLO=1, PEER_WELCOME=2, PEER_ADD=3, PEER_DEL=4,
    PEER_ACK=5, PEER_DEAD=6, PEER_RESET=7, PEER_STATS=8, PEER_IDLE=9,
};
struct peer_message {
    uint8_t type,flags;
    uint64_t epoch;   // STATS: TX bytes
    uint64_t value;   // peer id or HELLO features; STATS: RX bytes
    uint8_t mac[6],ip[4];
};
static inline void peer_encode(uint8_t out[PEER_MESSAGE],const struct peer_message *m){
    memset(out,0,PEER_MESSAGE);memcpy(out,"JPC1",4);out[4]=m->type;out[5]=m->flags;
    for(unsigned i=0;i<8;i++)out[8+i]=(uint8_t)(m->epoch>>(8*i));
    unsigned width=m->type==PEER_STATS?8:4;
    for(unsigned i=0;i<width;i++)out[16+i]=(uint8_t)(m->value>>(8*i));
    if(m->type!=PEER_STATS){memcpy(out+20,m->mac,6);memcpy(out+26,m->ip,4);}
}
// 0 on success, -1 for anything that is not a well-formed message.
static inline int peer_decode(const uint8_t in[PEER_MESSAGE],struct peer_message *m){
    if(memcmp(in,"JPC1",4)||in[6]||in[7]||in[4]<PEER_HELLO||in[4]>PEER_IDLE)return -1;
    memset(m,0,sizeof(*m));m->type=in[4];m->flags=in[5];
    for(unsigned i=0;i<8;i++)m->epoch|=(uint64_t)in[8+i]<<(8*i);
    unsigned width=m->type==PEER_STATS?8:4;
    for(unsigned i=0;i<width;i++)m->value|=(uint64_t)in[16+i]<<(8*i);
    if(m->type!=PEER_STATS){
        if(in[30]||in[31])return -1;
        memcpy(m->mac,in+20,6);memcpy(m->ip,in+26,4);
    }
    return 0;
}
