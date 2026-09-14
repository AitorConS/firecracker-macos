// SPDX-License-Identifier: Apache-2.0
#ifndef HVF_CONTROL_H
#define HVF_CONTROL_H
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
// Wire bytes, never a native struct: magic, version, kind, reserved, LE operation.
struct control_reader { uint8_t bytes[16]; size_t used; };
static int control_send(int fd, uint8_t kind, uint64_t operation) {
    uint8_t bytes[16]={'H','V','F','C',1,kind,0,0};
    for(unsigned i=0;i<8;i++)bytes[8+i]=(uint8_t)(operation>>(i*8));
    return send(fd,bytes,sizeof(bytes),MSG_DONTWAIT)==sizeof(bytes) ? 0 : -1;
}
// 1: complete frame; 0: incomplete/would block; -1: disconnected/invalid.
static int control_receive(int fd, struct control_reader *r, uint8_t *kind, uint64_t *operation) {
    ssize_t n=recv(fd,r->bytes+r->used,sizeof(r->bytes)-r->used,MSG_DONTWAIT);
    if(n<0)return (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR) ? 0 : -1;
    if(!n)return -1;
    r->used+=(size_t)n;
    if(r->used<sizeof(r->bytes))return 0;
    r->used=0;
    if(memcmp(r->bytes,"HVFC",4)||r->bytes[4]!=1||r->bytes[6]||r->bytes[7])return -1;
    *kind=r->bytes[5];*operation=0;
    for(unsigned i=0;i<8;i++)*operation|=(uint64_t)r->bytes[8+i]<<(i*8);
    return 1;
}
#endif
