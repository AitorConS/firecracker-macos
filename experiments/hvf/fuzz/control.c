// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "control.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size>4096)return 0;
    int pair[2];
    if(socketpair(AF_UNIX,SOCK_STREAM,0,pair))abort();
    struct control_reader reader={0};
    uint8_t kind=0;uint64_t operation=0;
    // Arbitrary fragmentation, coalesced messages and EOF in partial frames.
    size_t offset=0;
    while(offset<size){
        size_t chunk=1+data[offset]%31;
        if(chunk>size-offset)chunk=size-offset;
        if(send(pair[0],data+offset,chunk,MSG_DONTWAIT)!=(ssize_t)chunk)abort();
        offset+=chunk;
        if(control_receive(pair[1],&reader,&kind,&operation)<0)break;
    }
    shutdown(pair[0],SHUT_WR);
    for(size_t i=0;i<=size/16+1;i++)if(control_receive(pair[1],&reader,&kind,&operation)<0)break;
    close(pair[0]);close(pair[1]);
    // Exercise the encoder too, with arbitrary operation bits.
    if(socketpair(AF_UNIX,SOCK_STREAM,0,pair))abort();
    uint64_t id=0;memcpy(&id,data,size<8?size:8);
    assert(!control_send(pair[0],'A',id));
    reader=(struct control_reader){0};
    assert(control_receive(pair[1],&reader,&kind,&operation)==1);
    assert(kind=='A' && operation==id);
    close(pair[0]);close(pair[1]);
    return 0;
}
