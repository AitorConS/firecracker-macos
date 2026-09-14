// SPDX-License-Identifier: Apache-2.0
#ifndef HVF_SNAPSHOT_IO_H
#define HVF_SNAPSHOT_IO_H
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
// Explicit little-endian fields; never write native structs, pointers or FDs.
struct snapshot_io {int fd, restore, error; const uint8_t *input; size_t remaining;};
static inline void snapshot_bytes(struct snapshot_io *s,void *data,size_t size){
    if(s->input){if(size>s->remaining){s->error=1;return;}memcpy(data,s->input,size);s->input+=size;s->remaining-=size;return;}
    uint8_t *p=data;
    while(size && !s->error){ssize_t n=s->restore?read(s->fd,p,size):write(s->fd,p,size);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){s->error=1;break;}p+=n;size-=(size_t)n;
    }
}
static inline uint64_t snapshot_number(struct snapshot_io *s,uint64_t value,unsigned width){
    uint8_t bytes[8];for(unsigned i=0;i<width;i++)bytes[i]=(uint8_t)(value>>(8*i));
    snapshot_bytes(s,bytes,width);value=0;
    for(unsigned i=0;i<width;i++)value|=(uint64_t)bytes[i]<<(8*i);
    return value;
}
#define SNAP(s,field) ((field)=snapshot_number((s),(uint64_t)(field),sizeof(field)))
static inline void snapshot_magic(struct snapshot_io *s,const char magic[8]){
    char bytes[8];memcpy(bytes,magic,8);snapshot_bytes(s,bytes,8);
    if(memcmp(bytes,magic,8))s->error=1;
}
static inline int snapshot_end(struct snapshot_io *s){
    if(s->input){if(s->remaining)s->error=1;}
    else if(s->restore){char byte;ssize_t n;do{n=read(s->fd,&byte,1);}while(n<0&&errno==EINTR);if(n!=0)s->error=1;}
    else if(fsync(s->fd))s->error=1;
    return s->error?-1:0;
}
#endif
