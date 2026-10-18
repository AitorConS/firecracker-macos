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
// Guest RAM and disks are mostly zeros. Snapshot files leave zero pages as
// holes (16 KiB is the host page size) and read back only their data extents.
#define SNAPSHOT_PAGE 16384
static inline int snapshot_zero(const uint8_t *p,size_t n){
    const uint64_t *w=(const uint64_t *)(const void *)p;size_t words=n/8;
    for(size_t i=0;i<words;i++)if(w[i])return 0;
    for(size_t i=words*8;i<n;i++)if(p[i])return 0;
    return 1;
}
// Writes the non-zero pages of data at offset base of fd, which the caller has
// already extended to its full length. Runs are capped at 1 MiB per write.
static inline int snapshot_write_sparse(int fd,const uint8_t *data,size_t size,off_t base){
    size_t i=0;
    while(i<size){
        size_t n=size-i>SNAPSHOT_PAGE?SNAPSHOT_PAGE:size-i;
        if(snapshot_zero(data+i,n)){i+=n;continue;}
        size_t start=i;i+=n;
        while(i<size&&i-start<(1u<<20)){
            n=size-i>SNAPSHOT_PAGE?SNAPSHOT_PAGE:size-i;
            if(snapshot_zero(data+i,n))break;
            i+=n;
        }
        const uint8_t *p=data+start;size_t left=i-start;off_t at=base+(off_t)start;
        while(left){
            ssize_t w=pwrite(fd,p,left,at);
            if(w<0&&errno==EINTR)continue;
            if(w<=0)return -1;
            p+=w;left-=(size_t)w;at+=w;
        }
    }
    return 0;
}
// Calls visit(offset,length,ctx) for each data extent of the first size bytes
// of fd; holes are skipped. Without hole information the whole range is data.
static inline int snapshot_extents(int fd,off_t size,int (*visit)(off_t,off_t,void *),void *ctx){
    off_t pos=0;
    while(pos<size){
        off_t data=lseek(fd,pos,SEEK_DATA),hole;
        if(data<0){
            if(errno==ENXIO)return 0;
            if(errno!=EINVAL&&errno!=ENOTSUP)return -1;
            data=pos;hole=size;
        }else{
            if(data>=size)return 0;
            hole=lseek(fd,data,SEEK_HOLE);
            if(hole<0)return -1;
            if(hole>size)hole=size;
        }
        if(visit(data,hole-data,ctx))return -1;
        pos=hole;
    }
    return 0;
}
#endif
