// SPDX-License-Identifier: Apache-2.0
// Production block code with injected host syscall outcomes: descriptor edits,
// short I/O, write/flush errors, latched storage errors, request ordering
// around F_FULLFSYNC, read-only drives, snapshots and the final close flush.
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/file.h>
static const char *fault_case;
static uint8_t *fixture;
static unsigned read_calls,write_calls,flush_calls,fsync_calls;
static int short_io;
static int write_errno[16],flush_errno[16];
static char trace[64];
static unsigned trace_len;
static uint16_t used_at_flush=0xffff;
static uint8_t status_at_flush;
static const uint8_t *flush_status;
#define DESC 0x10000
#define AVAIL 0x11000
#define USED 0x12000
#define STATUS 0x58000
struct wire_desc{uint64_t addr;uint32_t len;uint16_t flags,next;};
static int is(const char *name){return !strcmp(fault_case,name);}
static void note(char c){if(trace_len+1<sizeof(trace))trace[trace_len++]=c;}
static ssize_t injected_read(int fd,void *buffer,size_t count,off_t offset){
    read_calls++;note('R');
    if(is("eof"))return 0;
    if(is("descriptor-edit") && read_calls==1){
        struct wire_desc *descriptors=(void *)(fixture+DESC);
        descriptors[1].addr=UINT64_MAX;descriptors[1].len=UINT32_MAX;
        descriptors[2].addr=UINT64_MAX;
        memset(fixture+0x20000,0xff,16);
    }
    return pread(fd,buffer,short_io&&count>7?7:count,offset);
}
static ssize_t injected_write(int fd,const void *buffer,size_t count,off_t offset){
    write_calls++;note('W');
    if(write_calls<16 && write_errno[write_calls]){errno=write_errno[write_calls];return -1;}
    return pwrite(fd,buffer,short_io&&count>7?7:count,offset);
}
static int injected_fullsync(int fd,int command,...){
    assert(command==F_FULLFSYNC);flush_calls++;note('F');
    memcpy(&used_at_flush,fixture+USED+2,2);
    if(flush_status)status_at_flush=*flush_status;
    if(flush_calls<16 && flush_errno[flush_calls]){errno=flush_errno[flush_calls];return -1;}
    return fcntl(fd,F_FULLFSYNC);
}
// Counts any weaker fallback; production code must never call fsync().
static int injected_fsync(int fd){fsync_calls++;note('S');return fsync(fd);}
#define pread injected_read
#define pwrite injected_write
#define fcntl injected_fullsync
#define fsync injected_fsync
#ifndef DEVICES_C
#define DEVICES_C "../../src/hvf-vmm/native/devices.c"
#endif
#include DEVICES_C
#undef pread
#undef pwrite
#undef fcntl
#undef fsync
static unsigned submitted;
static void write_reg(uint64_t offset,unsigned size,uint64_t value){assert(devices_mmio(BAR+offset,size,1,&value));}
// Queue one request: 0 read, 1 write, 4 flush. Data is one 512-byte sector.
static unsigned submit(uint32_t type,uint64_t sector,uint8_t fill){
    unsigned k=submitted++;assert(k<32);
    struct wire_desc *d=(void *)(fixture+DESC);
    uint16_t head=3*k;uint64_t header=0x20000+0x40*k,data=0x30000+0x1000*k;
    uint32_t words[2]={type,0};memcpy(fixture+header,words,8);memcpy(fixture+header+8,&sector,8);
    fixture[STATUS+k]=0xff;
    if(type==4){
        d[head]=(struct wire_desc){BASE+header,16,1,head+1};
        d[head+1]=(struct wire_desc){BASE+STATUS+k,1,2,0};
    }else{
        d[head]=(struct wire_desc){BASE+header,16,1,head+1};
        d[head+1]=(struct wire_desc){BASE+data,512,type==0?3:1,head+2};
        d[head+2]=(struct wire_desc){BASE+STATUS+k,1,2,0};
        if(type==1)memset(fixture+data,fill,512);
    }
    memcpy(fixture+AVAIL+4+2*k,&head,2);
    uint16_t idx=submitted;memcpy(fixture+AVAIL+2,&idx,2);
    return k;
}
static void kick(void){write_reg(16,2,0);}
static uint8_t status(unsigned k){return fixture[STATUS+k];}
static uint16_t used_idx(void){uint16_t v;memcpy(&v,fixture+USED+2,2);return v;}
static uint32_t used_id(unsigned i){uint32_t v;memcpy(&v,fixture+USED+4+8*i,4);return v;}
static uint8_t *data(unsigned k){return fixture+0x30000+0x1000*k;}
static void expect_sector(int fd,uint64_t sector,uint8_t fill){
    uint8_t b[512];assert(pread(fd,b,512,sector*512)==512);
    for(unsigned i=0;i<512;i++)assert(b[i]==fill);
}
int main(int argc,char **argv){
    assert(argc==2);fault_case=argv[1];fixture=calloc(1,1<<20);assert(fixture);
    char path[]="/tmp/hvf-fault-XXXXXX";int fd=mkstemp(path);assert(fd>=0);unlink(path);assert(!ftruncate(fd,8192));
    uint8_t pattern[512];for(unsigned i=0;i<512;i++)pattern[i]=(uint8_t)i;assert(pwrite(fd,pattern,512,0)==512);
    struct hvf_drive drive={.fd=fd,.read_only=is("flush-readonly")};
    struct hvf_options config={.drive_count=1,.drives=&drive};assert(!devices_init(fixture,1<<20,NULL,&config));
    write_reg(18,1,7);write_reg(8,4,(BASE+DESC)>>12);
    uint64_t c[4];int closed=0;
    if(is("short-read")||is("descriptor-edit")){
        short_io=1;submit(0,0,0);kick();
        assert(status(0)==0 && read_calls>1 && !memcmp(pattern,data(0),512));
        devices_metrics(c);assert(c[1]==512 && c[3]==0);
    }else if(is("eof")){
        submit(0,0,0);kick();assert(status(0)==1);
        // Read failures do not imply lost writes and must not latch.
        submit(4,0,0);kick();assert(status(1)==0 && flush_calls==1);
    }else if(is("short-write")){
        short_io=1;submit(1,0,0xa5);kick();
        assert(status(0)==0 && write_calls>1);expect_sector(fd,0,0xa5);
        devices_metrics(c);assert(c[2]==512);
    }else if(is("write-eintr")){
        write_errno[1]=EINTR;submit(1,0,0xa6);submit(4,0,0);kick();
        assert(status(0)==0 && status(1)==0 && write_calls==2 && flush_calls==1);expect_sector(fd,0,0xa6);
    }else if(is("io-error")||is("no-space")){
        if(is("no-space")){short_io=1;write_errno[2]=ENOSPC;}else write_errno[1]=EIO;
        submit(1,0,0xa5);submit(4,0,0);kick();
        // The write fails and the following FLUSH fails without claiming durability.
        assert(status(0)==1 && status(1)==1 && flush_calls==0);
        devices_metrics(c);assert(c[3]==2 && c[2]==(is("no-space")?7U:0U));
    }else if(is("flush-error")||is("flush-unsupported")){
        flush_errno[1]=is("flush-error")?EIO:ENOTSUP;submit(4,0,0);kick();
        assert(status(0)==1 && flush_calls==1 && fsync_calls==0);
        devices_metrics(c);assert(c[3]==1);
    }else if(is("flush-eintr")){
        flush_errno[1]=EINTR;submit(4,0,0);kick();assert(status(0)==0 && flush_calls==2);
    }else if(is("flush-success")){
        submit(1,1,0x5a);submit(4,0,0);kick();
        assert(status(0)==0 && status(1)==0 && flush_calls==1 && fsync_calls==0);expect_sector(fd,1,0x5a);
    }else if(is("flush-sticky")){
        flush_errno[1]=EIO;submit(4,0,0);kick();assert(status(0)==1);
        // The host would now report success; the device must still refuse.
        submit(1,2,0x3c);submit(4,0,0);kick();
        assert(status(1)==0 && status(2)==1 && flush_calls==1);expect_sector(fd,2,0x3c);
    }else if(is("ordering")){
        submit(1,0,0x11);submit(1,1,0x22);unsigned f=submit(4,0,0);submit(1,2,0x33);
        flush_status=fixture+STATUS+f;kick();
        // Earlier writes reach the host before F_FULLFSYNC; the FLUSH result is
        // published only after it returns; later writes follow in order.
        assert(!strcmp(trace,"WWFW"));assert(used_at_flush==2 && status_at_flush==0xff);
        for(unsigned k=0;k<4;k++){assert(status(k)==0);assert(used_id(k)==3*k);}
        assert(used_idx()==4);
        expect_sector(fd,0,0x11);expect_sector(fd,1,0x22);expect_sector(fd,2,0x33);
    }else if(is("flush-readonly")){
        submit(4,0,0);submit(1,0,0x77);kick();
        assert(status(0)==0 && status(1)==1 && flush_calls==0 && write_calls==0);
        assert(pread(fd,data(0),512,0)==512 && !memcmp(data(0),pattern,512));
        devices_close();closed=1;assert(flush_calls==0);
    }else if(is("snapshot-latched")){
        int null=open("/dev/null",O_WRONLY);assert(null>=0);
        struct snapshot_io s={.fd=null};devices_snapshot(&s);assert(!s.error);
        flush_errno[1]=EIO;submit(4,0,0);kick();assert(status(0)==1);
        struct snapshot_io latched={.fd=null};devices_snapshot(&latched);assert(latched.error);
        close(null);
    }else if(is("close-flush")){
        submit(1,3,0x44);kick();assert(status(0)==0 && flush_calls==0);
        devices_close();closed=1;assert(flush_calls==1 && fsync_calls==0);
    }else if(is("close-latched")){
        write_errno[1]=EIO;submit(1,3,0x44);kick();assert(status(0)==1);
        devices_close();closed=1;assert(flush_calls==0 && fsync_calls==0);
    }else{
        fprintf(stderr,"unknown case %s\n",fault_case);return 2;
    }
    if(!closed)devices_close();
    close(fd);free(fixture);printf("PASS %s\n",fault_case);return 0;
}
