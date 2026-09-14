// SPDX-License-Identifier: Apache-2.0
// Exercise production device code; only the interrupt/network host edges are stubbed.
#include "devices.h"
#include "net.h"
#include "input.h"
#include "net_backend.h"
#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define BASE 0x40000000ULL
#define SIZE (1<<20)
static jmp_buf rejected;
static net_receive_fn receive_packet;
static uint8_t ram[SIZE];
static int disk=-1;
_Noreturn void fuzz_exit(int status){if(status==2)longjmp(rejected,1);abort();}
int fuzz_log(FILE *stream,const char *format,...){(void)stream;(void)format;return 0;}
int net_backend_open(const struct hvf_options *o,net_receive_fn cb){(void)o;receive_packet=cb;return 0;}
void net_backend_send(const void *p,size_t n){(void)p;(void)n;}
void net_backend_poll(void){}
void net_backend_close(void){receive_packet=NULL;}
static void put(size_t off,unsigned size,uint64_t value){memcpy(ram+off,&value,size);}
static void desc(unsigned i,uint64_t addr,uint32_t len,uint16_t flags,uint16_t next){
    size_t off=0x10000+16*i;put(off,8,addr);put(off+8,4,len);put(off+12,2,flags);put(off+14,2,next);
}
static void wr(unsigned target,uint64_t off,unsigned size,uint64_t value){
    if(target==0)devices_mmio(0x10000000+off,size,1,&value);
    else if(target==1)net_mmio(0x10010000+off,size,1,&value);
    else input_mmio(0x09030000+off,size,1,&value);
}
int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    if(size<2)return 0;
    if(disk<0){char path[]="/tmp/hvf-fuzz-XXXXXX";disk=mkstemp(path);assert(disk>=0);unlink(path);assert(ftruncate(disk,4096)==0);}
    memset(ram,0,sizeof(ram));
    struct hvf_drive drive={.fd=disk,.read_only=!!(data[1]&1)};
    static const uint8_t payload[]={0,1,2,255};
    struct hvf_firmware fw={.name="opt/example/data",.data=payload,.len=4};
    struct hvf_options options={.drive_count=1,.drives=&drive,.firmware_count=1,.firmware=&fw,.network_enabled=1};
    assert(devices_init(ram,SIZE,NULL,&options)==0);assert(net_init(ram,SIZE,&options)==0);input_init(ram,SIZE,1);
    if(!setjmp(rejected)){
        unsigned target=data[0]%5;
        if(target==4){
            struct snapshot_io input={.fd=-1,.restore=1,.input=data+2,.remaining=size-2};
            devices_snapshot(&input);net_snapshot(&input);input_snapshot(&input);
            (void)snapshot_end(&input);
        }
        desc(0,BASE+0x20000,16,1,1);desc(1,BASE+0x30000,512,3,2);desc(2,BASE+0x40000,1,2,0);
        put(0x11002,2,1);
        if(target==1){desc(0,BASE+0x20000,64,(data[1]&2)?2:0,0);}
        if(target==2){for(unsigned i=0;i<4;i++){desc(i,BASE+0x20000+8*i,8,2,0);put(0x11004+2*i,2,i);}put(0x11002,2,4);}
        // Structured mutations reach valid queues and malformed DMA/chains. Every
        // record selects a byte in descriptors, ring, header, event buffer or MMIO.
        for(size_t p=2;p+3<size&&p<4098;p+=4){
            unsigned region=data[p]%5,off=data[p+1]|((data[p+2]&15)<<8);
            static const size_t regions[]={0x10000,0x11000,0x12000,0x20000,0x30000};
            ram[regions[region]+off]=data[p+3];
        }
        if(target==0){wr(0,18,1,7);wr(0,8,4,(BASE+0x10000)>>12);wr(0,16,2,0);devices_poll();}
        if(target==1){wr(1,18,1,7);wr(1,14,2,(data[1]&2)?0:1);wr(1,8,4,(BASE+0x10000)>>12);
            if(data[1]&2)receive_packet(payload,sizeof(payload),NULL);else net_poll();}
        if(target==2){wr(2,0x24,4,1);wr(2,0x20,4,1);wr(2,0x38,4,64);wr(2,0x80,4,BASE+0x10000);wr(2,0x90,4,BASE+0x11000);wr(2,0xa0,4,BASE+0x12000);wr(2,0x44,4,1);wr(2,0x70,4,15);input_power_button();}
        // Arbitrary PCI ECAM, BAR, firmware and MMIO accesses, with architectural widths.
        static const uint64_t bases[]={0x3f000000,0x3f008000,0x10000000,0x10010000,0x09020000,0x09030000};
        for(size_t p=2;p+11<size&&p<770;p+=12){
            uint64_t value;memcpy(&value,data+p+4,8);uint64_t addr=bases[data[p]%6]+data[p+1]+((data[p+2]&15)<<8);
            unsigned width=1U<<(data[p+3]&3);int write=!!(data[p+3]&4);
            devices_mmio(addr,width,write,&value);net_mmio(addr,width,write,&value);input_mmio(addr,width,write,&value);
        }
    }
    devices_close();net_close();return 0;
}
