// SPDX-License-Identifier: Apache-2.0
// Exercise legacy block completion, ISR, and shared SPI routing without a guest.
#include "devices.h"
#include <Hypervisor/Hypervisor.h>
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BASE 0x40000000ULL
#define BAR 0x10000000ULL
#define SIZE (1<<20)
struct descriptor {uint64_t addr;uint32_t len;uint16_t flags,next;};
static uint8_t *ram;
static unsigned rises,falls;
static bool level;

hv_return_t hv_gic_set_spi(uint32_t intid,bool asserted){
    assert(intid==35 && level!=asserted);
    level=asserted;
    if(asserted)rises++;else falls++;
    return HV_SUCCESS;
}
static uint64_t bar(unsigned device){return BAR+(device==2?4:device==1?3:0)*0x10000ULL;}
static unsigned ring(unsigned device){return 0x10000+device*0x10000;}
static uint16_t *avail(unsigned device){return (uint16_t *)(ram+ring(device)+4096);}
static uint16_t *used(unsigned device){return (uint16_t *)(ram+ring(device)+8192);}
static void wr(unsigned device,unsigned offset,unsigned width,uint64_t value){
    assert(devices_mmio(bar(device)+offset,width,1,&value));
}
static uint64_t rd(unsigned device,unsigned offset){
    uint64_t value=0;
    assert(devices_mmio(bar(device)+offset,1,0,&value));
    return value;
}
static void complete(unsigned device,unsigned request){
    struct descriptor *d=(void *)(ram+ring(device));
    unsigned header=0x40000+device*0x10000+request*32;
    unsigned status=header+16;
    d[request*2]=(struct descriptor){BASE+header,16,1,(uint16_t)(request*2+1)};
    d[request*2+1]=(struct descriptor){BASE+status,1,2,0};
    *(uint32_t *)(ram+header)=42; // unsupported request completes without host I/O
    avail(device)[2+request]=request*2;
    avail(device)[1]++;
    wr(device,16,2,0);
    assert(ram[status]==2 && used(device)[1]==request+1);
}
int main(void){
    ram=calloc(1,SIZE);assert(ram);
    int fds[3];struct hvf_drive drives[3];
    for(unsigned i=0;i<3;i++){
        char path[]="/tmp/hvf-block-irq-XXXXXX";
        fds[i]=mkstemp(path);assert(fds[i]>=0 && ftruncate(fds[i],4096)==0);
        unlink(path);drives[i]=(struct hvf_drive){.fd=fds[i],.read_only=1};
    }
    struct hvf_options options={.drive_count=3,.drives=drives};
    assert(devices_init(ram,SIZE,NULL,&options)==0);
    for(unsigned i=0;i<3;i++){
        wr(i,18,1,7);wr(i,8,4,(BASE+ring(i))>>12);
    }
    // Device 0 and device 2 occupy PCI slots 0 and 4, sharing SPI 35.
    avail(0)[0]=1;
    complete(0,0);
    assert(!level && rises==0 && rd(0,19)==0);
    avail(0)[0]=0;
    complete(0,1);
    assert(level && rises==1);
    complete(0,2);
    assert(rises==1); // pending ISR prevents a redundant raise
    avail(0)[0]=1;
    complete(0,3);
    assert(level && rises==1 && used(0)[1]==4);
    complete(2,0);
    assert(level && rises==1); // shared line remains high without another GIC call
    assert(rd(0,19)==1 && level && falls==0);
    assert(rd(0,19)==0 && level && falls==0);
    assert(rd(2,19)==1 && !level && falls==1);
    // A suppressed completion must not clear a pending ISR, including when
    // another device sharing the line is acknowledged or reset.
    avail(0)[0]=0;
    complete(0,4);
    avail(0)[0]=1;
    complete(0,5);
    assert(level && rises==2 && rd(0,19)==1 && falls==2);
    complete(2,1);
    assert(level && rises==3);
    wr(0,18,1,0);
    assert(level && falls==2 && rd(0,19)==0);
    wr(2,18,1,0);
    assert(!level && falls==3 && rd(2,19)==0);
    // The VMM snapshots block ISR and level; it restores the GIC separately.
    avail(2)[0]=avail(2)[1]=used(2)[1]=0;
    wr(2,18,1,7);wr(2,8,4,(BASE+ring(2))>>12);
    complete(2,0);
    assert(level && rises==4);
    FILE *file=tmpfile();assert(file);
    struct snapshot_io saved={.fd=fileno(file)};
    devices_snapshot(&saved);assert(!saved.error);
    wr(2,18,1,0);
    assert(!level && falls==4);
    assert(lseek(fileno(file),0,SEEK_SET)==0);
    struct snapshot_io restored={.fd=fileno(file),.restore=1};
    devices_snapshot(&restored);assert(!restored.error);
    level=true;
    complete(2,1);
    assert(level && rises==4 && rd(2,19)==1 && falls==5);
    fclose(file);
    devices_close();
    for(unsigned i=0;i<3;i++)close(fds[i]);
    free(ram);
    return 0;
}
