// SPDX-License-Identifier: Apache-2.0
// Device boundary tests, using real HVF interrupt routing but no executing guest.
#include "devices.h"
#include <Hypervisor/Hypervisor.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#define BASE 0x40000000ULL
#define BAR 0x10000000ULL
#define SIZE (1<<20)
struct descriptor { uint64_t addr; uint32_t len; uint16_t flags,next; };
static int witness=-1;
static uint8_t original[512];
static void unchanged(void){if(witness>=0){uint8_t data[512];assert(pread(witness,data,512,0)==512);assert(!memcmp(data,original,512));}}
static void wr(uint64_t off,unsigned size,uint64_t v){assert(devices_mmio(BAR+off,size,1,&v));}
int main(int argc,char **argv){
    assert(argc==2);const char *test=argv[1];
    uint8_t *ram=calloc(1,SIZE);assert(ram);
    char path[]="/tmp/hvf-device-test-XXXXXX";int fd=mkstemp(path);assert(fd>=0);assert(ftruncate(fd,4096)==0);
    uint8_t pattern[512];for(unsigned i=0;i<512;i++)pattern[i]=i;
    assert(pwrite(fd,pattern,sizeof(pattern),0)==sizeof(pattern));
    struct hvf_drive drive={.fd=fd,.read_only=!strcmp(test,"readonly")};
    const uint8_t payload[]={0,1,2,255};
    struct hvf_firmware fw={.name="opt/example/data",.data=payload,.len=4};
    struct hvf_options options={.drive_count=1,.drives=&drive,.firmware_count=1,.firmware=&fw};
    assert(devices_init(ram,SIZE,NULL,&options)==0);unlink(path);
    assert(hv_vm_create(NULL)==HV_SUCCESS);hv_gic_config_t gc=hv_gic_config_create();
    assert(hv_gic_config_set_distributor_base(gc,0x8000000)==HV_SUCCESS);
    assert(hv_gic_config_set_redistributor_base(gc,0x80a0000)==HV_SUCCESS);
    assert(hv_gic_create(gc)==HV_SUCCESS);os_release(gc);
    hv_vcpu_t cpu;hv_vcpu_exit_t *ex;assert(hv_vcpu_create(&cpu,&ex,NULL)==HV_SUCCESS);
    struct descriptor *desc=(void*)(ram+0x10000);
    desc[0]=(struct descriptor){BASE+0x20000,16,1,1};
    desc[1]=(struct descriptor){BASE+0x30000,512,3,2};
    desc[2]=(struct descriptor){BASE+0x40000,1,2,0};
    uint32_t *header=(void*)(ram+0x20000);
    if(!strcmp(test,"write")||!strcmp(test,"readonly")||!strcmp(test,"malformed-tail")){header[0]=1;desc[1].flags=1;memset(ram+0x30000,0xa5,512);}
    if(!strcmp(test,"malformed-tail")){witness=fd;memcpy(original,pattern,512);assert(!atexit(unchanged));desc[2].len=2;}
    if(!strcmp(test,"oob"))desc[1].addr=BASE+SIZE-256;
    if(!strcmp(test,"cycle")){desc[1].next=1;}
    if(!strcmp(test,"short-header"))desc[0].len=15;
    if(!strcmp(test,"unknown")){header[0]=42;desc[0].next=2;}
    uint16_t *avail=(void*)(ram+0x11000);avail[1]=1;avail[2]=0;
    wr(18,1,7);wr(8,4,(BASE+0x10000)>>12);wr(16,2,0);
    if(!strcmp(test,"firmware")){
        uint64_t v=0x2000;assert(devices_mmio(0x09020008,2,1,&v));
        for(unsigned i=0;i<4;i++){v=99;assert(devices_mmio(0x09020000,1,0,&v));assert(v==payload[i]);}
        v=99;assert(devices_mmio(0x09020000,1,0,&v)&&v==0);
    }
    uint8_t status=ram[0x40000];assert(status==(!strcmp(test,"readonly")?1:!strcmp(test,"unknown")?2:0));
    assert(*(uint16_t*)(ram+0x12002)==1);
    uint64_t value=0;assert(devices_mmio(BAR+19,1,0,&value)&&value==1);assert(devices_mmio(BAR+19,1,0,&value)&&value==0);
    if(!strcmp(test,"read"))assert(!memcmp(ram+0x30000,pattern,512));
    if(!strcmp(test,"write")){assert(pread(fd,pattern,512,0)==512);for(unsigned i=0;i<512;i++)assert(pattern[i]==0xa5);}
    if(!strcmp(test,"readonly")){uint8_t data[512];assert(pread(fd,data,512,0)==512);assert(!memcmp(data,pattern,512));}
    wr(18,1,0);value=9;assert(devices_mmio(BAR+8,4,0,&value)&&value==0);
    devices_close();assert(hv_vcpu_destroy(cpu)==HV_SUCCESS);assert(hv_vm_destroy()==HV_SUCCESS);close(fd);free(ram);return 0;
}
