// SPDX-License-Identifier: Apache-2.0
// VirtIO 1.0 MMIO input device: standard EV_KEY/KEY_POWER, no guest agent.
#include "input.h"
#include <Hypervisor/Hypervisor.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#define BASE 0x09030000ULL
#define RAM 0x40000000ULL
#define MAXQ 64
static uint8_t *memory;static size_t memory_size;static int enabled;
static uint32_t status,irqstatus,feature_sel,driver_sel,qsel,feature_hi;
static uint8_t config[136];
struct queue{uint64_t desc,avail,used;uint32_t num,ready;uint16_t last,done;};
static struct queue queues[2];
static void fail(const char *why){fprintf(stderr,"input device error: %s\n",why);exit(2);}
static uint8_t *dma(uint64_t a,size_t n){if(a<RAM||n>memory_size||a-RAM>memory_size-n)fail("DMA range");return memory+a-RAM;}
static uint64_t get(const void *p,unsigned n){uint64_t v=0;memcpy(&v,p,n);return v;}
static void put(void *p,unsigned n,uint64_t v){memcpy(p,&v,n);}
static void irq(void){if(hv_gic_set_spi(40,irqstatus!=0)!=HV_SUCCESS)fail("IRQ");}
void input_init(void *ram,size_t size,int active){memory=ram;memory_size=size;enabled=active;status=irqstatus=feature_sel=driver_sel=qsel=feature_hi=0;memset(config,0,sizeof(config));memset(queues,0,sizeof(queues));}
static void configuration(void){
    memset(config+2,0,sizeof(config)-2);
    if(config[0]==1){const char name[]="VMM Power Button";config[2]=sizeof(name);memcpy(config+8,name,sizeof(name));}
    else if(config[0]==3){config[2]=8;put(config+8,2,6);put(config+10,2,0x1af4);put(config+12,2,1);put(config+14,2,1);}
    else if(config[0]==0x11 && config[1]==1){config[2]=15;config[8+116/8]=1<<(116%8);}
}
int input_mmio(uint64_t addr,unsigned size,int write,uint64_t *v){
    if(!enabled||addr<BASE||addr>=BASE+0x1000)return 0;
    unsigned off=addr-BASE;
    if(off>=0x100 && off<0x188){
        if(size>4 || size>sizeof(config)-(off-0x100))return 0;
        if(write){if(size!=1||off>0x101)return 0;config[off-0x100]=*v;configuration();}
        else *v=get(config+(off-0x100),size);return 1;
    }
    if(size!=4||off&3)return 0;
    struct queue *q=qsel<2?&queues[qsel]:NULL;
    if(!write){switch(off){
        case 0:*v=0x74726976;break;case 4:*v=2;break;case 8:*v=18;break;case 12:*v=0x1af4;break;
        case 0x10:*v=feature_sel==1?1:0;break;case 0x34:*v=q?MAXQ:0;break;
        case 0x44:*v=q?q->ready:0;break;case 0x60:*v=irqstatus;break;case 0x70:*v=status;break;case 0xfc:*v=0;break;
        default:return 0;
    }return 1;}
    switch(off){
        case 0x14:feature_sel=*v;break;case 0x24:driver_sel=*v;break;
        case 0x20:if(driver_sel==1){if(*v&~1U)return 0;feature_hi=*v;}else if(*v)return 0;break;
        case 0x30:qsel=*v;break;
        case 0x38:if(!q||q->ready||!*v||*v>MAXQ||(*v&(*v-1)))return 0;q->num=*v;break;
        case 0x44:if(!q||*v>1||(*v&&!q->num))return 0;q->ready=*v;break;
        case 0x50:if(*v>1)return 0;break; // event buffers are consumed on a power request
        case 0x64:irqstatus&=~*v;irq();break;
        case 0x70:status=*v;if(!status){memset(queues,0,sizeof(queues));feature_hi=irqstatus=0;irq();}else if((status&8)&&feature_hi!=1)status&=~8U;break;
        case 0x80:case 0x84:case 0x90:case 0x94:case 0xa0:case 0xa4:{
            if(!q||q->ready)return 0;uint64_t *address=off<0x90?&q->desc:off<0xa0?&q->avail:&q->used;
            unsigned shift=(off&4)?32:0;*address=(*address&~(0xffffffffULL<<shift))|((*v&0xffffffffULL)<<shift);break;
        }
        default:return 0;
    }return 1;
}
int input_power_button(void){
    struct queue *q=&queues[0];if(!enabled||!(status&4)||!q->ready)return 0;
    uint16_t available=get(dma(q->avail+2,2),2);atomic_thread_fence(memory_order_acquire);
    if((uint16_t)(available-q->last)>q->num)fail("available ring overrun");
    if((uint16_t)(available-q->last)<4)return 0;
    // Validate all four independent event buffers before making any DMA write.
    uint16_t heads[4];uint64_t addresses[4];
    for(unsigned i=0;i<4;i++){
        heads[i]=get(dma(q->avail+4+2*((q->last+i)%q->num),2),2);
        if(heads[i]>=q->num)fail("descriptor index");
        uint8_t *d=dma(q->desc+16*heads[i],16);addresses[i]=get(d,8);
        if(get(d+8,4)<8||get(d+12,2)!=2)fail("event descriptor");dma(addresses[i],8);
    }
    const uint16_t type[]={1,0,1,0},code[]={116,0,116,0};const uint32_t value[]={1,0,0,0};
    for(unsigned i=0;i<4;i++){
        uint8_t *event=dma(addresses[i],8);put(event,2,type[i]);put(event+2,2,code[i]);put(event+4,4,value[i]);
        uint8_t *used=dma(q->used+4+8*(q->done%q->num),8);put(used,4,heads[i]);put(used+4,4,8);q->done++;q->last++;
    }
    atomic_thread_fence(memory_order_release);put(dma(q->used+2,2),2,q->done);irqstatus|=1;irq();return 1;
}
