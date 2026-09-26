// SPDX-License-Identifier: Apache-2.0
// Exercise real virtio-net queue completion and ISR behavior without a guest.
#include "net.h"
#include "net_backend.h"
#include <Hypervisor/Hypervisor.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BASE 0x40000000ULL
#define BAR 0x10010000ULL
#define SIZE (1<<20)
#define RX_RING 0x10000
#define TX_RING 0x20000
struct descriptor { uint64_t addr; uint32_t len; uint16_t flags,next; };
static uint8_t *memory;
static net_receive_fn deliver;
static unsigned rises,falls,sends;
static bool level;

hv_return_t hv_gic_set_spi(uint32_t intid,bool asserted){
    assert(intid==36);
    assert(level!=asserted);
    level=asserted;
    if(asserted)rises++;else falls++;
    return HV_SUCCESS;
}
int net_backend_open(const struct hvf_options *options,net_receive_fn receive){
    (void)options;deliver=receive;return 0;
}
int net_backend_send(const void *data,size_t size){
    assert(data && size==14);sends++;return 1;
}
void net_backend_poll(void){}
void net_backend_close(void){deliver=NULL;}
void net_backend_health(void){}

static void write_reg(unsigned offset,unsigned width,uint64_t value){
    assert(net_mmio(BAR+offset,width,1,&value));
}
static uint64_t read_reg(unsigned offset,unsigned width){
    uint64_t value=0;
    assert(net_mmio(BAR+offset,width,0,&value));
    return value;
}
static uint16_t *avail(unsigned ring){return (uint16_t *)(memory+ring+4096);}
static uint16_t *used(unsigned ring){return (uint16_t *)(memory+ring+8192);}
static void tx(unsigned slot){
    struct descriptor *d=(void *)(memory+TX_RING);
    d[slot]=(struct descriptor){BASE+0x30000+slot*64,24,0,0};
    memset(memory+0x30000+slot*64,0,24); // valid zero virtio header and Ethernet frame
    avail(TX_RING)[2+slot]=slot;
    avail(TX_RING)[1]++;
    write_reg(16,2,1);
}
static void rx(unsigned slot){
    struct descriptor *d=(void *)(memory+RX_RING);
    d[slot]=(struct descriptor){BASE+0x40000+slot*64,64,2,0};
    avail(RX_RING)[2+slot]=slot;
    avail(RX_RING)[1]++;
    char frame[14]={0};
    assert(deliver(frame,sizeof(frame),NULL)==(ssize_t)sizeof(frame));
}
int main(void){
    memory=calloc(1,SIZE);assert(memory);
    struct hvf_options options={.network_enabled=1};
    assert(net_init(memory,SIZE,&options)==0);
    write_reg(18,1,4);
    write_reg(14,2,0);write_reg(8,4,(BASE+RX_RING)>>12);
    write_reg(14,2,1);write_reg(8,4,(BASE+TX_RING)>>12);

    // Nanos sets NO_INTERRUPT on its polling TX queue. Used entries still
    // advance, and the guest sees no spurious ISR/GIC signal.
    avail(TX_RING)[0]=1;
    tx(0);
    assert(sends==1 && used(TX_RING)[1]==1 && rises==0 && read_reg(19,1)==0);

    // The guest re-arms interrupts when its software queue stalls. Multiple
    // completions before ISR acknowledgement should cause just one GIC raise.
    avail(TX_RING)[0]=0;
    tx(1);tx(2);
    assert(sends==3 && used(TX_RING)[1]==3 && rises==1);
    assert(read_reg(19,1)==1 && falls==1);
    assert(read_reg(19,1)==0 && falls==1);
    tx(3);
    assert(used(TX_RING)[1]==4 && rises==2);
    assert(read_reg(19,1)==1 && falls==2);

    // If RX finishes while interrupts are suppressed, re-arming plus the
    // guest's used-index check observes it; a later frame must wake it.
    avail(RX_RING)[0]=1;
    rx(0);
    assert(used(RX_RING)[1]==1 && rises==2 && read_reg(19,1)==0);
    avail(RX_RING)[0]=0;
    assert(used(RX_RING)[1]==1);
    rx(1);
    assert(used(RX_RING)[1]==2 && rises==3 && read_reg(19,1)==1);
    rx(2);
    assert(used(RX_RING)[1]==3 && rises==4 && read_reg(19,1)==1);

    // Device snapshot carries ISR and ring indices; the GIC snapshot carries
    // the asserted level. A restored pending ISR must still be acknowledged,
    // and another completion must not send a redundant GIC raise.
    tx(4);
    assert(rises==5 && read_reg(19,1)==1);
    tx(5);
    assert(rises==6);
    FILE *file=tmpfile();assert(file);
    struct snapshot_io saved={.fd=fileno(file)};
    net_snapshot(&saved);assert(!saved.error);
    write_reg(18,1,0);
    assert(lseek(fileno(file),0,SEEK_SET)==0);
    struct snapshot_io restored={.fd=fileno(file),.restore=1};
    net_snapshot(&restored);assert(!restored.error);
    level=true; // the surrounding VMM restores the GIC separately
    tx(6);
    assert(used(TX_RING)[1]==7 && rises==6 && level);
    assert(read_reg(19,1)==1 && !level);
    tx(7);
    assert(used(TX_RING)[1]==8 && rises==7 && level);
    fclose(file);

    net_close();free(memory);return 0;
}
