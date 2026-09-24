// SPDX-License-Identifier: Apache-2.0
// Real VirtIO receive path, with only the host interrupt and IPC edges stubbed.
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "net_backend.h"
#include "net.h"
static net_receive_fn deliver;
static unsigned polls;
static unsigned char memory[1<<20];
int net_backend_open(const struct hvf_options *o,net_receive_fn fn){(void)o;deliver=fn;return 0;}
int net_backend_send(const void *p,size_t n){(void)p;(void)n;return 1;}
void net_backend_poll(void){polls++;}
void net_backend_close(void){}
static void put(unsigned off,unsigned size,uint64_t value){memcpy(memory+off,&value,size);}
static void reg(unsigned off,unsigned size,uint64_t value){assert(net_mmio(0x10010000+off,size,1,&value));}
int main(void){
    struct hvf_options options={.network_enabled=1};
    assert(!net_init(memory,sizeof(memory),&options));
    reg(14,2,0);reg(8,4,0x40010);reg(18,1,4);
    unsigned char packet[64];memset(packet,42,sizeof(packet));
    errno=0;assert(deliver(packet,sizeof(packet),NULL)==-1 && errno==EAGAIN);
    uint64_t metrics[6];net_metrics(metrics);assert(metrics[1]==0 && metrics[4]==0);
    // Post one writable descriptor and notify RX, then retry exactly the frame.
    put(0x10000,8,0x40020000);put(0x10008,4,2048);put(0x1000c,2,2);
    put(0x11004,2,0);put(0x11002,2,1);
    reg(16,2,0);assert(polls==1);
    assert(deliver(packet,sizeof(packet),NULL)==sizeof(packet));
    assert(!memcmp(memory+0x20000+10,packet,sizeof(packet)));
    net_metrics(metrics);assert(metrics[1]==1 && metrics[4]==0);
    assert(deliver(packet,sizeof(packet),NULL)==-1 && errno==EAGAIN);
    // Pause must not wait for parked CPUs to return buffers.
    net_quiesce(1);assert(deliver(packet,sizeof(packet),NULL)==sizeof(packet));
    net_metrics(metrics);assert(metrics[1]==1 && metrics[4]==1 && metrics[5]==sizeof(packet));
    net_quiesce(0);assert(deliver(packet,sizeof(packet),NULL)==-1 && errno==EAGAIN);
    puts("VirtIO RX retry, refill kick and quiescent drain: PASS");
}
