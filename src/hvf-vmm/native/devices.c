// SPDX-License-Identifier: Apache-2.0
// Legacy VirtIO PCI block devices over opaque, pre-opened block files.
#include "devices.h"
#include "budget.h"
static struct budget disk_budget;
#include <Hypervisor/Hypervisor.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#ifdef HVF_CRASH_JOURNAL
// Test-only power-loss journal (experiments/hvf/durability); never in releases.
#include "crash_journal.h"
#endif
#define BASE 0x40000000ULL
#define BAR 0x10000000ULL
#define ECAM 0x3f000000ULL
#define QSZ 256
static uint8_t *memory;
static size_t memory_size;
struct block {
    int diskfd, read_only, irq_level;
    unsigned slot;
    uint64_t disk_size;
    uint8_t config[256], status, isr;
    uint32_t bar, guest_features, pfn;
    uint16_t qsel, last_avail, used_idx;
    unsigned long requests;
    uint64_t read_bytes,write_bytes,errors;
    // First host write/flush errno. Once set, every later FLUSH fails.
    int storage_errno;
};
static struct block blocks[4];
static unsigned block_count;
static uint16_t fw_selector;
static unsigned fw_offset;
static const struct hvf_firmware *firmware;
static unsigned firmware_count;
static uint8_t fw_dir[4+64*64];
static int guest_exit=-1;
static uint8_t panic_config[256];
static uint32_t panic_bar=0x10020000;
static void fail(const char *why) { fprintf(stderr,"device error: %s\n",why); exit(2); }
static void irq(struct block *block,int level) {
    block->irq_level=level;unsigned line=35+block->slot%4;int high=0;
    for(unsigned i=0;i<block_count;i++)if(35+blocks[i].slot%4==line)high|=blocks[i].irq_level;
    if(hv_gic_set_spi(line,high)!=HV_SUCCESS)fail("GIC SPI");
}
static uint64_t get(const void *p, unsigned size) { uint64_t v=0; memcpy(&v,p,size); return v; }
static void put(void *p, unsigned size,uint64_t v) { memcpy(p,&v,size); }
static uint8_t *guest(uint64_t pa, uint64_t len) {
    if(pa<BASE || len>memory_size || pa-BASE>memory_size-len) fail("DMA outside guest RAM");
    return memory+(pa-BASE);
}
struct desc { uint64_t addr; uint32_t len; uint16_t flags,next; };
static struct desc descriptor(struct block *block,uint16_t idx) {
    if(idx>=QSZ) fail("invalid descriptor index");
    struct desc d; memcpy(&d,guest(((uint64_t)block->pfn<<12)+16*idx,16),16);
    if(d.flags & ~3U) fail("unsupported descriptor flags");
    guest(d.addr,d.len); return d;
}
static int flush_disk(int fd) {
    int result;
    // Do not acknowledge a weaker fsync after a failed full flush. The guest
    // must see unsupported filesystems and I/O failures as device errors.
    do {
        result = fcntl(fd, F_FULLFSYNC);
    } while (result == -1 && errno == EINTR);
    return result;
}
// A failed pwrite or F_FULLFSYNC may leave host pages dropped or unwritten,
// and the Nanos TFS log clears its dirty state even when its flush fails. A
// later successful F_FULLFSYNC would then acknowledge data that never reached
// storage, so the first error is latched: FLUSH fails until the VMM restarts.
static void latch_storage_error(struct block *block,int error) {
    if(block->storage_errno)return;
    block->storage_errno=error?error:EIO;
    fprintf(stderr,"block[%u]: host storage error %d (%s); FLUSH fails until restart\n",
            (unsigned)(block-blocks),block->storage_errno,strerror(block->storage_errno));
}
static void notify(struct block *block) {
    if(!(block->status&4) || !block->pfn) fail("queue used before ready");
    uint64_t avail=((uint64_t)block->pfn<<12)+16*QSZ;
    uint64_t used=(avail+4+2*QSZ+2+4095)&~4095ULL;
    uint16_t upto=get(guest(avail+2,2),2);
    atomic_thread_fence(memory_order_acquire);
    if((uint16_t)(upto-block->last_avail)>QSZ) fail("available ring overrun");
    uint16_t before=block->last_avail;uint64_t turn_bytes=0;
    while(block->last_avail!=upto && (uint16_t)(block->last_avail-before)<32 && turn_bytes<(8ULL<<20)) {
        uint16_t head=get(guest(avail+4+2*(block->last_avail%QSZ),2),2);
        struct desc h=descriptor(block,head);
        if(h.len!=16 || (h.flags&2) || !(h.flags&1)) fail("invalid block header");
        uint8_t header[16];memcpy(header,guest(h.addr,16),sizeof(header));
        uint32_t type=get(header,4);uint64_t sector=get(header+8,8);
        struct desc chain[QSZ];unsigned count=0;uint16_t index=h.next;
        uint64_t transferred=0;
        // Snapshot and validate the entire chain before any disk side effect.
        // Guest descriptor edits cannot redirect a descriptor after validation.
        for(;;){
            if(count>=QSZ-1)fail("descriptor cycle");
            struct desc d=descriptor(block,index);chain[count++]=d;
            if(!(d.flags&1)){
                if(!(d.flags&2)||d.len!=1)fail("invalid block->status descriptor");
                break;
            }
            transferred+=d.len;if(transferred>(4ULL<<20))fail("request exceeds 4 MiB");
            if((type==0||type==1) && !!(d.flags&2)!=(type==0))fail("incorrect block DMA direction");
            index=d.next;
        }
        if(!budget_take(&disk_budget,transferred,1))break;
        uint64_t offset=0;uint8_t result=(type==0||type==1||type==4)?0:2;uint32_t written=1;
        if(type==1 && block->read_only)result=1;
        if(sector>block->disk_size/512)result=1;else offset=sector*512;
        uint8_t *status_byte=guest(chain[count-1].addr,1);
        for(unsigned j=0;j+1<count;j++){
            struct desc d=chain[j];
            if(type==0||type==1){
                if(d.len>block->disk_size || offset>block->disk_size-d.len)result=1;
                if(!result){
                    size_t done=0;
                    while(done<d.len){
                        ssize_t n=type==0?pread(block->diskfd,guest(d.addr,d.len)+done,d.len-done,offset+done):pwrite(block->diskfd,guest(d.addr,d.len)+done,d.len-done,offset+done);
                        if(n<0&&errno==EINTR)continue;
                        if(n<=0){
                            result=1;
                            if(type==1)latch_storage_error(block,n<0?errno:EIO);
                            break;
                        }
                        done+=n;
                        if(type==0)block->read_bytes+=(uint64_t)n;else block->write_bytes+=(uint64_t)n;
                    }
                    if(type==0)written+=done;
                }
                offset+=d.len;
            }else result=2;
        }
        // FLUSH has header and block->status only; perform it before publishing completion.
        if(type==4 && !block->read_only){
            if(block->storage_errno)result=1;
            else if(flush_disk(block->diskfd)){result=1;latch_storage_error(block,errno);}
        }
        if(result)block->errors++;
        *status_byte=result;turn_bytes+=transferred;
        put(guest(used+4+8*(block->used_idx%QSZ),8),4,head);
        put(guest(used+8+8*(block->used_idx%QSZ),4),4,written);
        atomic_thread_fence(memory_order_release);
        put(guest(used+2,2),2,++block->used_idx);
        block->last_avail++; block->requests++;
    }
    if(block->last_avail!=before){block->isr|=1; irq(block,1);}
}
int devices_init(void *ram,size_t size,const char *disk,const struct hvf_options *options) {
    budget_init(&disk_budget,options->disk_bytes_per_second,options->disk_operations_per_second,4ULL<<20,32);
    memset(blocks,0,sizeof(blocks));memset(fw_dir,0,sizeof(fw_dir));memset(panic_config,0,sizeof(panic_config));
    block_count=fw_selector=fw_offset=0;guest_exit=-1;panic_bar=0x10020000;
    for(unsigned i=0;i<4;i++)blocks[i].diskfd=-1;
    if(options->drive_count>4)return -1;
#ifdef HVF_CRASH_JOURNAL
    crash_journal_open();  // after the FD sweep, before the sandbox
#endif
    memory=ram; memory_size=size;
    put(panic_config,2,0x1b36);put(panic_config+2,2,0x11);put(panic_config+0x10,4,panic_bar);
    (void)disk;
    firmware=options->firmware;firmware_count=options->firmware_count;
    if(firmware_count>64)return -1;
    for(unsigned i=0;i<firmware_count;i++){
        const struct hvf_firmware *file=&firmware[i];unsigned n=file->len;
        if(n>65536 || strlen(file->name)>55)return -1;
        uint8_t *entry=fw_dir+4+64*i;
        entry[0]=n>>24;entry[1]=n>>16;entry[2]=n>>8;entry[3]=n;
        entry[4]=0;entry[5]=0x20+i;memcpy(entry+8,file->name,strlen(file->name));
    }
    fw_dir[3]=firmware_count;
    block_count=options->drive_count;
    const unsigned slots[]={0,3,4,6};
    for(unsigned i=0;i<block_count;i++){
        struct block *block=&blocks[i];block->slot=slots[i];block->bar=BAR+slots[i]*0x10000;
        block->read_only=options->drives[i].read_only;
        block->diskfd=dup(options->drives[i].fd);
        struct stat st;
        if(block->diskfd<0 || fstat(block->diskfd,&st) || !S_ISREG(st.st_mode) || st.st_size<512 || st.st_size%512)return -1;
        block->disk_size=st.st_size;
#ifdef HVF_CRASH_JOURNAL
        crash_journal_register(block->diskfd);
#endif
        put(block->config,2,0x1af4);put(block->config+2,2,0x1001);block->config[0xb]=1;
        put(block->config+0x10,4,block->bar);put(block->config+0x2c,2,0x1af4);put(block->config+0x2e,2,2);block->config[0x3d]=1;
    }
    return 0;
}

static int block_mmio(struct block *block,uint64_t addr,unsigned size,int write,uint64_t *v) {
    if(addr>=ECAM+block->slot*0x8000 && addr<ECAM+block->slot*0x8000+256) {
        uint64_t off=addr-ECAM-block->slot*0x8000;
        if(size>4 || off+size>256) return 0;
        if(write) {
            if(off>=0x10 && off<0x28 && size==4) {
                if(off==0x10) { block->bar=(uint32_t)*v; put(block->config+off,4,block->bar==0xffffffff ? 0xfffff000 : (block->bar&~15U)); }
            } else if(off==4 && size==2) put(block->config+off,size,*v);
        } else *v=get(block->config+off,size);
        return 1;
    }
    uint64_t base=block->bar&~15U;
    if(block->diskfd<0 || addr<base || addr>=base+4096) return 0;
    uint64_t off=addr-base;
    if(write) {
        switch(off) {
        case 4: if(size!=4) return 0; block->guest_features=*v; if(block->guest_features & ~((1U<<9)|(block->read_only?(1U<<5):0))) return 0; break;
        case 8: if(size!=4 || block->qsel) return 0; block->pfn=*v; block->last_avail=block->used_idx=0; break;
        case 14: if(size!=2) return 0; block->qsel=*v; break;
        case 16: if(size!=2 || *v) return 0; notify(block); break;
        case 18: if(size!=1) return 0; block->status=*v; if(!block->status) { block->pfn=0;block->last_avail=block->used_idx=0;block->guest_features=0;block->isr=0;irq(block,0); } break;
        default: return 0;
        }
    } else {
        switch(off) {
        case 0: *v=(1U<<9)|(block->read_only?(1U<<5):0); break; // FLUSH
        case 4: *v=block->guest_features; break;
        case 8: *v=block->qsel?0:block->pfn; break;
        case 12: *v=block->qsel?0:QSZ; break;
        case 14: *v=block->qsel; break;
        case 18: *v=block->status; break;
        case 19: *v=block->isr;block->isr=0;irq(block,0);break;
        default:
            if(off>=20 && off+size<=28) *v=(block->disk_size/512)>>((off-20)*8);
            else return 0;
        }
    }
    return 1;
}

int devices_mmio(uint64_t addr,unsigned size,int write,uint64_t *v) {
    if(addr>=0x3f010000 && addr<0x3f010100) {
        unsigned off=addr-0x3f010000;
        if(size>4||off+size>256)return 0;
        if(write){if(off==0x10&&size==4){panic_bar=*v;put(panic_config+off,4,panic_bar==0xffffffff?0xfffff000:panic_bar&~15U);}else if(off==4&&size==2)put(panic_config+off,size,*v);}
        else *v=get(panic_config+off,size);
        return 1;
    }
    if(addr==(panic_bar&~15U) && size==1) {
        if(write){if(*v&1){guest_exit=1;fprintf(stderr,"HVF: guest failure via pvpanic\n");}}else *v=1;
        return 1;
    }
    if(addr==0x09020008 && size==2 && write) { fw_selector=(*v>>8)|((*v&255)<<8);fw_offset=0;return 1; }
    if(addr==0x09020000 && size==1 && !write) {
        *v=0;
        if(fw_selector==0 && fw_offset<4)*v=(uint8_t)"QEMU"[fw_offset];
        else if(fw_selector==0x19 && fw_offset<4+64*fw_dir[3])*v=fw_dir[fw_offset];
        else if(fw_selector>=0x20 && fw_selector<0x20+firmware_count){const struct hvf_firmware *file=&firmware[fw_selector-0x20];if(fw_offset<file->len)*v=file->data[fw_offset];}
        if(fw_offset<0xffffffff)fw_offset++;
        return 1;
    }
    for(unsigned i=0;i<block_count;i++)if(block_mmio(&blocks[i],addr,size,write,v))return 1;
    if(addr>=ECAM && addr<ECAM+0x1000000){if(!write)*v=0xffffffff;return 1;}
    return 0;
}
uint64_t devices_queue_depth(void){
    uint64_t total=0;
    for(unsigned i=0;i<block_count;i++){
        struct block *b=&blocks[i];
        if(b->pfn && (b->status&4)){
            uint16_t n=get(guest(((uint64_t)b->pfn<<12)+16*QSZ+2,2),2);
            if((uint16_t)(n-b->last_avail)>QSZ)fail("available ring overrun");
            total+=(uint16_t)(n-b->last_avail);
        }
    }
    return total;
}
int devices_pending(void){return devices_queue_depth()!=0;}
void devices_poll(void){for(unsigned i=0;i<block_count;i++)if(blocks[i].pfn && (blocks[i].status&4))notify(&blocks[i]);}
int devices_exit_status(void){return guest_exit;}
void devices_close(void) {
    for(unsigned i=0;i<block_count;i++)if(blocks[i].diskfd>=0){
        struct block *b=&blocks[i];
        // A guest may exit without a final FLUSH; do not leave its last writes
        // only in host cache. The guest is gone, so failures are only logged.
        if(!b->read_only){
            if(b->storage_errno)fprintf(stderr,"block[%u]: final flush skipped after storage error %d\n",i,b->storage_errno);
            else if(flush_disk(b->diskfd))fprintf(stderr,"block[%u]: final F_FULLFSYNC failed: %s\n",i,strerror(errno));
        }
        fprintf(stderr,"block[%u]: %lu requests\n",i,b->requests);close(b->diskfd);b->diskfd=-1;
    }
}

// Caller holds the global device I/O lock, as for MMIO and polling.
void devices_metrics(uint64_t out[4]) {
    memset(out,0,4*sizeof(*out));
    for(unsigned i=0;i<block_count;i++){
        out[0]+=blocks[i].requests;out[1]+=blocks[i].read_bytes;
        out[2]+=blocks[i].write_bytes;out[3]+=blocks[i].errors;
    }
}

void devices_snapshot(struct snapshot_io *s){
    // A latched storage error is not serialized; never let a restore clear it.
    for(unsigned i=0;i<block_count;i++)if(!s->restore && !s->input && blocks[i].storage_errno){s->error=1;return;}
    uint32_t count=block_count;SNAP(s,count);if(count!=block_count){s->error=1;return;}
    for(unsigned i=0;i<block_count;i++){
        struct block *b=&blocks[i];uint64_t size=b->disk_size;uint32_t ro=b->read_only;
        SNAP(s,size);SNAP(s,ro);if(size!=b->disk_size || ro!=(uint32_t)b->read_only){s->error=1;return;}
        snapshot_bytes(s,b->config,sizeof(b->config));SNAP(s,b->status);SNAP(s,b->isr);
        SNAP(s,b->bar);SNAP(s,b->guest_features);SNAP(s,b->pfn);SNAP(s,b->qsel);
        SNAP(s,b->last_avail);SNAP(s,b->used_idx);SNAP(s,b->irq_level);
        SNAP(s,b->requests);SNAP(s,b->read_bytes);SNAP(s,b->write_bytes);SNAP(s,b->errors);
    }
    SNAP(s,fw_selector);SNAP(s,fw_offset);SNAP(s,panic_bar);
    snapshot_bytes(s,panic_config,sizeof(panic_config));
}
