// SPDX-License-Identifier: Apache-2.0
// Bring-up laboratory; deliberately independent of the Linux Firecracker VMM.
#include <Hypervisor/Hypervisor.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <mach/mach_time.h>
#include "devices.h"
#include "net.h"
#include "net_backend.h"
#include "hvf.h"
#include "input.h"
#include "seatbelt.h"
#include "control.h"
#include "cpu_snapshot.h"
#include <stdatomic.h>
#include <signal.h>
#include <errno.h>

#define RAM_BASE 0x40000000ULL
static size_t ram_size;
static _Atomic uint64_t cpu_exits[4];
static uint64_t clock_offset_ns;
static uint32_t uart[19];
static int snapshot_dirfd=-1;
static uint64_t capture_operation;
static unsigned captured_cpus;
static int capture_error;
static uint64_t restore_started, restore_physical_delta;
#define CHECK(expr) do { hv_return_t r = (expr); if (r != HV_SUCCESS) { \
    fprintf(stderr, "%s: 0x%x\n", #expr, r); exit(1); } } while (0)

static int mmio(uint64_t addr, unsigned size, int write, uint64_t *value) {
    // PL011 transmit console, register interface and level TX interrupt.

    if(addr>=0x09000fe0 && addr<=0x09000ffc && !(addr&3) && !write && size<=4){
        const uint8_t ids[]={0x11,0x10,0x14,0,0x0d,0xf0,0x05,0xb1};
        *value=ids[(addr-0x09000fe0)/4];return 1;
    }
    if(addr>=0x09000000 && addr<=0x09000048 && !(addr&3) && (size==1||size==2||size==4)){
        unsigned off=addr-0x09000000;
        if(write){
            if(off==0){putchar(*value&255);fflush(stdout);}
            else uart[off/4]=*value;
            if(off==0x38 || off==0x44)CHECK(hv_gic_set_spi(33,(uart[0x38/4]&0x20)!=0));
        }else if(off==0x18)*value=0x90;
        else if(off==0x3c)*value=0x20;
        else if(off==0x40)*value=uart[0x38/4]&0x20;
        else if(off==0)*value=0;
        else *value=uart[off/4];
        return 1;
    }
    // Read-only PL031 clock and identification; no interrupt emulation.
    if (addr == 0x09010000 && !write && size == 4) {
        *value = (uint32_t)(time(NULL)-clock_offset_ns/1000000000); return 1;
    }
    if (addr >= 0x09010fe0 && addr <= 0x09010ffc &&
        !(addr & 3) && !write && (size == 1 || size == 4)) {
        const uint8_t ids[] = {0x31,0x10,0x04,0x00,0x0d,0xf0,0x05,0xb1};
        *value = ids[(addr - 0x09010fe0) / 4]; return 1;
    }
    if (input_mmio(addr,size,write,value))return 1;
    if (net_mmio(addr,size,write,value)) return 1;
    return devices_mmio(addr, size, write, value);
}


#define MAX_CPUS 4
struct cpu {
    hv_vcpu_t id;
    pthread_t thread;
    unsigned index;
    int ready, started, parked;
    uint64_t clock_offset, captured;
    uint64_t entry, context, os_lock, os_double_lock;
};
static struct cpu cpus[MAX_CPUS];
static unsigned ncpus=1;
static const struct hvf_options *options;
static pthread_mutex_t io_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t state_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_change=PTHREAD_COND_INITIALIZER;
static atomic_int result=-1;
static volatile sig_atomic_t stop_requested;
static void stop_signal(int sig){stop_requested=sig;}
static unsigned stopped;
static int teardown_released;
static int pause_requested, resume_hold;
static uint64_t clock_offset;
static int snapshot_open(const char *name,int restore){
    int fd=openat(snapshot_dirfd,name,restore?(O_RDONLY|O_NOFOLLOW|O_NONBLOCK):(O_WRONLY|O_CREAT|O_NOFOLLOW|O_NONBLOCK),0600);
    struct stat st;if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1){close(fd);return -1;}
    if(!restore && ftruncate(fd,0)){close(fd);return -1;}return fd;
}
static int cpu_snapshot(struct cpu *c,int restore){
    char name[32];snprintf(name,sizeof(name),"cpu-%u.bin",c->index);
    struct snapshot_io s={.fd=snapshot_open(name,restore),.restore=restore};if(s.fd<0)return -1;
    snapshot_magic(&s,"HVFCPU01");
    struct snapshot_sme sme=snapshot_sme_header(c->id,&s);
    uint32_t index=c->index;SNAP(&s,index);if(index!=c->index)s.error=1;
    SNAP(&s,c->started);SNAP(&s,c->entry);SNAP(&s,c->context);SNAP(&s,c->os_lock);SNAP(&s,c->os_double_lock);
    if(c->started!=0 && c->started!=1)s.error=1;
    for(unsigned i=HV_REG_X0;i<=HV_REG_CPSR;i++){
        uint64_t value=0;if(!restore && hv_vcpu_get_reg(c->id,(hv_reg_t)i,&value))s.error=1;
        SNAP(&s,value);if(restore && !s.error && hv_vcpu_set_reg(c->id,(hv_reg_t)i,value))s.error=1;
    }
    for(unsigned i=0;i<32;i++){
        hv_simd_fp_uchar16_t value={0};if(!restore && hv_vcpu_get_simd_fp_reg(c->id,(hv_simd_fp_reg_t)i,&value))s.error=1;
        snapshot_bytes(&s,&value,16);if(restore && !s.error && hv_vcpu_set_simd_fp_reg(c->id,(hv_simd_fp_reg_t)i,value))s.error=1;
    }
    for(unsigned i=0;i<sizeof(snapshot_sysregs)/sizeof(snapshot_sysregs[0]);i++){
        uint64_t value=0;uint16_t reg=snapshot_sysregs[i];
        uint8_t present=hv_vcpu_get_sys_reg(c->id,snapshot_sysregs[i],&value)==HV_SUCCESS;
        SNAP(&s,reg);SNAP(&s,present);SNAP(&s,value);
        if(reg!=snapshot_sysregs[i] || present>1)s.error=1;
        if(restore && reg==HV_SYS_REG_CNTP_CVAL_EL0)value+=restore_physical_delta;
        if(restore && present && !s.error && hv_vcpu_set_sys_reg(c->id,snapshot_sysregs[i],value)){
            fprintf(stderr,"snapshot system register %x rejected\n",reg);s.error=1;
        }
    }
    for(unsigned i=0;i<sizeof(snapshot_icc)/sizeof(snapshot_icc[0]);i++){
        uint64_t value=0;uint16_t reg=snapshot_icc[i];
        if(!restore && hv_gic_get_icc_reg(c->id,snapshot_icc[i],&value))s.error=1;
        SNAP(&s,reg);SNAP(&s,value);if(reg!=snapshot_icc[i])s.error=1;
        if(restore && !s.error && hv_gic_set_icc_reg(c->id,snapshot_icc[i],value))s.error=1;
    }
    bool masked=false;if(!restore && hv_vcpu_get_vtimer_mask(c->id,&masked))s.error=1;
    uint8_t mask=masked;SNAP(&s,mask);if(mask>1)s.error=1;
    if(restore && !s.error && hv_vcpu_set_vtimer_mask(c->id,mask!=0))s.error=1;
    snapshot_sme_data(c->id,&s,sme);
    int failed=snapshot_end(&s);close(s.fd);return failed;
}
// All HVF register operations stay on the owning vCPU thread. Offline secondary
// CPUs join the same barrier, and remain offline after its release.
static void cpu_checkpoint(struct cpu *c){
    pthread_mutex_lock(&state_lock);
    for(;;){
        if(atomic_load(&result)>=0)break;
        if(pause_requested){
            c->parked=1;pthread_cond_broadcast(&state_change);
            if(capture_operation && c->captured!=capture_operation){
                if(cpu_snapshot(c,0))capture_error=1;
                c->captured=capture_operation;captured_cpus++;pthread_cond_broadcast(&state_change);
            }
        }
        else {
            if(c->clock_offset!=clock_offset){
                CHECK(hv_vcpu_set_vtimer_offset(c->id,clock_offset));
                c->clock_offset=clock_offset;
            }
            c->parked=0;pthread_cond_broadcast(&state_change);
            if(c->started && !resume_hold)break;
        }
        pthread_cond_wait(&state_change,&state_lock);
    }
    pthread_mutex_unlock(&state_lock);
}
static int parked_cpus(void){
    int count=0;pthread_mutex_lock(&state_lock);
    for(unsigned i=0;i<ncpus;i++)count+=cpus[i].parked;
    pthread_mutex_unlock(&state_lock);return count;
}
static void kick_cpus(void){
    hv_vcpu_t ids[MAX_CPUS];for(unsigned i=0;i<ncpus;i++)ids[i]=cpus[i].id;
    CHECK(hv_vcpus_exit(ids,ncpus));
}

static double seconds(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec+t.tv_nsec/1e9;
}
static void finish(int status) {
    int expected=-1;
    atomic_compare_exchange_strong(&result,&expected,status);
}
static void *cpu_main(void *arg) {
    struct cpu *c=arg;
    hv_vcpu_exit_t *ex;
    CHECK(hv_vcpu_create(&c->id,&ex,NULL));
    CHECK(hv_vcpu_set_sys_reg(c->id,HV_SYS_REG_MPIDR_EL1,0x80000000|c->index));
    CHECK(hv_vcpu_set_reg(c->id,HV_REG_CPSR,0x3c5));
    CHECK(hv_vcpu_set_sys_reg(c->id,HV_SYS_REG_SCTLR_EL1,0x30900180));
    CHECK(hv_vcpu_set_reg(c->id,HV_REG_X1,0));
    CHECK(hv_vcpu_set_reg(c->id,HV_REG_X2,0));
    CHECK(hv_vcpu_set_reg(c->id,HV_REG_X3,0));
    pthread_mutex_lock(&state_lock);
    if(options->restore && cpu_snapshot(c,1)){fprintf(stderr,"CPU snapshot restore failed\n");exit(2);}
    c->ready=1;pthread_cond_broadcast(&state_change);
    pthread_mutex_unlock(&state_lock);
    cpu_checkpoint(c);
    if(!options->restore){CHECK(hv_vcpu_set_reg(c->id,HV_REG_PC,c->entry));CHECK(hv_vcpu_set_reg(c->id,HV_REG_X0,c->context));}
    unsigned long exits=0;
    while(atomic_load(&result)<0) {
        cpu_checkpoint(c);
        if(atomic_load(&result)>=0)break;
        exits++;
        CHECK(hv_vcpu_run(c->id));
        atomic_fetch_add_explicit(&cpu_exits[c->index],1,memory_order_relaxed);
        if(ex->reason==HV_EXIT_REASON_CANCELED)continue;
        pthread_mutex_lock(&io_lock);
        uint64_t pc;
        CHECK(hv_vcpu_get_reg(c->id,HV_REG_PC,&pc));
        uint64_t esr=ex->exception.syndrome;
        unsigned ec=(unsigned)(esr>>26);
        if(options->trace)fprintf(stderr,"cpu=%u exit=%lu ec=%x pc=%llx ipa=%llx esr=%llx\n",c->index,exits,ec,pc,ex->exception.physical_address,esr);
        if(ex->reason==HV_EXIT_REASON_EXCEPTION && ec==0x24 && (esr&(1ULL<<24))) {
            unsigned reg=(esr>>16)&31,size=1U<<((esr>>22)&3);
            int write=(esr>>6)&1;
            uint64_t value=0;
            if(!write && (esr&(1ULL<<21)))goto unsupported;
            if(write && reg!=31)CHECK(hv_vcpu_get_reg(c->id,(hv_reg_t)(HV_REG_X0+reg),&value));
            if(!mmio(ex->exception.physical_address,size,write,&value))goto unsupported;
            if(size<8)value&=(1ULL<<(size*8))-1;
            if(!write && reg!=31)CHECK(hv_vcpu_set_reg(c->id,(hv_reg_t)(HV_REG_X0+reg),value));
            CHECK(hv_vcpu_set_reg(c->id,HV_REG_PC,pc+4));
            if(devices_exit_status()>=0)finish(devices_exit_status());
        } else if(ex->reason==HV_EXIT_REASON_EXCEPTION && ec==0x18) {
            unsigned rt=(esr>>5)&31,read=esr&1;
            unsigned op0=(esr>>20)&3,op1=(esr>>14)&7,crn=(esr>>10)&15,crm=(esr>>1)&15,op2=(esr>>17)&7;
            uint64_t value=0;
            if(!read && rt!=31)CHECK(hv_vcpu_get_reg(c->id,(hv_reg_t)(HV_REG_X0+rt),&value));
            if(op0==2 && op1==0 && crn==1 && op2==4 && (crm==0||crm==1||crm==3)){
                if(crm==0){if(read)goto unsupported;c->os_lock=value&1;}
                else if(crm==1){if(!read)goto unsupported;value=8|(c->os_lock<<1);}
                else {if(read)value=c->os_double_lock;else c->os_double_lock=value&1;}
            }else {
                hv_sys_reg_t sys=(hv_sys_reg_t)((op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2);
                hv_return_t r=read?hv_vcpu_get_sys_reg(c->id,sys,&value):hv_vcpu_set_sys_reg(c->id,sys,value);
                if(r!=HV_SUCCESS)goto unsupported;
            }
            if(read && rt!=31)CHECK(hv_vcpu_set_reg(c->id,(hv_reg_t)(HV_REG_X0+rt),value));
            CHECK(hv_vcpu_set_reg(c->id,HV_REG_PC,pc+4));
        } else if(ex->reason==HV_EXIT_REASON_EXCEPTION && ec==0x16) {
            uint64_t call,ret=(uint64_t)-1;
            CHECK(hv_vcpu_get_reg(c->id,HV_REG_X0,&call));
            if(call==0x84000008) {fprintf(stderr,"HVF: PSCI SYSTEM_OFF\n");finish(0);}
            else if(call==0x84000009) {fprintf(stderr,"HVF: PSCI SYSTEM_RESET requested\n");finish(3);}
            else if(call==0x84000000)ret=0x00000002; // PSCI 0.2
            else if(call==0xc4000003 || call==0x84000003) {
                uint64_t target,entry,context;
                CHECK(hv_vcpu_get_reg(c->id,HV_REG_X1,&target));
                CHECK(hv_vcpu_get_reg(c->id,HV_REG_X2,&entry));
                CHECK(hv_vcpu_get_reg(c->id,HV_REG_X3,&context));
                fprintf(stderr,"CPU_ON target=%llx entry=%llx context=%llx\n",target,entry,context);
                ret=(uint64_t)-2;
                if(target<ncpus && entry>=RAM_BASE && entry<RAM_BASE+ram_size && !(entry&3)) {
                    pthread_mutex_lock(&state_lock);
                    struct cpu *other=&cpus[target];
                    if(other->started)ret=(uint64_t)-4;
                    else {other->entry=entry;other->context=context;other->started=1;ret=0;pthread_cond_broadcast(&state_change);}
                    pthread_mutex_unlock(&state_lock);
                }
            }
            CHECK(hv_vcpu_set_reg(c->id,HV_REG_X0,ret));
        } else {
unsupported:
            fprintf(stderr,"unsupported exit: cpu=%u reason=%u ec=%x esr=%llx pc=%llx ipa=%llx\n",c->index,ex->reason,ec,esr,pc,ex->exception.physical_address);
            uint64_t fault_esr,fault_elr;
            CHECK(hv_vcpu_get_sys_reg(c->id,HV_SYS_REG_ESR_EL1,&fault_esr));
            CHECK(hv_vcpu_get_sys_reg(c->id,HV_SYS_REG_ELR_EL1,&fault_elr));
            fprintf(stderr,"guest exception: ESR_EL1=%llx ELR_EL1=%llx\n",fault_esr,fault_elr);
            finish(2);
        }
        pthread_mutex_unlock(&io_lock);
    }
    if(atomic_load(&result)<0)finish(2);
    // Every vCPU must stop before the GIC topology is dismantled.
    pthread_mutex_lock(&state_lock);
    stopped++;pthread_cond_broadcast(&state_change);
    while(stopped<ncpus || !teardown_released)pthread_cond_wait(&state_change,&state_lock);
    pthread_mutex_unlock(&state_lock);
    CHECK(hv_vcpu_destroy(c->id));
    return NULL;
}

static int snapshot_state(int restore,uint64_t frozen_ticks){
    struct snapshot_io s={.fd=snapshot_open("devices.bin",restore),.restore=restore};if(s.fd<0)return -1;
    snapshot_magic(&s,"HVFDEV01");
    uint32_t memory=options->memory_mib,count=ncpus;
    SNAP(&s,memory);SNAP(&s,count);if(memory!=options->memory_mib||count!=ncpus)s.error=1;
    uint64_t virtual_ticks=frozen_ticks-clock_offset,physical_ticks=frozen_ticks;
    uint64_t rtc=(uint64_t)time(NULL)-clock_offset_ns/1000000000;
    SNAP(&s,virtual_ticks);SNAP(&s,physical_ticks);SNAP(&s,rtc);
    if(restore){
        restore_started=mach_absolute_time();clock_offset=restore_started-virtual_ticks;
        restore_physical_delta=restore_started-physical_ticks;
        clock_offset_ns=((uint64_t)time(NULL)-rtc)*1000000000;
    }
    for(unsigned i=0;i<19;i++)SNAP(&s,uart[i]);
    devices_snapshot(&s);input_snapshot(&s);net_snapshot(&s);
    int failed=snapshot_end(&s);close(s.fd);return failed;
}
static int snapshot_gic(int restore){
    int fd=snapshot_open("gic.bin",restore);if(fd<0)return -1;
    hv_gic_state_t state=NULL;size_t size=0;struct stat st;
    if(restore){if(fstat(fd,&st)||st.st_size<=0||st.st_size>(64LL<<20)){close(fd);return -1;}size=(size_t)st.st_size;}
    else {state=hv_gic_state_create();if(!state||hv_gic_state_get_size(state,&size)||!size||size>(64ULL<<20)){if(state)os_release(state);close(fd);return -1;}}
    void *data=malloc(size);if(!data){if(state)os_release(state);close(fd);return -1;}
    struct snapshot_io io={.fd=fd,.restore=restore};
    if(!restore && hv_gic_state_get_data(state,data))io.error=1;
    snapshot_bytes(&io,data,size);
    if(restore && !io.error && hv_gic_set_state(data,size))io.error=1;
    int failed=snapshot_end(&io);free(data);if(state)os_release(state);close(fd);return failed;
}
static int snapshot_save(void *ram,uint64_t frozen_ticks){
    struct rlimit limit;if(getrlimit(RLIMIT_FSIZE,&limit)||ram_size>limit.rlim_cur)return -1;
    for(unsigned i=0;i<options->drive_count;i++){struct stat st;if(fstat(options->drives[i].fd,&st)||(uint64_t)st.st_size>limit.rlim_cur)return -1;}
    if(snapshot_state(0,frozen_ticks)||snapshot_gic(0))return -1;
    int fd=snapshot_open("ram.bin",0);if(fd<0)return -1;
    struct snapshot_io io={.fd=fd};
    for(size_t offset=0;offset<ram_size&&!io.error;offset+=131072){size_t size=ram_size-offset;if(size>131072)size=131072;snapshot_bytes(&io,(uint8_t*)ram+offset,size);}
    int failed=snapshot_end(&io);close(fd);if(failed)return -1;
    uint8_t buffer[131072];
    for(unsigned i=0;i<options->drive_count;i++){
        struct stat st;int source=options->drives[i].fd;
        if(fstat(source,&st)||st.st_size<512||st.st_size>(1LL<<40)||fsync(source))return -1;
        char name[32];snprintf(name,sizeof(name),"disk-%u.bin",i);fd=snapshot_open(name,0);if(fd<0)return -1;
        io=(struct snapshot_io){.fd=fd};
        for(off_t offset=0;offset<st.st_size&&!io.error;){
            size_t size=(uint64_t)(st.st_size-offset)>sizeof(buffer)?sizeof(buffer):(size_t)(st.st_size-offset);
            ssize_t n=pread(source,buffer,size,offset);if(n<0&&errno==EINTR)continue;
            if(n<=0){io.error=1;break;}snapshot_bytes(&io,buffer,(size_t)n);offset+=n;
        }
        failed=snapshot_end(&io);close(fd);if(failed)return -1;
    }
    return 0;
}
int hvf_run(const char *ram_path,uint64_t entry,const char *disk,const struct hvf_options *settings) {
    struct sigaction action={0};action.sa_handler=stop_signal;sigemptyset(&action.sa_mask);
    sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);
    options=settings;
    if(options->snapshot_dir){snapshot_dirfd=open(options->snapshot_dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(snapshot_dirfd<0)return 1;}
    if(options->restore)pause_requested=1;
    ncpus=options->cpus;
    if(options->memory_mib<64||options->memory_mib>2048)return 1;
    ram_size=(size_t)options->memory_mib<<20;
    if(ncpus<1 || ncpus>MAX_CPUS || entry<RAM_BASE || entry>=RAM_BASE+ram_size || (entry&3))return 1;
    int fd=options->restore?snapshot_open("ram.bin",1):open(ram_path,O_RDONLY);struct stat st;
    if(fd<0||fstat(fd,&st)||st.st_size<=0 || (uint64_t)st.st_size>ram_size){fprintf(stderr,"RAM image length does not match configured memory\n");if(fd>=0)close(fd);return 1;}
    void *ram=mmap(NULL,ram_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(ram==MAP_FAILED){perror("mmap");close(fd);return 1;}
    size_t loaded=0;
    while(loaded<(size_t)st.st_size){
        ssize_t n=pread(fd,(uint8_t*)ram+loaded,(size_t)st.st_size-loaded,loaded);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){perror("read RAM image");close(fd);munmap(ram,ram_size);return 1;}
        loaded+=n;
    }
    close(fd);
    input_init(ram,ram_size,options->power_button);
    if(devices_init(ram,ram_size,disk,options)){perror("disk");devices_close();munmap(ram,ram_size);return 1;}
    if(net_init(ram,ram_size,options)){fprintf(stderr,"network setup failed\n");net_close();devices_close();munmap(ram,ram_size);return 1;}
    CHECK(hv_vm_create(NULL));
    CHECK(hv_vm_map(ram,RAM_BASE,ram_size,HV_MEMORY_READ|HV_MEMORY_WRITE|HV_MEMORY_EXEC));
    hv_gic_config_t gic=hv_gic_config_create();
    CHECK(hv_gic_config_set_distributor_base(gic,0x08000000));
    CHECK(hv_gic_config_set_redistributor_base(gic,0x080a0000));
    CHECK(hv_gic_config_set_msi_region_base(gic,0x08020000));
    CHECK(hv_gic_config_set_msi_interrupt_range(gic,64,64));
    CHECK(hv_gic_create(gic));os_release(gic);
    if(options->security && !options->security->development && hvf_sandbox_install(options->security->vmm_profile)){
        net_close();devices_close();return 1;
    }
    if(options->restore && snapshot_state(1,0)){fprintf(stderr,"device snapshot restore failed\n");return 2;}
    fprintf(stderr,"HVF: %u vCPU, %u MiB, entry=0x%llx\n",ncpus,options->memory_mib,entry);
    for(unsigned i=0;i<ncpus;i++) {
        cpus[i].index=i;
        if(pthread_create(&cpus[i].thread,NULL,cpu_main,&cpus[i])){fprintf(stderr,"vCPU thread creation failed\n");exit(1);}
        pthread_mutex_lock(&state_lock);
        while(!cpus[i].ready)pthread_cond_wait(&state_change,&state_lock);
        pthread_mutex_unlock(&state_lock);
    }
    pthread_mutex_lock(&state_lock);
    for(unsigned i=0;i<ncpus;i++)while(!cpus[i].ready)pthread_cond_wait(&state_change,&state_lock);
    if(options->restore){
        uint64_t operation=strtoull(getenv("HVF_OPERATION_ID")?getenv("HVF_OPERATION_ID"):"0",NULL,10);
        net_backend_pause(1,operation);double until=seconds()+3;
        while(!net_backend_pause_ready(operation)){if(seconds()>until){fprintf(stderr,"restore broker pause failed\n");exit(2);}usleep(1000);}
    }
    if(options->restore && snapshot_gic(1)){fprintf(stderr,"GIC snapshot restore failed\n");exit(2);}
    if(!options->restore){cpus[0].entry=entry;cpus[0].context=RAM_BASE;cpus[0].started=1;}
    if(options->ready_fd>=0){if(control_send(options->ready_fd,options->restore?'P':'R',strtoull(getenv("HVF_OPERATION_ID") ? getenv("HVF_OPERATION_ID") : "0",NULL,10))){fprintf(stderr,"startup supervisor disconnected\n");exit(1);}}
    pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
    double deadline=seconds()+options->timeout_ms/1000.0;
    int metrics_fd=-1;
    const char *metrics_env=getenv("HVF_METRICS_FD");
    if(metrics_env)metrics_fd=atoi(metrics_env);
    double next_metrics=0;uint64_t dropped_metrics=0;
    int power_pending=0;
    uint64_t power_operation=0;
    struct control_reader control={0};
    // 0 running, 1 park CPUs/drain devices, 2 pause broker/drain RX, 3 paused,
    // 4 resume broker, 5 release CPUs. Supervisor remains independently responsive.
    unsigned phase=options->restore?3:0;
    uint64_t transition=0, paused_ticks=options->restore?restore_started:0;
    double transition_deadline=0;
    while(atomic_load(&result)<0) {
        if(stop_requested)finish(128+stop_requested);
        if(options->ready_fd>=0){
            uint8_t kind;uint64_t operation;
            int n=control_receive(options->ready_fd,&control,&kind,&operation);
            if(n==1){
                if(kind=='S' && phase==0 && operation>power_operation){power_pending=1;power_operation=operation;}
                else if(kind=='X' && operation==power_operation)power_pending=0;
                else if(kind=='P' && phase==0 && operation>transition && !power_pending){
                    transition=operation;phase=1;transition_deadline=seconds()+300;
                    pthread_mutex_lock(&state_lock);pause_requested=1;
                    pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
                }
                else if(kind=='C' && phase==3 && operation>transition){
                    transition=operation;phase=6;transition_deadline=seconds()+300;
                    pthread_mutex_lock(&state_lock);capture_operation=operation;captured_cpus=0;capture_error=0;
                    pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
                }
                else if(kind=='U' && phase==3 && operation>transition){
                    transition=operation;phase=4;transition_deadline=seconds()+5;
                    net_backend_pause(0,transition);
                }
                else finish(2);
            }
            if(n<0){fprintf(stderr,"HVF: invalid or disconnected supervisor control\n");finish(143);}
        }
        if(phase==1)kick_cpus(); // Repeat: a CPU can enter hv_vcpu_run after an earlier kick.
        pthread_mutex_lock(&io_lock);
        if(phase<3){devices_poll();net_poll();}else net_backend_health();
        if(phase==1 && parked_cpus()==(int)ncpus && !devices_pending() && !net_pending_tx()){
            paused_ticks=mach_absolute_time();
            net_backend_pause(1,transition);phase=2;
        }
        if(phase==2 && net_backend_pause_ready(transition) && !net_backend_pending_rx()){
            phase=3;if(control_send(options->ready_fd,'P',transition))finish(143);
        }
        if(phase==4 && net_backend_pause_ready(transition)){
            uint64_t elapsed=mach_absolute_time()-paused_ticks;
            mach_timebase_info_data_t timebase;mach_timebase_info(&timebase);
            clock_offset_ns+=(uint64_t)((__uint128_t)elapsed*timebase.numer/timebase.denom);
            pthread_mutex_lock(&state_lock);clock_offset+=elapsed;resume_hold=1;pause_requested=0;
            pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
            phase=5;
        }
        if(phase==6){
            pthread_mutex_lock(&state_lock);int ready=captured_cpus==ncpus;int failed=capture_error;pthread_mutex_unlock(&state_lock);
            if(ready){if(!failed)failed=snapshot_save(ram,paused_ticks);phase=3;
                if(control_send(options->ready_fd,failed?'E':'C',transition))finish(143);
            }
        }
        if(phase==5 && parked_cpus()==0){
            pthread_mutex_lock(&state_lock);resume_hold=0;pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
            phase=0;if(control_send(options->ready_fd,'U',transition))finish(143);
        }
        if(phase && phase!=3 && seconds()>transition_deadline){fprintf(stderr,"HVF: pause/resume barrier deadline\n");finish(124);}
        if(power_pending && input_power_button()){power_pending=0;if(control_send(options->ready_fd,'A',power_operation))finish(143);}
        if(metrics_fd>=0 && seconds()>=next_metrics){
            uint64_t values[26];
            for(unsigned i=0;i<4;i++)values[i]=atomic_load_explicit(&cpu_exits[i],memory_order_relaxed);
            devices_metrics(values+4);net_metrics(values+8);values[14]=(uint64_t)net_backend_pid();
            values[15]=devices_queue_depth();net_queue_depths(values+16);net_backend_metrics(values+18);values[25]=dropped_metrics;
            uint8_t packet[8+26*8]={'H','V','F','M',2,26,0,0};
            for(unsigned i=0;i<26;i++)for(unsigned j=0;j<8;j++)packet[8+i*8+j]=(uint8_t)(values[i]>>(8*j));
            // Datagram telemetry is best-effort and cannot hold up guest/control progress.
            if(send(metrics_fd,packet,sizeof(packet),MSG_DONTWAIT)!=(ssize_t)sizeof(packet))dropped_metrics++;
            next_metrics=seconds()+0.1;
        }
        pthread_mutex_unlock(&io_lock);
        if(options->timeout_ms && seconds()>=deadline){fprintf(stderr,"HVF: watchdog deadline\n");finish(124);}
        usleep(1000);
    }
    pthread_mutex_lock(&state_lock);pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
    // A canceled exit wakes sleeping/running CPUs so all can join teardown.
    hv_vcpu_t ids[MAX_CPUS];for(unsigned i=0;i<ncpus;i++)ids[i]=cpus[i].id;
    CHECK(hv_vcpus_exit(ids,ncpus));
    pthread_mutex_lock(&state_lock);teardown_released=1;pthread_cond_broadcast(&state_change);pthread_mutex_unlock(&state_lock);
    for(unsigned i=0;i<ncpus;i++)pthread_join(cpus[i].thread,NULL);
    CHECK(hv_vm_unmap(RAM_BASE,ram_size));CHECK(hv_vm_destroy());
    net_close();devices_close();munmap(ram,ram_size);
    if(metrics_fd>=0)close(metrics_fd);
    if(options->ready_fd>=0)close(options->ready_fd);
    return atomic_load(&result);
}

#ifdef HVF_STANDALONE
#include <sys/resource.h>
int main(int argc,char **argv) {
    if(argc!=3 && argc!=4)return 1;
    char *end;uint64_t entry=strtoull(argv[2],&end,16);if(*end)return 1;
    struct hvf_options settings={.cpus=1,.memory_mib=128,.timeout_ms=10000,.ready_fd=-1};
    if(getenv("HVF_CPUS")){settings.cpus=strtoul(getenv("HVF_CPUS"),&end,10);if(*end)return 1;}
    if(getenv("HVF_PROBE_CPU_LIMIT")){uint64_t value=strtoull(getenv("HVF_PROBE_CPU_LIMIT"),&end,10);if(*end||!value||value>31536000)return 1;struct rlimit limit={value,value};if(setrlimit(RLIMIT_CPU,&limit))return 1;}
    settings.trace=getenv("HVF_TRACE")!=NULL;
    return hvf_run(argv[1],entry,argc==4?argv[3]:NULL,&settings);
}
#endif
