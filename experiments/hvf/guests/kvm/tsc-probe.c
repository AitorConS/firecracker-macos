// SPDX-License-Identifier: Apache-2.0
// Independent ioctl evidence: no Firecracker code or altered KVM configuration.
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(void) {
    int kvm=open("/dev/kvm",O_RDWR|O_CLOEXEC);
    if(kvm<0){perror("/dev/kvm");return 1;}
    int vm=ioctl(kvm,KVM_CREATE_VM,0),cpu=vm<0?-1:ioctl(vm,KVM_CREATE_VCPU,0);
    if(cpu<0){perror("create vCPU");return 1;}
    int khz=ioctl(cpu,KVM_GET_TSC_KHZ,0);
    if(khz<=0){perror("GET_TSC_KHZ");return 1;}
    printf("tsc_control=%d get_tsc_khz=%d initial_khz=%d\n",ioctl(kvm,KVM_CHECK_EXTENSION,KVM_CAP_TSC_CONTROL),ioctl(kvm,KVM_CHECK_EXTENSION,KVM_CAP_GET_TSC_KHZ),khz);
    unsigned rates[]={(unsigned)khz+(unsigned)khz*250/1000000*2,(unsigned)khz/2};
    for(unsigned i=0;i<2;i++){
        errno=0;int result=ioctl(cpu,KVM_SET_TSC_KHZ,rates[i]),error=errno;
        printf("requested_khz=%u set_result=%d errno=%d actual_khz=%d\n",rates[i],result,error,ioctl(cpu,KVM_GET_TSC_KHZ,0));
    }
    close(cpu);close(vm);close(kvm);return 0;
}
