#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Report backend availability separately from test success; unavailable exits 77."""
import argparse,fcntl,json,os,platform,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('backend',choices=['hvf','kvm']);a=p.parse_args()
result={'backend':a.backend,'system':platform.system(),'machine':platform.machine(),'available':False,'tests_passed':False}
try:
    if a.backend=='hvf':
        if platform.system()!='Darwin' or platform.machine()!='arm64' or platform.mac_ver()[0].split('.')[0]!='26':raise RuntimeError('requires macOS 26 ARM64')
        if subprocess.check_output(['sysctl','-n','kern.hv_support'],text=True).strip()!='1':raise RuntimeError('Hypervisor capability unavailable')
        result['probe']='kern.hv_support; actual entitled VM creation is tested by test-native.sh'
    else:
        if platform.system()!='Linux' or platform.machine()!='x86_64':raise RuntimeError('requires Linux x86_64 KVM')
        fd=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC)
        try:
            version=fcntl.ioctl(fd,0xAE00,0)
            if version!=12:raise RuntimeError(f'unsupported KVM API {version}')
            vm=fcntl.ioctl(fd,0xAE01,0);os.close(vm)
        finally:os.close(fd)
        result['probe']='KVM API 12 and successful empty VM creation'
    result['available']=True
except (OSError,RuntimeError,subprocess.SubprocessError) as error:result['reason']=str(error)
print(json.dumps(result,indent=2));raise SystemExit(0 if result['available'] else 77)
