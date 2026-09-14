#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real KVM block/network smoke. Run as root inside a private network namespace."""
import argparse,json,os,socket,subprocess,time,urllib.request
from pathlib import Path

def until(fn,seconds=30):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            value=fn()
            if value:return value
        except OSError:pass
        time.sleep(.05)
    raise RuntimeError('guest readiness timeout')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);a=p.parse_args()
    # Never modify the initial host network namespace.
    if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):p.error('run via sudo unshare --net')
    work=a.work.resolve();logs=work/'logs';logs.mkdir(exist_ok=True);tap='fcvalidation'
    subprocess.run(['ip','tuntap','add','dev',tap,'mode','tap'],check=True)
    results=[]
    try:
        subprocess.run(['ip','addr','add','192.0.2.1/30','dev',tap],check=True);subprocess.run(['ip','link','set',tap,'up'],check=True);subprocess.run(['ip','link','set','lo','up'],check=True)
        for cpus in [1,2]:
            disk=work/f'kvm-disk-{cpus}.raw'
            with disk.open('wb') as f:f.truncate(64<<20);f.write(b'HVF_GENERIC_BLOCK_V1')
            config={'boot-source':{'kernel_image_path':str(work/'vmlinux'),'initrd_path':str(work/'guest/initrd.gz'),'boot_args':'console=ttyS0 reboot=k panic=-1 pci=off rdinit=/init'},'machine-config':{'vcpu_count':cpus,'mem_size_mib':256},'drives':[{'drive_id':'disk0','path_on_host':str(disk),'is_root_device':False,'is_read_only':False}],'network-interfaces':[{'iface_id':'eth0','host_dev_name':tap,'guest_mac':'02:12:34:56:78:90'}]}
            cfg=work/f'kvm-{cpus}.json';cfg.write_text(json.dumps(config))
            for boot in [1,2]:
                logfile=logs/f'guest-{cpus}-{boot}.log'
                with logfile.open('wb') as log:
                    vm=subprocess.Popen([str(a.binary.resolve()),'--no-api','--config-file',str(cfg)],stdout=log,stderr=subprocess.STDOUT)
                    try:
                        def info():
                            if vm.poll() is not None:raise RuntimeError('VM exited: '+logfile.read_text()[-6000:])
                            with urllib.request.urlopen('http://192.0.2.2:9000/',timeout=.5) as r:return json.load(r)
                        data=until(info);assert data=={'arch':'x86_64','count':boot,'cpus':cpus},data
                        payload=bytes(range(256))*4096
                        for _ in range(4):
                            with urllib.request.urlopen(urllib.request.Request('http://192.0.2.2:9000/echo',data=payload),timeout=10) as r:assert r.read()==payload
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                            s.settimeout(2);s.sendto(b'kvm-udp',('192.0.2.2',9001));assert s.recv(256)==b'kvm-udp'
                        with urllib.request.urlopen('http://192.0.2.2:9000/exit',timeout=2) as r:assert r.read()==b'bye'
                        assert vm.wait(timeout=10)==0,logfile.read_text()[-6000:]
                        result={'cpus':cpus,'boot':boot,'disk_counter':data['count'],'tcp_bytes':4*len(payload),'udp':True,'guest_reset_exit_i8042':True};results.append(result);print(json.dumps(result),flush=True)
                    finally:
                        if vm.poll() is None:
                            vm.terminate()
                            try:vm.wait(timeout=3)
                            except subprocess.TimeoutExpired:vm.kill();vm.wait(timeout=3)
    finally:subprocess.run(['ip','link','delete',tap],check=True)
    (logs/'smoke-result.json').write_text(json.dumps(results,indent=2)+'\n')
if __name__=='__main__':main()
