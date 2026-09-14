#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an x86_64 Linux smoke initrd; requires static busybox and GCC on Linux."""
import argparse,gzip,hashlib,json,platform,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);p.add_argument('--busybox',default='/usr/bin/busybox');args=p.parse_args()
    if platform.system()!='Linux' or platform.machine()!='x86_64':p.error('requires Linux x86_64')
    work=args.output.resolve();work.mkdir(parents=True,exist_ok=True)
    # Fail instead of silently packaging a dynamically linked executable without its loader.
    assert 'INTERP' not in subprocess.check_output(['readelf','-l',args.busybox],text=True)
    subprocess.run(['gcc','-D_GNU_SOURCE','-static','-O2','-pthread','-Wall','-Wextra','-Werror',str(Path(__file__).with_name('main.c')),'-o',str(work/'vmm-test')],check=True)
    init=b'''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
ip link set lo up
ip link set eth0 up
ip addr add 192.0.2.2/30 dev eth0
exec /vmm-test
'''
    files={'.':(0o40755,b''),'bin':(0o40755,b''),'proc':(0o40755,b''),'sys':(0o40755,b''),'dev':(0o40755,b''),'bin/busybox':(0o100755,Path(args.busybox).read_bytes()),'init':(0o100755,init),'vmm-test':(0o100755,(work/'vmm-test').read_bytes()),'TRAILER!!!':(0,b'')}
    archive=bytearray()
    for ino,(name,(mode,data)) in enumerate(files.items(),1):
        encoded=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
        archive.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded);archive.extend(bytes(-len(archive)%4));archive.extend(data);archive.extend(bytes(-len(archive)%4))
    (work/'initrd.gz').write_bytes(gzip.compress(archive,mtime=0))
    (work/'guest-assets.json').write_text(json.dumps({name:hashlib.sha256((work/name).read_bytes()).hexdigest() for name in ['vmm-test','initrd.gz']},indent=2)+'\n')
if __name__=='__main__':main()
