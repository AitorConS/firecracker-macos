#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a generic Linux test guest from pinned Alpine netboot assets and Go."""
import argparse,gzip,hashlib,json,os,shutil,stat,struct,subprocess,tempfile,urllib.request,zlib
from pathlib import Path
import guest_tools
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
def prepare(work,go):
    go=guest_tools.compiler(go);extractors={name:guest_tools.extractor(name) for name in ['bsdtar','unsquashfs']}
    work.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((HERE/'assets.json').read_text())
    for name,asset in manifest.items():
        path=work/name
        if not path.exists():
            with urllib.request.urlopen(asset['url'],timeout=60) as response:
                data=response.read(32*1024*1024+1)
            if hashlib.sha256(data).hexdigest()!=asset['sha256']:raise RuntimeError('asset checksum mismatch: '+name)
            path.write_bytes(data)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=asset['sha256']:raise RuntimeError('cached asset checksum mismatch: '+name)
    image=(work/'vmlinuz-virt').read_bytes()
    # Linux EFI zboot header: payload offset/length and compression at fixed offsets.
    if image[4:8]!=b'zimg' or image[24:28]!=b'gzip':raise RuntimeError('unsupported EFI zboot container')
    offset,length=struct.unpack_from('<II',image,8)
    if offset+length>len(image):raise RuntimeError('truncated zboot payload')
    kernel=zlib.decompress(image[offset:offset+length],31)
    if kernel[56:60]!=b'ARM\x64':raise RuntimeError('payload is not Linux Image')
    (work/'Image').write_bytes(kernel)
    with tempfile.TemporaryDirectory(prefix='linux-root-',dir=work) as td:
        tree=Path(td)
        subprocess.run([extractors['bsdtar'],'-xf',str(work/'initramfs-virt'),'-C',str(tree)],check=True)
        modules=tree/'extra-modules'
        subprocess.run([extractors['unsquashfs'],'-no-progress','-d',str(modules),str(work/'modloop-virt'),'modules/*/kernel/drivers/input/evdev.ko'],check=True,stdout=subprocess.DEVNULL)
        evdev=next(modules.rglob('evdev.ko'));shutil.copyfile(evdev,tree/'evdev.ko');shutil.rmtree(modules)
        subprocess.run([go,'build' ,'-trimpath','-buildvcs=false','-o',str(tree/'vmm-test'),str(HERE/'main.go')],env={**os.environ,'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'0','GOTOOLCHAIN':'local','GOARM64':'v8.0'},check=True)
        shutil.copyfile(HERE/'init',tree/'init');(tree/'init').chmod(0o755)
        names=['.']
        for base,dirs,files in os.walk(tree):
            dirs.sort()
            for name in sorted(dirs+files):names.append(str((Path(base)/name).relative_to(tree)))
        # Deterministic newc: normalized ownership, timestamps, inode numbering.
        archive=bytearray()
        for ino,name in enumerate(names+['TRAILER!!!'],1):
            if name=='TRAILER!!!':mode=0;data=b''
            else:
                path=tree/name;mode=path.lstat().st_mode
                if stat.S_ISLNK(mode):data=os.readlink(path).encode()
                elif stat.S_ISREG(mode):data=path.read_bytes()
                elif stat.S_ISDIR(mode):data=b''
                else:raise RuntimeError('unsupported archive entry '+name)
            encoded=name.encode()+b'\0'
            fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
            archive.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded)
            archive.extend(bytes((-len(archive))%4));archive.extend(data);archive.extend(bytes((-len(archive))%4))
        (work/'test-initrd.gz').write_bytes(gzip.compress(archive,mtime=0))
    disk=work/'disk.raw'
    if not disk.exists():
        with disk.open('wb') as f:f.truncate(64<<20);f.write(b'HVF_GENERIC_BLOCK_V1')
    config={'boot-source':{'kernel_image_path':str(work/'Image'),'boot_protocol':'linux-image','initrd_path':str(work/'test-initrd.gz'),'boot_args':'console=ttyAMA0 rdinit=/init panic=-1'},'machine-config':{'vcpu_count':4,'mem_size_mib':256,'power_button':True},'drives':[{'drive_id':'disk0','path_on_host':str(disk)}],'network-interfaces':[{'iface_id':'eth0','guest_mac':'02:12:34:56:78:90','backend':'slirp','forwards':[{'protocol':'tcp','host_addr':'127.0.0.1','host_port':19000,'guest_addr':'10.0.2.15','guest_port':9000},{'protocol':'udp','host_addr':'127.0.0.1','host_port':19001,'guest_addr':'10.0.2.15','guest_port':9001}]}]}
    config['security']={'version':1,'listeners':[{'protocol':f['protocol'],'address':f['host_addr'],'port':f['host_port']} for f in config['network-interfaces'][0]['forwards']]}
    (work/'config.json').write_text(json.dumps(config,indent=2)+'\n')
    guest_tools.provenance(work,go,extractors)
    return config
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'build/linux-guest')
    parser.add_argument('--go',default=os.environ.get('GO'))
    args=parser.parse_args();prepare(args.output.resolve(),args.go)
    print(args.output.resolve()/'config.json')
