#!/usr/bin/env python3
"""Build a minimal Debian ARM64 guest from locked official kernel/BusyBox packages."""
import argparse,gzip,hashlib,json,lzma,os,shutil,stat,struct,subprocess,sys,tempfile,urllib.request,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
LINUX=HERE.parent/'linux'
sys.path.insert(0,str(LINUX))
import guest_tools
def run(*args,**kwargs):subprocess.run([str(a) for a in args],check=True,**kwargs)
def decompress(path):
    data=path.read_bytes()
    if path.suffix=='.xz':return lzma.decompress(data)
    if path.suffix=='.gz':return gzip.decompress(data)
    if path.suffix=='.zst':raise RuntimeError('unexpected zstd module; lock/build tool must be updated explicitly')
    return data
def module_dependencies(data):
    if data[:6]!=b'\x7fELF\x02\x01':raise RuntimeError('unsupported module ELF')
    offset=struct.unpack_from('<Q',data,40)[0];width,count,index=struct.unpack_from('<HHH',data,58)
    if width!=64 or offset+width*count>len(data) or index>=count:raise RuntimeError('invalid module section table')
    start,size=struct.unpack_from('<QQ',data,offset+index*width+24);strings=data[start:start+size]
    for i in range(count):
        name=struct.unpack_from('<I',data,offset+i*width)[0]
        if strings[name:].split(b'\0',1)[0]==b'.modinfo':
            start,size=struct.unpack_from('<QQ',data,offset+i*width+24)
            for field in data[start:start+size].split(b'\0'):
                if field.startswith(b'depends='):return [v for v in field[8:].decode().split(',') if v]
    return []
def archive(tree):
    names=['.']
    for base,dirs,files in os.walk(tree):
        dirs.sort()
        names.extend(str((Path(base)/n).relative_to(tree)) for n in sorted(dirs+files))
    output=bytearray()
    for inode,name in enumerate(names+['TRAILER!!!'],1):
        if name=='TRAILER!!!':mode=0;data=b''
        else:
            path=tree/name;mode=path.lstat().st_mode
            if stat.S_ISLNK(mode):data=os.readlink(path).encode()
            elif stat.S_ISREG(mode):data=path.read_bytes()
            elif stat.S_ISDIR(mode):data=b''
            else:raise RuntimeError('unsupported initrd entry '+name)
        encoded=name.encode()+b'\0';fields=[inode,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
        output.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded)
        output.extend(bytes((-len(output))%4));output.extend(data);output.extend(bytes((-len(output))%4))
    return gzip.compress(output,mtime=0)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'build/debian-guest')
    parser.add_argument('--go',type=Path,default=None)
    args=parser.parse_args();args.go=guest_tools.compiler(args.go);extractor=guest_tools.extractor('bsdtar');work=args.output.resolve();work.mkdir(parents=True,exist_ok=True)
    assets=json.loads((HERE/'assets.json').read_text())
    for name,asset in assets.items():
        path=work/name
        if not path.exists():
            temporary=path.with_suffix('.partial')
            with urllib.request.urlopen(asset['url'],timeout=60) as response,temporary.open('wb') as out:
                while chunk:=response.read(131072):out.write(chunk)
            temporary.replace(path)
        if path.stat().st_size!=asset['size'] or hashlib.sha256(path.read_bytes()).hexdigest()!=asset['sha256']:raise RuntimeError('Debian asset checksum mismatch: '+name)
    with tempfile.TemporaryDirectory(prefix='debian-extract-',dir=work) as temporary:
        stage=Path(temporary);packages=stage/'packages';packages.mkdir()
        for name in assets:
            unpack=stage/name;unpack.mkdir();run(extractor,'-xf',work/name,'-C',unpack)
            payload=next(unpack.glob('data.tar.*'));run(extractor,'-xf',payload,'-C',packages)
        kernel=next((packages/'boot').glob('vmlinuz-*')).read_bytes()
        if kernel[4:8]==b'zimg':
            offset,length=struct.unpack_from('<II',kernel,8)
            if kernel[24:28]!=b'gzip':raise RuntimeError('unexpected zboot compression')
            kernel=zlib.decompress(kernel[offset:offset+length],31)
        elif kernel[:2]==b'\x1f\x8b':kernel=gzip.decompress(kernel)
        if kernel[56:60]!=b'ARM\x64':raise RuntimeError('Debian kernel is not an ARM64 Image')
        (work/'Image').write_bytes(kernel)
        tree=stage/'root';tree.mkdir()
        for directory in ['bin','dev','proc','sys','etc','lib/modules']:(tree/directory).mkdir(parents=True,exist_ok=True)
        busybox=next(p for p in packages.rglob('busybox') if p.is_file());shutil.copyfile(busybox,tree/'bin/busybox');(tree/'bin/busybox').chmod(0o755)
        (tree/'bin/sh').symlink_to('busybox')
        module_root=next(p for p in packages.rglob('modules') if p.is_dir())
        version=next(p for p in module_root.iterdir() if p.is_dir());target=tree/'lib/modules'/version.name;target.mkdir()
        index={p.name.split('.')[0]:p for p in version.rglob('*.ko*')}
        selected={}
        def select(name):
            if name in selected or name not in index:return
            data=decompress(index[name]);selected[name]=(data,module_dependencies(data))
            for dependency in selected[name][1]:select(dependency)
        for name in ['virtio','virtio_ring','virtio_pci','virtio_pci_legacy_dev','virtio_pci_modern_dev','virtio_blk','virtio_net','virtio_mmio','virtio_input','evdev']:select(name)
        for name,(data,dependencies) in selected.items():(target/(name+'.ko')).write_bytes(data)
        def dependencies(name,seen=None):
            seen=set() if seen is None else seen;result=[]
            for dependency in selected[name][1]:
                if dependency in selected and dependency not in seen:
                    seen.add(dependency);result.append(dependency);result.extend(dependencies(dependency,seen))
            return result
        # modules.dep records the transitive closure in load order, as depmod does.
        (target/'modules.dep').write_text(''.join(name+'.ko: '+' '.join(d+'.ko' for d in dependencies(name))+'\n' for name in sorted(selected)))
        for name in ['modules.builtin','modules.builtin.modinfo']:
            if (version/name).exists():shutil.copyfile(version/name,target/name)
        if 'evdev' in selected:(tree/'evdev.ko').write_bytes(selected['evdev'][0])
        else:(tree/'evdev.ko').write_bytes(b'')
        shutil.copyfile(LINUX/'init',tree/'init');(tree/'init').chmod(0o755)
        (tree/'etc/os-release').write_text('ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n')
        for copyright in packages.glob('usr/share/doc/*/copyright'):
            target_notice=tree/copyright.relative_to(packages);target_notice.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(copyright,target_notice)
        tool=json.loads((LINUX/'tools.json').read_text())['go']['version']
        environment={**os.environ,'GOTOOLCHAIN':'local','GOOS':'linux','GOARCH':'arm64','GOARM64':'v8.0','CGO_ENABLED':'0'}
        if subprocess.check_output([args.go,'version'],env=environment,text=True).split()[2]!=tool:raise RuntimeError('Go toolchain differs from lock')
        run(args.go,'build','-trimpath','-buildvcs=false','-o',tree/'vmm-test',LINUX/'main.go',env=environment)
        (work/'test-initrd.gz').write_bytes(archive(tree))
    disk=work/'disk.raw'
    if not disk.exists():
        with disk.open('wb') as out:out.truncate(64<<20);out.write(b'HVF_GENERIC_BLOCK_V1')
    config={'boot-source':{'kernel_image_path':str(work/'Image'),'boot_protocol':'linux-image','initrd_path':str(work/'test-initrd.gz'),'boot_args':'console=ttyAMA0 rdinit=/init panic=-1'},'machine-config':{'vcpu_count':4,'mem_size_mib':256,'power_button':True},'drives':[{'drive_id':'disk0','path_on_host':str(disk)}],'network-interfaces':[{'iface_id':'eth0','guest_mac':'02:12:34:56:78:90','backend':'slirp','forwards':[{'protocol':'tcp','host_addr':'127.0.0.1','host_port':19000,'guest_addr':'10.0.2.15','guest_port':9000},{'protocol':'udp','host_addr':'127.0.0.1','host_port':19001,'guest_addr':'10.0.2.15','guest_port':9001}]}],'security':{'version':1,'listeners':[{'protocol':'tcp','address':'127.0.0.1','port':19000},{'protocol':'udp','address':'127.0.0.1','port':19001}]}}
    guest_tools.provenance(work,args.go,{'bsdtar':extractor})
    (work/'config.json').write_text(json.dumps(config,indent=2)+'\n');print(work/'config.json')
if __name__=='__main__':main()
