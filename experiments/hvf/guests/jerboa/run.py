#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional adapter for an externally prepared Jerboa ELF and block image."""
import argparse,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel',type=Path,required=True)
p.add_argument('--disk',type=Path,required=True)
p.add_argument('--binary',type=Path,default=ROOT/'build/macos-arm64/firecracker')
p.add_argument('--cpus',type=int,default=1)
p.add_argument('--port',type=int)
p.add_argument('--env',action='append',default=[])
p.add_argument('--persistent',action='store_true')
a=p.parse_args()
for value in a.env:
    if '=' not in value or '\n' in value or '\0' in value:p.error('expected KEY=VALUE')
with tempfile.TemporaryDirectory(prefix='jerboa-guest-config-') as td:
    work=Path(td);env=work/'env';env.write_text(''.join(s+'\n' for s in a.env))
    c={'boot-source':{'kernel_image_path':str(a.kernel.resolve()),'boot_protocol':'elf'},'machine-config':{'vcpu_count':a.cpus,'mem_size_mib':128},'drives':[{'drive_id':'root','path_on_host':str(a.disk.resolve()),'is_root_device':True,'copy_on_start':not a.persistent}],'firmware':{'opt/uni/env':str(env)}}
    if a.port:
        c['network-interfaces']=[{'iface_id':'net0','guest_mac':'52:54:00:12:34:56','backend':'slirp','forwards':[{'protocol':proto,'host_addr':'127.0.0.1','host_port':a.port,'guest_addr':'10.0.2.15','guest_port':port} for proto,port in [('tcp',8080),('udp',8081)]]}]
    path=work/'config.json';path.write_text(json.dumps(c))
    raise SystemExit(subprocess.call([str(a.binary.resolve()),'--no-api','--config-file',str(path)]))
