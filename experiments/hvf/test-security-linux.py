#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guest-visible exact destination and explicit DNS policy regressions."""
import argparse,copy,gzip,http.server,json,socket,struct,subprocess,tempfile,threading
from pathlib import Path
from test_control import BINARY,ROOT
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,default=ROOT/'build/linux-guest/config.json');args=parser.parse_args()
base=json.loads(args.config.read_text())
requests=[];queries=[];stop=threading.Event()
class HTTP(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))));self.send_response(200);self.end_headers();self.wfile.write(b'outbound-ok')
    def log_message(self,format,*args):
        with (ROOT/'experiments/hvf/build/security-http.log').open('a') as log:log.write(repr((self.requestline,dict(self.headers),format%args))+'\n')
with tempfile.TemporaryDirectory(prefix='hvf-policy-') as work,http.server.HTTPServer(('127.0.0.1',0),HTTP) as server,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
    work=Path(work);disk=work/'disk'
    # Existing cached guests predate DNS tests. Add a deterministic initramfs
    # layer selecting the virtual resolver, without rebuilding the Go fixture.
    layer=bytearray()
    for ino,(name,mode,data) in enumerate([('etc',0o40755,b''),('etc/resolv.conf',0o100644,b'nameserver 10.0.2.3\noptions timeout:1 attempts:1\n'),('TRAILER!!!',0,b'')],1):
        encoded=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
        layer.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded);layer.extend(bytes(-len(layer)%4));layer.extend(data);layer.extend(bytes(-len(layer)%4))
    initrd=work/'dns-initrd.gz';initrd.write_bytes(Path(base['boot-source']['initrd_path']).read_bytes()+gzip.compress(layer,mtime=0))
    base['boot-source']['initrd_path']=str(initrd)
    with disk.open('wb') as f:f.truncate(64<<20);f.write(b'HVF_GENERIC_BLOCK_V1')
    dns.bind(('127.0.0.1',0));dns.settimeout(.2)
    def resolve():
        while not stop.is_set():
            try:packet,peer=dns.recvfrom(4096)
            except socket.timeout:continue
            if len(packet)<17:continue
            end=12
            while end<len(packet) and packet[end]:end+=packet[end]+1
            if end+5>len(packet):continue
            question=packet[12:end+5];kind=struct.unpack('!H',packet[end+1:end+3])[0];queries.append(kind)
            answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.0.2.2') if kind==1 else b''
            dns.sendto(packet[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(answer)),0,0)+question+answer,peer)
    web=threading.Thread(target=server.serve_forever,daemon=True);resolver=threading.Thread(target=resolve,daemon=True);web.start();resolver.start()
    allowed={'protocol':'tcp','address':'127.0.0.1','port':server.server_port}
    cases=[('deny-default',{'version':1},'10.0.2.2',False),
           ('wrong-address',{'version':1,'egress':[{**allowed,'address':'127.0.0.2'}]},'10.0.2.2',False),
           ('wrong-port',{'version':1,'egress':[{**allowed,'port':server.server_port%65535+1}]},'10.0.2.2',False),
           ('allow-address',{'version':1,'egress':[allowed]},'10.0.2.2',True),
           ('deny-implicit-dns',{'version':1,'egress':[allowed]},'allowed.test',False),
           ('allow-explicit-dns',{'version':1,'egress':[allowed],'dns':{'address':'127.0.0.1','port':dns.getsockname()[1]}},'allowed.test',True)]
    results=[]
    try:
        for name,policy,host,success in cases:
            cfg=copy.deepcopy(base);cfg['machine-config']['vcpu_count']=1;cfg['drives'][0]['path_on_host']=str(disk);cfg['network-interfaces'][0]['forwards']=[]
            cfg['security']=policy;cfg['hvf']={'max_runtime_ms':3000 if not success else 10000}
            cfg['boot-source']['boot_args']+=f' vmm.callback=http://{host}:{server.server_port}/'
            path=work/'config.json';path.write_text(json.dumps(cfg));before=len(requests);before_dns=len(queries)
            p=subprocess.run([str(BINARY),'--no-api','--config-file',str(path)],capture_output=True,timeout=15)
            logs=ROOT/'experiments/hvf/build/security-linux';logs.mkdir(exist_ok=True)
            (logs/(name+'.stdout')).write_bytes(p.stdout);(logs/(name+'.stderr')).write_bytes(p.stderr)
            reached=len(requests)>before
            assert reached==success,(name,queries,p.stdout.decode(errors='replace'),p.stderr.decode(errors='replace'))
            assert (p.returncode==0)==success,(name,p.returncode,p.stderr.decode(errors='replace'))
            if name=='deny-implicit-dns':assert len(queries)==before_dns
            if name=='allow-explicit-dns':assert len(queries)>before_dns
            results.append({'case':name,'passed':True,'host_reached':reached,'dns_queries':len(queries)-before_dns})
        print(json.dumps(results,indent=2))
    finally:stop.set();server.shutdown();web.join();resolver.join(timeout=1)
