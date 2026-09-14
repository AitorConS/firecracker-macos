#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded concurrent outbound TCP/DNS/UDP test with exact guest byte checks."""
import argparse,concurrent.futures,gzip,http.server,json,os,signal,socket,struct,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def overlay(entries):
    layer=bytearray()
    for ino,(name,mode,data) in enumerate(entries+[('TRAILER!!!',0,b'')],1):
        encoded=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(encoded),0]
        layer.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded);layer.extend(bytes(-len(layer)%4));layer.extend(data);layer.extend(bytes(-len(layer)%4))
    return gzip.compress(layer,mtime=0)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/'build/macos-arm64/firecracker');p.add_argument('--runs',type=int,default=5);p.add_argument('--count',type=int,default=64);p.add_argument('--workers',type=int,default=8);p.add_argument('--dns-count',type=int,default=16);p.add_argument('--small',action='store_true');p.add_argument('--keep-going',action='store_true');p.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/astra-network-evidence/linux');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    received=[];queries=[];stop=threading.Event()
    # Instrument anomalies instead of dying on them: an unhandled exception in
    # the resolver thread silently disables DNS for every later run. A datagram
    # whose sender is one of this harness's own sockets means a guest proxy was
    # given a port the harness holds; answering it starts a loop between two host
    # sockets that outlives the VM and starves the real traffic, so count it and
    # drop it rather than feed it.
    anomalies={'malformed':0,'self_addressed':0,'cross_addressed':0,'detail':[]}
    def anomaly(kind,where,peer,size):
        anomalies[kind]+=1
        if len(anomalies['detail'])<16:anomalies['detail'].append({'kind':kind,'socket':where,'peer':peer,'bytes':size})
    class HTTP(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ident,size=map(int,self.path.strip('/').split('/'));body=bytes((ident*31+k*17)%251 for k in range(size));received.append({'id':ident,'size':size})
            self.send_response(200)
            self.send_header('X-Request-ID',str(ident))
            if ident%2:self.send_header('Content-Length',str(size))
            self.send_header('Connection','close');self.end_headers()
            # Header/body split and varied chunks exercise short reads and EOF.
            for pos in range(0,size,997 if ident%3 else 16384):self.wfile.write(body[pos:pos+(997 if ident%3 else 16384)])
            self.wfile.flush()
            with (a.output/'host-sent.jsonl').open('a') as log:log.write(json.dumps({'id':ident,'size':size,'peer':self.client_address,'sent':True})+'\n')
        def log_message(self,*args):pass
    class Server(http.server.ThreadingHTTPServer):request_queue_size=128;daemon_threads=True
    with tempfile.TemporaryDirectory(prefix='hvf-net-',dir='/tmp') as tmp,Server(('127.0.0.1',0),HTTP) as web,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        tmp=Path(tmp);go=ROOT/'experiments/hvf/build/guest-tools/go/bin/go';guest=tmp/'guest'
        subprocess.run([go,'build','-trimpath','-buildvcs=false','-o',guest,ROOT/'experiments/hvf/test-network-closure-guest.go'],check=True,env={**os.environ,'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'0','GOTOOLCHAIN':'local','GOCACHE':str(ROOT/'experiments/hvf/build/network-go-cache')})
        dns.bind(('127.0.0.1',0));dns.settimeout(.2);udp.bind(('127.0.0.1',web.server_port));udp.settimeout(.2)
        def resolve():
            mine=dns.getsockname();ours={mine,udp.getsockname()}
            while not stop.is_set():
                try:packet,peer=dns.recvfrom(4096)
                except socket.timeout:continue
                except OSError:break
                if peer in ours:
                    anomaly('self_addressed' if peer==mine else 'cross_addressed','dns',peer,len(packet));continue
                try:
                    end=12
                    while end<len(packet) and packet[end]:end+=packet[end]+1
                    kind=struct.unpack('!H',packet[end+1:end+3])[0];question=packet[12:end+5]
                except (struct.error,IndexError):
                    anomaly('malformed','dns',peer,len(packet));continue
                queries.append(kind)
                answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.0.2.2') if kind==1 else b''
                dns.sendto(packet[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(answer)),0,0)+question+answer,peer)
        def echo():
            mine=udp.getsockname();ours={mine,dns.getsockname()}
            while not stop.is_set():
                try:data,peer=udp.recvfrom(65536)
                except socket.timeout:continue
                except OSError:break
                if peer in ours:
                    anomaly('self_addressed' if peer==mine else 'cross_addressed','echo',peer,len(data));continue
                udp.sendto(data,peer)
        threads=[threading.Thread(target=f,daemon=True) for f in (web.serve_forever,resolve,echo)]
        for t in threads:t.start()
        results=[]
        try:
            base=json.loads((ROOT/'build/linux-guest/config.json').read_text());initrd=tmp/'initrd.gz';initrd.write_bytes(Path(base['boot-source']['initrd_path']).read_bytes()+overlay([('vmm-test',0o100755,guest.read_bytes()),('etc',0o40755,b''),('etc/resolv.conf',0o100644,b'nameserver 10.0.2.3\noptions timeout:1 attempts:1\n')]))
            for run in range(a.runs):
                cfg=json.loads(json.dumps(base));disk=tmp/'disk';disk.write_bytes(b'HVF_GENERIC_BLOCK_V1');disk.open('r+b').truncate(64<<20)
                cfg['drives'][0]['path_on_host']=str(disk);cfg['boot-source']['initrd_path']=str(initrd);cfg['machine-config']['vcpu_count']=1 if run%2==0 else 4;cfg['network-interfaces'][0]['forwards']=[]
                cfg['security']={'version':1,'egress':[{'protocol':proto,'address':'127.0.0.1','port':web.server_port} for proto in ('tcp','udp')],'dns':{'address':'127.0.0.1','port':dns.getsockname()[1]}}
                cfg['hvf']={'max_runtime_ms':120000};host='closure.test' if run%2 else '10.0.2.2';count=a.dns_count if run%2 else a.count;cfg['boot-source']['boot_args']+=f' closure.host={host} closure.port={web.server_port} closure.count={count} closure.workers={a.workers} closure.small={int(a.small)}'
                path=tmp/'config.json';path.write_text(json.dumps(cfg));before=len(queries);before_bad=(anomalies['malformed'],anomalies['self_addressed'],anomalies['cross_addressed']);start=time.monotonic()
                runtime=tmp/'runtime';runtime.mkdir(exist_ok=True);handles={}
                with (tmp/'stdout').open('w+b') as stdout,(tmp/'stderr').open('w+b') as stderr:
                    proc=subprocess.Popen([a.binary.resolve(),'--no-api','--config-file',path],stdout=stdout,stderr=stderr,env={**os.environ,'TMPDIR':str(runtime)},start_new_session=True)
                    def terminate():
                        # Killing the supervisor alone leaves the VMM, broker and
                        # authority running: the supervisor puts them in its own
                        # session. Select them by this run's private TMPDIR, which
                        # cannot match another session working in this checkout.
                        proc.kill()
                        listing=subprocess.run(['ps','-A','-o','pid=,command='],capture_output=True,text=True).stdout
                        for entry in listing.splitlines():
                            pid,_,command=entry.strip().partition(' ')
                            if str(runtime) in command and str(a.binary.resolve()) in command:
                                try:os.kill(int(pid),signal.SIGKILL)
                                except (ProcessLookupError,PermissionError,ValueError):pass
                    try:
                        while proc.poll() is None:
                            for log in [Path(d)/'startup.log' for d,_,names in os.walk(runtime) if 'startup.log' in names]:
                                if log not in handles:
                                    try:handles[log]=log.open('rb')
                                    except FileNotFoundError:pass
                            if time.monotonic()-start>130:terminate();raise TimeoutError('VM exceeded 130 seconds')
                            time.sleep(.01)
                        stdout.seek(0);stderr.seek(0);r=subprocess.CompletedProcess(proc.args,proc.returncode,stdout.read(),stderr.read())
                    finally:
                        terminate();proc.wait()
                        (a.output/f'{run}.native.log').write_bytes(b''.join(f.read() for f in handles.values()))
                        for f in handles.values():f.close()
                (a.output/f'{run}.stdout').write_bytes(r.stdout);(a.output/f'{run}.stderr').write_bytes(r.stderr)
                line=next((s.split('NETWORK_CLOSURE ',1)[1] for s in r.stdout.decode(errors='replace').splitlines() if 'NETWORK_CLOSURE ' in s),None);result=json.loads(line) if line else {'error':'missing guest result'}
                result.update(run=run,host=host,returncode=r.returncode,seconds=time.monotonic()-start,dns_queries=len(queries)-before,
                              host_malformed=anomalies['malformed']-before_bad[0],host_self_addressed=anomalies['self_addressed']-before_bad[1],
                              host_cross_addressed=anomalies['cross_addressed']-before_bad[2]);results.append(result);(a.output/'results.json').write_text(json.dumps(results,indent=2));print(json.dumps(result),flush=True)
                result['passed']=(r.returncode==0 and result.get('http_ok')==count*a.workers and result.get('udp_ok')==64
                                  and not result.get('failures') and not result['host_malformed'] and not result['host_self_addressed'] and not result['host_cross_addressed']
                                  and (host!='closure.test' or result['dns_queries']>0))
                (a.output/'results.json').write_text(json.dumps(results,indent=2))
                if not a.keep_going:assert result['passed'],result
            assert all(r['passed'] for r in results),'Failures recorded in results.json'
        finally:
            stop.set();web.shutdown()
            for t in threads:t.join(2)
            (a.output/'host.json').write_text(json.dumps({'requests':received,'dns_queries':queries,'anomalies':anomalies}))
if __name__=='__main__':main()
