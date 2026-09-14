#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generic Linux disk/network acceptance; no Jerboa paths or image tools."""
import argparse,concurrent.futures,copy,http.server,json,os,socket,subprocess,tempfile,threading,time,urllib.request
from pathlib import Path
from test_control import api,BINARY,ROOT

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def until(fn,seconds=8):
    deadline=time.monotonic()+seconds
    while True:
        try:
            result=fn()
            if result:return result
        except OSError:pass
        if time.monotonic()>deadline:raise RuntimeError('deadline waiting for guest/API')
        time.sleep(.02)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'build/linux-guest/config.json')
    args=parser.parse_args();base=json.loads(args.config.read_text())
    with tempfile.TemporaryDirectory(prefix='generic-linux-') as td:
        work=Path(td);runtime=work/'tmp';runtime.mkdir()
        for cpus in [1,4]:
            cfg=copy.deepcopy(base);cfg['machine-config']['vcpu_count']=cpus
            disk=work/f'disk-{cpus}'
            with disk.open('wb') as f:f.truncate(64<<20);f.write(b'HVF_GENERIC_BLOCK_V1')
            cfg['drives'][0]['path_on_host']=str(disk)
            tcp,udp=port(),port();cfg['network-interfaces'][0]['forwards'][0]['host_port']=tcp;cfg['network-interfaces'][0]['forwards'][1]['host_port']=udp
            cfg['security']={'version':1,'listeners':[{'protocol':f['protocol'],'address':f['host_addr'],'port':f['host_port']} for f in cfg['network-interfaces'][0]['forwards']]}
            sock=work/'api.sock';logpath=work/f'linux-{cpus}.log'
            with logpath.open('w') as log:
                process=subprocess.Popen([str(BINARY),'--api-sock',str(sock)],stdout=log,stderr=log,env={**os.environ,'TMPDIR':str(runtime)})
                try:
                    until(lambda:sock.exists(),3)
                    for key,value in cfg.items():
                        if key=='drives':
                            for drive in value:assert api(sock,'PUT','/drives/'+drive['drive_id'],drive)[0]==204
                        else:assert api(sock,'PUT','/'+key,value)[0]==204
                    for expected in [1,2]:
                        status,body=api(sock,'PUT','/actions',{'action_type':'InstanceStart'});assert status==202 and body["state"]=="Starting",body
                        url=f'http://127.0.0.1:{tcp}'
                        def info():
                            with urllib.request.urlopen(url,timeout=.3) as r:return json.load(r)
                        data=until(info)
                        assert data['count']==expected and data['cpus']==cpus and data['arch']=='arm64',data
                        assert data['kernel'].startswith('Linux version ') and data['mac']==cfg['network-interfaces'][0]['guest_mac'],data
                        if expected==1:
                            cycles=100 if cpus==4 else 3
                            for cycle in range(cycles):
                                code,op=api(sock,'PUT','/actions',{'action_type':'Pause'})
                                assert code==202,op
                                until(lambda:api(sock,'GET','/')[1]['state']=='Paused',5)
                                if cycle==0:
                                    time.sleep(.15)
                                    before=api(sock,'GET','/metrics')[1]
                                    time.sleep(.2)
                                    after=api(sock,'GET','/metrics')[1]
                                    for cpu in range(cpus):
                                        key=f'vcpu_{cpu}_exits_total';assert before[key]==after[key],(before,after)
                                    assert before['block_requests_total']==after['block_requests_total']
                                    assert before['net_rx_packets_total']==after['net_rx_packets_total']
                                code,op=api(sock,'PUT','/actions',{'action_type':'Resume'})
                                assert code==202,op
                                until(lambda:api(sock,'GET','/')[1]['state']=='Running',5)
                            assert until(info)['count']==expected
                            print(f'PASS Linux: {cpus} CPUs, {cycles} pause/resume cycles, frozen exits and I/O',flush=True)
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                            s.settimeout(2);s.sendto(b'generic-udp',('127.0.0.1',udp));assert s.recv(256)==b'generic-udp'
                        payload=bytes(range(256))*4096
                        def echo(_):
                            with urllib.request.urlopen(urllib.request.Request(url+'/echo',data=payload),timeout=10) as r:assert r.read()==payload
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(echo,range(16)))
                        metrics=until(lambda:(m if (m:=api(sock,'GET','/metrics')[1]).get('net_tx_bytes_total',0)>=16<<20 and m.get('net_rx_bytes_total',0)>=16<<20 else None))
                        assert metrics['block_requests_total']>0 and metrics['block_read_bytes_total']>0 and metrics['block_write_bytes_total']>0,metrics
                        assert metrics['broker_pid']>1 and metrics['broker_resident_bytes']>0,metrics
                        assert metrics['block_errors_total']==0 and metrics['native_sample_age_seconds']<1,metrics
                        assert all(metrics[f'vcpu_{cpu}_exits_total']>0 for cpu in range(cpus)),metrics
                        assert api(sock,'PUT','/actions',{'action_type':'Shutdown','timeout_ms':5000})[0]==202
                        state=until(lambda:(s if (s:=api(sock,'GET','/')[1])['state']=='Exited' else None))
                        assert state['exit_code']==0 and state['shutdown_delivered'],state
                        with disk.open('rb') as f:
                            f.seek(1024);assert f.read(19)==b'POWER_BUTTON_SYNCED'
                        print(f'PASS Linux: {cpus} CPUs, boot {expected}, block persistence, MAC, TCP 16 MiB, UDP, orderly guest poweroff',flush=True)
                    if cpus==1:
                        boot=copy.deepcopy(cfg['boot-source']);boot['boot_args']+=' vmm.ignore_power=1'
                        assert api(sock,'PUT','/boot-source',boot)[0]==204
                        assert api(sock,'PUT','/actions',{'action_type':'InstanceStart'})[0]==202
                        assert until(info)['count']==3
                        assert api(sock,'PUT','/actions',{'action_type':'Shutdown','timeout_ms':200})[0]==202
                        state=until(lambda:(s if (s:=api(sock,'GET','/')[1])['state']=='Running' else None))
                        assert state['shutdown_delivered'] and state['last_error']['fault_code']=='SHUTDOWN_TIMEOUT',state
                        assert api(sock,'PUT','/actions',{'action_type':'ForceStop'})[0]==202
                        until(lambda:api(sock,'GET','/')[1]['state']=='Exited')
                        print('PASS Linux: delivered power event can be ignored; timeout preserves guest until explicit ForceStop',flush=True)
                except Exception:
                    print(logpath.read_text(),flush=True);print(api(sock,'GET','/')[1],flush=True);raise
                finally:
                    if process.poll() is None:process.terminate();process.wait(timeout=4)
            assert not sock.exists() and not list(runtime.iterdir())
        # An interface with no published ports still supports outbound traffic.
        result=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                result.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))));self.send_response(200);self.end_headers();self.wfile.write(b'outbound-ok')
            def log_message(self,*args):pass
        with http.server.HTTPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            cfg['security']={'version':1,'egress':[{'protocol':'tcp','address':'127.0.0.1','port':server.server_port}]}
            cfg['network-interfaces'][0]['forwards']=[]
            cfg['boot-source']['boot_args']+=f' vmm.callback=http://10.0.2.2:{server.server_port}/'
            path=work/'outbound.json';path.write_text(json.dumps(cfg))
            try:
                p=subprocess.run([str(BINARY),'--no-api','--config-file',str(path)],capture_output=True,timeout=15)
                assert p.returncode==0,p.stdout.decode(errors='replace')+p.stderr.decode(errors='replace')
                assert result and result[0]['count']==3,result
                print('PASS Linux: outbound networking with zero forwarding rules',flush=True)
            finally:server.shutdown();thread.join()
if __name__=='__main__':main()
