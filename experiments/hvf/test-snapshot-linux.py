#!/usr/bin/env python3
"""Snapshot/restore SMP Linux, disks, virtual clock, GIC timers and fresh networking."""
import argparse,copy,json,os,socket,subprocess,tempfile,time,urllib.request
from pathlib import Path
from test_control import api,BINARY,ROOT
def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def until(check,timeout=10):
    deadline=time.monotonic()+timeout
    while True:
        try:
            result=check()
            if result:return result
        except OSError:pass
        if time.monotonic()>deadline:raise RuntimeError('snapshot test deadline')
        time.sleep(.02)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'build/linux-snapshot-guest/config.json')
    parser.add_argument('--output-prefix',type=Path,default=ROOT/'experiments/hvf/build/snapshot-linux')
    args=parser.parse_args();base=json.loads(args.config.read_text());args.output_prefix.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hvf-linux-snapshot-') as temporary:
        work=Path(temporary);cfg=copy.deepcopy(base)
        disk=work/'original-disk'
        with disk.open('wb') as out:out.truncate(64<<20);out.write(b'HVF_GENERIC_BLOCK_V1')
        cfg['drives'][0]['path_on_host']=str(disk)
        cfg['machine-config']['vcpu_count']=4
        tcp,udp=port(),port()
        cfg['network-interfaces'][0]['forwards'][0]['host_port']=tcp
        cfg['network-interfaces'][0]['forwards'][1]['host_port']=udp
        cfg['security']={'version':1,'listeners':[{'protocol':f['protocol'],'address':f['host_addr'],'port':f['host_port']} for f in cfg['network-interfaces'][0]['forwards']]}
        config=work/'config.json';config.write_text(json.dumps(cfg));sock=work/'api.sock'
        logpath=Path(str(args.output_prefix)+'-vmm.log')
        with logpath.open('w') as log:
            process=subprocess.Popen([str(BINARY),'--api-sock',str(sock),'--config-file',str(config)],stdout=log,stderr=log)
            def state(expected):
                def check():
                    value=api(sock,'GET','/')[1]
                    if value['state'] in ['Failed','Exited'] and value['state']!=expected:raise RuntimeError(value)
                    return value if value['state']==expected else None
                return until(check,15)
            def action(name,expected):
                code,body=api(sock,'PUT','/actions',{'action_type':name});assert code==202,body
                return state(expected)
            def http(path='/',data=None):
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{tcp}'+path,data=data),timeout=3) as response:return response.read()
            def clock():return float(http('/clock').split()[0])
            def capture(path):
                code,body=api(sock,'PUT','/snapshot/create',{'snapshot_path':str(path)});assert code==202,body
                state('Paused');result=api(sock,'GET',f"/operations/{body['operation_id']}")[1];assert result['status']=='succeeded',result
            try:
                until(lambda:sock.exists(),3);state('Running')
                first=json.loads(until(http,10));assert first['cpus']==4 and first['count']==1,first
                original=bytes(range(256))*2;changed=b'X'*512
                assert http('/disk',original)==original
                before=clock();action('Pause','Paused');snapshot=work/'snapshot';capture(snapshot)
                time.sleep(2);action('Resume','Running');assert clock()-before<1.5
                assert http('/disk',changed)==changed
                action('ForceStop','Exited')
                with disk.open('r+b') as out:out.seek(4096);out.write(b'Z'*512);out.flush();os.fsync(out.fileno())
                code,body=api(sock,'PUT','/snapshot/load',{'snapshot_path':str(snapshot)});assert code==202,body
                state('Paused');time.sleep(2)
                metrics=api(sock,'GET','/metrics')[1]
                action('Resume','Running')
                restored=json.loads(until(http,10));assert restored['cpus']==4 and restored['count']==1,restored
                assert http('/disk')==original
                assert clock()-before<1.5,(before,clock())
                payload=bytes(range(256))*4096;assert http('/echo',payload)==payload
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp_socket:
                    udp_socket.settimeout(3);udp_socket.sendto(b'snapshot-udp',('127.0.0.1',udp));assert udp_socket.recv(64)==b'snapshot-udp'
                assert http('/disk',changed)==changed
                action('Pause','Paused');second=work/'second';capture(second)
                with (second/'disk-0.bin').open('rb') as inp:inp.seek(4096);assert inp.read(512)==changed
                action('Resume','Running');action('Shutdown','Exited')
                assert api(sock,'GET','/')[1]['exit_code']==0
                report={'cpus':4,'restored_without_reboot':True,'disk_copy_independent':True,
                        'virtual_clock_frozen':True,'tcp_bytes':len(payload),'udp':True,'power_button_and_timers':True}
                Path(str(args.output_prefix)+'.json').write_text(json.dumps(report,indent=2)+'\n')
                print('PASS snapshot Linux SMP:',json.dumps(report))
            finally:
                if process.poll() is None:process.terminate();process.wait(timeout=5)
if __name__=='__main__':main()
