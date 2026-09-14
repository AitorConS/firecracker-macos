#!/usr/bin/env python3
"""Bounded disk/network/lifecycle stability sample (24h by default; 8h: --seconds 28800)."""
import argparse,datetime,json,os,socket,subprocess,tempfile,time,urllib.request
from pathlib import Path
from test_control import api,BINARY,ROOT

def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'build/linux-snapshot-guest/config.json')
    parser.add_argument('--seconds',type=float,default=86400)
    parser.add_argument('--interval',type=float,default=5)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not 1<=args.seconds<=172800 or not .1<=args.interval<=60:raise SystemExit('invalid campaign duration/interval')
    work=args.output.resolve();work.mkdir(parents=True,exist_ok=False);temporary=tempfile.TemporaryDirectory(prefix='hvf-soak-',dir='/tmp');control=Path(temporary.name);runtime=control/'runtime';runtime.mkdir()
    config=json.loads(args.config.read_text());tcp,udp=port(),port()
    disk=work/'disk.raw'
    with disk.open('wb') as output:output.truncate(64<<20);output.write(b'HVF_GENERIC_BLOCK_V1')
    config['drives'][0]['path_on_host']=str(disk);config['machine-config']['vcpu_count']=4
    config['network-interfaces'][0]['forwards'][0]['host_port']=tcp;config['network-interfaces'][0]['forwards'][1]['host_port']=udp
    config['security']={'version':1,'listeners':[{'protocol':f['protocol'],'address':f['host_addr'],'port':f['host_port']} for f in config['network-interfaces'][0]['forwards']]}
    config_path=work/'config.json';config_path.write_text(json.dumps(config,indent=2)+'\n')
    sock=control/'api.sock';started=time.monotonic();pids={};maximum={};baseline={}
    report={'status':'starting','target_seconds':args.seconds,'acceptance_24h_passed':False,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'iterations':0,'tcp_bytes':0,'snapshots':0,'max_api_seconds':0.0}
    report['sample_label']=f'{args.seconds/3600:g}h' if args.seconds%3600==0 else f'{args.seconds:g}s'
    def checkpoint():
        report['elapsed_seconds']=time.monotonic()-started;report['max_resident_bytes']=maximum
        temporary=work/'progress.tmp';temporary.write_text(json.dumps(report,indent=2)+'\n');temporary.replace(work/'progress.json')
    def request(method,path,body=None):
        before=time.monotonic();response=api(sock,method,path,body)
        elapsed=time.monotonic()-before;report['max_api_seconds']=max(report['max_api_seconds'],elapsed)
        if elapsed>2:raise RuntimeError(f'API query took {elapsed:.3f} seconds')
        return response
    def until(check,seconds=30):
        deadline=time.monotonic()+seconds
        while True:
            try:
                value=check()
                if value:return value
            except OSError:pass
            if time.monotonic()>deadline:raise RuntimeError('soak readiness deadline')
            time.sleep(.02)
    def state(expected):
        def check():
            value=request('GET','/')[1]
            if value['state'] in ['Failed','Exited'] and expected!=value['state']:raise RuntimeError(value)
            return value if value['state']==expected else None
        return until(check,300)
    def action(name,expected):
        status,body=request('PUT','/actions',{'action_type':name})
        if status!=202:raise RuntimeError(body)
        return state(expected)
    def http(path='/',data=None):
        with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{tcp}'+path,data=data),timeout=15) as response:return response.read()
    def snapshot():
        action('Pause','Paused');code,op=request('PUT','/snapshot/create',{'snapshot_path':str(work/'snapshot')})
        if code!=202:raise RuntimeError(op)
        state('Paused');result=request('GET',f"/operations/{op['operation_id']}")[1]
        if result['status']!='succeeded':raise RuntimeError(result)
        action('Resume','Running');report['snapshots']+=1
    def identity(pid):
        return subprocess.run(['/bin/ps','-p',str(pid),'-o','lstart=,comm='],capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'}).stdout.strip()
    def children(pid):
        output=subprocess.run(['/usr/bin/pgrep','-P',str(pid)],capture_output=True,text=True).stdout
        return [int(value) for value in output.split()]
    checkpoint();caffeinate=None;process=None
    try:
        caffeinate=subprocess.Popen(['/usr/bin/caffeinate','-i','-w',str(os.getpid())])
        with (work/'vmm.log').open('w') as log:
            process=subprocess.Popen([str(BINARY),'--api-sock',str(sock),'--config-file',str(config_path)],env={**os.environ,'TMPDIR':str(runtime)},stdout=log,stderr=log)
            until(lambda:sock.exists(),5);state('Running');until(http,15)
            snapshot()  # warm all RAM and capture buffers before the RSS baseline
            payload=bytes(range(256))*4096
            for _ in range(3):assert http('/echo',payload)==payload
            metrics=request('GET','/metrics')[1]
            baseline={name:metrics[name] for name in ('vmm_resident_bytes','broker_resident_bytes','supervisor_resident_bytes')}
            report['baseline_resident_bytes']=baseline;report['vmm_build_id']=request('GET','/capabilities')[1]['vmm_build_id']
            stack=[process.pid]
            while stack:
                pid=stack.pop();pids[pid]=identity(pid);stack.extend(children(pid))
            report['runtime_directory']=str(runtime);report['processes']=pids;started=time.monotonic();next_snapshot=started+3600;next_report=started
            report['status']='running';checkpoint()
            while time.monotonic()-started<args.seconds:
                turn=time.monotonic();iteration=report['iterations'];data=iteration.to_bytes(8,'little')*64
                assert http('/disk',data)==data
                assert http('/disk')==data
                assert http('/echo',payload)==payload;report['tcp_bytes']+=len(payload)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
                    connection.settimeout(5);connection.sendto(data,('127.0.0.1',udp));assert connection.recv(1024)==data
                metrics=request('GET','/metrics')[1]
                assert metrics['block_errors_total']==0,metrics
                for name,original in baseline.items():
                    maximum[name]=max(maximum.get(name,0),metrics[name])
                    if metrics[name]>original+(64<<20):raise RuntimeError(f'unbounded RSS growth: {name}: {original} -> {metrics[name]}')
                assert len(request('GET','/operations')[1])<=64
                report['iterations']+=1
                if time.monotonic()>=next_snapshot:snapshot();next_snapshot+=3600
                if time.monotonic()>=next_report:
                    report['latest_metrics']=metrics;checkpoint();next_report+=60
                    print(json.dumps({'elapsed':report['elapsed_seconds'],'iterations':report['iterations'],'max_rss':maximum}),flush=True)
                time.sleep(max(0,min(args.interval-(time.monotonic()-turn),args.seconds-(time.monotonic()-started))))
            report['active_seconds']=time.monotonic()-started
            action('Shutdown','Exited');assert request('GET','/')[1]['exit_code']==0
            process.terminate();process.wait(timeout=5)
            until(lambda:all(identity(pid)!=expected for pid,expected in pids.items()),10)
            leftovers=list(runtime.iterdir());report['remaining_runtime_paths']=[str(p) for p in leftovers];assert not leftovers,leftovers
            report['status']='passed';report['acceptance_24h_passed']=args.seconds>=86400 and report['active_seconds']>=86400
            checkpoint()
    except BaseException as error:
        report['status']='failed';report['error']=repr(error);checkpoint();raise
    finally:
        if process is not None and process.poll() is None:process.terminate();process.wait(timeout=5)
        if caffeinate is not None and caffeinate.poll() is None:caffeinate.terminate();caffeinate.wait(timeout=3)
        temporary.cleanup()
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
