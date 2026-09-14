#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real Linux throughput bound and control responsiveness during limited I/O."""
import argparse
from pathlib import Path
import concurrent.futures,json,socket,time,urllib.request
from test_control import ControlTests,api,ROOT
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,default=ROOT/'build/linux-guest/config.json');args=parser.parse_args()
c=ControlTests();c.setUp()
try:
    cfg=json.loads(args.config.read_text())
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    disk=c.work/'disk'
    with disk.open('wb') as f:f.truncate(64<<20);f.write(b'HVF_GENERIC_BLOCK_V1')
    drive=cfg['drives'][0];drive['path_on_host']=str(disk)
    c.put('/drives/'+drive['drive_id'],drive)
    c.put('/boot-source',cfg['boot-source']);c.put('/machine-config',cfg['machine-config'])
    net=cfg['network-interfaces'][0];net['forwards']=[{'protocol':'tcp','host_addr':'127.0.0.1','host_port':port,'guest_addr':'10.0.2.15','guest_port':9000}]
    c.put('/network-interfaces',[net]);c.put('/security',{'version':1,'listeners':[{'protocol':'tcp','address':'127.0.0.1','port':port}]})
    c.put('/limits',{'version':1,'network_bytes_per_second':1<<20,'disk_bytes_per_second':1<<20})
    c.start();url=f'http://127.0.0.1:{port}'
    deadline=time.monotonic()+12
    while True:
        try:
            with urllib.request.urlopen(url,timeout=.3) as r:assert json.load(r)['arch']=='arm64'
            break
        except OSError:
            assert time.monotonic()<deadline;time.sleep(.02)
    payload=bytes(range(256))*4096
    def transfer():
        start=time.monotonic()
        with urllib.request.urlopen(urllib.request.Request(url+'/echo',data=payload),timeout=8) as r:assert r.read()==payload
        return time.monotonic()-start
    latencies=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        task=pool.submit(transfer)
        while not task.done():
            start=time.monotonic();assert api(c.sock,'GET','/metrics')[0]==200;latencies.append(time.monotonic()-start);time.sleep(.02)
        elapsed=task.result()
    # 2 MiB payload total at 1 MiB/s, allowing the initial 256 KiB burst.
    assert elapsed>=1.5,elapsed
    assert max(latencies)<.5,max(latencies)
    assert api(c.sock,'PUT','/actions',{'action_type':'ForceStop'})[0]==202;c.wait_state('Exited')
    print(json.dumps({'passed':True,'echo_bytes':len(payload),'elapsed_seconds':elapsed,'max_api_latency_seconds':max(latencies)}))
finally:
    c.log.flush();(ROOT/'experiments/hvf/build/io-limits-vmm.log').write_bytes((c.work/'log').read_bytes())
    for index,path in enumerate(c.runtime.rglob('startup.log')):(ROOT/f'experiments/hvf/build/io-limits-native-{index}.log').write_bytes(path.read_bytes())
    c.tearDown()
