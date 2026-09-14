# SPDX-License-Identifier: Apache-2.0
"""Control plane regressions with a synthetic ELF; no external guest/toolchain."""
import fcntl,http.client,json,os,signal,socket,struct,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BINARY=Path(os.environ.get('HVF_BINARY',ROOT/'build/macos-arm64/firecracker'))
def elf(words=None):
    words=words or [0xd503207f,0x17ffffff] # WFI; branch to WFI
    code=struct.pack('<'+'I'*len(words),*words);pa=0x40400000
    return (b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,183,1,pa,64,0,0,64,56,1,0,0,0)+struct.pack('<IIQQQQQQ',1,5,120,pa,pa,len(code),len(code),4)+code)
def api(path,method,endpoint,body=None):
    class UnixHTTP(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(35);self.sock.connect(str(path))
    c=UnixHTTP('localhost')
    try:
        c.request(method,endpoint,None if body is None else json.dumps(body),{'Content-Type':'application/json'})
        r=c.getresponse();b=r.read();return r.status,json.loads(b) if b else None
    finally:c.close()
class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hvf-control-');self.work=Path(self.temp.name)
        self.sock=self.work/'api.sock';self.runtime=self.work/'tmp';self.runtime.mkdir()
        self.log=(self.work/'log').open('w');self.p=subprocess.Popen([str(BINARY),'--api-sock',str(self.sock)],env={**os.environ,'TMPDIR':str(self.runtime)},stdout=self.log,stderr=self.log)
        deadline=time.monotonic()+3
        while not self.sock.exists():
            if self.p.poll() is not None or time.monotonic()>deadline:raise RuntimeError('API failed to bind')
            time.sleep(.01)
        self.kernel=self.work/'kernel';self.kernel.write_bytes(elf())
        self.put('/boot-source',{'kernel_image_path':str(self.kernel)})
    def tearDown(self):
        if self.p.poll() is None:self.p.terminate();self.p.wait(timeout=4)
        if not getattr(self,"crashed",False):
            self.assertFalse(self.sock.exists());self.assertEqual(list(self.runtime.iterdir()),[])
        self.log.close();self.temp.cleanup()
    def put(self,path,body):self.assertEqual(api(self.sock,'PUT',path,body)[0],204)
    def wait_state(self,expected,seconds=4):
        deadline=time.monotonic()+seconds
        while True:
            state=api(self.sock,'GET','/')[1]
            if state['state']==expected:return state
            self.assertLess(time.monotonic(),deadline,state);time.sleep(.01)
    def start(self,expected='Running'):
        code,body=api(self.sock,'PUT','/actions',{'action_type':'InstanceStart'})
        self.assertEqual(code,202);self.assertEqual(body['state'],'Starting')
        return self.wait_state(expected)
    def test_pause_resume_100_cycles_with_offline_secondary_cpus(self):
        self.kernel.write_bytes(elf([0xd2a12001,0xb9401820,0x17ffffff]))
        self.put('/machine-config',{'vcpu_count':4,'mem_size_mib':64})
        self.start()
        self.assertTrue(api(self.sock,'GET','/capabilities')[1]['pause'])
        for cycle in range(100):
            code,op=api(self.sock,'PUT','/actions',{'action_type':'Pause'})
            self.assertEqual(code,202,op);self.wait_state('Paused')
            self.assertEqual(api(self.sock,'GET','/operations/'+str(op['operation_id']))[1]['status'],'succeeded')
            self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Pause'})[0],409)
            if cycle==0:
                time.sleep(.15)
                before=api(self.sock,'GET','/metrics')[1]['vcpu_0_exits_total']
                time.sleep(.2)
                self.assertEqual(api(self.sock,'GET','/metrics')[1]['vcpu_0_exits_total'],before)
            code,op=api(self.sock,'PUT','/actions',{'action_type':'Resume'})
            self.assertEqual(code,202,op);self.wait_state('Running')
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Pause'})[0],202)
        self.wait_state('Paused')
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited')

    def test_pause_freezes_virtual_counter(self):
        # CNTVCT loop resets via PSCI if consecutive samples differ by >1 second.
        self.kernel.write_bytes(elf([0xd53be002,0xd53be043,0xd53be044,0xcb030085,
            0xeb0200bf,0x54000068,0xaa0403e3,0x17fffffb,
            0xd2800120,0xf2b08000,0xd4000002,0x17fffffd]))
        self.start();time.sleep(.05)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Pause'})[0],202)
        self.wait_state('Paused');time.sleep(2)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Resume'})[0],202)
        self.wait_state('Running');time.sleep(.1)
        self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Running')

    def test_paused_broker_death_is_observed(self):
        self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}])
        self.start();broker=self.broker()
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Pause'})[0],202)
        self.wait_state('Paused');os.kill(broker,signal.SIGKILL)
        state=self.wait_state('Exited',3)
        self.assertNotEqual(state['exit_code'],0)
        self.assertEqual(api(self.sock,'GET','/metrics')[0],200)

    def test_force_stop_cancels_pause_transition(self):
        self.start()
        code,op=api(self.sock,'PUT','/actions',{'action_type':'Pause'})
        self.assertEqual(code,202)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited')
        self.assertIn(api(self.sock,'GET','/operations/'+str(op['operation_id']))[1]['status'],['cancelled','succeeded'])

    def test_rss_group_budget_is_external_and_api_survives(self):
        # Touch 128 MiB of guest RAM; configured but untouched pages are not RSS.
        self.kernel.write_bytes(elf([0xd2a82001,0xd2900002,0xf900003f,0x91400421,0xf1000442,0x54ffffa1,0xd503207f,0x17ffffff]))
        self.put('/machine-config',{'mem_size_mib':256})
        self.put('/limits',{'version':1,'rss_mib':64})
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'InstanceStart'})[0],202)
        deadline=time.monotonic()+4
        while True:
            state=api(self.sock,'GET','/')[1]
            if state['state'] in ['Failed','Exited']:break
            self.assertLess(time.monotonic(),deadline,state);time.sleep(.01)
        self.assertIn('RSS_LIMIT_EXCEEDED',state['last_error']['fault_message'])
        self.put('/limits',{'version':1})
        self.kernel.write_bytes(elf())
        self.start()
        self.assertEqual(api(self.sock,'GET','/capabilities')[1]['limits']['rss_enforcement'],'reactive')

    def test_cpu_time_limit_stops_busy_guest(self):
        self.kernel.write_bytes(elf([0x14000000])) # branch to itself: consumes host CPU
        self.put('/limits',{'version':1,'cpu_seconds':1})
        self.start()
        state=self.wait_state('Exited',4)
        self.assertNotEqual(state['exit_code'],0)
        self.assertIn('CPU_LIMIT_EXCEEDED',state['last_error']['fault_message'])
        self.assertEqual(api(self.sock,'GET','/metrics')[0],200)

    def test_headless_is_supervised_for_cpu_limit(self):
        self.kernel.write_bytes(elf([0x14000000]))
        config=self.work/'headless.json';config.write_text(json.dumps({'boot-source':{'kernel_image_path':str(self.kernel)},'security':{'version':1},'limits':{'version':1,'cpu_seconds':1}}))
        result=subprocess.run([str(BINARY),'--no-api','--config-file',str(config)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertIn('CPU_LIMIT_EXCEEDED',result.stderr)

    def test_file_size_limit_fails_startup(self):
        self.put('/limits',{'version':1,'file_size_bytes':1<<20})
        state=self.start('Failed')
        self.assertEqual(state['last_error']['fault_code'],'BOOT_FAILED')
        self.assertEqual(api(self.sock,'GET','/')[0],200)

    def test_authority_death_stops_vm_and_preserves_api(self):
        self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}]);self.start()
        broker=self.broker();authority=int(subprocess.check_output(['pgrep','-P',str(broker)],text=True).strip())
        os.kill(authority,signal.SIGKILL);state=self.wait_state('Exited',3)
        self.assertNotEqual(state['exit_code'],0);self.assertIn('socket authority disconnected',state['last_error']['fault_message']);self.assertEqual(api(self.sock,'GET','/metrics')[0],200)

    def test_security_migration_and_explicit_permissions(self):
        config=self.work/'old.json';config.write_text(json.dumps({'boot-source':{'kernel_image_path':str(self.kernel)},'network-interfaces':[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp','forwards':[{'protocol':'tcp','host_addr':'127.0.0.1','host_port':19999,'guest_addr':'10.0.2.15','guest_port':80}]}]}))
        original=config.read_bytes()
        rejected=subprocess.run([str(BINARY),'--config-file',str(config),'--check-config'],capture_output=True,text=True)
        self.assertNotEqual(rejected.returncode,0);self.assertIn('SECURITY_MIGRATION_REQUIRED',rejected.stderr)
        report=json.loads(subprocess.check_output([str(BINARY),'--config-file',str(config),'--migrate-config']))
        self.assertEqual(report['configuration']['security']['listeners'],[])
        self.assertEqual(report['configuration']['security']['egress'],[])
        self.assertEqual(report['required_listener_permissions'],[{'protocol':'tcp','address':'127.0.0.1','port':19999}])
        self.assertEqual(config.read_bytes(),original)
        self.assertEqual(api(self.sock,'PUT','/security',{'version':2})[0],400)
        self.assertEqual(api(self.sock,'PUT','/security',{'version':1,'egress':[{'protocol':'tcp','address':'0.0.0.0','port':80}]})[0],400)
        self.start()
        self.assertEqual(api(self.sock,'PUT','/security',{'version':1,'mode':'development'})[0],409)

    def test_elf_error_is_returned_and_can_retry(self):
        self.kernel.write_bytes(b'not an ELF')
        body=self.start('Failed')['last_error'];self.assertEqual(body['fault_code'],'BOOT_FAILED');self.assertIn('ELF',body['fault_message'])
        self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Failed')
        self.kernel.write_bytes(elf());self.start()
        self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Running')
    def test_locked_source_cannot_be_copied(self):
        disk=self.work/'disk';disk.write_bytes(bytes(4096))
        self.put('/drives/d',{'drive_id':'d','path_on_host':str(disk),'copy_on_start':True})
        with disk.open('rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            body=self.start('Failed')['last_error'];self.assertIn('disk lock failed',body['fault_message'])
        self.start()
    def test_native_port_failure_is_returned(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));reserved.listen()
            self.put('/security',{'version':1,'listeners':[{'protocol':'tcp','address':'127.0.0.1','port':reserved.getsockname()[1]}]})
            self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp','forwards':[{'protocol':'tcp','host_addr':'127.0.0.1','host_port':reserved.getsockname()[1],'guest_addr':'10.0.2.15','guest_port':1234}]}])
            body=self.start('Failed')['last_error'];self.assertIn('network setup failed',body['fault_message'])
        self.assertEqual(api(self.sock,'GET','/capabilities')[0],200)
    def test_vm_exit_preserves_api_and_exit_state(self):
        self.kernel.write_bytes(elf([0x52800100,0x72b08000,0xd4000002]))
        self.start('Exited')
        deadline=time.monotonic()+2
        while True:
            state=api(self.sock,'GET','/')[1]
            if state['state']=='Exited':break
            self.assertLess(time.monotonic(),deadline);time.sleep(.01)
        self.assertEqual(state['exit_code'],0)
    def test_supervisor_crash_stops_vm(self):
        self.start()
        children=subprocess.check_output(['pgrep','-P',str(self.p.pid)],text=True).split()
        self.assertEqual(len(children),1)
        self.crashed=True;self.p.kill();self.p.wait(timeout=3)
        deadline=time.monotonic()+3
        while True:
            try:os.kill(int(children[0]),0)
            except ProcessLookupError:break
            self.assertLess(time.monotonic(),deadline,'orphan VM after supervisor SIGKILL');time.sleep(.02)
        # SIGKILL cannot run the parent's destructors. The harness owns and removes
        # its remaining socket/config directory; the VM itself must not survive.
    def test_orphan_recovery_waits_for_child_lease(self):
        self.start()
        old=next(self.runtime.glob('hvf-supervisor-*'))
        child=int(subprocess.check_output(['pgrep','-P',str(self.p.pid)],text=True).strip())
        # Keep the group non-orphaned: POSIX otherwise resumes stopped orphan
        # groups with SIGHUP+SIGCONT, so the VMM would release its lease normally.
        keeper=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],preexec_fn=lambda:os.setpgid(0,child))
        os.kill(child,signal.SIGSTOP)
        def restart():
            self.p=subprocess.Popen([str(BINARY),'--api-sock',str(self.sock)],env={**os.environ,'TMPDIR':str(self.runtime)},stdout=self.log,stderr=self.log)
            deadline=time.monotonic()+3
            while not self.sock.exists():
                self.assertIsNone(self.p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
            self.wait_state('Not started')
        try:
            self.p.kill();self.p.wait(timeout=3)
            self.sock.unlink() # harness owns this stale API socket
            restart()
            self.assertTrue(old.exists(),'live VMM lease must prevent reclamation')
        finally:
            os.kill(child,signal.SIGCONT)
            keeper.terminate();keeper.wait(timeout=2)
        deadline=time.monotonic()+3
        while True:
            try:os.kill(child,0)
            except ProcessLookupError:break
            self.assertLess(time.monotonic(),deadline);time.sleep(.02)
        self.p.terminate();self.p.wait(timeout=4)
        restart()
        self.assertFalse(old.exists(),'released orphan workspace should be recovered')
    def broker(self):
        deadline=time.monotonic()+2
        while True:
            metrics=api(self.sock,'GET','/metrics')[1]
            if metrics.get('broker_pid',0)>1:return metrics['broker_pid']
            self.assertLess(time.monotonic(),deadline,metrics);time.sleep(.01)
    def test_broker_death_stops_vm_and_keeps_api(self):
        self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}])
        self.start();broker=self.broker()
        self.assertNotEqual(broker,self.p.pid)
        os.kill(broker,signal.SIGKILL)
        state=self.wait_state('Exited')
        self.assertEqual(state['exit_code'],2)
        self.assertEqual(api(self.sock,'GET','/capabilities')[0],200)
    def test_supervisor_crash_stops_network_broker(self):
        self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}])
        self.start();broker=self.broker()
        child=int(subprocess.check_output(['pgrep','-P',str(self.p.pid)],text=True).strip())
        self.crashed=True;self.p.kill();self.p.wait(timeout=3)
        deadline=time.monotonic()+3
        for pid in [child,broker]:
            while True:
                try:os.kill(pid,0)
                except ProcessLookupError:break
                self.assertLess(time.monotonic(),deadline,'orphan VMM/broker');time.sleep(.02)
    def test_network_exists_without_forwards(self):
        self.put('/network-interfaces',[{'iface_id':'n','guest_mac':'02:00:00:00:00:01','backend':'slirp'}])
        self.start()
    def test_start_can_be_cancelled_without_closing_api(self):
        disk=self.work/'large-disk'
        with disk.open('wb') as f:f.truncate(256<<20)
        self.put('/drives/d',{'drive_id':'d','path_on_host':str(disk),'copy_on_start':True})
        begin=time.monotonic()
        code,body=api(self.sock,'PUT','/actions',{'action_type':'InstanceStart'})
        self.assertEqual(code,202);self.assertEqual(body['state'],'Starting')
        self.assertLess(time.monotonic()-begin,.5)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited')
        self.assertEqual(api(self.sock,'GET','/capabilities')[0],200)
    def test_shutdown_requires_capability(self):
        self.start()
        code,body=api(self.sock,'PUT','/actions',{'action_type':'Shutdown'})
        self.assertEqual(code,409);self.assertEqual(body['fault_code'],'UNSUPPORTED_CAPABILITY')
    def test_shutdown_timeout_requires_explicit_escalation(self):
        self.put('/machine-config',{'vcpu_count':1,'mem_size_mib':64,'power_button':True})
        self.start()
        for force,expected in [(False,'Running'),(True,'Exited')]:
            code,_=api(self.sock,'PUT','/actions',{'action_type':'Shutdown','timeout_ms':100,'force_on_timeout':force})
            self.assertEqual(code,202)
            state=self.wait_state(expected)
            self.assertEqual(state['last_error']['fault_code'],'SHUTDOWN_TIMEOUT')
            self.assertFalse(state['shutdown_delivered'])
    def test_metrics_json_and_prometheus(self):
        self.start()
        code,metrics=api(self.sock,'GET','/metrics')
        self.assertEqual(code,200)
        self.assertGreater(metrics['supervisor_resident_bytes'],0)
        self.assertGreater(metrics['vmm_resident_bytes'],0)
        self.assertGreaterEqual(metrics['state_transitions_total'],2)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2);client.connect(str(self.sock))
            client.sendall(b'GET /metrics HTTP/1.1\r\nAccept: text/plain\r\n\r\n')
            response=b''
            while chunk:=client.recv(4096):response+=chunk
        self.assertIn(b'Content-Type: text/plain; version=0.0.4',response)
        self.assertIn(b'hvf_supervisor_resident_bytes ',response)
    def test_operation_result_survives_restart(self):
        self.kernel.write_bytes(b'broken')
        failed=self.start('Failed')['operation_id']
        old=api(self.sock,'GET',f'/operations/{failed}')[1]
        self.assertEqual(old['status'],'failed')
        self.assertEqual(old['result']['fault_code'],'BOOT_FAILED')
        self.kernel.write_bytes(elf());self.start()
        self.assertEqual(api(self.sock,'GET',f'/operations/{failed}')[1],old)
        code,_=api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})
        self.assertEqual(code,202)
        state=self.wait_state('Exited')
        op=api(self.sock,'GET',f"/operations/{state['operation_id']}")[1]
        self.assertEqual(op['status'],'succeeded')
    def test_slow_clients_do_not_block_shutdown_deadline(self):
        self.put('/machine-config',{'vcpu_count':1,'mem_size_mib':64,'power_button':True})
        self.start()
        clients=[]
        try:
            for _ in range(16):
                client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                client.connect(str(self.sock));client.sendall(b'PUT /actions HTTP/1.1\r\nContent-Length: 100\r\n\r\n{')
                clients.append(client)
            begin=time.monotonic()
            self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Shutdown','timeout_ms':100})[0],202)
            state=self.wait_state('Running')
            self.assertEqual(state['last_error']['fault_code'],'SHUTDOWN_TIMEOUT')
            self.assertLess(time.monotonic()-begin,1.0)
            self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
            self.wait_state('Exited')
        finally:
            for client in clients:client.close()
    def test_force_stop_preserves_api_and_allows_restart(self):
        self.start()
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'InstanceStart'})[0],409)
        self.assertEqual(api(self.sock,'PUT','/machine-config',{'vcpu_count':2})[0],409)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited');self.start()
if __name__=='__main__':unittest.main()
