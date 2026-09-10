# SPDX-License-Identifier: Apache-2.0
"""Control plane regressions with a synthetic ELF; no external guest/toolchain."""
import fcntl,http.client,json,os,socket,struct,subprocess,tempfile,time,unittest
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
    def test_force_stop_preserves_api_and_allows_restart(self):
        self.start()
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'InstanceStart'})[0],409)
        self.assertEqual(api(self.sock,'PUT','/machine-config',{'vcpu_count':2})[0],409)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited');self.start()
if __name__=='__main__':unittest.main()
