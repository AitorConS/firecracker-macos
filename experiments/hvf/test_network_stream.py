# SPDX-License-Identifier: Apache-2.0
"""Generic Unix Ethernet capability, reconnect and snapshot capture API."""
import os,socket,struct,subprocess,tempfile,time,unittest
from pathlib import Path
from test_control import BINARY,api,elf

class StreamTests(unittest.TestCase):
    def test_capability_reconnect_and_snapshot_capture(self):
        with tempfile.TemporaryDirectory(prefix='hvf-stream-') as td:
            work=Path(td);kernel=work/'kernel';kernel.write_bytes(elf())
            sock=work/'api';link=work/'link'
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(link));os.chmod(link,0o600);listener.listen(1);listener.settimeout(5)
            with (work/'log').open('w') as log:
                p=subprocess.Popen([str(BINARY),'--api-sock',str(sock)],stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+5
                    while not sock.exists():
                        self.assertIsNone(p.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    self.assertEqual(api(sock,'PUT','/boot-source',{'kernel_image_path':str(kernel)})[0],204)
                    self.assertEqual(api(sock,'PUT','/security',{'version':1,'unix_stream':str(link)})[0],204)
                    self.assertEqual(api(sock,'PUT','/network-interfaces',[{'iface_id':'net0','guest_mac':'02:00:00:00:00:01','backend':'unix-stream','socket_path':str(link)}])[0],204)
                    self.assertEqual(api(sock,'PUT','/actions',{'action_type':'InstanceStart'})[0],202)
                    c,_=listener.accept()
                    try:
                        # Invalid frame disconnects only the transport, never the VMM.
                        c.sendall(struct.pack('!I',0xffffffff))
                    finally:c.close()
                    c,_=listener.accept();c.close()
                    deadline=time.monotonic()+5
                    while api(sock,'GET','/')[1]['state']!='Running':
                        self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    cap=api(sock,'GET','/capabilities')[1]
                    self.assertIn('unix-stream',cap['network_backends'])
                    self.assertTrue(cap['unix_stream']['snapshots'])
                    self.assertEqual(cap['unix_stream']['snapshot_restore'],'compatible-interface-fresh-socket')
                    self.assertEqual(cap['network_policy'],'external-switch-unix-capability')
                    self.assertEqual(api(sock,'PUT','/actions',{'action_type':'Pause'})[0],202)
                    deadline=time.monotonic()+5
                    while api(sock,'GET','/')[1]['state']!='Paused':
                        self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    code,body=api(sock,'PUT','/snapshot/create',{'snapshot_path':str(work/'snapshot')})
                    self.assertEqual(code,202,body)
                    deadline=time.monotonic()+10
                    while api(sock,'GET','/operations/'+str(body['operation_id']))[1]['status'] in ('pending','running'):
                        self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    self.assertEqual(api(sock,'GET','/operations/'+str(body['operation_id']))[1]['status'],'succeeded')
                    self.assertTrue((work/'snapshot'/'manifest.json').is_file())
                    self.assertEqual(api(sock,'PUT','/actions',{'action_type':'Resume'})[0],202)
                finally:
                    p.terminate();p.wait(timeout=5);listener.close()
