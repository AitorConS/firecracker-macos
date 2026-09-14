# SPDX-License-Identifier: Apache-2.0
"""Real-HVF snapshot publication, restore and hostile-manifest regressions."""
import hashlib,json,os,time,unittest
import test_control as control
api=control.api
class SnapshotTests(unittest.TestCase):
    setUp=control.ControlTests.setUp
    tearDown=control.ControlTests.tearDown
    put=control.ControlTests.put
    start=control.ControlTests.start
    wait_state=control.ControlTests.wait_state
    def pause(self):
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Pause'})[0],202)
        self.wait_state('Paused')
    def capture(self,path):
        code,op=api(self.sock,'PUT','/snapshot/create',{'snapshot_path':str(path)})
        self.assertEqual(code,202,op);self.wait_state('Paused',10)
        result=api(self.sock,'GET','/operations/'+str(op['operation_id']))[1]
        self.assertEqual(result['status'],'succeeded',result)
    def stop(self):
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited')
    def load(self,path,expected='Paused'):
        code,op=api(self.sock,'PUT','/snapshot/load',{'snapshot_path':str(path)})
        self.assertEqual(code,202,op)
        return self.wait_state(expected,10)
    def test_capture_restore_paused_ram_and_offline_cpus(self):
        self.put('/machine-config',{'vcpu_count':4,'mem_size_mib':64})
        self.start();self.pause();snapshot=self.work/'snapshot';self.capture(snapshot)
        first=json.loads((snapshot/'manifest.json').read_text())
        self.assertEqual(first['components']['ram.bin']['size'],64<<20)
        self.assertEqual(len([k for k in first['components'] if k.startswith('cpu-')]),4)
        self.capture(snapshot)  # atomic replacement of a complete previous snapshot
        self.stop();self.kernel.unlink();self.load(snapshot)
        second=self.work/'snapshot2';self.capture(second)
        self.assertEqual(first['components']['ram.bin'],json.loads((second/'manifest.json').read_text())['components']['ram.bin'])
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'Resume'})[0],202)
        self.wait_state('Running');time.sleep(.05)
        self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Running')
    def test_rejects_corruption_paths_sizes_and_incompatible_host(self):
        self.put('/machine-config',{'mem_size_mib':64});self.start();self.pause()
        snapshot=self.work/'snapshot';self.capture(snapshot);self.stop()
        path=snapshot/'manifest.json';original=path.read_bytes();manifest=json.loads(original)
        mutations=[]
        import copy
        for key,value in [('format_version',99)]:
            changed=copy.deepcopy(manifest);changed[key]=value;mutations.append((changed,'unsupported snapshot format'))
        changed=copy.deepcopy(manifest);changed['config']['boot-source']['kernel_image_path']='../kernel';mutations.append((changed,'non-canonical component paths'))
        changed=copy.deepcopy(manifest);changed['components']['ram.bin']['size']=1<<50;mutations.append((changed,'invalid snapshot component size'))
        changed=copy.deepcopy(manifest);del changed['components']['cpu-0.bin'];mutations.append((changed,'snapshot component set mismatch'))
        # Manifest shape is rejected before an asynchronous restore is accepted.
        for changed,message in mutations:
            with self.subTest(message=message):
                path.write_text(json.dumps(changed))
                code,body=api(self.sock,'PUT','/snapshot/load',{'snapshot_path':str(snapshot)})
                self.assertEqual(code,400,body)
                self.assertIn(message,body['fault_message'])
                self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Exited')
        changed=copy.deepcopy(manifest);changed['compatibility']['host']='0'*32
        path.write_text(json.dumps(changed));state=self.load(snapshot,'Failed');self.assertIsNotNone(state['last_error'])
        path.write_bytes(original)
        cpu=snapshot/'cpu-0.bin';saved=cpu.read_bytes();cpu.unlink();cpu.symlink_to(self.kernel)
        self.assertIn('BOOT_FAILED',self.load(snapshot,'Failed')['last_error']['fault_code'])
        cpu.unlink();cpu.write_bytes(saved)
        with (snapshot/'ram.bin').open('r+b') as ram:ram.seek(8192);byte=ram.read(1);ram.seek(8192);ram.write(bytes([byte[0]^1]))
        self.assertIn('integrity mismatch',self.load(snapshot,'Failed')['last_error']['fault_message'])

    def test_failed_capture_preserves_previous_snapshot_and_paused_vm(self):
        self.put('/machine-config',{'mem_size_mib':64});self.start();self.pause()
        snapshot=self.work/'snapshot';self.capture(snapshot);before=(snapshot/'manifest.json').read_bytes();self.stop()
        self.put('/limits',{'version':1,'file_size_bytes':8<<20});self.start();self.pause()
        code,op=api(self.sock,'PUT','/snapshot/create',{'snapshot_path':str(snapshot)})
        self.assertEqual(code,202);self.wait_state('Paused',10)
        self.assertEqual(api(self.sock,'GET','/operations/'+str(op['operation_id']))[1]['status'],'failed')
        self.assertEqual((snapshot/'manifest.json').read_bytes(),before)
        self.assertEqual(api(self.sock,'GET','/')[1]['state'],'Paused')

    def test_restore_cancellation_keeps_supervisor_responsive(self):
        self.put('/machine-config',{'mem_size_mib':64});self.start();self.pause()
        snapshot=self.work/'snapshot';self.capture(snapshot);self.stop()
        code,op=api(self.sock,'PUT','/snapshot/load',{'snapshot_path':str(snapshot)})
        self.assertEqual(code,202)
        self.assertEqual(api(self.sock,'PUT','/actions',{'action_type':'ForceStop'})[0],202)
        self.wait_state('Exited',10)
        self.assertEqual(api(self.sock,'GET','/metrics')[0],200)
        self.assertEqual(api(self.sock,'GET','/operations/'+str(op['operation_id']))[1]['status'],'cancelled')

    def test_all_disks_readonly_and_firmware_are_self_contained(self):
        self.put('/machine-config',{'vcpu_count':4,'mem_size_mib':64})
        sources=[]
        for index in range(4):
            disk=self.work/f'disk-{index}';disk.write_bytes(bytes([index+1])*8192);sources.append(disk)
            self.put('/drives/'+str(index),{'drive_id':str(index),'path_on_host':str(disk),'is_read_only':index%2==1})
        firmware=self.work/'firmware';firmware.write_bytes(b'firmware snapshot payload');sources.append(firmware)
        self.put('/firmware',{'opt/test/data':str(firmware)})
        self.start();self.pause();snapshot=self.work/'snapshot';self.capture(snapshot);self.stop()
        for index in range(4):self.assertEqual((snapshot/f'disk-{index}.bin').read_bytes(),bytes([index+1])*8192)
        for path in sources:path.unlink()
        self.kernel.unlink();self.load(snapshot)
        second=self.work/'second';self.capture(second)
        first=json.loads((snapshot/'manifest.json').read_text());last=json.loads((second/'manifest.json').read_text())
        for name in first['components']:
            if name.startswith(('disk-','firmware-')):self.assertEqual(first['components'][name],last['components'][name])
        self.assertEqual([d['is_read_only'] for d in last['config']['drives']],[False,True,False,True])

    def test_native_state_rejects_payload_corruption_even_with_matching_hash(self):
        self.put('/machine-config',{'mem_size_mib':64});self.start();self.pause()
        snapshot=self.work/'snapshot';self.capture(snapshot);self.stop()
        path=snapshot/'manifest.json';original=path.read_bytes()
        for name in ['cpu-0.bin','devices.bin','gic.bin']:
            component=snapshot/name;saved=component.read_bytes()
            # Manifest integrity alone does not replace native state validation.
            damaged=bytes(len(saved));component.write_bytes(damaged)
            manifest=json.loads(original);manifest['components'][name]['sha256']=hashlib.sha256(damaged).hexdigest()
            path.write_text(json.dumps(manifest));state=self.load(snapshot,'Failed')
            self.assertIsNotNone(state['last_error'])
            self.assertEqual(api(self.sock,'GET','/metrics')[0],200)
            component.write_bytes(saved);path.write_bytes(original)
