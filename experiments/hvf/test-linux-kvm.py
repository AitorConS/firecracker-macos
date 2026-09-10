#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pending Linux/KVM verifier. Requires a native Linux host and upstream guest config."""
import argparse,fcntl,json,os,platform,shutil,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path,help='Upstream Firecracker JSON; absolute kernel/initrd/disk paths')
    parser.add_argument('--boot-marker',required=True,help='Guest serial text proving the intended workload reached readiness')
    parser.add_argument('--timeout',type=int,default=60)
    parser.add_argument('--output',type=Path,default=ROOT/'experiments/hvf/build/kvm-validation')
    args=parser.parse_args()
    if platform.system()!='Linux':parser.error('PENDING: requires Linux with /dev/kvm; macOS/HVF is not a substitute')
    if not 1<=args.timeout<=600:parser.error('--timeout must be 1..600')
    with open('/dev/kvm','rb',buffering=0) as kvm:
        if fcntl.ioctl(kvm,0xae00,0)!=12:raise RuntimeError('unexpected KVM API version')
    cfg=json.loads(args.config.read_text())
    args.output.mkdir(parents=True,exist_ok=True)
    # Build and unit tests belong to the original Linux backend. Capture evidence
    # separately from the hardware guest smoke; neither implies upstream parity.
    with (args.output/'build-test.log').open('wb') as log:
        subprocess.run(['cargo','build','--release','-p','firecracker'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
        subprocess.run(['cargo','test','-p','vmm','-p','firecracker'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
    target=Path(os.environ.get('CARGO_TARGET_DIR',ROOT/'build/cargo_target'))
    binary=target/'release/firecracker'
    with tempfile.TemporaryDirectory(prefix='firecracker-kvm-') as td:
        work=Path(td)
        for index,drive in enumerate(cfg.get('drives',[])):
            source=Path(drive['path_on_host'])
            if not source.is_absolute():raise ValueError('drive paths must be absolute')
            # Preserve caller assets even when the guest writes to a block device.
            destination=work/f'disk-{index}';shutil.copyfile(source,destination);drive['path_on_host']=str(destination)
        for key in ['kernel_image_path','initrd_path']:
            path=cfg['boot-source'].get(key)
            if path and not Path(path).is_absolute():raise ValueError('boot paths must be absolute')
        config=work/'config.json';config.write_text(json.dumps(cfg))
        logfile=args.output/'guest.log';ready=False;code=None
        with logfile.open('wb') as log:
            process=subprocess.Popen([str(binary),'--no-api','--config-file',str(config)],stdout=log,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+args.timeout
                while time.monotonic()<deadline:
                    if args.boot_marker.encode() in logfile.read_bytes():ready=True;break
                    if process.poll() is not None:break
                    time.sleep(.1)
            finally:
                if process.poll() is None:process.terminate()
                try:code=process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();code=process.wait(timeout=5)
        report={'host':platform.platform(),'kvm_api':12,'guest_marker_observed':ready,'exit_code':code,
                'scope':'native build, unit tests, KVM guest serial readiness; no parity or performance claim'}
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        if not ready:raise RuntimeError(f'guest marker not observed; inspect {logfile}')
        print(json.dumps(report,indent=2))
if __name__=='__main__':main()
