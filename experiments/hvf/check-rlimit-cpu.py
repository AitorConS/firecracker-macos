#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce HVF execution with/without RLIMIT_CPU, never infer compatibility."""
import json,os,struct,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='hvf-cpu-limit-') as work:
    ram=Path(work)/'ram.bin'
    with ram.open('wb') as f:
        f.truncate(128<<20);f.seek(0x400000);f.write(struct.pack('<III',0x52800100,0x72b08000,0xd4000002))
    results={}
    for mode in ['baseline','rlimit_cpu']:
        env=dict(os.environ);env.pop('HVF_PROBE_CPU_LIMIT',None)
        if mode=='rlimit_cpu':env['HVF_PROBE_CPU_LIMIT']='86400'
        with subprocess.Popen([str(root/'build/hvf-probe'),str(ram),'40400000'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
            timeout=False
            try:out,err=p.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                timeout=True;p.kill();out,err=p.communicate()
            results[mode]={'exit_code':p.returncode,'timeout':timeout,'stderr':err.decode(errors='replace')}
    assert results['baseline']['exit_code']==0,results
    results['rlimit_cpu_hvf_compatible']=results['rlimit_cpu']['exit_code']==0
    print(json.dumps(results,indent=2))
