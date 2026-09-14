#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run cargo --no-run artifacts in private network namespaces, preserving results."""
import argparse,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--build-log',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--only',help='Exact test executable basename to rerun');p.add_argument('--filter',help='Run only matching libtest names');a=p.parse_args()
executables=re.findall(r'Executable .*?\(([^\n]+)\)',a.build_log.read_text())
if not executables:raise SystemExit('no compiled test artifacts found')
a.output.mkdir(parents=True,exist_ok=True);results=[]
for name in executables:
    path=Path(name);path=path if path.is_absolute() else a.source/path
    if a.only and path.name!=a.only:continue
    package='firecracker' if path.name.startswith(('firecracker-','verify_dependencies-')) else 'vmm'
    manifest=(a.source/'src'/package).resolve()
    log=a.output/(path.name+'.log')
    with log.open('wb') as f:
        process=subprocess.Popen(['sudo','-n','unshare','--net','env',f'CARGO_MANIFEST_DIR={manifest}','sh','-c','ip link set lo up; exec "$@"','sh',str(path.resolve()),'--test-threads=1']+([a.filter] if a.filter else []),cwd=manifest,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
        try:code=process.wait(timeout=600)
        except subprocess.TimeoutExpired:code=124
        finally:
            if process.poll() is None:
                subprocess.run(['sudo','-n','kill','-KILL','--',f'-{process.pid}'],check=True)
                process.wait(timeout=5)
    text=log.read_text(errors='replace');summaries=re.findall(r'test result: .*',text)
    result={'binary':path.name,'exit_code':code,'summary':summaries,'log':str(log)};results.append(result);print(json.dumps(result),flush=True)
if not results:raise SystemExit('no matching test artifacts executed')
(a.output/'unit-result.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(0 if all(r['exit_code']==0 for r in results) else 1)
