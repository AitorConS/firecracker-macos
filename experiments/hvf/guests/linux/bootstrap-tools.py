#!/usr/bin/env python3
"""Install the checksum-pinned Go compiler into the private HVF build directory."""
import hashlib,json,os,subprocess,tarfile,urllib.request
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
lock=json.loads((HERE/'tools.json').read_text())['go']
work=ROOT/'experiments/hvf/build/guest-tools';work.mkdir(parents=True,exist_ok=True)
archive=work/lock['filename']
if not archive.exists():
    temporary=archive.with_suffix('.partial')
    with urllib.request.urlopen(lock['url'],timeout=60) as response, temporary.open('wb') as output:
        while chunk:=response.read(131072):output.write(chunk)
    temporary.replace(archive)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['sha256']:raise SystemExit('Go archive checksum mismatch')
if not (work/'go/bin/go').exists():
    with tarfile.open(archive) as source:source.extractall(work)
version=subprocess.check_output([work/'go/bin/go','version'],text=True,env={**os.environ,'GOTOOLCHAIN':'local'})
if version.split()[2]!=lock['version']:raise SystemExit('Go version mismatch')
print(work/'go/bin/go')
