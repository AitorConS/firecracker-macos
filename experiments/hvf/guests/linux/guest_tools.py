"""Check the locked guest compiler/extractors and report build provenance."""
import hashlib,json,os,platform,shutil,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
LOCK=json.loads((HERE/'tools.json').read_text())
def compiler(path=None):
    if path is None:
        path=subprocess.check_output([sys.executable,HERE/'bootstrap-tools.py'],text=True).strip()
    path=str(Path(path).resolve())
    version=subprocess.check_output([path,'version'],text=True,env={**os.environ,'GOTOOLCHAIN':'local'}).split()[2]
    if version!=LOCK['go']['version']:raise RuntimeError('Go version differs from tools.json')
    return path

def extractor(name):
    path='/usr/bin/bsdtar' if name=='bsdtar' else shutil.which(os.environ.get('UNSQUASHFS','unsquashfs'))
    if not path:raise RuntimeError('unsquashfs is required to prepare Alpine; see tools.json')
    path=Path(path).resolve();lock=LOCK[name]
    version=subprocess.run([path,'--version' if name=='bsdtar' else '-version'],capture_output=True,text=True).stdout.strip()
    if not version.startswith(lock['version_prefix']) or hashlib.sha256(path.read_bytes()).hexdigest()!=lock['sha256']:
        raise RuntimeError(name+' differs from tools.json: verify the new extractor and explicitly update the lock')
    return str(path)

def provenance(work,go,extractors):
    paths={'go':go,**extractors}
    report={'host':platform.platform(),'python':sys.version,'tools':{name:{'path':str(path),'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest()} for name,path in paths.items()},
            'outputs':{name:hashlib.sha256((work/name).read_bytes()).hexdigest() for name in ['Image','test-initrd.gz']}}
    (work/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
