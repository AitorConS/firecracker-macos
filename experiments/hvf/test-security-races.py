#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic path replacement between validation/open using copied real modules.
Only a one-shot scheduling hook is inserted; file opening/identity checks are real.
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-dir',type=Path,default=ROOT/'src/hvf-vmm/src');p.add_argument('--output',type=Path,required=True);p.add_argument('--expect-control-failures',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True);out=a.output.resolve();src=a.source_dir.resolve();hashes={}
 for name in ['resources.rs','block.rs','security.rs']:
  text=(src/name).read_text();hashes[name]=hashlib.sha256(text.encode()).hexdigest()
  if name=='resources.rs':
   if 'open_validated(path, writable, &expected)' in text:
    text=text.replace('open_validated(path, writable, &expected)','{ crate::run_hook(); open_validated(path, writable, &expected) }',1)
   else:text=text.replace('    let mut source = OpenOptions::new()', '    crate::run_hook();\n    let mut source = OpenOptions::new()',1)
  if name=='block.rs' and 'crate::resources::open_regular' not in text:text=text.replace('    let mut source = OpenOptions::new()', '    crate::run_hook();\n    let mut source = OpenOptions::new()',1)
  if name=='security.rs':text+='\npub(crate) fn profile_for_test(p: &Policy) -> &std::ffi::CStr { &p._vmm }\n'
  (out/name).write_text(text)
 (out/'source-hashes.json').write_text(json.dumps(hashes,indent=2))
 (out/'Cargo.toml').write_text('''[package]
name="hvf-path-race-probe"
version="0.0.0"
edition="2024"
[workspace]
[lib]
path="lib.rs"
[dependencies]
libc="=0.2.189"
serde={version="=1.0.229",features=["derive"]}
serde_json="=1.0.151"
tempfile="=3.27.0"
''')
 (out/'lib.rs').write_text('''#![allow(dead_code)]
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Drive {drive_id:String,path_on_host:std::path::PathBuf,is_root_device:bool,copy_on_start:bool,is_read_only:bool}
mod resources; mod block; mod security;
thread_local! {static HOOK:std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);}
fn run_hook(){let hook=HOOK.with(|h|h.borrow_mut().take());if let Some(h)=hook {h();}}
fn race(disk:bool,kind:u8){
 let t=tempfile::tempdir().unwrap();let dir=t.path().join("selected");std::fs::create_dir(&dir).unwrap();let path=dir.join("file");std::fs::write(&path,vec![7;4096]).unwrap();let outside=t.path().join("outside");std::fs::create_dir(&outside).unwrap();std::fs::write(outside.join("file"),vec![9;4096]).unwrap();
 let chosen=path.clone();let parent=dir.clone();let old=t.path().join("old");let target=outside.clone();
 HOOK.with(|h|h.replace(Some(Box::new(move||{match kind {
  0=>{std::fs::rename(&chosen,&old).unwrap();std::fs::write(&chosen,vec![9;4096]).unwrap();},
  1=>{std::fs::rename(&parent,&old).unwrap();std::fs::create_dir(&parent).unwrap();std::fs::write(parent.join("file"),vec![9;4096]).unwrap();},
  2=>{std::fs::rename(&parent,&old).unwrap();std::os::unix::fs::symlink(&target,&parent).unwrap();},
  3=>{std::fs::rename(&chosen,&old).unwrap();std::os::unix::fs::symlink(target.join("file"),&chosen).unwrap();},_=>unreachable!()}
 }))));
 let result=if disk {let d=Drive{drive_id:"d".into(),path_on_host:path,is_root_device:false,copy_on_start:false,is_read_only:false};block::open(&d,&t.path().join("copy")).map(|_|())}else{resources::stage(&path,&t.path().join("copy"),4096,&std::sync::atomic::AtomicBool::new(false)).map(|_|())};
 assert!(HOOK.with(|h|h.borrow().is_none()),"hook not reached");println!("disk={disk} race={kind} rejected={} error={:?}",result.is_err(),result.as_ref().err());assert!(result.is_err(),"replacement accepted");assert_eq!(std::fs::read(outside.join("file")).unwrap(),vec![9;4096]);
}
macro_rules! case {($name:ident,$disk:expr,$kind:expr)=>{#[test]fn $name(){race($disk,$kind);}}}
case!(stage_file,false,0);case!(stage_parent_dir,false,1);case!(stage_parent_symlink,false,2);case!(stage_final_symlink,false,3);
case!(disk_file,true,0);case!(disk_parent_dir,true,1);case!(disk_parent_symlink,true,2);case!(disk_final_symlink,true,3);
#[test]fn disk_profile_replacement(){
 let t=tempfile::tempdir().unwrap();let work=t.path().join("private");std::fs::create_dir(&work).unwrap();let path=t.path().join("disk");let target=t.path().join("outside");std::fs::write(&path,vec![7;4096]).unwrap();std::fs::write(&target,vec![9;4096]).unwrap();
 let d=Drive{drive_id:"d".into(),path_on_host:path.clone(),is_root_device:false,copy_on_start:false,is_read_only:false};let _selected=block::open(&d,&work.join("copy")).unwrap();std::fs::remove_file(&path).unwrap();std::os::unix::fs::symlink(&target,&path).unwrap();
  let p=security::Policy::new(&security::Security::default(),&work,&[d]).unwrap();let profile=security::profile_for_test(&p).to_str().unwrap();println!("profile={profile}");let canonical=std::fs::canonicalize(&target).unwrap();let result=std::process::Command::new(std::env::var("HVF_PROFILE_HELPER").unwrap()).args([profile,canonical.to_str().unwrap()]).output().unwrap();println!("helper={} {}",result.status,String::from_utf8_lossy(&result.stdout));assert!(result.status.success(),"replacement path granted after disk opened: {}",String::from_utf8_lossy(&result.stderr));
}
''')
 helper=out/'profile-helper';subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-I'+str(ROOT/'src/hvf-vmm/native'),str(ROOT/'experiments/hvf/test-security-profile.c'),str(ROOT/'src/hvf-vmm/native/sandbox.c'),'-o',str(helper)],check=True)
 env={**os.environ,'RUSTUP_TOOLCHAIN':'1.97.0','HVF_PROFILE_HELPER':str(helper)}
 if not shutil.which('cargo'):
  env.update(RUSTUP_HOME=str(ROOT/'experiments/hvf/build/rustup'),CARGO_HOME=str(ROOT/'experiments/hvf/build/cargo'))
  env['PATH']=env['CARGO_HOME']+'/bin:'+env.get('PATH','/usr/bin:/bin')
 # The Seatbelt helper forks: serialize tests so its pre-exec descriptor copy
 # cannot transiently retain another test's flock after that test closes it.
 cmd=['cargo','test','--offline','--manifest-path',str(out/'Cargo.toml'),'--target-dir',str(out/'target'),'--','--nocapture','--test-threads=1'];result=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=90);(out/'tests.log').write_text(result.stdout+result.stderr);print(result.stdout+result.stderr);summary={'command':cmd,'exit':result.returncode,'expected_control_failures':a.expect_control_failures};(out/'result.json').write_text(json.dumps(summary,indent=2))
 if a.expect_control_failures:
  assert result.returncode==101 and '7 failed' in result.stdout and '7 passed' in result.stdout,summary
  assert 'replacement_path_access=1' in result.stdout, 'control profile must prove real access; sandbox installation failure is not evidence'
 else:assert result.returncode==0,summary
if __name__=='__main__':main()
