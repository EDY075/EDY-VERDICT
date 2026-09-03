// Node callers use the same closed-action PowerShell wrapper as QA. No Rust
// executable resolution or caller-supplied argv/environment overrides here.
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const actions=new Set(['MetadataWorkspace','MetadataWindows','DesktopProductionTree']);
export function projectRust(action){
  if(!actions.has(action))throw Error('PROJECT_RUST_ACTION_DENIED');
  return execFileSync('pwsh',['-NoProfile','-NonInteractive','-File',path.join(root,'scripts','Invoke-ProjectRust.ps1'),'-Action',action],{
    cwd:root,encoding:'utf8',maxBuffer:64*1024*1024,windowsHide:true,
    env:{...process.env,RUSTUP_HOME:path.join(root,'.local','rustup'),CARGO_HOME:path.join(root,'.local','cargo')},
  });
}
