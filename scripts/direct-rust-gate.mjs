// Read-only, dependency-free static gate for controlled automation. This is not
// shell interception or a proof against deliberately obfuscated hostile code.
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const exceptions=Object.freeze({
  'scripts/Invoke-ProjectRust.ps1':'closed-action project-local execution owner',
  'scripts/Invoke-GlobalRustInventory.ps1':'explicit neutral-CWD read-only inventory owner',
  'scripts/direct-rust-gate.mjs':'static gate source; command names are detection data',
  'tests/direct-rust-gate.test.mjs':'inert adversarial command strings, never executed',
});
const tool=String.raw`(?:cargo(?:-[a-z0-9_-]+)?|rustup|rustc|rustdoc|rustfmt|clippy(?:-driver)?)(?:\.exe)?`;
const executable=new RegExp(String.raw`(?:^|[/\\\s"'\x60])${tool}(?=$|[\s"'\x60,;)])`,'i');
const bare=new RegExp(String.raw`(?:^|[\n;&|{}])\s*(?:@|call\s+|exec\s+|&\s*)?["']?(?:[^\s"';&|]*[/\\])?${tool}["']?(?=\s|$)`,'im');
const processCall=/\b(?:execFileSync|execFile|execSync|exec|spawnSync|spawn|execa|execaSync|Command::new)\s*\(/g;
function firstArgument(source,start){
  let depth=0,quote=null,escaped=false,index=start;
  for(;index<source.length;index++){
    const character=source[index];
    if(quote){if(escaped)escaped=false;else if(character==='\\')escaped=true;else if(character===quote)quote=null;continue;}
    if(['"',"'",'`'].includes(character)){quote=character;continue;}
    if('([{'.includes(character))depth++;
    else if(')]}'.includes(character)){if(depth===0)break;depth--;}
    else if(character===','&&depth===0)break;
  }
  return source.slice(start,index);
}

export function directCalls(source,file){
  if(file.endsWith('package.json')){
    const parsed=JSON.parse(source);
    return Object.entries(parsed.scripts??{}).flatMap(([name,value])=>directCalls(String(value),`${file}:${name}.sh`));
  }
  if(file.endsWith('.md')){
    return [...source.matchAll(/```(?:powershell|ps1|bash|sh|shell|cmd|bat)\s*\n([\s\S]*?)```/gi)].flatMap(match=>directCalls(match[1],`${file}.sh`));
  }
  const clean=source.replace(/^\s*(?:#|\/\/|REM\s).*$/gim,'').replace(/^\s*(?:-\s*)?(?:run|command|script):(?=\s|$)\s*/gim,'');
  const results=[];
  if(bare.test(clean))results.push('direct shell Rust command');
  const aliases=new Set();
  for(const line of clean.split(/\r?\n/)){
    const assignment=line.match(/(?:\b(?:const|let|var)\s+|\$)([\w]+)\s*=\s*(.+)/);
    if(assignment&&executable.test(assignment[2]))aliases.add(assignment[1].toLowerCase());
  }
  // Fixed-point alias propagation catches simple renamed executable variables.
  for(let pass=0;pass<8;pass++)for(const match of clean.matchAll(/(?:\b(?:const|let|var)\s+|\$)([\w]+)\s*=\s*\$?([\w]+)\s*[;\r\n]/g)){
    if(aliases.has(match[2].toLowerCase()))aliases.add(match[1].toLowerCase());
  }
  const suspicious=value=>executable.test(value)||[...aliases].some(alias=>new RegExp(`^\\$?${alias}\\b`,'i').test(value.trim()));
  for(const match of clean.matchAll(processCall))if(suspicious(firstArgument(clean,match.index+match[0].length)))results.push('direct child-process Rust command');
  for(const match of clean.matchAll(/(?:&\s+|\bStart-Process\s+(?:-FilePath\s+)?)("[^"]*"|'[^']*'|\([^)]*\)|[^\s;]+)/gi))if(suspicious(match[1]))results.push('direct PowerShell Rust command');
  // A Tauri CLI script can indirectly resolve Cargo without the project wrapper.
  if(/(?:^|[;&|\n])\s*(?:(?:pnpm|npx)\s+)?tauri(?:\.exe)?(?:\s|$)/im.test(clean))results.push('unwrapped Tauri build entry');
  return [...new Set(results)];
}

export function auditProject(){
  const paths=[...new Set(execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root,encoding:'utf8',windowsHide:true}).split('\0').filter(Boolean))];
  const findings=[];let scanned=0;
  for(const file of paths){
    // Imported archival documents and license texts are data, not automation.
    if(file.startsWith('docs/legacy/')||exceptions[file])continue;
    if(!/\.(?:ps1|psm1|bat|cmd|sh|bash|mjs|cjs|js|ts|rs|yml|yaml|md)$/.test(file)&&!file.endsWith('package.json'))continue;
    scanned++;
    const source=readFileSync(path.join(root,file),'utf8');
    for(const reason of directCalls(source,file))findings.push({file,reason});
  }
  return {schema:'EDY_DIRECT_RUST_GATE_V1',scanned,exceptions,findings,direct_invocations:findings.length,result:findings.length?'FAIL':'PASS'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const result=auditProject();
  if(!process.argv.includes('--quiet')||result.findings.length)console.log(JSON.stringify(result,null,2));
  if(result.findings.length)process.exitCode=1;
}
