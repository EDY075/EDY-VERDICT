import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {auditProject,directCalls,exceptions} from '../scripts/direct-rust-gate.mjs';

for(const tool of ['rustup','cargo','cargo-deny','rustc','rustfmt','clippy']){
  test(`direct ${tool} is denied in controlled script formats`,()=>{
    const cases=[
      [`${tool} --version`,'script.ps1'],
      [`& '.local/bin/${tool}.exe' --version`,'script.ps1'],
      [`Start-Process -FilePath "D:\\tools\\${tool}.exe"`,'script.ps1'],
      [`@${tool.toUpperCase()}.exe --version`,'script.cmd'],
      [`echo ok && ${tool} --version`,'script.sh'],
      [`spawn('${tool}', ['--version']);`,'e2e.mjs'],
      [`execFileSync(path.join(root,'${tool}.exe'), []);`,'e2e.mjs'],
      [`Command::new("${tool}").arg("--version").status();`,'build.rs'],
      [`- run: ${tool} --version`,'workflow.yml'],
      [`const toolPath = 'D:\\tools\\${tool}.exe';\nexecFileSync(toolPath, []);`,'audit.mjs'],
      [`$toolPath = Join-Path $root '${tool}.exe'\n& $toolPath --version`,'release.ps1'],
      [JSON.stringify({scripts:{qa:`${tool} --version`}}),'package.json'],
      ['```powershell\n'+tool+' --version\n```','README.md'],
    ];
    for(const [source,file] of cases)assert(directCalls(source,file).length>0,`${tool}: ${file}: ${source}`);
  });
}
test('ordinary wrappers, descriptions and inventory paths are not commands',()=>{
  assert.deepEqual(directCalls("& './scripts/Invoke-ProjectRust.ps1' -Action CargoDeny",'qa.ps1'),[]);
  assert.deepEqual(directCalls("Add-Tool 'Rust' (Join-Path $bin 'rustc.exe')",'inventory.ps1'),[]);
  assert.deepEqual(directCalls("const label = 'cargo';\nconsole.log(label);",'ui.mjs'),[]);
});
test('no wildcard exemption or argument-forwarding bridge',()=>{
  assert.equal(Object.keys(exceptions).length,4);
  assert(Object.keys(exceptions).every(file=>!file.includes('*')&&!file.endsWith('/')));
  const bridge=readFileSync('scripts/project-rust.mjs','utf8');
  assert.match(bridge,/if\(!actions.has\(action\)\)throw/);
  assert.doesNotMatch(bridge,/\.\.\.options|\.\.\.args/);
  const wrapper=readFileSync('scripts/Invoke-ProjectRust.ps1','utf8');
  assert(wrapper.indexOf('Assert-ProjectRustEnvironment.ps1')<wrapper.indexOf('$Executable = $null'));
  assert(wrapper.indexOf('direct-rust-gate.mjs')<wrapper.indexOf('$Executable = $null'));
  assert.match(wrapper,/\$env:RUSTC = \$Rustc/);
  assert.match(wrapper,/\$env:RUSTUP_AUTO_INSTALL = '0'/);
});
test('controlled repository automation has zero direct Rust invocations',()=>{
  assert.deepEqual(auditProject().findings,[]);
});
