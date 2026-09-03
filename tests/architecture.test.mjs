import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const projectRoot=path.resolve('.');
const rustupHome=path.join(projectRoot,'.local','rustup');const cargoHome=path.join(projectRoot,'.local','cargo');
const toolchainBin=path.join(rustupHome,'toolchains','1.98.0-x86_64-pc-windows-msvc','bin');const cargoExe=path.join(toolchainBin,'cargo.exe');
assert(existsSync(cargoExe),'project-local Cargo toolchain required');
const rustEnv={...process.env,RUSTUP_HOME:rustupHome,CARGO_HOME:cargoHome,RUSTC:path.join(toolchainBin,'rustc.exe'),RUSTDOC:path.join(toolchainBin,'rustdoc.exe'),PATH:`${toolchainBin}${path.delimiter}${process.env.PATH??''}`};
const cargo=(args,options={})=>execFileSync(cargoExe,args,{encoding:'utf8',env:rustEnv,...options});
const metadata = JSON.parse(cargo(['metadata', '--no-deps', '--locked', '--format-version', '1'], { maxBuffer: 16 * 1024 * 1024 }));
const allowed = {
  'edy-core': [],
  'edy-repository': ['edy-core'],
  'edy-engine-manager': ['edy-core','edy-repository'],
  'edy-providers': ['edy-core'],
  'edy-storage': ['edy-core'],
  'edy-reporting': ['edy-core','edy-engine-manager','edy-repository'],
  'edy-cli': ['edy-core','edy-engine-manager','edy-providers','edy-reporting','edy-storage'],
  'edy-desktop': ['edy-core','edy-engine-manager','edy-providers','edy-reporting','edy-repository','edy-storage'],
};

test('workspace has exactly the frozen crates and internal edges', () => {
  assert.deepEqual(metadata.packages.map(p=>p.name).sort(), Object.keys(allowed).sort());
  for (const p of metadata.packages) {
    const internal = p.dependencies.filter(d=>d.name.startsWith('edy-')).map(d=>d.name).sort();
    assert.deepEqual(internal, [...allowed[p.name]].sort(),p.name);
  }
});
test('core cannot depend on infrastructure directly or transitively', () => {
  const core=metadata.packages.find(p=>p.name==='edy-core');
  assert.deepEqual(core.dependencies.map(d=>d.name).sort(),['serde','serde_json','sha2']);
  assert.match(readFileSync('crates/edy-core/src/lib.rs','utf8'),/forbid\(unsafe_code\)/);
  assert.doesNotMatch(readFileSync('crates/edy-core/src/lib.rs','utf8'),/\b(tauri|tokio|rusqlite|reqwest|webview2)\s*::/i);
  const full=JSON.parse(cargo(['metadata','--locked','--format-version','1','--filter-platform','x86_64-pc-windows-msvc'],{maxBuffer:64*1024*1024}));
  const byId=new Map(full.packages.map(p=>[p.id,p]));const nodes=new Map(full.resolve.nodes.map(n=>[n.id,n]));
  const pending=[core.id];const seen=new Set();
  while(pending.length){const id=pending.pop();if(seen.has(id))continue;seen.add(id);assert.doesNotMatch(byId.get(id).name,/^(tauri|tokio|rusqlite|libsqlite3|reqwest|webview|wry|edy-(?!core))/);pending.push(...(nodes.get(id)?.dependencies||[]));}
});
test('no dangerous capability, generic IPC or plugin can be added silently', () => {
  const config=JSON.parse(readFileSync('apps/desktop/src-tauri/tauri.conf.json'));
  const security=config.app.security;
  assert.equal(config.app.withGlobalTauri,false);
  assert.equal(security.freezePrototype,true);
  assert.equal(security.dangerousDisableAssetCspModification,false);
  assert.equal(security.assetProtocol.enable,false);
  assert.deepEqual(security.capabilities,['main']);
  assert.equal(security.pattern.use,'isolation');
  assert.equal(security.csp['default-src'],"'none'");
  assert.equal(security.csp['connect-src'],'ipc: http://ipc.localhost');
  assert.doesNotMatch(JSON.stringify(security.csp),/\*|unsafe-eval|unsafe-inline|https:/);
  assert.deepEqual(config.plugins,{});
  assert.equal(config.bundle.active,false);
  assert.deepEqual(readdirSync('apps/desktop/src-tauri/capabilities'),['main.json']);
  const cap=JSON.parse(readFileSync('apps/desktop/src-tauri/capabilities/main.json'));
  assert.deepEqual(cap.windows,['main']);
  assert.equal(cap.remote,undefined);
  const commands=['get-foundation-status','get-engine-status','authorize-repository-target','inspect-repository-target','create-repository-scan','get-repository-inventory','inspect-file-target','authorize-file-target','create-file-scan','get-file-analysis','preview-installed-applications','authorize-installed-applications','create-installed-application-scan','get-installed-application-inventory','get-installed-application','get-vulnerability-provider-status','refresh-public-vulnerability-data','preview-url-target','authorize-url-target','create-url-scan','get-url-scan-analysis','get-url-redirect-chain','get-url-security-headers','get-url-cookie-observations','get-url-reputation-status','create-synthetic-scan','get-scan','list-scans','get-scan-progress','cancel-scan','list-findings','get-finding','generate-report','run-level5-correlation','cancel-level5-correlation','list-investigation-clusters','get-investigation-cluster','list-investigation-cases','get-investigation-case','create-investigation-case','update-investigation-case','get-investigation-graph','get-investigation-timeline','generate-investigation-report'];
  assert.deepEqual(cap.permissions,commands.map(command=>`allow-${command}`));
  for(const p of metadata.packages) {
    const plugins=p.dependencies.filter(d=>d.name.startsWith('tauri-plugin-'));
    if(p.name !== 'edy-desktop') assert.deepEqual(plugins,[]);
    else {
      assert.equal(plugins.length,1);
      assert.equal(plugins[0].name,'tauri-plugin-wdio-webdriver');
      assert.equal(plugins[0].req,'=1.3.0');
      assert.equal(plugins[0].optional,true);
      assert.deepEqual(p.features.default,[]);
      assert.deepEqual(p.features['native-e2e'],['dep:tauri-plugin-wdio-webdriver']);
    }
  }
  const source=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  for(const command of commands) assert.match(source,new RegExp(`\\b${command.replaceAll('-','_')}\\b`));
  assert.equal((source.match(/#\[tauri::command\]/g)||[]).length,commands.length);
});
test('native driver is opt-in debug-only and absent from the default production graph',()=>{
  const source=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  assert.match(source,/#\[cfg\(all\(feature = "native-e2e", not\(debug_assertions\)\)\)\]\s*compile_error!/);
  assert.match(source,/#\[cfg\(all\(feature = "native-e2e", debug_assertions\)\)\]\s*let builder = \{[\s\S]*?native_qa_size.is_none\(\)[\s\S]*?builder.plugin\(tauri_plugin_wdio_webdriver::init_with_port\(4445\)\)/);
  const tree=cargo(['tree','-p','edy-desktop','--locked','--edges','normal','--prefix','none']);
  assert.doesNotMatch(tree,/tauri-plugin-wdio|\baxum\b/);
  for(const name of ['main.tsx','App.tsx']) assert.doesNotMatch(readFileSync(`apps/desktop/src/${name}`,'utf8'),/wdio|webdriver|__TAURI_INTERNALS__/);
});
test('approved pins, lockfiles and script restrictions are present', () => {
  const p=JSON.parse(readFileSync('package.json'));
  assert.equal(p.packageManager,'pnpm@11.25.0');
  const cfg=readFileSync('pnpm-workspace.yaml','utf8');
  for (const control of ['ignoreScripts: true','ignorePnpmfile: true','verifyDepsBeforeRun: error','verifyStoreIntegrity: true']) assert(cfg.includes(control));
  assert(readFileSync('Cargo.lock').length>0);assert(readFileSync('pnpm-lock.yaml').length>0);
  const desktop=JSON.parse(readFileSync('apps/desktop/package.json'));
  for (const version of Object.values({...desktop.dependencies,...desktop.devDependencies})) assert.match(version,/^\d+\.\d+\.\d+$/);
});
