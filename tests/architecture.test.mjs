import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--locked', '--format-version', '1'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
const libraries = ['edy-core','edy-engine-manager','edy-providers','edy-storage','edy-reporting'];
const allowed = Object.fromEntries(libraries.map(n=>[n,n==='edy-core'?[]:['edy-core']]));
allowed['edy-cli'] = libraries;
allowed['edy-desktop'] = libraries;

test('workspace has exactly the frozen crates and internal edges', () => {
  assert.deepEqual(metadata.packages.map(p=>p.name).sort(), Object.keys(allowed).sort());
  for (const p of metadata.packages) {
    const internal = p.dependencies.filter(d=>d.name.startsWith('edy-')).map(d=>d.name).sort();
    assert.deepEqual(internal, [...allowed[p.name]].sort(),p.name);
  }
});
test('core cannot depend on infrastructure directly or transitively', () => {
  const core=metadata.packages.find(p=>p.name==='edy-core');
  assert.deepEqual(core.dependencies.map(d=>d.name).sort(),['serde','serde_json']);
  assert.match(readFileSync('crates/edy-core/src/lib.rs','utf8'),/forbid\(unsafe_code\)/);
  assert.doesNotMatch(readFileSync('crates/edy-core/src/lib.rs','utf8'),/\b(tauri|tokio|rusqlite|reqwest|webview2)\s*::/i);
  const full=JSON.parse(execFileSync('cargo',['metadata','--locked','--format-version','1','--filter-platform','x86_64-pc-windows-msvc'],{encoding:'utf8',maxBuffer:64*1024*1024}));
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
  assert.deepEqual(cap.permissions,['allow-foundation-status']);
  for(const p of metadata.packages) assert(!p.dependencies.some(d=>d.name.startsWith('tauri-plugin-')));
  const source=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  assert.match(source,/generate_handler!\[foundation_status\]/);
  assert.equal((source.match(/#\[tauri::command\]/g)||[]).length,1);
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
