import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import {projectRust} from '../scripts/project-rust.mjs';
const metadata = JSON.parse(projectRust('MetadataWorkspace'));
const allowed = {
  'edy-core': [],
  'edy-remediation': [],
  'edy-repository': ['edy-core'],
  'edy-engine-manager': ['edy-core','edy-repository'],
  'edy-providers': ['edy-core'],
  'edy-storage': ['edy-core','edy-remediation'],
  'edy-reporting': ['edy-core','edy-engine-manager','edy-remediation','edy-repository'],
  'edy-cli': ['edy-core','edy-engine-manager','edy-providers','edy-reporting','edy-storage'],
  'edy-desktop': ['edy-core','edy-engine-manager','edy-providers','edy-remediation','edy-reporting','edy-repository','edy-storage'],
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
  const full=JSON.parse(projectRust('MetadataWindows'));
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
  const commands=['get-foundation-status','get-engine-status','authorize-repository-target','inspect-repository-target','create-repository-scan','get-repository-inventory','inspect-file-target','authorize-file-target','create-file-scan','get-file-analysis','preview-installed-applications','authorize-installed-applications','create-installed-application-scan','get-installed-application-inventory','get-installed-application','get-vulnerability-provider-status','refresh-public-vulnerability-data','preview-url-target','authorize-url-target','create-url-scan','get-url-scan-analysis','get-url-redirect-chain','get-url-security-headers','get-url-cookie-observations','get-url-reputation-status','create-synthetic-scan','get-scan','list-scans','get-scan-progress','cancel-scan','list-findings','get-finding','generate-report','run-level5-correlation','cancel-level5-correlation','list-investigation-clusters','get-investigation-cluster','list-investigation-cases','get-investigation-case','create-investigation-case','update-investigation-case','get-investigation-graph','get-investigation-timeline','generate-investigation-report','list-remediation-candidates','cancel-remediation-verification','create-remediation-plan','get-remediation-plan','list-remediation-plans','preview-remediation-action','authorize-remediation-action','get-remediation-action-status','verify-remediation-action','get-verification-result','list-case-remediation-actions','generate-remediation-report'];
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
      assert.deepEqual(p.features['native-e2e'],['dep:tauri-plugin-wdio-webdriver','edy-remediation/native-e2e']);
    }
  }
  const source=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  for(const command of commands) assert.match(source,new RegExp(`\\b${command.replaceAll('-','_')}\\b`));
  assert.equal((source.match(/#\[tauri::command\]/g)||[]).length,commands.length);
});
test('L6-S01 production mutation is absent by compilation, routing and capabilities',()=>{
  const lib=readFileSync('crates/edy-remediation/src/lib.rs','utf8');
  for(const name of ['executor','service']) assert(lib.includes('#[cfg(any(test, feature = "test-remediation-executor"))]\nmod '+name+';'));
  assert.match(lib,/test-remediation-executor is forbidden in production release builds/);
  const backend=readFileSync('apps/desktop/src-tauri/src/remediation.rs','utf8');
  const manual=readFileSync('crates/edy-remediation/src/manual.rs','utf8');
  assert.doesNotMatch(backend,/apply_exact_edit|rollback_exact_edit|RemediationService|inspect_recovery_journal|ReplaceFile|write_all|fs::write|File::create/);
  assert.doesNotMatch(manual,/std::fs|OpenOptions|apply_exact_edit|rollback_exact_edit/);
  const main=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  const caps=JSON.stringify(JSON.parse(readFileSync('apps/desktop/src-tauri/capabilities/main.json')).permissions);
  assert.doesNotMatch(main,/fn apply_remediation_action|fn rollback_remediation_action/);
  assert.doesNotMatch(caps,/allow-apply-remediation-action|allow-rollback-remediation-action|write-file|patch-file|replace-text|execute-command/);
});
test('native driver is opt-in debug-only and absent from the default production graph',()=>{
  const source=readFileSync('apps/desktop/src-tauri/src/main.rs','utf8');
  assert.match(source,/#\[cfg\(all\(feature = "native-e2e", not\(debug_assertions\)\)\)\]\s*compile_error!/);
  assert.match(source,/#\[cfg\(all\(feature = "native-e2e", debug_assertions\)\)\]\s*let builder = \{[\s\S]*?native_qa_size.is_none\(\)[\s\S]*?builder.plugin\(tauri_plugin_wdio_webdriver::init_with_port\(4445\)\)/);
  const tree=projectRust('DesktopProductionTree');
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

test('release-candidate identity is coherent across Cargo, frontend, Tauri and reports', () => {
  const version='1.0.0-rc.1';
  const rootPackage=JSON.parse(readFileSync('package.json','utf8'));
  const desktopPackage=JSON.parse(readFileSync('apps/desktop/package.json','utf8'));
  const tauri=JSON.parse(readFileSync('apps/desktop/src-tauri/tauri.conf.json','utf8'));
  const workspace=readFileSync('Cargo.toml','utf8');
  const product=readFileSync('apps/desktop/src/product.ts','utf8');
  assert.equal(rootPackage.version,version);
  assert.equal(desktopPackage.version,version);
  assert.equal(tauri.version,version);
  assert.equal(tauri.productName,'EDY VERDICT');
  assert.match(workspace,new RegExp(`\\[workspace\\.package\\][\\s\\S]*?version = "${version.replaceAll('.','\\.')}"`));
  assert(product.includes(`PRODUCT_VERSION = "${version}"`));
  for(const name of ['edy-cli','edy-core','edy-desktop','edy-engine-manager','edy-providers','edy-remediation','edy-reporting','edy-repository','edy-storage']){
    const entry=new RegExp(`name = "${name}"\\r?\\nversion = "${version.replaceAll('.','\\.')}"`);
    assert.match(readFileSync('Cargo.lock','utf8'),entry);
  }
  assert.match(readFileSync('crates/edy-reporting/src/lib.rs','utf8'),/PRODUCT_VERSION.*env!\("CARGO_PKG_VERSION"\)/);
});
