// Real Windows Tauri/WebView2 end-to-end tests. No mock IPC, browser server or engines.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { createReadStream, closeSync, existsSync, ftruncateSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'));
const ledger = realpathSync(process.env.EDY_E2E_LEDGER ?? '');
assert(ledger.startsWith(path.resolve(root, '../_intake') + path.sep), 'explicit external project ledger required');
assert.equal(process.platform, 'win32');
const runId = Date.now().toString();
const fixtureRoot = path.join(root, '.local', `level2-e2e-fixtures-${runId}`);
const elementKey='element-6066-11e4-a52e-4f735466cecf';
class Element {
  constructor(driver,id){this.driver=driver;this.id=id;}
  async command(pathname,method='GET',body){return this.driver.request(`/element/${this.id}${pathname}`,method,body);}
  async click(){return this.command('/click','POST',{});}
  async clear(){return this.command('/clear','POST',{});}
  async setValue(value){await this.clear();return this.command('/value','POST',{text:value});}
  async getText(){return this.command('/text');}
  async isExisting(){return true;}
  async isEnabled(){return this.command('/enabled');}
  async waitForEnabled({timeout}){return until(async()=>this.isEnabled(),'element enabled',timeout);}
}
class Driver {
  constructor(sessionId){this.sessionId=sessionId;}
  static async connect(){
    const response=await fetch('http://127.0.0.1:4445/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capabilities:{alwaysMatch:{browserName:'tauri','wdio:tauriServiceOptions':{windowLabel:'main'}},firstMatch:[{}]}})});
    const body=await response.json();if(!response.ok)throw new Error(JSON.stringify(body));return new Driver(body.value.sessionId);
  }
  async request(pathname,method='GET',body){
    const response=await fetch(`http://127.0.0.1:4445/session/${this.sessionId}${pathname}`,{method,headers:{'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    const result=await response.json();if(!response.ok)throw new Error(`${method} ${pathname}: ${JSON.stringify(result.value)}`);return result.value;
  }
  async elements(selector){return (await this.request('/elements','POST',{using:'css selector',value:selector})).map(item=>new Element(this,item[elementKey]));}
  async $(selector){
    if(selector.startsWith('button=')){const wanted=selector.slice(7);for(const e of await this.elements('button'))if(await e.getText()===wanted)return e;throw new Error(`No semantic button: ${wanted}`);}
    const value=await this.request('/element','POST',{using:'css selector',value:selector});return new Element(this,value[elementKey]);
  }
  async execute(fn,...args){return this.request('/execute/sync','POST',{script:`return (${fn.toString()}).apply(null, arguments);`,args});}
  async executeAsync(fn,...args){return this.request('/execute/async','POST',{script:`return (${fn.toString()}).apply(null, arguments);`,args});}
  async deleteSession(){await this.request('','DELETE');}
}
mkdirSync(fixtureRoot);
const fixtures = {};
function fixture(name, data) { const p=path.join(fixtureRoot,name); writeFileSync(p,data,{flag:'wx'}); fixtures[name]=p; return p; }
fixture('benign-text.txt','EDY VERDICT controlled native E2E fixture. No secrets or malware.\n');
fixture('benign-binary.dat',Buffer.from([0,1,2,3,255,0,128]));
const pe=Buffer.alloc(512);
pe.write('MZ');pe.writeUInt32LE(0x80,0x3c);pe.write('PE\0\0',0x80);pe.writeUInt16LE(0x8664,0x84);pe.writeUInt16LE(1,0x86);pe.writeUInt16LE(0xf0,0x94);pe.writeUInt16LE(0x22,0x96);pe.writeUInt16LE(0x20b,0x98);pe.writeUInt32LE(0x1000,0xa8);pe.writeBigUInt64LE(0x140000000n,0xb0);pe.writeUInt16LE(3,0xdc);pe.writeUInt32LE(16,0x104);pe.write('.text',0x188);pe.writeUInt32LE(0x1000,0x190);pe.writeUInt32LE(0x200,0x198);pe.writeUInt32LE(0x60000020,0x1ac);
fixture('minimal-pe-synthetic.bin',pe);
fixture('malformed-pe.bin',Buffer.from('MZ malformed and intentionally truncated PE'));
const signed=Buffer.from(readFileSync(path.join(root,'crates/edy-engine-manager/tests/fixtures/level2/signed-test-only.hex'),'utf8').replace(/\s/g,''),'hex');
assert.equal(createHash('sha256').update(signed).digest('hex').toUpperCase(),'2FC5B08550136239E42793EDE57B79EBFFE342DA05B949BA17728C18133D22B5');
fixture('signed-synthetic.exe',signed); // Public signed artifact only. Never executed; no private key/certificate installation.
const large=path.join(fixtureRoot,'benign-large-cancel.dat');
const fd=openSync(large,'wx');try{ftruncateSync(fd,256*1024*1024);}finally{closeSync(fd);}fixtures['benign-large-cancel.dat']=large;
const matrix=[];const results=[];let browser;let app;let viewport;
function json(name,value){writeFileSync(path.join(ledger,name),JSON.stringify(value,null,2)+'\n');}
async function until(fn,description,timeout=20000){const end=Date.now()+timeout;let last;do{try{const v=await fn();if(v)return v;}catch(e){last=e;}await delay(80);}while(Date.now()<end);throw new Error(`Timed out: ${description}; ${last?.message??''}`);}
async function text(){return browser.execute(()=>document.body.innerText);}
async function click(label){const element=await browser.$(`button=${label}`);await element.waitForEnabled({timeout:10000});await element.click();}
async function nav(label){await click(label);await until(async()=>await (await browser.$('h1')).getText()===label,`page ${label}`);}
async function ipc(command,request){
  assert(['get_file_analysis','get_scan','get_scan_progress','list_scans','list_findings','generate_report','get_foundation_status'].includes(command));
  const response=await browser.executeAsync((command,request,done)=>{
    window.__TAURI_INTERNALS__.invoke(command,request===null?{}:{request}).then(value=>done({ok:true,value}),error=>done({ok:false,error}));
  },command,request);
  assert(response.ok,JSON.stringify(response));return response.value;
}
function stored(scanId){
  const db=new DatabaseSync(path.join(root,'.local/level2-native-qa-data/level0.sqlite3'),{readOnly:true});
  try{
    const row=db.prepare('SELECT payload,payload_sha256,revision FROM level2_file_snapshots WHERE scan_id=?').get(scanId);
    assert(row,'real SQLite row required');const bytes=typeof row.payload==='string'?Buffer.from(row.payload):Buffer.from(row.payload);
    const expected=createHash('sha256').update(bytes).digest('hex');
    const actual=typeof row.payload_sha256==='string'?row.payload_sha256:Buffer.from(row.payload_sha256).toString('hex');
    assert.equal(actual.toLowerCase(),expected);return {payload:JSON.parse(bytes.toString()),revision:row.revision,sha256:expected};
  }finally{db.close();}
}
async function screen(state){
  const layout=await browser.execute(()=>{
    const visible=e=>{const r=e.getBoundingClientRect();const c=getComputedStyle(e);return r.width>0&&r.height>0&&c.visibility!=='hidden'&&c.display!=='none';};
    const errors=[];
    for(const e of document.querySelectorAll('main button,main input,main select,main dd,main code')){
      if(!visible(e))continue;const r=e.getBoundingClientRect();const c=getComputedStyle(e);
      if(r.left < -1 || r.right>innerWidth+1)errors.push({text:e.textContent?.slice(0,60),reason:'horizontal clipping'});
      if(parseFloat(c.fontSize)<10)errors.push({text:e.textContent?.slice(0,60),reason:'font below 10px'});
      if(e.tagName==='INPUT'&&c.color==='rgb(0, 0, 0)'&&c.backgroundColor==='rgba(0, 0, 0, 0)')errors.push({text:e.getAttribute('aria-label'),reason:'black input on dark inherited panel'});
      // Document/ancestor scrolling is allowed; primary actions must not be permanently clipped.
      for(let p=e.parentElement;p&&p!==document.body;p=p.parentElement){const s=getComputedStyle(p);const pr=p.getBoundingClientRect();if(['hidden','clip'].includes(s.overflowY)&&(r.top<pr.top-1||r.bottom>pr.bottom+1))errors.push({text:e.textContent?.slice(0,60),reason:'unreachable vertical clipping'});}
    }
    return {width:innerWidth,height:innerHeight,documentWidth:document.documentElement.scrollWidth,horizontalOverflow:Math.max(0,document.documentElement.scrollWidth-innerWidth),errors};
  });
  const item={viewport,state,...layout,result:layout.horizontalOverflow===0&&layout.errors.length===0?'PASS':'FAIL'};matrix.push(item);json('E2E_MATRIX_WORKING.json',matrix);
  assert.equal(item.result,'PASS',JSON.stringify(item));
}
async function authorize(name){
  const target=fixtures[name];assert(target&&realpathSync(target).startsWith(realpathSync(fixtureRoot)+path.sep));
  await nav('Nova análise');await (await browser.$('[aria-label="File path"]')).setValue(target);
  await click('Preview file');await until(async()=>(await text()).includes('File preview'),'preview');await screen('preview');
  assert((await text()).includes(path.basename(target)));
  await click('Authorize this exact file');await until(async()=>(await text()).includes('Authorization captured'),'authorization');await screen('authorized');
}
async function start(){
  const old=(await ipc('list_scans',{offset:0,limit:50})).map(s=>s.id);
  await click('Confirm file analysis');
  return until(async()=> (await ipc('list_scans',{offset:0,limit:50})).find(s=>!old.includes(s.id)),'new real scan');
}
async function terminal(id){return until(async()=>{const r=await ipc('get_file_analysis',{scan_id:id});return ['partial','failed','cancelled','completed'].includes(r.state)&&r;},'terminal snapshot');}
async function digests(file){const h256=createHash('sha256'),h512=createHash('sha512');for await(const b of createReadStream(file)){h256.update(b);h512.update(b);}return {sha256:h256.digest('hex'),sha512:h512.digest('hex')};}
async function completedFlow(name,kind){
  await authorize(name);const scan=await start();const result=await terminal(scan.id);assert.equal(result.state,'partial');assert(result.analysis);
  const db=stored(scan.id);assert.deepEqual(db.payload.analysis,result.analysis);assert.equal(db.payload.state,result.state);
  const a=result.analysis;const hashes=await digests(fixtures[name]);assert.equal(a.hashes.sha256.toLowerCase(),hashes.sha256);assert.equal(a.hashes.sha512.toLowerCase(),hashes.sha512);
  await nav('Visão geral');await until(async()=>(await text()).includes(a.hashes.sha256),'real React result');await screen(kind);
  const body=await text();assert(body.includes(a.hashes.sha512));assert(body.includes(a.classification));
  assert(body.includes('Unavailable by execution policy'));assert(body.includes('Not checked'));assert(!/\b(?:No threats found|100% secure|TRUSTED FILE)\b/i.test(body));
  assert(!/^(?:SAFE|CLEAN|TRUSTED FILE)$/im.test(body));
  assert(body.includes(a.verdict.risk));assert(body.includes(a.verdict.confidence));
  assert.equal(a.coverage.hashing,'completed');assert.equal(a.coverage.classification,'completed');
  if(kind==='PE result'){assert(a.pe);assert.equal(a.pe.architecture,'x86_64');assert.equal(a.authenticode.signature_present,false);assert(body.includes('Unsigned'));}
  if(kind==='signature'){assert.equal(a.authenticode.signature_present,true);assert.equal(a.authenticode.cryptographic_status,'signed_valid_offline');assert.equal(a.authenticode.trust_chain_status,'trust_chain_untrusted');assert(body.includes('signed_valid_offline'));assert(body.includes('trust_chain_untrusted'));}
  if(kind==='malformed PE'){assert.equal(a.pe,null);assert(a.pe_error);assert(body.includes(a.pe_error));}
  await screen('coverage');await nav('Achados');await screen('findings');
  const findings=await ipc('list_findings',{scan_id:scan.id,offset:0,limit:100});
  const findingsText=await text();for(const f of findings)assert(findingsText.includes(f.title));
  await nav('Relatórios');
  const reports=[];
  for(const [reportKind,label] of [['executive','Executivo'],['technical','Técnico'],['developer','Desenvolvedor']]){
    const direct=await ipc('generate_report',{scan_id:scan.id,kind:reportKind});
    await click(`Gerar relatório: ${label}`);
    const report=await until(async()=>{const pre=await browser.$('[aria-label="JSON report"]');if(!await pre.isExisting())return false;const p=JSON.parse(await pre.getText());return p.kind===reportKind&&p;},`report ${reportKind}`);
    assert.deepEqual(report,JSON.parse(direct.json));
    assert.equal(report.scan_id,scan.id);assert.equal(report.disposition,a.verdict.disposition);assert.equal(report.file_name,name);
    assert.deepEqual(report.unavailable_checks,a.coverage.unavailable_checks);
    if(reportKind!=='executive'){assert.equal(report.sha256,a.hashes.sha256);assert.equal(report.sha512,a.hashes.sha512);}else{assert.equal(report.sha256,null);}
    reports.push(report);await screen(`reports ${reportKind}`);
  }
  results.push({viewport,flow:kind,fixture:name,result:'PASS',scan_id:scan.id,native:result,sqlite:db,reports});json('LEVEL2_NATIVE_E2E_RESULT_WORKING.json',results);
}
async function changedFlow(){
  const name=`target-changed-${viewport}.txt`;fixture(name,'Controlled initial target\n');await authorize(name);
  writeFileSync(fixtures[name],'Controlled changed target with distinct size\n');
  const scan=await start();const result=await terminal(scan.id);assert.equal(result.terminal_error,'TARGET_CHANGED');assert.equal(result.analysis,null);
  assert.equal(stored(scan.id).payload.analysis,null);await nav('Visão geral');await until(async()=>(await text()).includes('TARGET_CHANGED'),'target changed safe UI');await screen('target changed');await screen('error');
  results.push({viewport,flow:'target change',result:'PASS',native:result,sqlite:stored(scan.id)});
}
async function cancellationFlow(){
  await authorize('benign-large-cancel.dat');const scan=await start();await nav('Progresso');
  await until(async()=>await(await browser.$('button=Cancelar')).isExisting(),'actual cancel control');
  const active=await ipc('get_scan_progress',{scan_id:scan.id});assert.equal(active.status,'running');assert.equal(active.phase,'streaming_hashes');await screen('progress');
  await click('Cancelar');const result=await terminal(scan.id);assert.equal(result.state,'cancelled');assert.equal(result.analysis,null);
  await until(async()=>(await text()).includes('cancelled'),'cancelled UI');await screen('cancelled');
  const before=stored(scan.id);await delay(1000);const after=stored(scan.id);assert.deepEqual(after,before,'no late worker write/progress');
  assert.equal((await ipc('get_scan',{scan_id:scan.id})).verdict,null);
  await nav('Visão geral');await until(async()=>(await text()).includes('CANCELLED'),'cancelled no-verdict overview');assert((await text()).includes('No final file verdict'));await screen('cancelled overview');
  results.push({viewport,flow:'cancellation',result:'PASS',native:result,sqlite:after});
}
async function launch(size){
  assert(!app);assert(!await fetch('http://127.0.0.1:4445/status',{signal:AbortSignal.timeout(500)}).then(()=>true,()=>false),'test port already occupied');
  const qa=path.join(root,'.local/level2-native-qa-data');
  if(existsSync(qa)){assert.equal(realpathSync(qa),qa);renameSync(qa,`${qa}-archive-${runId}-${size}`);}
  const out=openSync(path.join(ledger,`native-${runId}-${size}.stdout.log`),'wx');const err=openSync(path.join(ledger,`native-${runId}-${size}.stderr.log`),'wx');
  app=spawn(path.join(root,'target/debug/edy-desktop.exe'),[`--level2-native-qa=${size}`],{cwd:root,windowsHide:true,stdio:['ignore',out,err]});closeSync(out);closeSync(err);
  await until(()=>fetch('http://127.0.0.1:4445/status',{signal:AbortSignal.timeout(500)}).then(r=>r.ok,()=>false),'embedded listener',30000);
  browser=await Driver.connect();
  await until(async()=>(await text()).includes('Infraestrutura disponível'),'real foundation IPC');
  const runtime=await browser.execute(()=>({url:location.href,userAgent:navigator.userAgent,width:innerWidth,height:innerHeight,mocked:!!window.__wdio_mocks__}));
  assert.equal(runtime.mocked,false);assert(runtime.url.startsWith('http://tauri.localhost/'));assert.deepEqual([runtime.width,runtime.height],size.split('x').map(Number));
  assert.equal((await ipc('get_foundation_status',null)).ipc,'restricted');json(`runtime-${size}.json`,runtime);
}
async function stop(){
  if(browser){await browser.deleteSession().catch(()=>{});browser=null;}
  if(app){const process=app;app=null;if(process.exitCode===null){process.kill();await Promise.race([once(process,'exit'),delay(10000)]);assert(process.exitCode!==null||process.signalCode!==null,'native child shutdown');}}
}
let failed;
try{
  for(viewport of (process.env.EDY_E2E_VIEWPORTS??'1366x768,1920x1080,2560x1440').split(',')){
    assert(['1366x768','1920x1080','2560x1440'].includes(viewport));
    await launch(viewport);await screen('empty');
    for(const [name,kind] of [['benign-text.txt','text result'],['benign-binary.dat','binary result'],['minimal-pe-synthetic.bin','PE result'],['signed-synthetic.exe','signature'],['malformed-pe.bin','malformed PE']])await completedFlow(name,kind);
    await changedFlow();await cancellationFlow();await stop();
  }
}catch(error){failed=error;json('NATIVE_E2E_FAILURE.json',{message:error.message,stack:error.stack,viewport,body:browser?await text().catch(()=>null):null});console.error(error);}
finally{
  await stop();json('LEVEL2_NATIVE_E2E_RESULT.json',{status:failed?'FAIL':'PASS',runId,results,matrix_rows:matrix.length,actual_tauri:true,mocked_ipc:false,fixture_root:fixtureRoot});
  const csv='VIEWPORT,STATE,RESULT,HORIZONTAL_OVERFLOW,ERRORS\n'+matrix.map(r=>[r.viewport,r.state,r.result,r.horizontalOverflow,JSON.stringify(r.errors)].map(s=>'"'+String(s).replaceAll('"','""')+'"').join(',')).join('\n')+'\n';
  for(const name of ['E2E_MATRIX.csv','LEVEL2_NATIVE_E2E_MATRIX.csv'])writeFileSync(path.join(ledger,name),csv);
}
if(failed)process.exitCode=1;else console.log(`NATIVE E2E PASS: ${results.length} real flows; ${matrix.length} semantic screen assertions`);
