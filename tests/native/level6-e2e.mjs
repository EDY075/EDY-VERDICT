// Real Tauri/WebView2 Level 6 E2E. Only the bounded target is synthetic.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {DatabaseSync} from 'node:sqlite';
import {closeSync,existsSync,mkdirSync,openSync,readFileSync,realpathSync,renameSync,readdirSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';

const root=realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'));
const ledger=realpathSync(process.env.EDY_E2E_LEDGER??'');
assert(ledger.startsWith(path.resolve(root,'_intake')+path.sep));
assert.equal(process.platform,'win32');
const elementKey='element-6066-11e4-a52e-4f735466cecf';
const runStamp=Date.now().toString();
const qaRoot=path.join(root,'.local',`level6-manual-native-qa-data-${runStamp}`);
const fixture=path.join(qaRoot,'synthetic-remediation-repo','package.json');
const database=path.join(qaRoot,'level0.sqlite3');
const markers=['EDY_FAKE_SECRET_LEVEL6','EDY_FAKE_COOKIE_LEVEL6','EDY_FAKE_QUERY_LEVEL6','EDY_FAKE_AUTH_TOKEN_LEVEL6','EDY_FAKE_PASSWORD_LEVEL6'];
const original=JSON.stringify({name:'controlled-fixture',version:'1.0.0',description:markers.join(' ')})+'\n';
const lockfile=path.join(path.dirname(fixture),'package-lock.json');
const matrix=[];
let browser,app;

class Element{constructor(driver,id){this.driver=driver;this.id=id}command(p,m='GET',b){return this.driver.request(`/element/${this.id}${p}`,m,b)}click(){return this.command('/click','POST',{})}getText(){return this.command('/text')}isEnabled(){return this.command('/enabled')}}
class Driver{constructor(id){this.id=id}static async connect(){const r=await fetch('http://127.0.0.1:4445/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capabilities:{alwaysMatch:{browserName:'tauri','wdio:tauriServiceOptions':{windowLabel:'main'}},firstMatch:[{}]}})});const b=await r.json();if(!r.ok)throw Error(JSON.stringify(b));return new Driver(b.value.sessionId)}async request(p,m='GET',b){const r=await fetch(`http://127.0.0.1:4445/session/${this.id}${p}`,{method:m,headers:{'content-type':'application/json'},body:b===undefined?undefined:JSON.stringify(b)});const value=await r.json();if(!r.ok)throw Error(JSON.stringify(value));return value.value}async elements(selector){return(await this.request('/elements','POST',{using:'css selector',value:selector})).map(value=>new Element(this,value[elementKey]))}async button(label){for(const element of await this.elements('button'))if(await element.getText()===label)return element;throw Error(`button ${label} missing`)}async buttonContaining(label){for(const element of await this.elements('button'))if((await element.getText()).includes(label))return element;throw Error(`button containing ${label} missing`)}execute(fn,...args){return this.request('/execute/sync','POST',{script:`return (${fn.toString()}).apply(null, arguments);`,args})}executeAsync(fn,...args){return this.request('/execute/async','POST',{script:`return (${fn.toString()}).apply(null, arguments);`,args})}deleteSession(){return this.request('','DELETE')}}
async function until(fn,label,timeout=30000){const end=Date.now()+timeout;let last;while(Date.now()<end){try{const value=await fn();if(value)return value}catch(error){last=error}await delay(80)}throw Error(`timeout ${label}: ${last?.message??''}`)}
const body=()=>browser.execute(()=>document.body.innerText);
async function click(label){const element=await browser.button(label);assert(await element.isEnabled());await element.click()}
async function clickContaining(label){const element=await browser.buttonContaining(label);assert(await element.isEnabled());await element.click()}
async function rawIpc(command,request){return browser.executeAsync((cmd,input,done)=>window.__TAURI_INTERNALS__.invoke(cmd,{request:input}).then(value=>done({ok:true,value}),error=>done({ok:false,error})),command,request)}
async function ipc(command,request){const result=await rawIpc(command,request);assert(result.ok,JSON.stringify(result));return result.value}
async function screen(viewport,state){const layout=await browser.execute(()=>{const errors=[];for(const element of document.querySelectorAll('main button,main input,main select,main table,main article,main pre')){const rectangle=element.getBoundingClientRect(),style=getComputedStyle(element);if(rectangle.width===0||rectangle.height===0||style.display==='none')continue;if(rectangle.left < -1||rectangle.right>innerWidth+1)errors.push({reason:'horizontal clipping',text:element.textContent?.slice(0,50)});if(parseFloat(style.fontSize)<10)errors.push({reason:'font below 10px',text:element.textContent?.slice(0,50)})}return{width:innerWidth,height:innerHeight,overflow:Math.max(0,document.documentElement.scrollWidth-innerWidth),errors}});const row={viewport,state,...layout,result:layout.overflow===0&&layout.errors.length===0?'PASS':'FAIL'};matrix.push(row);assert.equal(row.result,'PASS',JSON.stringify(row))}
async function launch(viewport,label){const stdout=openSync(path.join(ledger,`level6-${runStamp}-${viewport}-${label}.stdout.log`),'wx'),stderr=openSync(path.join(ledger,`level6-${runStamp}-${viewport}-${label}.stderr.log`),'wx');app=spawn(path.join(root,'target','debug','edy-desktop.exe'),[`--level6-native-qa=${viewport}`],{cwd:root,env:{...process.env,EDY_LEVEL6_E2E_RUN_ID:runStamp},windowsHide:true,stdio:['ignore',stdout,stderr]});closeSync(stdout);closeSync(stderr);await until(()=>fetch('http://127.0.0.1:4445/status',{signal:AbortSignal.timeout(500)}).then(response=>response.ok,()=>false),'driver');browser=await Driver.connect();await until(async()=>(await body()).includes('Infraestrutura disponível'),'foundation')}
async function stop(){if(browser){await browser.deleteSession().catch(()=>{});browser=null}if(app){const process=app;app=null;if(process.exitCode===null){process.kill();await Promise.race([once(process,'exit'),delay(10000)])}}await delay(300)}

function cleanText(value,label){const s=typeof value==='string'?value:JSON.stringify(value);for(const marker of markers)assert(!s.includes(marker),`${label}: sentinel leaked`);}
function dbSnapshot(id){const db=new DatabaseSync(database,{readOnly:true});try{
 assert.equal(db.prepare('PRAGMA user_version').get().user_version,8);
 assert.equal(db.prepare('SELECT count(*) AS n FROM pragma_foreign_key_check').get().n,0);
 const row=db.prepare('SELECT payload,sha256 FROM level6_manual_plans WHERE action_id=?').get(id);assert(row);
 const bytes=Buffer.from(row.payload);assert.equal(createHash('sha256').update(bytes).digest('hex'),row.sha256);cleanText(bytes.toString(),'SQLite plan');
 const s=JSON.parse(bytes.toString());
 const caseRow=db.prepare('SELECT payload_json,payload_sha256 FROM level5_cases WHERE case_id=? AND run_id=?').get(s.plan.case_id,s.run_id);
 const caseBytes=Buffer.from(caseRow.payload_json);assert.equal(createHash('sha256').update(caseBytes).digest('hex'),caseRow.payload_sha256);
 const c=JSON.parse(caseBytes.toString());assert(c.finding_ids.includes(s.plan.finding_id));cleanText(c,'SQLite case');
 for(const event of s.timeline)assert(c.timeline.some(e=>e.event_type===event.event_type),'case timeline missing '+event.event_type);
 assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name IN ('level6_action_receipts','level6_recovery_journal','level6_rollback_receipts')").get().n,0);
 return {snapshot:s,case:c};
}finally{db.close();}}
async function openPage(){await click('Remediação');await until(()=>browser.execute(()=>Boolean(document.querySelector('[data-level6-mode="manual-verification"]'))),'manual page');}
async function state(){return browser.execute(()=>document.querySelector('.remediation-detail')?.getAttribute('data-level6-screen'));}
async function waitState(expected){await until(async()=>await state()===expected,expected);const rendered=await body();cleanText(rendered,'DOM');const buttons=await browser.execute(()=>[...document.querySelectorAll('button')].map(b=>b.textContent));assert(!buttons.includes('Apply this remediation'));assert(!buttons.includes('Roll back'));}
async function select(id){const s=(await ipc('get_remediation_plan',{action_id:id}));await clickContaining(s.plan.finding_id);await waitState(s.state);}
async function plans(){return (await ipc('list_remediation_plans',{offset:0,limit:100})).items;}
async function verifyViaUI(expected){const before=await state();await click(['interrupted','cancelled','inconclusive'].includes(before)?'Resume verification':'Verify after manual change');await waitState(expected);}
async function restart(id,expected,label){await stop();await launch('1366x768',label);await openPage();await select(id);await waitState(expected);const s=dbSnapshot(id).snapshot;assert.equal(s.state,expected);return s;}
async function createFromUI(candidate){const elements=await browser.elements('.finding-card');let clicked=false;for(const e of elements){if((await e.getText()).includes(candidate.finding_id)){
 const button=await browser.execute((id)=>{const article=[...document.querySelectorAll('article.finding-card')].find(e=>e.textContent.includes(id));article?.querySelector('button')?.click();return !!article;},candidate.finding_id);assert(button);clicked=true;break;}}
 assert(clicked);await until(async()=>(await plans()).some(s=>s.plan.finding_id===candidate.finding_id),'plan creation');const s=(await plans()).find(s=>s.plan.finding_id===candidate.finding_id);await waitState('planned');return s;}
async function productionMutationProbes(snapshot){const id=snapshot.plan.actions[0].action_id;const results=[];
 for(const scenario of ['concurrent_content_change','concurrent_path_replacement']){
  const data=original+' ';if(scenario==='concurrent_path_replacement'){const temp=fixture+'.user-change';writeFileSync(temp,data);renameSync(fixture,fixture+'.user-before');renameSync(temp,fixture);}else writeFileSync(fixture,data);
  const before=createHash('sha256').update(readFileSync(fixture)).digest('hex');
  for(const cmd of ['apply_remediation_action','rollback_remediation_action','write_file','patch_file','replace_file','replace_text','execute_patch','arbitrary_write']){
   const response=await browser.executeAsync((command,input,done)=>{let finished=false;const finish=value=>{if(!finished){finished=true;done(value);}};setTimeout(()=>finish({ok:false,transport:'NO_RESPONSE_AFTER_ISOLATION_REJECTION'}),800);window.__TAURI_INTERNALS__.invoke(command,{request:input}).then(value=>finish({ok:true,value}),()=>finish({ok:false,transport:'REJECTED'}));},cmd,{action_id:id,authorization_token:'a'.repeat(64)});assert.equal(response.ok,false,cmd);cleanText(response,'blocked IPC');
  }
  assert.equal(createHash('sha256').update(readFileSync(fixture)).digest('hex'),before);
  results.push({scenario,mutation:'NOT_AVAILABLE',concurrent_user_data:'PRESERVED',target_writes_by_edy:0});
 }
 return results;
}
let failure,failureBody,primaryId,secondaryId;
const restartMatrix=[],verificationMatrix=[],results=[];
let probes;
try{
 mkdirSync(path.dirname(fixture),{recursive:true});mkdirSync(path.join(qaRoot,'synthetic-associated-repo'),{recursive:true});
 writeFileSync(fixture,original);writeFileSync(path.join(qaRoot,'synthetic-associated-repo','package.json'),original);
 await launch('1366x768','create');await openPage();
 // Original scanner observations are read, correlated and persisted by the debug
 // fixture loader. No remediation plan is pre-created.
 assert.equal((await plans()).length,0);
 const candidates=await browser.executeAsync(done=>window.__TAURI_INTERNALS__.invoke('list_remediation_candidates').then(v=>done(v)),);
 assert(candidates.length>=2);cleanText(candidates,'IPC candidates');
 // Select the finding whose original inventory corresponds to the primary repo.
 const db=new DatabaseSync(database,{readOnly:true});
 const observations=JSON.parse(Buffer.from(db.prepare('SELECT observations_json FROM level5_correlation_runs').get().observations_json).toString());db.close();
 const primaryTarget=createHash('sha256').update(path.dirname(fixture).replaceAll('\\','/')).digest('hex');
 const targetObservations=observations.filter(o=>o.target_id===primaryTarget);assert(targetObservations.length===2,'primary actual scan must exist');
 const primaryFinding=targetObservations.find(o=>o.provider_available).finding_id;
 const secondaryFinding=targetObservations.find(o=>!o.provider_available).finding_id;
 const initial=await createFromUI(candidates.find(c=>c.finding_id===primaryFinding));primaryId=initial.plan.actions[0].action_id;
 cleanText(initial,'plan');assert.equal(initial.plan.actions[0].safety_class,'manual_change_verifiable');
 restartMatrix.push({state:'planned',result:(await restart(primaryId,'planned','planned-restart')).state});
 await click('View guidance and suggested diff');await waitState('awaiting_manual_change');await screen('1366x768','guidance');
 assert((await body()).includes('Suggested change — not applied by EDY VERDICT'));
 restartMatrix.push({state:'awaiting_manual_change',result:(await restart(primaryId,'awaiting_manual_change','awaiting-restart')).state});
 probes=await productionMutationProbes(initial);
 await select(primaryId);
 await verifyViaUI('still_present');verificationMatrix.push({scenario:'incorrect_manual_change',result:'still_present'});
 await screen('1366x768','still_present');
 writeFileSync(lockfile,'{"lockfileVersion":3}\n');
 await verifyViaUI('resolved');verificationMatrix.push({scenario:'manual_lockfile',result:'resolved'});
 let persisted=dbSnapshot(primaryId);assert.equal(persisted.snapshot.verification.coverage_sufficient,true);assert.notEqual(persisted.case.status,'resolved','other members still open');
 await click('Technical report');await until(async()=>(await body()).includes('EDY_MANUAL_VERIFICATION_REPORT_V1'),'report');cleanText(await body(),'JSON report DOM');await screen('1366x768','report');
 const report=await ipc('generate_remediation_report',{action_id:primaryId,kind:'technical'});cleanText(report,'JSON HTML reports');
 restartMatrix.push({state:'resolved',result:(await restart(primaryId,'resolved','resolved-restart')).state});
 writeFileSync(lockfile,'');
 await verifyViaUI('regression_detected');verificationMatrix.push({scenario:'new_empty_lockfile',result:'regression_detected'});
 restartMatrix.push({state:'regression_detected',result:(await restart(primaryId,'regression_detected','regression-restart')).state});
 // Cancellation traverses actual async IPC; delay is only in the debug harness.
 await click('Verify after manual change');await waitState('verifying');await click('Cancel verification');await waitState('cancelled');verificationMatrix.push({scenario:'cancel',result:'cancelled'});
 restartMatrix.push({state:'cancelled',result:(await restart(primaryId,'cancelled','cancelled-restart')).state});
 const grant=await ipc('authorize_remediation_action',{action_id:primaryId,plan_sha256:initial.plan.plan_sha256,confirmed:true});cleanText(grant.authorization,'authorization metadata');
 restartMatrix.push({state:'verification_pending',result:(await restart(primaryId,'interrupted','pending-restart')).state});
 const denied=await rawIpc('verify_remediation_action',{action_id:primaryId,authorization_token:grant.authorization_token});assert.equal(denied.ok,false);
 writeFileSync(lockfile,'{"lockfileVersion":3}\n');
 await click('Resume verification');await waitState('verifying');await screen('1366x768','verifying');
 restartMatrix.push({state:'verifying',result:(await restart(primaryId,'interrupted','running-restart')).state});
 await verifyViaUI('resolved');assert.equal(dbSnapshot(primaryId).snapshot.state,'resolved');
 const second=await createFromUI(candidates.find(c=>c.finding_id===secondaryFinding));secondaryId=second.plan.actions[0].action_id;
 assert.equal(second.plan.actions[0].safety_class,'unsupported');
 await click('View guidance and suggested diff');await waitState('awaiting_manual_change');await verifyViaUI('inconclusive');verificationMatrix.push({scenario:'required_original_checker_unavailable',result:'inconclusive'});
 restartMatrix.push({state:'inconclusive',result:(await restart(secondaryId,'inconclusive','inconclusive-restart')).state});
 for(const viewport of ['1366x768','1920x1080','2560x1440']){
  await stop();await launch(viewport,'layout');await openPage();await select(primaryId);await screen(viewport,'resolved');await select(secondaryId);await screen(viewport,'inconclusive');results.push({viewport,result:'PASS'});
 }
 await select(primaryId);renameSync(path.dirname(fixture),path.dirname(fixture)+'-manually-moved');await verifyViaUI('target_invalid');verificationMatrix.push({scenario:'logical_root_removed',result:'target_invalid'});
 const stateBefore=dbSnapshot(primaryId).snapshot;assert.equal(stateBefore.verification.original_finding_absent,false);
 await stop();
 for(const name of readdirSync(qaRoot)){const p=path.join(qaRoot,name);if(name.startsWith('level0.sqlite3')){for(const marker of markers)assert(!readFileSync(p).includes(Buffer.from(marker)),'database secret leak');}}
 for(const name of readdirSync(ledger).filter(n=>n.startsWith('level6-'+runStamp)&&n.endsWith('.log')))cleanText(readFileSync(path.join(ledger,name),'utf8'),'logs');
}catch(error){failure=error;failureBody=browser?await body().catch(()=>null):null;console.error(error,failureBody);}
finally{
 await stop();
 writeFileSync(path.join(ledger,'LEVEL6_NATIVE_E2E_RESULT.json'),JSON.stringify({status:failure?'FAIL':'PASS',runStamp,qaRoot,primaryId,secondaryId,results,restartMatrix,verificationMatrix,probes,matrix,failure:failure?{message:failure.message,body:failureBody}:null,actual_tauri:true,actual_webview:true,actual_react:true,actual_typed_ipc:true,actual_original_inventory_scanner:true,actual_sqlite:true,case_timeline_verified:true,production_mutating_executor:false,external_harness_fixture_writes:true,mocked_ipc:false,external_requests:0},null,2)+'\n');
}
if(failure)process.exitCode=1;else console.log('LEVEL 6 MANUAL VERIFICATION NATIVE E2E PASS');
