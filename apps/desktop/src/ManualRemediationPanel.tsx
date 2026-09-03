import {useEffect,useState} from "react";
import {remediationApi} from "./remediation-api";
import type {ManualSnapshot,ManualReport,RemediationCandidate} from "./remediation-api";

export function ManualRemediationDetail({snapshot,busy=false,onReview,onVerify,onCancel,onReport}:{readonly snapshot:ManualSnapshot;readonly busy?:boolean;readonly onReview?:()=>void;readonly onVerify?:()=>void;readonly onCancel?:()=>void;readonly onReport?:()=>void}){
 const action=snapshot.plan.actions[0]!;
 const running=busy||snapshot.state==="verifying";
 return <section className="data-panel remediation-detail" data-level6-screen={snapshot.state}>
  <h2>Review remediation guidance</h2><p className="coverage-warning">Manual action required. Suggested change — not applied by EDY VERDICT.</p>
  <dl><dt>Case</dt><dd><code>{snapshot.plan.case_id}</code></dd><dt>Finding</dt><dd><code>{snapshot.plan.finding_id}</code></dd><dt>Target</dt><dd><code>{action.precondition.canonical_path}</code></dd><dt>Safety class</dt><dd>{action.safety_class}</dd><dt>State</dt><dd>{snapshot.state}</dd><dt>Required checks</dt><dd>{action.verification.scanner_id}: {action.verification.required_checks.join(", ")}</dd></dl>
  <ul>{snapshot.guidance.map((s,i)=><li key={i}>{s}</li>)}</ul>
  <div className="report-actions">{snapshot.state==="planned"?<button disabled={running} onClick={onReview}>View guidance and suggested diff</button>:<button disabled={running||snapshot.state==="verification_pending"} onClick={onVerify}>{["cancelled","interrupted","inconclusive"].includes(snapshot.state)?"Resume verification":"Verify after manual change"}</button>}{running&&<button onClick={onCancel}>Cancel verification</button>}<button disabled={running} onClick={onReport}>Technical report</button></div>
  {snapshot.state!=="planned"&&<section><h3>Suggested change — not applied by EDY VERDICT</h3><pre aria-label="Sanitized suggested diff">{snapshot.suggested_diff??"No executable diff. Review the original finding guidance."}</pre></section>}
  {snapshot.verification&&<section aria-label="Verification result"><h3>{snapshot.verification.outcome}</h3><p>{snapshot.verification.explanation_safe}</p><p>Coverage: {snapshot.verification.coverage_sufficient?"sufficient":"insufficient"}</p></section>}
  <p>{snapshot.limitations.join(" ")}</p><h3>Persisted case timeline</h3><ol>{snapshot.timeline.map(e=><li key={e.sequence}>{e.event_type}</li>)}</ol>
 </section>;
}

export function ManualRemediationPanel(){
 const [candidates,setCandidates]=useState<readonly RemediationCandidate[]>([]),[plans,setPlans]=useState<readonly ManualSnapshot[]>([]),[selected,setSelected]=useState<string|null>(null),[busy,setBusy]=useState(false),[failure,setFailure]=useState<string|null>(null),[report,setReport]=useState<ManualReport|null>(null);
 const current=plans.find(s=>s.plan.actions[0]?.action_id===selected)??plans[0]??null;
 async function refresh(){const [p,c]=await Promise.all([remediationApi.list(),remediationApi.candidates()]);setPlans(p);setCandidates(c);}
 useEffect(()=>{let active=true;void Promise.all([remediationApi.list(),remediationApi.candidates()]).then(([p,c])=>{if(active){setPlans(p);setCandidates(c);}}).catch(()=>{if(active)setFailure("Guidance data is unavailable");});return()=>{active=false;};},[]);
 useEffect(()=>{if(!busy)return;let active=true;const timer=setInterval(()=>{void remediationApi.list().then(p=>{if(active)setPlans(p);}).catch(()=>{});},250);return()=>{active=false;clearInterval(timer);};},[busy]);
 async function run(work:()=>Promise<unknown>){setBusy(true);setFailure(null);try{await work();await refresh();}catch{setFailure("Request could not complete; no automatic target change was performed.");await refresh().catch(()=>{});}finally{setBusy(false);}}
 return <div className="workflow-stack" data-level6-mode="manual-verification">
  <section className="data-panel"><h2>Cases and findings — remediation</h2><p>Automatic target changes and rollback are policy blocked for every target.</p>{failure&&<p role="alert">{failure}</p>}
  <div className="card-list">{candidates.map(c=><article className="finding-card" key={`${c.run_id}/${c.case_id}/${c.finding_id}`}><strong>{c.case_title}</strong><small>Case: {c.case_status}</small><code>{c.finding_id}</code><button disabled={busy} onClick={()=>{void run(async()=>{const s=await remediationApi.create(c);setSelected(s.plan.actions[0]!.action_id);});}}>Create remediation plan</button></article>)}</div>{candidates.length===0&&<p>No confirmed case/finding available.</p>}</section>
  {plans.length>0&&<section className="data-panel"><h3>Saved plans</h3><div className="card-list">{plans.map(p=><button disabled={busy} className="finding-card" key={p.plan.actions[0]!.action_id} onClick={()=>setSelected(p.plan.actions[0]!.action_id)}><strong>{p.plan.finding_id}</strong><small>{p.state}</small></button>)}</div></section>}
  {current&&<ManualRemediationDetail snapshot={current} busy={busy} onReview={()=>{void run(()=>remediationApi.review(current.plan.actions[0]!.action_id));}} onVerify={()=>{void run(()=>remediationApi.verify(current));}} onCancel={()=>{void remediationApi.cancel(current.plan.actions[0]!.action_id).catch(()=>setFailure("Verification is not yet running; no resolution was claimed."));}} onReport={()=>{void run(async()=>setReport(await remediationApi.report(current.plan.actions[0]!.action_id,"technical")));}}/>}
  {report&&<section className="data-panel" data-level6-screen="report"><h2>Verification report</h2><pre aria-label="Manual verification JSON report">{report.json}</pre></section>}
 </div>;
}
