import { invoke } from "@tauri-apps/api/core";

export const MANUAL_STATES=["planned","awaiting_manual_change","verification_pending","verifying","resolved","still_present","inconclusive","regression_detected","target_invalid","cancelled","interrupted"] as const;
export type ManualState=typeof MANUAL_STATES[number];
export interface ManualAction {readonly action_id:string;readonly finding_id:string;readonly case_id:string;readonly safety_class:"guidance_only"|"manual_change_verifiable"|"policy_blocked"|"unsupported";readonly explanation_safe:string;readonly precondition:{readonly canonical_path:string};readonly verification:{readonly scanner_id:string;readonly required_checks:readonly string[]}}
export interface ManualSnapshot {readonly plan:{readonly plan_id:string;readonly plan_sha256:string;readonly case_id:string;readonly finding_id:string;readonly actions:readonly ManualAction[]};readonly run_id:string;readonly state:ManualState;readonly revision:number;readonly guidance:readonly string[];readonly suggested_diff:string|null;readonly limitations:readonly string[];readonly verification:{readonly outcome:ManualState;readonly explanation_safe:string;readonly coverage_sufficient:boolean;readonly required_checks_executed:boolean;readonly stable_during_scan:boolean}|null;readonly timeline:readonly {readonly sequence:number;readonly event_type:string;readonly at_utc:string}[]}
export interface RemediationCandidate {readonly run_id:string;readonly case_id:string;readonly case_title:string;readonly case_status:string;readonly finding_id:string}
export interface ManualReport {readonly action_id:string;readonly kind:"executive"|"technical"|"analyst";readonly json:string;readonly html:string}
const SHA=/^[a-f0-9]{64}$/,ACTION=/^rma-v1-[a-f0-9]{64}$/,CASE=/^case-v1-[a-f0-9]{64}$/,UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function bad():never{throw new Error("Manual verification response rejected");}
function object(v:unknown):Record<string,unknown>{if(!v||typeof v!=="object"||Array.isArray(v))return bad();return v as Record<string,unknown>;}
function text(v:unknown,n=4096):string{if(typeof v!=="string"||v.length>n||/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(v)||v.toLowerCase().includes("edy_fake_"))return bad();return v;}
function matched(v:unknown,re:RegExp):string{const s=text(v,128);if(!re.test(s))return bad();return s;}
function integer(v:unknown):number{if(!Number.isSafeInteger(v)||(v as number)<0)return bad();return v as number;}
function boolean(v:unknown):boolean{if(typeof v!=="boolean")return bad();return v;}
function list<T>(v:unknown,max:number,parse:(v:unknown)=>T):readonly T[]{if(!Array.isArray(v)||v.length>max)return bad();return Object.freeze(v.map(parse));}
function strings(v:unknown,max=16):readonly string[]{return list(v,max,x=>text(x));}
function state(v:unknown):ManualState{if(!MANUAL_STATES.includes(v as ManualState))return bad();return v as ManualState;}
export function parseManualSnapshot(value:unknown):ManualSnapshot{
 const s=object(value),p=object(s.plan);
 if(["receipt","rollback_receipt","journal","backup","patch"].some(k=>k in s))return bad();
 const actions=list(p.actions,1,v=>{const a=object(v),pre=object(a.precondition),ver=object(a.verification),rollback=object(a.rollback);if(rollback.eligible!==false||!["guidance_only","manual_change_verifiable","policy_blocked","unsupported"].includes(a.safety_class as string))return bad();return Object.freeze({action_id:matched(a.action_id,ACTION),finding_id:text(a.finding_id,128),case_id:matched(a.case_id,CASE),safety_class:a.safety_class as ManualAction["safety_class"],explanation_safe:text(a.explanation_safe),precondition:Object.freeze({canonical_path:text(pre.canonical_path)}),verification:Object.freeze({scanner_id:text(ver.scanner_id,128),required_checks:strings(ver.required_checks)})});});
 if(actions.length!==1||actions[0]!.case_id!==p.case_id||actions[0]!.finding_id!==p.finding_id)return bad();
 const verification=s.verification===null?null:(()=>{const v=object(s.verification);return Object.freeze({outcome:state(v.outcome),explanation_safe:text(v.explanation_safe),coverage_sufficient:boolean(v.coverage_sufficient),required_checks_executed:boolean(v.required_checks_executed),stable_during_scan:boolean(v.stable_during_scan)});})();
 return Object.freeze({plan:Object.freeze({plan_id:matched(p.plan_id,UUID),plan_sha256:matched(p.plan_sha256,SHA),case_id:matched(p.case_id,CASE),finding_id:text(p.finding_id,128),actions}),run_id:matched(s.run_id,UUID),state:state(s.state),revision:integer(s.revision),guidance:strings(s.guidance),suggested_diff:s.suggested_diff===null?null:text(s.suggested_diff),limitations:strings(s.limitations),verification,timeline:list(s.timeline,256,v=>{const e=object(v);return Object.freeze({sequence:integer(e.sequence),event_type:text(e.event_type,80),at_utc:text(e.at_utc,40)});})});
}
function candidate(v:unknown):RemediationCandidate{const c=object(v);return Object.freeze({run_id:matched(c.run_id,UUID),case_id:matched(c.case_id,CASE),case_title:text(c.case_title,512),case_status:text(c.case_status,40),finding_id:text(c.finding_id,128)});}
async function request<T>(cmd:string,payload:Record<string,unknown>,parse:(v:unknown)=>T):Promise<T>{return parse(await invoke(cmd,{request:payload}));}
export const remediationApi=Object.freeze({
 candidates:async()=>list(await invoke("list_remediation_candidates"),100,candidate),
 list:()=>request("list_remediation_plans",{offset:0,limit:100},v=>list(object(v).items,100,parseManualSnapshot)),
 create:(c:RemediationCandidate)=>request("create_remediation_plan",{run_id:matched(c.run_id,UUID),case_id:matched(c.case_id,CASE),finding_id:text(c.finding_id,128)},parseManualSnapshot),
 review:(id:string)=>request("preview_remediation_action",{action_id:matched(id,ACTION)},parseManualSnapshot),
 get:(id:string)=>request("get_remediation_action_status",{action_id:matched(id,ACTION)},parseManualSnapshot),
 verify:async(s:ManualSnapshot)=>{
  const id=s.plan.actions[0]!.action_id;
  const token=await request("authorize_remediation_action",{action_id:matched(id,ACTION),plan_sha256:matched(s.plan.plan_sha256,SHA),confirmed:true},v=>{const a=object(v);return matched(a.authorization_token,SHA);});
  // A short-lived rescan-only authority stays in this closure, never storage or React state.
  return request("verify_remediation_action",{action_id:id,authorization_token:token},parseManualSnapshot);
 },
 cancel:(id:string)=>request("cancel_remediation_verification",{action_id:matched(id,ACTION)},boolean),
 report:(id:string,kind:ManualReport["kind"])=>request("generate_remediation_report",{action_id:matched(id,ACTION),kind},v=>{const r=object(v);if(!["executive","technical","analyst"].includes(r.kind as string))return bad();return Object.freeze({action_id:matched(r.action_id,ACTION),kind:r.kind as ManualReport["kind"],json:text(r.json,131072),html:text(r.html,131072)});}),
});
