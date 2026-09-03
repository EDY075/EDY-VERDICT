import {renderToStaticMarkup} from "react-dom/server";
import {describe,it,expect} from "vitest";
import {MANUAL_STATES,parseManualSnapshot} from "./remediation-api";
import {ManualRemediationDetail} from "./ManualRemediationPanel";

function wire(){const id=`rma-v1-${"a".repeat(64)}`,caseId=`case-v1-${"b".repeat(64)}`,uuid="018f4c2a-1d3b-7abc-8def-0123456789f6";return {plan:{plan_id:uuid,plan_sha256:"c".repeat(64),case_id:caseId,finding_id:"finding-a",actions:[{action_id:id,finding_id:"finding-a",case_id:caseId,safety_class:"manual_change_verifiable",explanation_safe:"Review only",precondition:{canonical_path:"Synthetic authorized repository"},verification:{scanner_id:"edy-inventory",required_checks:["original inventory check"]},rollback:{eligible:false}}]},run_id:uuid,state:"planned",revision:1,guidance:["Manual action required"],suggested_diff:"Suggested change — not applied by EDY VERDICT",limitations:["Verification limited to checks executed"],verification:null,timeline:[{sequence:1,event_type:"REMEDIATION_PLAN_CREATED",at_utc:"2026-09-03T00:00:00Z"}]};}

describe("production manual remediation",()=>{
 it.each(MANUAL_STATES)("renders %s without apply/rollback",state=>{
  const s=parseManualSnapshot({...wire(),state});const html=renderToStaticMarkup(<ManualRemediationDetail snapshot={s}/>);
  expect(html).toContain(`data-level6-screen="${state}"`);expect(html).not.toContain("Apply this remediation");expect(html).not.toContain(">Roll back<");expect(html).toContain("not applied by EDY VERDICT");
 });
 it.each(["EDY_FAKE_SECRET_LEVEL6","EDY_FAKE_COOKIE_LEVEL6","EDY_FAKE_QUERY_LEVEL6","EDY_FAKE_AUTH_TOKEN_LEVEL6","EDY_FAKE_PASSWORD_LEVEL6"])("refuses contaminated guidance %s",sentinel=>{
  expect(()=>parseManualSnapshot({...wire(),guidance:[sentinel]})).toThrow();
 });
 it("denies legacy executable classes and write journal responses",()=>{
  const s=wire();s.plan.actions[0]!.safety_class="test_only_reversible";expect(()=>parseManualSnapshot(s)).toThrow();
  expect(()=>parseManualSnapshot({...wire(),journal:{}})).toThrow();
 });
 it("escapes markup in the normal read-only view",()=>{const s=parseManualSnapshot({...wire(),guidance:["<script>not executed</script>"]});const html=renderToStaticMarkup(<ManualRemediationDetail snapshot={s}/>);expect(html).not.toContain("<script>");expect(html).toContain("&lt;script&gt;");});
});
