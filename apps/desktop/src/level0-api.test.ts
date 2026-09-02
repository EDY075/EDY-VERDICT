import { describe, expect, it } from "vitest";
import { parseEngineStatus, parseFileAnalysisView, parseFileAuthorization, parseFileTargetPreview, parseFinding, parseReport, parseScanProgress, parseScanSummary } from "./level0-api";

const scanId = "018f4c2a-1d3b-7abc-8def-0123456789ab";

describe("Level 0 IPC response validation", () => {
  it("accepts exact bounded contracts", () => {
    expect(parseEngineStatus({ id: "yara-x", version: "1.20.0", state: "ready", detail_safe: "Integrity verified" }).state).toBe("ready");
    expect(parseScanSummary({ id: scanId, state: "partial", verdict: "needs_review", risk: "high", confidence: "low", coverage: { total: 4, completed: 2, failed: 1, unavailable: 1, skipped: 0 } }).confidence).toBe("low");
    expect(parseScanProgress({ scan_id: scanId, phase: "engine", completed_tasks: 1, total_tasks: 4, percent: 25, elapsed_ms: 10, current_engine: "yara-x", status: "running" }).percent).toBe(25);
    expect(parseFinding({ id: "018f4c2a-1d3b-7abc-8def-0123456789ac", scan_id: scanId, title: "Synthetic", category: "fixture", severity: "high", risk: "high", confidence: "medium", status: "open", sources: ["yara-x"], affected_component: "fixture.bin", rule_ids: ["RULE-1"], evidence_ids: ["018f4c2a-1d3b-7abc-8def-0123456789ad"], remediation_guidance: "Review safely", limitations: ["Synthetic only"] }).sources).toEqual(["yara-x"]);
    expect(parseReport({ scan_id: scanId, kind: "technical", schema: "REPORT_SCHEMA_V2", json: "{}" }).kind).toBe("technical");
  });

  it("rejects invalid ids, oversized progress and malformed report JSON", () => {
    expect(() => parseScanSummary({ id: "../../etc", state: "completed", verdict: null, risk: null, confidence: null, coverage: { total: 0, completed: 0, failed: 0, unavailable: 0, skipped: 0 } })).toThrow();
    expect(() => parseScanProgress({ scan_id: scanId, phase: "x", completed_tasks: 2, total_tasks: 1, percent: 101, elapsed_ms: 0, current_engine: null, status: "running" })).toThrow();
    expect(() => parseReport({ scan_id: scanId, kind: "technical", schema: "REPORT_SCHEMA_V2", json: "<script>" })).toThrow();
    expect(() => parseEngineStatus({ id: "yara-x", version: "1.20.0", state: "ready", detail_safe: "ok", secret: "unexpected" })).toThrow();
    expect(() => parseScanSummary({ id: scanId, state: "completed", verdict: null, risk: null, confidence: null, coverage: { total: 0, completed: 0, failed: 0, unavailable: 0, skipped: 0, clean: true } })).toThrow();
  });

  it("keeps risk confidence and coverage as distinct dimensions", () => {
    const scan = parseScanSummary({ id: scanId, state: "partial", verdict: "needs_review", risk: "critical", confidence: "low", coverage: { total: 4, completed: 1, failed: 1, unavailable: 2, skipped: 0 } });
    expect(scan.risk).toBe("critical");
    expect(scan.confidence).toBe("low");
    expect(scan.coverage.completed).toBe(1);
  });

  it("validates Level 2 preview authorization and analysis contracts", () => {
    const identity={volume_id:"123",file_id:"456",size:3,last_write_time:"134000000000000000",attributes:32};
    expect(parseFileTargetPreview({preview_id:scanId,requested_path:"D:/fixture.bin",canonical_path:"D:/fixture.bin",file_name:"fixture.bin",identity,detected_type:"unknown_binary",proposed_checks:["streaming_sha256"],policy_limitations:["YARA policy blocked"],max_file_size:268435456}).identity.file_id).toBe("456");
    expect(parseFileAuthorization({authorization_id:scanId,canonical_path:"D:/fixture.bin",size:3,detected_type:"unknown_binary",proposed_checks:["streaming_sha256"],policy_limitations:["YARA policy blocked"]}).size).toBe(3);
    const analysis={target:{authorization_id:scanId,requested_path:"D:/fixture.bin",canonical_path:"D:/fixture.bin",identity,authorized_at_utc:"2026-09-02T00:00:00Z",snapshot_version:"FILE_SNAPSHOT_V1",max_file_size:268435456},hashes:{sha256:"a".repeat(64),sha512:"b".repeat(128),bytes_hashed:3},classification:"unknown_binary",pe:null,pe_error:null,authenticode:{signature_present:false,cryptographic_status:"unsigned",trust_chain_status:"unsigned",publisher:{subject:null,issuer:null,certificate_fingerprint:null,signing_time:null,timestamp_present:null,trusted_timestamp_present:null},offline_cache_only:true},yara_observations:[],reputation:{privacy_mode:"local_only",availability:"not_configured",provider:null,known:null,malicious_count:null,suspicious_count:null,status:"not_checked"},findings:[],coverage:{hashing:"completed",classification:"completed",pe_inspection:"failed",authenticode:"not_applicable",yara:"policy_blocked",reputation:"not_checked",target_stable:true,unavailable_checks:["yara_x_real_execution_policy_blocked","file_reputation_not_checked"]},verdict:{disposition:"insufficient_coverage",risk_score:0,risk:"info",confidence_score:50,confidence:"medium",reasons:["Some checks unavailable"]}};
    const parsed=parseFileAnalysisView({scan_id:scanId,state:"partial",progress:{scan_id:scanId,phase:"reporting",completed_tasks:8,total_tasks:8,percent:100,elapsed_ms:25,current_engine:null,status:"partial"},analysis,terminal_error:null});
    expect(parsed.analysis?.hashes.sha256).toBe("a".repeat(64));
    expect(parsed.analysis?.authenticode.cryptographic_status).toBe("unsigned");
    expect(parsed.analysis?.reputation.status).toBe("not_checked");
    const envelope={scan_id:scanId,state:"partial",progress:{scan_id:scanId,phase:"reporting",completed_tasks:8,total_tasks:8,percent:100,elapsed_ms:25,current_engine:null,status:"partial"},analysis,terminal_error:null};
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,signature_present:"yes"}}})).toThrow();
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,offline_cache_only:false}}})).toThrow();
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,cryptographic_status:"safe"}}})).toThrow();
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,coverage:{...analysis.coverage,yara:"clean"}}})).toThrow();
    const untrusted = parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,signature_present:true,cryptographic_status:"signed_valid_offline",trust_chain_status:"trust_chain_untrusted",publisher:{...analysis.authenticode.publisher,signing_time:"2026-09-02T12:03:04Z",timestamp_present:false,trusted_timestamp_present:false}}}});
    expect(untrusted.analysis?.authenticode.cryptographic_status).toBe("signed_valid_offline");
    expect(untrusted.analysis?.authenticode.trust_chain_status).toBe("trust_chain_untrusted");
    expect(untrusted.analysis?.authenticode.publisher?.signing_time).toBe("2026-09-02T12:03:04Z");
    expect(untrusted.analysis?.authenticode.publisher?.trusted_timestamp_present).toBe(false);
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,cryptographic_status:"trust_chain_untrusted"}}})).toThrow();
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,trust_chain_status:"signed_valid_offline"}}})).toThrow();
    expect(()=>parseFileAnalysisView({...envelope,analysis:{...analysis,authenticode:{...analysis.authenticode,publisher:{...analysis.authenticode.publisher,trusted_timestamp_present:"yes"}}}})).toThrow();
  });

  it("rejects unsafe Level 2 hash and identity shapes", () => {
    expect(()=>parseFileTargetPreview({preview_id:scanId,requested_path:"D:/fixture.bin",canonical_path:"D:/fixture.bin",file_name:"fixture.bin",identity:{volume_id:1,file_id:2,size:3,last_write_time:4,attributes:32},detected_type:"unknown_binary",proposed_checks:[],policy_limitations:[],max_file_size:268435456})).toThrow();
  });
});
