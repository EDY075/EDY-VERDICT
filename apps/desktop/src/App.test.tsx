import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FoundationView } from "./App";
import { parseFoundationStatus } from "./foundation";

describe("Level 0 product shell", () => {
  it("renders the approved navigation and distinct verdict dimensions", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const html = renderToStaticMarkup(<FoundationView status={status} failed={false} />);
    for (const label of ["EDY VERDICT", "Visão geral", "Nova análise", "Achados", "Engines", "Relatórios", "Cobertura", "Risco", "Confiança"]) {
      expect(html).toContain(label);
    }
    expect(html).toContain('data-mode="production-empty"');
    expect(html).toContain("Core · Storage · IPC restricted");
    expect(html).not.toContain("100% secure");
    expect(html).not.toContain("safe guaranteed");
  });

  it("never claims readiness while pending or failed", () => {
    for (const failed of [false, true]) {
      const html = renderToStaticMarkup(<FoundationView status={null} failed={failed} />);
      expect(html).not.toContain("Infraestrutura disponível");
      expect(html).toContain("Fail closed");
    }
  });

  it("contains both approved locales and themes without remote assets", () => {
    const html = renderToStaticMarkup(<FoundationView status={null} failed={false} />);
    for (const value of ["pt-BR", "en", "professional", "neon"]) expect(html).toContain(value);
    expect(html).not.toContain("https://");
    expect(html).not.toContain("http://");
  });

  it("renders backend-provided dimensions without turning coverage into safety", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const html = renderToStaticMarkup(<FoundationView status={status} failed={false} scans={[{
      id: "018f4c2a-1d3b-7abc-8def-0123456789ab",
      state: "partial",
      verdict: "needs_review",
      risk: "high",
      confidence: "low",
      coverage: { total: 4, completed: 2, failed: 1, unavailable: 1, skipped: 0 },
    }]} />);
    expect(html).toContain("2/4");
    expect(html).toContain("high");
    expect(html).toContain("low");
    expect(html).toContain("needs_review");
    expect(html).not.toContain("50% secure");
  });

  it("shows only a safe presentation error", () => {
    const html = renderToStaticMarkup(<FoundationView status={null} failed error="Backend response rejected or unavailable" />);
    expect(html).toContain("Backend response rejected or unavailable");
    expect(html).not.toContain("stack trace");
  });

  it("renders Level 1 filters, full detail, multi-source evidence and secret redaction", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const html = renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="findings" findings={[{
      id: "018f4c2a-1d3b-7abc-8def-0123456789ac",
      scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab",
      title: "Potential secret detected; raw match removed",
      category: "secret", severity: "high", risk: "high", confidence: "high", status: "open",
      sources: ["gitleaks", "trivy"], affected_component: "config/test-secret.env",
      rule_ids: ["generic-api-key"], evidence_ids: ["018f4c2a-1d3b-7abc-8def-0123456789ad"],
      remediation_guidance: "Revoke if real and rescan", limitations: ["Synthetic adapter only"],
    }]} />);
    for (const label of ["All", "Secrets", "Vulnerabilities", "Misconfiguration", "Supply Chain", "License", "Severity", "Status", "Confidence", "Affected component", "Rule / ID", "Evidence", "Supporting sources", "Remediation guidance", "Limitations"]) expect(html).toContain(label);
    expect(html).toContain("gitleaks, trivy");
    expect(html).toContain("[REDACTED]");
    expect(html).toContain("reveal is unavailable");
    expect(html).not.toContain("synthetic_secret_value");
  });

  it("renders partial coverage dimensions without turning coverage into safety", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const html = renderToStaticMarkup(<FoundationView status={status} failed={false} scans={[{
      id: "018f4c2a-1d3b-7abc-8def-0123456789ab", state: "partial", verdict: "inconclusive", risk: "high", confidence: "medium",
      coverage: { total: 7, completed: 5, failed: 0, unavailable: 2, skipped: 0 },
    }]} />);
    for (const label of ["Planned", "Executed / passed", "Failed", "Unavailable", "Skipped", "Partial coverage"]) expect(html).toContain(label);
    expect(html).not.toContain("security pass</strong>");
  });

  it("renders cancellation and report states without a final verdict claim", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const progress = renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="progress" progress={{ scan_id: "018f4c2a-1d3b-7abc-8def-0123456789ab", phase: "dependency_checks", completed_tasks: 3, total_tasks: 7, percent: 42, elapsed_ms: 10, current_engine: "fake-osv", status: "cancelled" }} />);
    expect(progress).toContain("cancelled");
    expect(progress).not.toContain(">Cancelar<");
    const report = renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="reports" scans={[{ id: "018f4c2a-1d3b-7abc-8def-0123456789ab", state: "partial", verdict: "inconclusive", risk: "medium", confidence: "low", coverage: { total: 7, completed: 5, failed: 0, unavailable: 2, skipped: 0 } }]} />);
    for (const label of ["Executivo", "Técnico", "Desenvolvedor"]) expect(report).toContain(label);
  });

  it("renders explicit Level 2 preview and confirmation without automatic analysis", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const identity={volume_id:"123",file_id:"456",size:42,last_write_time:"134000000000000000",attributes:32};
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="new-scan" filePreview={{preview_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",requested_path:"D:/fixture.bin",canonical_path:"D:/fixture.bin",file_name:"fixture.bin",identity,detected_type:"unknown_binary",proposed_checks:["streaming_sha256","offline_authenticode_when_applicable"],policy_limitations:["YARA-X real execution is unavailable by execution policy"],max_file_size:268435456}} fileAuthorization={{authorization_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",canonical_path:"D:/fixture.bin",size:42,detected_type:"unknown_binary",proposed_checks:["streaming_sha256"],policy_limitations:["YARA policy blocked"]}} />);
    for(const label of ["File / Binary Security","File preview","Resolved location","Detected type","Authorize this exact file","Confirm file analysis","unavailable by execution policy","Not checked"]) expect(html).toContain(label);
    expect(html).not.toContain("No threats found");
  });

  it("renders distinct identity hash PE signature YARA reputation finding and coverage panels", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const identity={volume_id:"123",file_id:"456",size:3,last_write_time:"134000000000000000",attributes:32};
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} fileAnalysis={{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",state:"partial",progress:{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",phase:"reporting",completed_tasks:8,total_tasks:8,percent:100,elapsed_ms:25,current_engine:null,status:"partial"},terminal_error:null,analysis:{target:{canonical_path:"D:/fixture.bin",identity},hashes:{sha256:"a".repeat(64),sha512:"b".repeat(128),bytes_hashed:3},classification:"pe_executable",pe:{machine:34404,architecture:"x86_64",subsystem:3,timestamp:0,image_base:5368709120,entry_point_rva:4096,is_dll:false,signature_present:false,sections:[]},pe_error:null,authenticode:{signature_present:false,cryptographic_status:"unsigned",trust_chain_status:"unsigned",offline_cache_only:true},yara_observations:[],reputation:{privacy_mode:"local_only",availability:"not_configured",provider:null,known:null,malicious_count:null,suspicious_count:null,status:"not_checked"},findings:[],coverage:{hashing:"completed",classification:"completed",pe_inspection:"completed",authenticode:"completed",yara:"policy_blocked",reputation:"not_checked",target_stable:true,unavailable_checks:["yara","reputation"]},verdict:{disposition:"insufficient_coverage",risk_score:0,risk:"info",confidence_score:66,confidence:"medium",reasons:["coverage down"]}}}} />);
    for(const label of ["File Identity","Hashes","SHA-256","SHA-512","PE Metadata","Digital Signature","Unsigned","YARA","Unavailable by execution policy","Reputation","Not checked","Findings","Coverage"]) expect(html).toContain(label);
    expect(html).toContain("This is not a clean guarantee");
    expect(html).not.toContain("SAFE");
  });

  it("renders target changed and cancelled terminals without a final verdict", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    for(const terminal of [{phase:"target_changed",error:"TARGET_CHANGED",state:"failed" as const},{phase:"cancelled",error:"CANCELLED",state:"cancelled" as const}]){
      const html=renderToStaticMarkup(<FoundationView status={status} failed={false} fileAnalysis={{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",state:terminal.state,progress:{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",phase:terminal.phase,completed_tasks:2,total_tasks:8,percent:null,elapsed_ms:10,current_engine:null,status:terminal.state},analysis:null,terminal_error:terminal.error}} />);
      expect(html).toContain(terminal.error);
      expect(html).toContain("No final file verdict was generated");
    }
  });
});
