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

  it("renders the Level 3 preview, coverage, identity and vulnerability evidence conservatively",()=>{
    const status=parseFoundationStatus({core:"ready",storage:"ready",ipc:"restricted",schema_version:1});
    const coverage={registry_machine_64:true,registry_machine_32:true,registry_current_user_64:true,registry_current_user_32:true,msix_current_user:true,other_users:false,portable_applications:false,filesystem_crawl:false,limitations:["Portable applications are outside coverage."]} as const;
    const app={application_id:`appv1-${"b".repeat(32)}`,name:"Fixture App",normalized_name:"fixture app",publisher:"Fixture Corp.",normalized_publisher:"fixture corp",version:{raw:"1.0.0",kind:"sem_ver" as const,canonical:"1.0.0",numeric:[1,0,0]},sources:[{kind:"registry" as const,scope:"machine" as const,view:"registry64" as const,source_id:"fixture"}],product_code:null,package_family_name:null,install_location:null,display_icon:null,display_icon_signature:null,install_date_reported:"20260902",system_component:false,release_type:null,identity:{state:"curated" as const,cpe:"cpe:2.3:a:fixture:app:*:*:*:*:*:*:*:*",purl:null,reason:"versioned curated alias matched",alias_dataset:"IDENTITY_ALIAS_DATA_V1"}};
    const finding={fingerprint_version:"INSTALLED_APP_VULNERABILITY_V1" as const,fingerprint:`iav1-${"d".repeat(32)}`,application_id:app.application_id,application_name:app.name,installed_version:"1.0.0",cve:"CVE-2099-0001",affected:"affected" as const,identity_state:"curated" as const,priority:"immediate" as const,priority_reasons:["CISA KEV lists this validated CVE; this does not prove host exploitation."],cvss_score:9.8,cvss_severity:"CRITICAL",kev:{cve:"CVE-2099-0001",date_added:"2099-01-01",due_date:null,required_action:null},epss:{cve:"CVE-2099-0001",probability:0.9,percentile:0.99,score_date:"2099-01-01",model_version:"v1"},fixed_version:"2.0.0",sources:["NVD"],limitations:["Availability not established"]};
    const providers=(["NVD","CISA_KEV","EPSS"] as const).map(provider=>({provider,state:"ready" as const,dataset_version:"fixture",fetched_at_utc:null,sha256:"c".repeat(64),freshness:"synthetic_fixture"}));
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="installed-apps" installedPreview={{preview_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",application_count:1,system_component_count:0,inventory_fingerprint:"a".repeat(64),coverage,requires_confirmation:true}} installedAuthorization={{authorization_id:"018f4c2a-1d3b-7abc-8def-0123456789ac",application_count:1,inventory_fingerprint:"a".repeat(64),coverage}} providerStatus={providers} installedInventory={{scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ad",state:"completed",snapshot:{schema:"INSTALLED_APPLICATION_SNAPSHOT_V1",applications:[app],coverage},findings:[finding],provider_status:providers}}/>);
    for(const label of ["Installed Application Security","Preview inventory","Authorize this snapshot","Confirm installed-app analysis","Provider status","Inventory coverage","Fixture App","curated","CVE-2099-0001","immediate","No finding does not mean clean","does not prove host exploitation","availability on this host is not established"])expect(html).toContain(label);
    expect(html).not.toContain("No threats found");expect(html).not.toContain("host exploited</strong>");
  });

  it("renders stale and unavailable Level 3 provider coverage explicitly",()=>{
    const status=parseFoundationStatus({core:"ready",storage:"ready",ipc:"restricted",schema_version:1});
    const providers=[
      {provider:"NVD",state:"stale_cache",dataset_version:"fixture-old",fetched_at_utc:"2026-08-01T00:00:00Z",sha256:"a".repeat(64),freshness:"stale_age_over_24h"},
      {provider:"CISA_KEV",state:"unavailable",dataset_version:null,fetched_at_utc:null,sha256:null,freshness:"no_validated_cache"},
      {provider:"EPSS",state:"ready",dataset_version:"fixture",fetched_at_utc:"2026-09-02T00:00:00Z",sha256:"b".repeat(64),freshness:"age_within_48h"},
    ] as const;
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="installed-apps" providerStatus={providers}/>);
    for(const label of ["Provider status","stale_cache","stale_age_over_24h","unavailable","no_validated_cache"])expect(html).toContain(label);
    expect(html).not.toContain("No vulnerabilities");
  });

  it("renders Level 4 authorization and passive evidence without query or cookie values",()=>{
    const status=parseFoundationStatus({core:"ready",storage:"ready",ipc:"restricted",schema_version:1});
    const target={display_url:"https://target.example/path?token=[REDACTED]",scheme:"https" as const,canonical_host:"target.example",path:"/path",port:443 as const,query_present:true,query_parameter_names:["token"],fragment_present:false,idna_ascii:false,public_ip_literal:false};
    const progress={scan_id:"018f4c2a-1d3b-7abc-8def-0123456789ab",phase:"reporting",completed_tasks:7,total_tasks:7,percent:100,elapsed_ms:10,current_engine:null,status:"partial" as const};
    const analysis={schema:"PASSIVE_WEB_ANALYSIS_V1" as const,scan_id:progress.scan_id,state:"partial",query_policy:"send" as const,target,final_target:target,dns:[{canonical_host:"target.example",public_addresses:["93.184.216.34"],selected_address:"93.184.216.34",address_families:["ipv4"],resolved_at_utc:"2026-09-02T00:00:00Z",state:"resolved_public_and_pinned"}],tls:[{attempted:true,certificate_state:"valid",validation_enabled:true,hostname_validation_enabled:true,protocol:null,cipher:null,subject:null,issuer:null,not_before:null,not_after:null,fingerprint_sha256:null,san_count:null,error:null}],redirects:[],final_http_status:200,headers:[{name:"content-security-policy",state:"observed",value_sanitized:"default-src 'self'",interpretation:"Observed",class:"informational",guidance:"Review"}],cookies:[{safe_identifier:"session",secure:true,http_only:true,same_site:"lax",domain_present:false,path:null,max_age_or_expires_present:false,partitioned:false,prefix:null,observations:[]}],reputation:{provider:"URLhaus",state:"unavailable_byok_not_configured",exact_match:null,dataset_version:null,explanation:"Not checked — optional provider not configured."},findings:[],risk:"info" as const,confidence:"high" as const,coverage:{dns:"executed",tls:"executed",http:"executed",redirects:"executed",headers:"executed",cookies:"executed",reputation:"unavailable",limitations:["Passive only"]}};
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="web-url" urlPreview={{preview_id:progress.scan_id,target,query_policy:"send",requires_confirmation:true}} urlAuthorization={{authorization_id:"018f4c2a-1d3b-7abc-8def-0123456789ac",target,query_policy:"send"}} webAnalysis={{scan_id:progress.scan_id,state:"partial",progress,analysis,terminal_error:null}}/>);
    for(const label of ["Web / URL Security","Sanitized preview","DNS / Target","TLS","Redirects","Security headers","Cookie attributes","Value never retained","Reputation","Coverage"])expect(html).toContain(label);
    expect(html).toContain("token=[REDACTED]");
    expect(html).not.toContain("EDY_FAKE_QUERY_SECRET_LEVEL4");
    expect(html).not.toContain("EDY_FAKE_COOKIE_SECRET_LEVEL4");
  });

  it("renders the production manual remediation page without mutating controls",()=>{
    const status=parseFoundationStatus({core:"ready",storage:"ready",ipc:"restricted",schema_version:1});
    const html=renderToStaticMarkup(<FoundationView status={status} failed={false} initialPage="remediation"/>);
    expect(html).toContain("Automatic target changes and rollback are policy blocked");
    expect(html).not.toContain("Apply this remediation");
    expect(html).not.toContain(">Roll back<");
  });
});
