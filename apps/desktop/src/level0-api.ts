import { invoke } from "@tauri-apps/api/core";
import { parseFoundationStatus } from "./foundation";
import type { FoundationStatus } from "./foundation";

export type EngineState = "ready" | "unavailable" | "tampered" | "policy_blocked";
export type ScanState = "queued" | "preparing" | "running" | "cancellation_requested" | "cancelled" | "completed" | "partial" | "failed";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface EngineStatus {
  readonly id: "yara-x" | "gitleaks" | "trivy" | "osv-scanner";
  readonly version: string;
  readonly state: EngineState;
  readonly detail_safe: string;
}

export interface CoverageView {
  readonly total: number;
  readonly completed: number;
  readonly failed: number;
  readonly unavailable: number;
  readonly skipped: number;
}

export interface ScanSummary {
  readonly id: string;
  readonly state: ScanState;
  readonly verdict: string | null;
  readonly risk: Severity | null;
  readonly confidence: Confidence | null;
  readonly coverage: CoverageView;
}

export interface ScanProgress {
  readonly scan_id: string;
  readonly phase: string;
  readonly completed_tasks: number;
  readonly total_tasks: number;
  readonly percent: number | null;
  readonly elapsed_ms: number;
  readonly current_engine: string | null;
  readonly status: ScanState;
}

export interface FindingView {
  readonly id: string;
  readonly scan_id: string;
  readonly title: string;
  readonly category: string;
  readonly severity: Severity;
  readonly risk: Severity;
  readonly confidence: Confidence;
  readonly status: string;
  readonly sources: readonly string[];
  readonly affected_component: string;
  readonly rule_ids: readonly string[];
  readonly evidence_ids: readonly string[];
  readonly remediation_guidance: string;
  readonly limitations: readonly string[];
}

export interface ReportView {
  readonly scan_id: string;
  readonly kind: "executive" | "technical" | "developer";
  readonly schema: "REPORT_SCHEMA_V2";
  readonly json: string;
}

export interface SafeIpcError {
  readonly code: string;
  readonly message_safe: string;
  readonly correlation_id: string;
}

export interface RepositoryAuthorization {
  readonly authorization_id: string; readonly canonical_root: string;
  readonly estimated_files: number; readonly estimated_bytes: number;
  readonly exclusions: readonly string[]; readonly inventory_status: string; readonly readiness: string;
  readonly limits: { readonly max_files:number; readonly max_total_bytes:number; readonly max_file_bytes:number; readonly max_depth:number };
}

export interface FileTargetPreview {
  readonly preview_id: string;
  readonly requested_path: string; readonly canonical_path: string; readonly file_name: string;
  readonly identity: { readonly volume_id:string; readonly file_id:string; readonly size:number; readonly last_write_time:string; readonly attributes:number };
  readonly detected_type: "generic_file"|"pe_executable"|"pe_dll"|"unknown_binary";
  readonly proposed_checks: readonly string[]; readonly policy_limitations: readonly string[]; readonly max_file_size:number;
}

export interface FileAuthorization {
  readonly authorization_id:string; readonly canonical_path:string; readonly size:number; readonly detected_type:string;
  readonly proposed_checks:readonly string[]; readonly policy_limitations:readonly string[];
}

export interface FileAnalysisData {
  readonly target:{ readonly canonical_path:string; readonly identity:FileTargetPreview["identity"] };
  readonly hashes:{ readonly sha256:string; readonly sha512:string; readonly bytes_hashed:number };
  readonly classification:string;
  readonly pe:null|{ readonly machine:number; readonly architecture:string; readonly subsystem:number; readonly timestamp:number; readonly image_base:number; readonly entry_point_rva:number; readonly is_dll:boolean; readonly signature_present:boolean; readonly sections:readonly {readonly name:string;readonly virtual_size:number;readonly raw_size:number;readonly characteristics:number}[] };
  readonly pe_error:string|null;
  readonly authenticode:{readonly signature_present:boolean;readonly cryptographic_status:string;readonly trust_chain_status:string;readonly offline_cache_only:boolean;readonly publisher?:{readonly subject:string|null;readonly issuer:string|null;readonly certificate_fingerprint:string|null;readonly signing_time:string|null;readonly timestamp_present:boolean|null}};
  readonly yara_observations:readonly unknown[];
  readonly reputation:{readonly privacy_mode:string;readonly availability:string;readonly provider:string|null;readonly known:boolean|null;readonly malicious_count:number|null;readonly suspicious_count:number|null;readonly status:string};
  readonly findings:readonly FindingView[];
  readonly coverage:{readonly hashing:string;readonly classification:string;readonly pe_inspection:string;readonly authenticode:string;readonly yara:string;readonly reputation:string;readonly target_stable:boolean;readonly unavailable_checks:readonly string[]};
  readonly verdict:{readonly disposition:string;readonly risk_score:number;readonly risk:Severity;readonly confidence_score:number;readonly confidence:Confidence;readonly reasons:readonly string[]};
}

export interface FileAnalysisView {
  readonly scan_id:string; readonly state:ScanState; readonly progress:ScanProgress;
  readonly analysis:FileAnalysisData|null; readonly terminal_error:string|null;
}

const ENGINE_IDS = ["yara-x", "gitleaks", "trivy", "osv-scanner"] as const;
const ENGINE_STATES = ["ready", "unavailable", "tampered", "policy_blocked"] as const;
const SCAN_STATES = ["queued", "preparing", "running", "cancellation_requested", "cancelled", "completed", "partial", "failed"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const CONFIDENCES = ["low", "medium", "high"] as const;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Backend response rejected");
  return value as Record<string, unknown>;
}

function exact(item: Record<string, unknown>, keys: readonly string[]): void {
  const observed = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (observed.length !== expected.length || observed.some((key, index) => key !== expected[index])) {
    throw new Error("Backend response rejected");
  }
}

function text(value: unknown, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("Backend response rejected");
  return value;
}

function member<const T extends readonly string[]>(value: unknown, values: T): T[number] {
  if (typeof value !== "string" || !values.includes(value)) throw new Error("Backend response rejected");
  return value as T[number];
}

function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) throw new Error("Backend response rejected");
  return value;
}

function nullable<T>(value: unknown, parse: (input: unknown) => T): T | null {
  return value === null ? null : parse(value);
}

function uuid(value: unknown): string {
  const result = text(value, 36);
  if (!UUID_V7.test(result)) throw new Error("Backend response rejected");
  return result;
}

function findingIdentifier(value: unknown): string {
  const result = text(value, 160);
  if (UUID_V7.test(result) || /^(?:yara_finding_v1|signature_finding_v1|pe_indicator_v1|reputation_finding_v1)-[0-9a-f]{64}$/u.test(result)) return result;
  throw new Error("Backend response rejected");
}

function stringList(value:unknown, maximum=32, itemMaximum=2048):readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error("Backend response rejected");
  return Object.freeze(value.map(item=>text(item,itemMaximum)));
}

function coverage(value: unknown): CoverageView {
  const item = record(value);
  exact(item, ["total", "completed", "failed", "unavailable", "skipped"]);
  const result = {
    total: integer(item.total, 1024), completed: integer(item.completed, 1024),
    failed: integer(item.failed, 1024), unavailable: integer(item.unavailable, 1024),
    skipped: integer(item.skipped, 1024),
  };
  if (result.completed + result.failed + result.unavailable + result.skipped > result.total) throw new Error("Backend response rejected");
  return Object.freeze(result);
}

export function parseEngineStatus(value: unknown): EngineStatus {
  const item = record(value);
  exact(item, ["id", "version", "state", "detail_safe"]);
  return Object.freeze({
    id: member(item.id, ENGINE_IDS), version: text(item.version, 32),
    state: member(item.state, ENGINE_STATES), detail_safe: text(item.detail_safe, 256),
  });
}

export function parseScanSummary(value: unknown): ScanSummary {
  const item = record(value);
  exact(item, ["id", "state", "verdict", "risk", "confidence", "coverage"]);
  return Object.freeze({
    id: uuid(item.id), state: member(item.state, SCAN_STATES),
    verdict: nullable(item.verdict, (input) => text(input, 64)),
    risk: nullable(item.risk, (input) => member(input, SEVERITIES)),
    confidence: nullable(item.confidence, (input) => member(input, CONFIDENCES)),
    coverage: coverage(item.coverage),
  });
}

export function parseScanProgress(value: unknown): ScanProgress {
  const item = record(value);
  exact(item, ["scan_id", "phase", "completed_tasks", "total_tasks", "percent", "elapsed_ms", "current_engine", "status"]);
  const percent = nullable(item.percent, (input) => integer(input, 100));
  const result = {
    scan_id: uuid(item.scan_id), phase: text(item.phase, 64),
    completed_tasks: integer(item.completed_tasks, 1024), total_tasks: integer(item.total_tasks, 1024),
    percent, elapsed_ms: integer(item.elapsed_ms),
    current_engine: nullable(item.current_engine, (input) => text(input, 64)),
    status: member(item.status, SCAN_STATES),
  };
  if (result.completed_tasks > result.total_tasks) throw new Error("Backend response rejected");
  return Object.freeze(result);
}

export function parseFinding(value: unknown): FindingView {
  const item = record(value);
  exact(item, ["id", "scan_id", "title", "category", "severity", "risk", "confidence", "status", "sources", "affected_component", "rule_ids", "evidence_ids", "remediation_guidance", "limitations"]);
  if (!Array.isArray(item.sources) || item.sources.length > 16 || !Array.isArray(item.rule_ids) || !Array.isArray(item.evidence_ids) || !Array.isArray(item.limitations)) throw new Error("Backend response rejected");
  return Object.freeze({
    id: findingIdentifier(item.id), scan_id: uuid(item.scan_id), title: text(item.title, 256),
    category: text(item.category, 64), severity: member(item.severity, SEVERITIES),
    risk: member(item.risk, SEVERITIES), confidence: member(item.confidence, CONFIDENCES),
    status: text(item.status, 64), sources: Object.freeze(item.sources.map((source) => text(source, 64))),
    affected_component: text(item.affected_component, 4096),
    rule_ids: Object.freeze(item.rule_ids.map((rule) => text(rule, 256))),
    evidence_ids: Object.freeze(item.evidence_ids.map((evidence) => text(evidence, 512))),
    remediation_guidance: text(item.remediation_guidance, 2048),
    limitations: Object.freeze(item.limitations.map((limitation) => text(limitation, 2048))),
  });
}

export function parseReport(value: unknown): ReportView {
  const item = record(value);
  exact(item, ["scan_id", "kind", "schema", "json"]);
  const json = text(item.json, 2 * 1024 * 1024);
  JSON.parse(json);
  if (item.schema !== "REPORT_SCHEMA_V2") throw new Error("Backend response rejected");
  return Object.freeze({
    scan_id: uuid(item.scan_id), kind: member(item.kind, ["executive", "technical", "developer"] as const),
    schema: "REPORT_SCHEMA_V2", json,
  });
}

export function parseRepositoryAuthorization(value: unknown): RepositoryAuthorization {
  const item = record(value);
  exact(item, ["authorization_id","canonical_root","estimated_files","estimated_bytes","exclusions","limits","inventory_status","readiness"]);
  if (!Array.isArray(item.exclusions)) throw new Error("Backend response rejected");
  const limits = record(item.limits); exact(limits,["max_files","max_total_bytes","max_file_bytes","max_depth"]);
  return Object.freeze({ authorization_id:uuid(item.authorization_id), canonical_root:text(item.canonical_root,4096),
    estimated_files:integer(item.estimated_files), estimated_bytes:integer(item.estimated_bytes),
    exclusions:Object.freeze(item.exclusions.map(x=>text(x,128))), inventory_status:text(item.inventory_status,64), readiness:text(item.readiness,128),
    limits:Object.freeze({max_files:integer(limits.max_files),max_total_bytes:integer(limits.max_total_bytes),max_file_bytes:integer(limits.max_file_bytes),max_depth:integer(limits.max_depth,128)}) });
}

export function parseFileTargetPreview(value:unknown):FileTargetPreview {
  const item=record(value); exact(item,["preview_id","requested_path","canonical_path","file_name","identity","detected_type","proposed_checks","policy_limitations","max_file_size"]);
  const identity=record(item.identity); exact(identity,["volume_id","file_id","size","last_write_time","attributes"]);
  return Object.freeze({preview_id:uuid(item.preview_id),requested_path:text(item.requested_path,4096),canonical_path:text(item.canonical_path,4096),file_name:text(item.file_name,512),
    identity:Object.freeze({volume_id:text(identity.volume_id,32),file_id:text(identity.file_id,32),size:integer(identity.size),last_write_time:text(identity.last_write_time,32),attributes:integer(identity.attributes,0xffffffff)}),
    detected_type:member(item.detected_type,["generic_file","pe_executable","pe_dll","unknown_binary"] as const),proposed_checks:stringList(item.proposed_checks,16,128),policy_limitations:stringList(item.policy_limitations,16),max_file_size:integer(item.max_file_size)});
}

export function parseFileAuthorization(value:unknown):FileAuthorization {
  const item=record(value); exact(item,["authorization_id","canonical_path","size","detected_type","proposed_checks","policy_limitations"]);
  return Object.freeze({authorization_id:uuid(item.authorization_id),canonical_path:text(item.canonical_path,4096),size:integer(item.size),detected_type:text(item.detected_type,64),proposed_checks:stringList(item.proposed_checks,16,128),policy_limitations:stringList(item.policy_limitations,16)});
}

function parseFileFinding(value:unknown,scanId:string):FindingView {
  const item=record(value); exact(item,["fingerprint_version","fingerprint","category","rule_id","title","severity","confidence","source","evidence"]);
  const fingerprint=findingIdentifier(item.fingerprint);
  return Object.freeze({id:fingerprint,scan_id:scanId,title:text(item.title,256),category:member(item.category,["file_metadata","file_integrity","executable_metadata","digital_signature","yara_match","file_reputation","suspicious_binary_indicator"] as const),severity:member(item.severity,SEVERITIES),risk:member(item.severity,SEVERITIES),confidence:member(item.confidence,CONFIDENCES),status:"open",sources:Object.freeze([text(item.source,128)]),affected_component:"authorized_file_identity",rule_ids:Object.freeze([text(item.rule_id,256)]),evidence_ids:stringList(item.evidence,32,512),remediation_guidance:"Review evidence and re-authorize before verification",limitations:Object.freeze(["YARA-X real execution is policy-blocked","Reputation was not checked"])});
}

function parseFileAnalysis(value:unknown,scanId:string):FileAnalysisData {
  const item=record(value); exact(item,["target","hashes","classification","pe","pe_error","authenticode","yara_observations","reputation","findings","coverage","verdict"]);
  const target=record(item.target); exact(target,["authorization_id","requested_path","canonical_path","identity","authorized_at_utc","snapshot_version","max_file_size"]); const identity=record(target.identity); exact(identity,["volume_id","file_id","size","last_write_time","attributes"]);
  const hashes=record(item.hashes); exact(hashes,["sha256","sha512","bytes_hashed"]); const sha256=text(hashes.sha256,64),sha512=text(hashes.sha512,128); if(!/^[0-9a-f]{64}$/u.test(sha256)||!/^[0-9a-f]{128}$/u.test(sha512)) throw new Error("Backend response rejected");
  const auth=record(item.authenticode); exact(auth,["signature_present","cryptographic_status","trust_chain_status","publisher","offline_cache_only"]);
  for (const value of [auth.signature_present, auth.offline_cache_only]) if (typeof value !== "boolean") throw new Error("Backend response rejected");
  if (auth.offline_cache_only !== true) throw new Error("Backend response rejected");
  const signatureStates=["unsigned","signed_valid_offline","signed_invalid","trust_chain_valid_offline","trust_chain_unavailable_offline","indeterminate","error"] as const;
  member(auth.cryptographic_status,signatureStates); member(auth.trust_chain_status,signatureStates);
  const publisher=record(auth.publisher); exact(publisher,["subject","issuer","certificate_fingerprint","signing_time","timestamp_present"]);
  const publisherView=Object.freeze({subject:nullable(publisher.subject,value=>text(value,512)),issuer:nullable(publisher.issuer,value=>text(value,512)),certificate_fingerprint:nullable(publisher.certificate_fingerprint,value=>{const digest=text(value,64);if(!/^[0-9a-f]{64}$/u.test(digest))throw new Error("Backend response rejected");return digest;}),signing_time:nullable(publisher.signing_time,value=>text(value,64)),timestamp_present:nullable(publisher.timestamp_present,value=>{if(typeof value!=="boolean")throw new Error("Backend response rejected");return value;})});
  const reputation=record(item.reputation); exact(reputation,["privacy_mode","availability","provider","known","malicious_count","suspicious_count","status"]);
  const coverageItem=record(item.coverage); exact(coverageItem,["hashing","classification","pe_inspection","authenticode","yara","reputation","target_stable","unavailable_checks"]);
  for (const check of [coverageItem.hashing,coverageItem.classification,coverageItem.pe_inspection,coverageItem.authenticode,coverageItem.yara,coverageItem.reputation]) member(check,["completed","not_applicable","policy_blocked","not_checked","failed"] as const);
  if (typeof coverageItem.target_stable!=="boolean" || (reputation.known!==null && typeof reputation.known!=="boolean")) throw new Error("Backend response rejected");
  member(item.classification,["generic_file","pe_executable","pe_dll","unknown_binary"] as const);
  const verdict=record(item.verdict); exact(verdict,["disposition","risk_score","risk","confidence_score","confidence","reasons"]);
  let pe:FileAnalysisData["pe"]=null; if(item.pe!==null){const p=record(item.pe); exact(p,["machine","architecture","characteristics","subsystem","timestamp","image_base","entry_point_rva","sections","is_dll","signature_present"]); if(!Array.isArray(p.sections)||p.sections.length>96)throw new Error("Backend response rejected"); pe=Object.freeze({machine:integer(p.machine,0xffff),architecture:text(p.architecture,32),subsystem:integer(p.subsystem,0xffff),timestamp:integer(p.timestamp,0xffffffff),image_base:integer(p.image_base),entry_point_rva:integer(p.entry_point_rva,0xffffffff),is_dll:p.is_dll===true,signature_present:p.signature_present===true,sections:Object.freeze(p.sections.map(section=>{const s=record(section);exact(s,["name","virtual_size","raw_size","characteristics"]);return Object.freeze({name:text(s.name,8),virtual_size:integer(s.virtual_size,0xffffffff),raw_size:integer(s.raw_size,0xffffffff),characteristics:integer(s.characteristics,0xffffffff)});} ))});}
  if(!Array.isArray(item.findings)||item.findings.length>4096||!Array.isArray(item.yara_observations)||item.yara_observations.length>4096)throw new Error("Backend response rejected");
  return Object.freeze({target:Object.freeze({canonical_path:text(target.canonical_path,4096),identity:Object.freeze({volume_id:text(identity.volume_id,32),file_id:text(identity.file_id,32),size:integer(identity.size),last_write_time:text(identity.last_write_time,32),attributes:integer(identity.attributes,0xffffffff)})}),hashes:Object.freeze({sha256,sha512,bytes_hashed:integer(hashes.bytes_hashed)}),classification:text(item.classification,64),pe,pe_error:nullable(item.pe_error,input=>text(input,64)),authenticode:Object.freeze({signature_present:auth.signature_present===true,cryptographic_status:text(auth.cryptographic_status,64),trust_chain_status:text(auth.trust_chain_status,64),offline_cache_only:auth.offline_cache_only===true,publisher:publisherView}),yara_observations:Object.freeze(item.yara_observations),reputation:Object.freeze({privacy_mode:text(reputation.privacy_mode,32),availability:text(reputation.availability,32),provider:nullable(reputation.provider,input=>text(input,64)),known:reputation.known===null?null:reputation.known===true,malicious_count:nullable(reputation.malicious_count,input=>integer(input)),suspicious_count:nullable(reputation.suspicious_count,input=>integer(input)),status:text(reputation.status,64)}),findings:Object.freeze(item.findings.map(finding=>parseFileFinding(finding,scanId))),coverage:Object.freeze({hashing:text(coverageItem.hashing,32),classification:text(coverageItem.classification,32),pe_inspection:text(coverageItem.pe_inspection,32),authenticode:text(coverageItem.authenticode,32),yara:text(coverageItem.yara,32),reputation:text(coverageItem.reputation,32),target_stable:coverageItem.target_stable===true,unavailable_checks:stringList(coverageItem.unavailable_checks,16,128)}),verdict:Object.freeze({disposition:text(verdict.disposition,64),risk_score:integer(verdict.risk_score,100),risk:member(verdict.risk,SEVERITIES),confidence_score:integer(verdict.confidence_score,100),confidence:member(verdict.confidence,CONFIDENCES),reasons:stringList(verdict.reasons,16)})});
}

export function parseFileAnalysisView(value:unknown):FileAnalysisView {
  const item=record(value); exact(item,["scan_id","state","progress","analysis","terminal_error"]); const scanId=uuid(item.scan_id); const progress=parseScanProgress(item.progress); if(progress.scan_id!==scanId)throw new Error("Backend response rejected");
  return Object.freeze({scan_id:scanId,state:member(item.state,SCAN_STATES),progress,analysis:item.analysis===null?null:parseFileAnalysis(item.analysis,scanId),terminal_error:nullable(item.terminal_error,input=>text(input,128))});
}

async function call<T>(command: string, args: Record<string, unknown>, parse: (value: unknown) => T, timeoutMs: number | null = 8000): Promise<T> {
  if (timeoutMs === null) return parse(await invoke(command, args));
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const value = await Promise.race([
      invoke(command, args),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Backend unavailable")), timeoutMs); }),
    ]);
    return parse(value);
  } finally {
    clearTimeout(timer);
  }
}

export const level0Api = Object.freeze({
  foundation: (): Promise<FoundationStatus> => call("get_foundation_status", {}, parseFoundationStatus),
  engines: (): Promise<readonly EngineStatus[]> => call("get_engine_status", {}, (value) => {
    if (!Array.isArray(value) || value.length !== 4) throw new Error("Backend response rejected");
    const engines = value.map(parseEngineStatus);
    if (new Set(engines.map((engine) => engine.id)).size !== ENGINE_IDS.length
      || ENGINE_IDS.some((id) => !engines.some((engine) => engine.id === id))) throw new Error("Backend response rejected");
    return Object.freeze(engines);
  }),
  createSyntheticScan: (): Promise<ScanSummary> => call("create_synthetic_scan", { request: { fixture_id: "synthetic-target-a" } }, parseScanSummary, null),
  authorizeRepository: (path:string):Promise<RepositoryAuthorization> => call("authorize_repository_target",{request:{path:text(path,4096)}},parseRepositoryAuthorization,null),
  createRepositoryScan: (authorizationId:string):Promise<ScanSummary> => call("create_repository_scan",{request:{authorization_id:uuid(authorizationId),confirmed:true}},parseScanSummary,null),
  inspectFile: (path:string):Promise<FileTargetPreview> => call("inspect_file_target",{request:{path:text(path,4096)}},parseFileTargetPreview,null),
  authorizeFile: (previewId:string):Promise<FileAuthorization> => call("authorize_file_target",{request:{preview_id:uuid(previewId),confirmed:true}},parseFileAuthorization,null),
  createFileScan: (authorizationId:string):Promise<ScanSummary> => call("create_file_scan",{request:{authorization_id:uuid(authorizationId),confirmed:true}},parseScanSummary,null),
  getFileAnalysis: (scanId:string):Promise<FileAnalysisView> => {const expected=uuid(scanId);return call("get_file_analysis",{request:{scan_id:expected}},value=>{const result=parseFileAnalysisView(value);if(result.scan_id!==expected)throw new Error("Backend response rejected");return result;});},
  getScan: (scanId: string): Promise<ScanSummary> => {
    const expected = uuid(scanId);
    return call("get_scan", { request: { scan_id: expected } }, (value) => {
      const scan = parseScanSummary(value);
      if (scan.id !== expected) throw new Error("Backend response rejected");
      return scan;
    });
  },
  listScans: (): Promise<readonly ScanSummary[]> => call("list_scans", { request: { offset: 0, limit: 50 } }, (value) => {
    if (!Array.isArray(value) || value.length > 50) throw new Error("Backend response rejected");
    const scans = value.map(parseScanSummary);
    if (new Set(scans.map((scan) => scan.id)).size !== scans.length) throw new Error("Backend response rejected");
    return Object.freeze(scans);
  }),
  progress: (scanId: string): Promise<ScanProgress> => {
    const expected = uuid(scanId);
    return call("get_scan_progress", { request: { scan_id: expected } }, (value) => {
      const progress = parseScanProgress(value);
      if (progress.scan_id !== expected) throw new Error("Backend response rejected");
      return progress;
    });
  },
  cancel: (scanId: string): Promise<ScanProgress> => {
    const expected = uuid(scanId);
    return call("cancel_scan", { request: { scan_id: expected } }, (value) => {
      const progress = parseScanProgress(value);
      if (progress.scan_id !== expected) throw new Error("Backend response rejected");
      return progress;
    }, null);
  },
  findings: (scanId: string): Promise<readonly FindingView[]> => {
    const expected = uuid(scanId);
    return call("list_findings", { request: { scan_id: expected, offset: 0, limit: 100 } }, (value) => {
    if (!Array.isArray(value) || value.length > 100) throw new Error("Backend response rejected");
    const findings = value.map(parseFinding);
    if (findings.some((finding) => finding.scan_id !== expected)
      || new Set(findings.map((finding) => finding.id)).size !== findings.length) throw new Error("Backend response rejected");
    return Object.freeze(findings);
    });
  },
  getFinding: (findingId: string): Promise<FindingView> => {
    const expected = findingIdentifier(findingId);
    return call("get_finding", { request: { finding_id: expected } }, (value) => {
      const finding = parseFinding(value);
      if (finding.id !== expected) throw new Error("Backend response rejected");
      return finding;
    });
  },
  report: (scanId: string, kind: ReportView["kind"]): Promise<ReportView> => {
    const expected = uuid(scanId);
    return call("generate_report", { request: { scan_id: expected, kind } }, (value) => {
      const report = parseReport(value);
      if (report.scan_id !== expected || report.kind !== kind) throw new Error("Backend response rejected");
      return report;
    });
  },
});
