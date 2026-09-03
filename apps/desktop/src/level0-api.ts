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
  readonly authenticode:{readonly signature_present:boolean;readonly cryptographic_status:string;readonly trust_chain_status:string;readonly offline_cache_only:boolean;readonly publisher?:{readonly subject:string|null;readonly issuer:string|null;readonly certificate_fingerprint:string|null;readonly signing_time:string|null;readonly timestamp_present:boolean|null;readonly trusted_timestamp_present?:boolean|null}};
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

export type InstalledVersionKind = "sem_ver" | "dotted_numeric" | "vendor_specific" | "unknown";
export type InstalledIdentityState = "exact" | "curated" | "strong" | "heuristic" | "unmapped" | "conflicting";
export type InstalledPriority = "low" | "normal" | "high" | "immediate" | "review";
export interface InstalledInventoryCoverage { readonly registry_machine_64:boolean; readonly registry_machine_32:boolean; readonly registry_current_user_64:boolean; readonly registry_current_user_32:boolean; readonly msix_current_user:boolean; readonly other_users:boolean; readonly portable_applications:boolean; readonly filesystem_crawl:boolean; readonly limitations:readonly string[] }
export interface InstalledApplication { readonly application_id:string; readonly name:string; readonly normalized_name:string; readonly publisher:string|null; readonly normalized_publisher:string|null; readonly version:{readonly raw:string|null;readonly kind:InstalledVersionKind;readonly canonical:string|null;readonly numeric:readonly number[]}; readonly sources:readonly {readonly kind:"registry"|"msix";readonly scope:"machine"|"current_user";readonly view:"registry64"|"registry32"|"not_applicable";readonly source_id:string}[]; readonly product_code:string|null; readonly package_family_name:string|null; readonly install_location:string|null; readonly display_icon:string|null; readonly display_icon_signature:null|{readonly cryptographic_status:string;readonly trust_chain_status:string;readonly publisher_subject:string|null;readonly offline_cache_only:true;readonly limitation:string}; readonly install_date_reported:string|null; readonly system_component:boolean; readonly release_type:string|null; readonly identity:{readonly state:InstalledIdentityState;readonly cpe:string|null;readonly purl:string|null;readonly reason:string;readonly alias_dataset:string} }
export interface InstalledAppFinding { readonly fingerprint_version:"INSTALLED_APP_VULNERABILITY_V1";readonly fingerprint:string;readonly application_id:string;readonly application_name:string;readonly installed_version:string;readonly cve:string;readonly affected:"affected";readonly identity_state:InstalledIdentityState;readonly priority:InstalledPriority;readonly priority_reasons:readonly string[];readonly cvss_score:number|null;readonly cvss_severity:string|null;readonly fixed_version:string|null;readonly sources:readonly string[];readonly limitations:readonly string[];readonly kev:null|{readonly cve:string;readonly date_added:string;readonly due_date:string|null;readonly required_action:string|null};readonly epss:null|{readonly cve:string;readonly probability:number;readonly percentile:number;readonly score_date:string;readonly model_version:string|null} }
export interface DatasetStatus {readonly provider:"NVD"|"CISA_KEV"|"EPSS";readonly state:"ready"|"stale_cache"|"unavailable";readonly dataset_version:string|null;readonly fetched_at_utc:string|null;readonly sha256:string|null;readonly freshness:string}
export interface InstalledApplicationPreview {readonly preview_id:string;readonly application_count:number;readonly system_component_count:number;readonly inventory_fingerprint:string;readonly coverage:InstalledInventoryCoverage;readonly requires_confirmation:true}
export interface InstalledApplicationAuthorization {readonly authorization_id:string;readonly application_count:number;readonly inventory_fingerprint:string;readonly coverage:InstalledInventoryCoverage}
export interface InstalledApplicationInventory {readonly scan_id:string;readonly state:ScanState;readonly snapshot:{readonly schema:"INSTALLED_APPLICATION_SNAPSHOT_V1";readonly applications:readonly InstalledApplication[];readonly coverage:InstalledInventoryCoverage};readonly findings:readonly InstalledAppFinding[];readonly provider_status:readonly DatasetStatus[]}
export interface PublicDataRefresh {readonly provider_status:readonly DatasetStatus[];readonly host_inventory_transmitted:false}
export type QueryPolicy="send"|"strip";
export interface SanitizedUrlTarget {readonly display_url:string;readonly scheme:"http"|"https";readonly canonical_host:string;readonly path:string;readonly port:80|443;readonly query_present:boolean;readonly query_parameter_names:readonly string[];readonly fragment_present:boolean;readonly idna_ascii:boolean;readonly public_ip_literal:boolean}
export interface UrlTargetPreview {readonly preview_id:string;readonly target:SanitizedUrlTarget;readonly query_policy:QueryPolicy;readonly requires_confirmation:true}
export interface UrlTargetAuthorization {readonly authorization_id:string;readonly target:SanitizedUrlTarget;readonly query_policy:QueryPolicy}
export interface PassiveWebAnalysis {readonly schema:"PASSIVE_WEB_ANALYSIS_V1";readonly scan_id:string;readonly state:string;readonly query_policy:QueryPolicy;readonly target:SanitizedUrlTarget;readonly final_target:SanitizedUrlTarget|null;readonly dns:readonly {readonly canonical_host:string;readonly public_addresses:readonly string[];readonly selected_address:string|null;readonly address_families:readonly string[];readonly resolved_at_utc:string;readonly state:string}[];readonly tls:readonly {readonly attempted:boolean;readonly certificate_state:string;readonly validation_enabled:boolean;readonly hostname_validation_enabled:boolean;readonly protocol:string|null;readonly cipher:string|null;readonly subject:string|null;readonly issuer:string|null;readonly not_before:string|null;readonly not_after:string|null;readonly fingerprint_sha256:string|null;readonly san_count:number|null;readonly error:string|null}[];readonly redirects:readonly {readonly hop:number;readonly status:number;readonly source_scheme:string;readonly source_host:string;readonly destination_scheme:string;readonly destination_host:string;readonly destination_display_url:string;readonly same_origin:boolean;readonly followed:boolean;readonly outcome:string}[];readonly final_http_status:number|null;readonly headers:readonly {readonly name:string;readonly state:string;readonly value_sanitized:string|null;readonly interpretation:string;readonly class:string;readonly guidance:string}[];readonly cookies:readonly {readonly safe_identifier:string;readonly secure:boolean;readonly http_only:boolean;readonly same_site:string;readonly domain_present:boolean;readonly path:string|null;readonly max_age_or_expires_present:boolean;readonly partitioned:boolean;readonly prefix:string|null;readonly observations:readonly string[]}[];readonly reputation:{readonly provider:string;readonly state:string;readonly exact_match:boolean|null;readonly dataset_version:string|null;readonly explanation:string};readonly findings:readonly unknown[];readonly risk:Severity;readonly confidence:Confidence;readonly coverage:{readonly dns:string;readonly tls:string;readonly http:string;readonly redirects:string;readonly headers:string;readonly cookies:string;readonly reputation:string;readonly limitations:readonly string[]}}
export interface WebAnalysisView {readonly scan_id:string;readonly state:ScanState;readonly progress:ScanProgress;readonly analysis:PassiveWebAnalysis|null;readonly terminal_error:string|null}

const ENGINE_IDS = ["yara-x", "gitleaks", "trivy", "osv-scanner"] as const;
const ENGINE_STATES = ["ready", "unavailable", "tampered", "policy_blocked"] as const;
const SCAN_STATES = ["queued", "preparing", "running", "cancellation_requested", "cancelled", "completed", "partial", "failed"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const CONFIDENCES = ["low", "medium", "high"] as const;
const VERSION_KINDS=["sem_ver","dotted_numeric","vendor_specific","unknown"] as const;
const IDENTITY_STATES=["exact","curated","strong","heuristic","unmapped","conflicting"] as const;
const PRIORITIES=["low","normal","high","immediate","review"] as const;
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

function jsonText(value: unknown, maximum: number): string {
  // Pretty JSON legitimately contains TAB/CR/LF. All other C0/DEL controls remain refused.
  if (typeof value !== "string" || value.length === 0 || value.length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) throw new Error("Backend response rejected");
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
  if (UUID_V7.test(result) || /^(?:(?:yara_finding_v1|signature_finding_v1|pe_indicator_v1|reputation_finding_v1)-[0-9a-f]{64}|(?:iav1|webv1)-[0-9a-f]{32})$/u.test(result)) return result;
  throw new Error("Backend response rejected");
}

function stringList(value:unknown, maximum=32, itemMaximum=2048):readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error("Backend response rejected");
  return Object.freeze(value.map(item=>text(item,itemMaximum)));
}

function boolean(value:unknown):boolean {if(typeof value!=="boolean")throw new Error("Backend response rejected");return value;}
function finite(value:unknown,minimum=0,maximum=1):number {if(typeof value!=="number"||!Number.isFinite(value)||value<minimum||value>maximum)throw new Error("Backend response rejected");return value;}
function sha256Optional(value:unknown):string|null{return nullable(value,input=>{const result=text(input,64);if(!/^[0-9a-f]{64}$/u.test(result))throw new Error("Backend response rejected");return result;});}
function parseInstalledCoverage(value:unknown):InstalledInventoryCoverage {const item=record(value);exact(item,["registry_machine_64","registry_machine_32","registry_current_user_64","registry_current_user_32","msix_current_user","other_users","portable_applications","filesystem_crawl","limitations"]);return Object.freeze({registry_machine_64:boolean(item.registry_machine_64),registry_machine_32:boolean(item.registry_machine_32),registry_current_user_64:boolean(item.registry_current_user_64),registry_current_user_32:boolean(item.registry_current_user_32),msix_current_user:boolean(item.msix_current_user),other_users:boolean(item.other_users),portable_applications:boolean(item.portable_applications),filesystem_crawl:boolean(item.filesystem_crawl),limitations:stringList(item.limitations,32,2048)});}
function parseInstalledApplication(value:unknown):InstalledApplication {const item=record(value);exact(item,["application_id","name","normalized_name","publisher","normalized_publisher","version","sources","product_code","package_family_name","install_location","display_icon","display_icon_signature","install_date_reported","system_component","release_type","identity"]);const applicationId=text(item.application_id,38);if(!/^appv1-[0-9a-f]{32}$/u.test(applicationId))throw new Error("Backend response rejected");const version=record(item.version);exact(version,["raw","kind","canonical","numeric"]);if(!Array.isArray(version.numeric)||version.numeric.length>8)throw new Error("Backend response rejected");const identity=record(item.identity);exact(identity,["state","cpe","purl","reason","alias_dataset"]);if(!Array.isArray(item.sources)||item.sources.length===0||item.sources.length>16)throw new Error("Backend response rejected");let signature:InstalledApplication["display_icon_signature"]=null;if(item.display_icon_signature!==null){const s=record(item.display_icon_signature);exact(s,["cryptographic_status","trust_chain_status","publisher_subject","offline_cache_only","limitation"]);if(s.offline_cache_only!==true)throw new Error("Backend response rejected");signature=Object.freeze({cryptographic_status:text(s.cryptographic_status,64),trust_chain_status:text(s.trust_chain_status,64),publisher_subject:nullable(s.publisher_subject,input=>text(input,512)),offline_cache_only:true,limitation:text(s.limitation,1024)});}return Object.freeze({application_id:applicationId,name:text(item.name,512),normalized_name:text(item.normalized_name,512),publisher:nullable(item.publisher,input=>text(input,512)),normalized_publisher:nullable(item.normalized_publisher,input=>text(input,512)),version:Object.freeze({raw:nullable(version.raw,input=>text(input,128)),kind:member(version.kind,VERSION_KINDS),canonical:nullable(version.canonical,input=>text(input,128)),numeric:Object.freeze(version.numeric.map(part=>integer(part)))}),sources:Object.freeze(item.sources.map(source=>{const s=record(source);exact(s,["kind","scope","view","source_id"]);return Object.freeze({kind:member(s.kind,["registry","msix"] as const),scope:member(s.scope,["machine","current_user"] as const),view:member(s.view,["registry64","registry32","not_applicable"] as const),source_id:text(s.source_id,1024)});})),product_code:nullable(item.product_code,input=>text(input,256)),package_family_name:nullable(item.package_family_name,input=>text(input,512)),install_location:nullable(item.install_location,input=>text(input,4096)),display_icon:nullable(item.display_icon,input=>text(input,4096)),display_icon_signature:signature,install_date_reported:nullable(item.install_date_reported,input=>text(input,64)),system_component:boolean(item.system_component),release_type:nullable(item.release_type,input=>text(input,128)),identity:Object.freeze({state:member(identity.state,IDENTITY_STATES),cpe:nullable(identity.cpe,input=>text(input,2048)),purl:nullable(identity.purl,input=>text(input,2048)),reason:text(identity.reason,512),alias_dataset:text(identity.alias_dataset,128)})});}
function parseDatasetStatus(value:unknown):DatasetStatus {const item=record(value);exact(item,["provider","state","dataset_version","fetched_at_utc","sha256","freshness"]);return Object.freeze({provider:member(item.provider,["NVD","CISA_KEV","EPSS"] as const),state:member(item.state,["ready","stale_cache","unavailable"] as const),dataset_version:nullable(item.dataset_version,input=>text(input,128)),fetched_at_utc:nullable(item.fetched_at_utc,input=>text(input,64)),sha256:sha256Optional(item.sha256),freshness:text(item.freshness,128)});}
function parseInstalledFinding(value:unknown):InstalledAppFinding {const item=record(value);exact(item,["fingerprint_version","fingerprint","application_id","application_name","installed_version","cve","affected","identity_state","priority","priority_reasons","cvss_score","cvss_severity","kev","epss","fixed_version","sources","limitations"]);const fingerprint=text(item.fingerprint,37);if(!/^iav1-[0-9a-f]{32}$/u.test(fingerprint)||item.fingerprint_version!=="INSTALLED_APP_VULNERABILITY_V1"||item.affected!=="affected")throw new Error("Backend response rejected");const applicationId=text(item.application_id,38);if(!/^appv1-[0-9a-f]{32}$/u.test(applicationId))throw new Error("Backend response rejected");let kev:InstalledAppFinding["kev"]=null;if(item.kev!==null){const k=record(item.kev);exact(k,["cve","date_added","due_date","required_action"]);kev=Object.freeze({cve:text(k.cve,32),date_added:text(k.date_added,32),due_date:nullable(k.due_date,input=>text(input,32)),required_action:nullable(k.required_action,input=>text(input,2048))});}let epss:InstalledAppFinding["epss"]=null;if(item.epss!==null){const e=record(item.epss);exact(e,["cve","probability","percentile","score_date","model_version"]);epss=Object.freeze({cve:text(e.cve,32),probability:finite(e.probability),percentile:finite(e.percentile),score_date:text(e.score_date,32),model_version:nullable(e.model_version,input=>text(input,128))});}return Object.freeze({fingerprint_version:"INSTALLED_APP_VULNERABILITY_V1",fingerprint,application_id:applicationId,application_name:text(item.application_name,512),installed_version:text(item.installed_version,128),cve:text(item.cve,32),affected:"affected",identity_state:member(item.identity_state,IDENTITY_STATES),priority:member(item.priority,PRIORITIES),priority_reasons:stringList(item.priority_reasons,16,1024),cvss_score:nullable(item.cvss_score,input=>finite(input,0,10)),cvss_severity:nullable(item.cvss_severity,input=>text(input,32)),kev,epss,fixed_version:nullable(item.fixed_version,input=>text(input,128)),sources:stringList(item.sources,16,128),limitations:stringList(item.limitations,16,2048)});}
function parseStatusList(value:unknown):readonly DatasetStatus[]{if(!Array.isArray(value)||value.length!==3)throw new Error("Backend response rejected");const result=value.map(parseDatasetStatus);if(new Set(result.map(item=>item.provider)).size!==3)throw new Error("Backend response rejected");return Object.freeze(result);}
export function parseInstalledApplicationPreview(value:unknown):InstalledApplicationPreview{const item=record(value);exact(item,["preview_id","application_count","system_component_count","inventory_fingerprint","coverage","requires_confirmation"]);const fingerprint=text(item.inventory_fingerprint,64);if(!/^[0-9a-f]{64}$/u.test(fingerprint)||item.requires_confirmation!==true)throw new Error("Backend response rejected");return Object.freeze({preview_id:uuid(item.preview_id),application_count:integer(item.application_count,16384),system_component_count:integer(item.system_component_count,16384),inventory_fingerprint:fingerprint,coverage:parseInstalledCoverage(item.coverage),requires_confirmation:true});}
export function parseInstalledApplicationAuthorization(value:unknown):InstalledApplicationAuthorization{const item=record(value);exact(item,["authorization_id","application_count","inventory_fingerprint","coverage"]);const fingerprint=text(item.inventory_fingerprint,64);if(!/^[0-9a-f]{64}$/u.test(fingerprint))throw new Error("Backend response rejected");return Object.freeze({authorization_id:uuid(item.authorization_id),application_count:integer(item.application_count,16384),inventory_fingerprint:fingerprint,coverage:parseInstalledCoverage(item.coverage)});}
export function parseInstalledApplicationInventory(value:unknown):InstalledApplicationInventory{const item=record(value);exact(item,["scan_id","state","snapshot","findings","provider_status"]);const snapshot=record(item.snapshot);exact(snapshot,["schema","applications","coverage"]);if(snapshot.schema!=="INSTALLED_APPLICATION_SNAPSHOT_V1"||!Array.isArray(snapshot.applications)||snapshot.applications.length>16384||!Array.isArray(item.findings)||item.findings.length>16384)throw new Error("Backend response rejected");return Object.freeze({scan_id:uuid(item.scan_id),state:member(item.state,SCAN_STATES),snapshot:Object.freeze({schema:"INSTALLED_APPLICATION_SNAPSHOT_V1",applications:Object.freeze(snapshot.applications.map(parseInstalledApplication)),coverage:parseInstalledCoverage(snapshot.coverage)}),findings:Object.freeze(item.findings.map(parseInstalledFinding)),provider_status:parseStatusList(item.provider_status)});}

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
  const json = jsonText(item.json, 2 * 1024 * 1024);
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
  member(auth.cryptographic_status,["unsigned","signed_valid_offline","signed_invalid","indeterminate","error"] as const);
  member(auth.trust_chain_status,["unsigned","trust_chain_valid_offline","trust_chain_untrusted","trust_chain_unavailable_offline","indeterminate","error"] as const);
  const publisher=record(auth.publisher); exact(publisher,["subject","issuer","certificate_fingerprint","signing_time","timestamp_present","trusted_timestamp_present"]);
  const publisherView=Object.freeze({subject:nullable(publisher.subject,value=>text(value,512)),issuer:nullable(publisher.issuer,value=>text(value,512)),certificate_fingerprint:nullable(publisher.certificate_fingerprint,value=>{const digest=text(value,64);if(!/^[0-9a-f]{64}$/u.test(digest))throw new Error("Backend response rejected");return digest;}),signing_time:nullable(publisher.signing_time,value=>text(value,64)),timestamp_present:nullable(publisher.timestamp_present,value=>{if(typeof value!=="boolean")throw new Error("Backend response rejected");return value;}),trusted_timestamp_present:nullable(publisher.trusted_timestamp_present,value=>{if(typeof value!=="boolean")throw new Error("Backend response rejected");return value;})});
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

function parseSanitizedUrlTarget(value:unknown):SanitizedUrlTarget{const item=record(value);exact(item,["display_url","scheme","canonical_host","path","port","query_present","query_parameter_names","fragment_present","idna_ascii","public_ip_literal"]);const scheme=member(item.scheme,["http","https"] as const);const port=integer(item.port,443);if((scheme==="http"&&port!==80)||(scheme==="https"&&port!==443))throw new Error("Backend response rejected");return Object.freeze({display_url:text(item.display_url,4096),scheme,canonical_host:text(item.canonical_host,253),path:text(item.path,2048),port:port as 80|443,query_present:boolean(item.query_present),query_parameter_names:stringList(item.query_parameter_names,32,128),fragment_present:boolean(item.fragment_present),idna_ascii:boolean(item.idna_ascii),public_ip_literal:boolean(item.public_ip_literal)});}
export function parseUrlTargetPreview(value:unknown):UrlTargetPreview{const item=record(value);exact(item,["preview_id","target","query_policy","requires_confirmation"]);if(item.requires_confirmation!==true)throw new Error("Backend response rejected");return Object.freeze({preview_id:uuid(item.preview_id),target:parseSanitizedUrlTarget(item.target),query_policy:member(item.query_policy,["send","strip"] as const),requires_confirmation:true});}
export function parseUrlTargetAuthorization(value:unknown):UrlTargetAuthorization{const item=record(value);exact(item,["authorization_id","target","query_policy"]);return Object.freeze({authorization_id:uuid(item.authorization_id),target:parseSanitizedUrlTarget(item.target),query_policy:member(item.query_policy,["send","strip"] as const)});}
function parseWebAnalysis(value:unknown):PassiveWebAnalysis{const item=record(value);exact(item,["schema","scan_id","state","query_policy","target","final_target","dns","tls","redirects","final_http_status","headers","cookies","reputation","findings","risk","confidence","coverage"]);if(item.schema!=="PASSIVE_WEB_ANALYSIS_V1"||!Array.isArray(item.dns)||item.dns.length>6||!Array.isArray(item.tls)||item.tls.length>6||!Array.isArray(item.redirects)||item.redirects.length>5||!Array.isArray(item.headers)||item.headers.length>64||!Array.isArray(item.cookies)||item.cookies.length>32||!Array.isArray(item.findings)||item.findings.length>128)throw new Error("Backend response rejected");const dns=Object.freeze(item.dns.map(value=>{const x=record(value);exact(x,["canonical_host","public_addresses","selected_address","address_families","resolved_at_utc","state"]);return Object.freeze({canonical_host:text(x.canonical_host,253),public_addresses:stringList(x.public_addresses,16,64),selected_address:nullable(x.selected_address,input=>text(input,64)),address_families:stringList(x.address_families,2,8),resolved_at_utc:text(x.resolved_at_utc,64),state:text(x.state,64)});}));const tls=Object.freeze(item.tls.map(value=>{const x=record(value);exact(x,["attempted","certificate_state","validation_enabled","hostname_validation_enabled","protocol","cipher","subject","issuer","not_before","not_after","fingerprint_sha256","san_count","error"]);return Object.freeze({attempted:boolean(x.attempted),certificate_state:text(x.certificate_state,32),validation_enabled:boolean(x.validation_enabled),hostname_validation_enabled:boolean(x.hostname_validation_enabled),protocol:nullable(x.protocol,input=>text(input,64)),cipher:nullable(x.cipher,input=>text(input,128)),subject:nullable(x.subject,input=>text(input,512)),issuer:nullable(x.issuer,input=>text(input,512)),not_before:nullable(x.not_before,input=>text(input,64)),not_after:nullable(x.not_after,input=>text(input,64)),fingerprint_sha256:nullable(x.fingerprint_sha256,input=>text(input,64)),san_count:nullable(x.san_count,input=>integer(input,65535)),error:nullable(x.error,input=>text(input,128))});}));const redirects=Object.freeze(item.redirects.map(value=>{const x=record(value);exact(x,["hop","status","source_scheme","source_host","destination_scheme","destination_host","destination_display_url","same_origin","followed","outcome"]);return Object.freeze({hop:integer(x.hop,5),status:integer(x.status,599),source_scheme:text(x.source_scheme,8),source_host:text(x.source_host,253),destination_scheme:text(x.destination_scheme,8),destination_host:text(x.destination_host,253),destination_display_url:text(x.destination_display_url,4096),same_origin:boolean(x.same_origin),followed:boolean(x.followed),outcome:text(x.outcome,64)});}));const headers=Object.freeze(item.headers.map(value=>{const x=record(value);exact(x,["name","state","value_sanitized","interpretation","class","guidance"]);return Object.freeze({name:text(x.name,128),state:text(x.state,64),value_sanitized:nullable(x.value_sanitized,input=>text(input,512)),interpretation:text(x.interpretation,2048),class:text(x.class,64),guidance:text(x.guidance,2048)});}));const cookies=Object.freeze(item.cookies.map(value=>{const x=record(value);exact(x,["safe_identifier","secure","http_only","same_site","domain_present","path","max_age_or_expires_present","partitioned","prefix","observations"]);return Object.freeze({safe_identifier:text(x.safe_identifier,80),secure:boolean(x.secure),http_only:boolean(x.http_only),same_site:text(x.same_site,32),domain_present:boolean(x.domain_present),path:nullable(x.path,input=>text(input,512)),max_age_or_expires_present:boolean(x.max_age_or_expires_present),partitioned:boolean(x.partitioned),prefix:nullable(x.prefix,input=>text(input,32)),observations:stringList(x.observations,16,512)});}));const reputation=record(item.reputation);exact(reputation,["provider","state","exact_match","dataset_version","explanation"]);const coverageItem=record(item.coverage);exact(coverageItem,["dns","tls","http","redirects","headers","cookies","reputation","limitations"]);return Object.freeze({schema:"PASSIVE_WEB_ANALYSIS_V1",scan_id:uuid(item.scan_id),state:text(item.state,32),query_policy:member(item.query_policy,["send","strip"] as const),target:parseSanitizedUrlTarget(item.target),final_target:nullable(item.final_target,parseSanitizedUrlTarget),dns,tls,redirects,final_http_status:nullable(item.final_http_status,input=>integer(input,599)),headers,cookies,reputation:Object.freeze({provider:text(reputation.provider,64),state:text(reputation.state,128),exact_match:reputation.exact_match===null?null:boolean(reputation.exact_match),dataset_version:nullable(reputation.dataset_version,input=>text(input,128)),explanation:text(reputation.explanation,2048)}),findings:Object.freeze(item.findings),risk:member(item.risk,SEVERITIES),confidence:member(item.confidence,CONFIDENCES),coverage:Object.freeze({dns:text(coverageItem.dns,64),tls:text(coverageItem.tls,64),http:text(coverageItem.http,64),redirects:text(coverageItem.redirects,64),headers:text(coverageItem.headers,64),cookies:text(coverageItem.cookies,64),reputation:text(coverageItem.reputation,64),limitations:stringList(coverageItem.limitations,32,2048)})});}
export function parseWebAnalysisView(value:unknown):WebAnalysisView{const item=record(value);exact(item,["scan_id","state","progress","analysis","terminal_error"]);const scanId=uuid(item.scan_id);const progress=parseScanProgress(item.progress);const analysis=nullable(item.analysis,parseWebAnalysis);if(progress.scan_id!==scanId||analysis?.scan_id!==scanId)throw new Error("Backend response rejected");return Object.freeze({scan_id:scanId,state:member(item.state,SCAN_STATES),progress,analysis,terminal_error:nullable(item.terminal_error,input=>text(input,128))});}

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
  previewInstalledApplications:(includeSystemComponents=false):Promise<InstalledApplicationPreview>=>call("preview_installed_applications",{request:{include_system_components:includeSystemComponents}},parseInstalledApplicationPreview,null),
  authorizeInstalledApplications:(previewId:string):Promise<InstalledApplicationAuthorization>=>call("authorize_installed_applications",{request:{preview_id:uuid(previewId),confirmed:true}},parseInstalledApplicationAuthorization,null),
  createInstalledApplicationScan:(authorizationId:string):Promise<ScanSummary>=>call("create_installed_application_scan",{request:{authorization_id:uuid(authorizationId),confirmed:true}},parseScanSummary,null),
  getInstalledApplicationInventory:(scanId:string):Promise<InstalledApplicationInventory>=>{const expected=uuid(scanId);return call("get_installed_application_inventory",{request:{scan_id:expected}},value=>{const result=parseInstalledApplicationInventory(value);if(result.scan_id!==expected)throw new Error("Backend response rejected");return result;});},
  getInstalledApplication:(scanId:string,applicationId:string):Promise<InstalledApplication>=>call("get_installed_application",{request:{scan_id:uuid(scanId),application_id:text(applicationId,38)}},parseInstalledApplication),
  vulnerabilityProviderStatus:():Promise<readonly DatasetStatus[]>=>call("get_vulnerability_provider_status",{},parseStatusList),
  refreshPublicVulnerabilityData:():Promise<PublicDataRefresh>=>call("refresh_public_vulnerability_data",{request:{confirmed:true}},value=>{const item=record(value);exact(item,["provider_status","host_inventory_transmitted"]);if(item.host_inventory_transmitted!==false)throw new Error("Backend response rejected");return Object.freeze({provider_status:parseStatusList(item.provider_status),host_inventory_transmitted:false});},null),
  previewUrlTarget:(url:string,queryPolicy:QueryPolicy):Promise<UrlTargetPreview>=>call("preview_url_target",{request:{url:text(url,2048),query_policy:queryPolicy}},parseUrlTargetPreview,null),
  authorizeUrlTarget:(previewId:string):Promise<UrlTargetAuthorization>=>call("authorize_url_target",{request:{preview_id:uuid(previewId),confirmed:true}},parseUrlTargetAuthorization,null),
  createUrlScan:(authorizationId:string):Promise<ScanSummary>=>call("create_url_scan",{request:{authorization_id:uuid(authorizationId),confirmed:true}},parseScanSummary,null),
  getUrlScanAnalysis:(scanId:string):Promise<WebAnalysisView>=>{const expected=uuid(scanId);return call("get_url_scan_analysis",{request:{scan_id:expected}},value=>{const result=parseWebAnalysisView(value);if(result.scan_id!==expected)throw new Error("Backend response rejected");return result;});},
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
