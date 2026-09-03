import { useEffect, useRef, useState } from "react";
import type { FoundationStatus } from "./foundation";
import { level0Api } from "./level0-api";
import { level5Api } from "./investigation-api";
import type { Cluster, CorrelationSummary, InvestigationCase, InvestigationGraph, InvestigationReport } from "./investigation-api";
import type { DatasetStatus, EngineStatus, FileAnalysisView, FileAuthorization, FileTargetPreview, FindingView, InstalledApplicationAuthorization, InstalledApplicationInventory, InstalledApplicationPreview, ReportView, ScanProgress, ScanSummary, RepositoryAuthorization, QueryPolicy, UrlTargetPreview, UrlTargetAuthorization, WebAnalysisView } from "./level0-api";

type Locale = "pt-BR" | "en";
type Theme = "professional" | "neon";
type Page = "overview" | "new-scan" | "web-url" | "installed-apps" | "investigations" | "progress" | "findings" | "history" | "engines" | "reports" | "settings";
type InvestigationUiState = "idle" | "running" | "complete" | "partial_correlation" | "cancelled" | "error";

const pages: readonly Page[] = ["overview", "new-scan", "web-url", "installed-apps", "investigations", "progress", "findings", "history", "engines", "reports", "settings"];
const terminalStates = new Set(["cancelled", "completed", "partial", "failed"]);

function safeUiError(error: unknown, fallback: string): string {
  const code = typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : "";
  const messages: Readonly<Record<string,string>> = {
    repository_path_refused: "Authorization rejected: the repository path did not satisfy local path policy.",
    repository_revalidation_required: "Path changed: renew authorization before scanning.",
    scan_quota_reached: "Limit reached: remove an older local synthetic scan before retrying.",
    repository_inventory_failed: "Repository inventory failed safely.",
    scan_not_cancellable: "Cancellation is unavailable because the scan is already terminal.",
    report_failed: "Report generation failed safely.",
    report_unavailable: "Report generation is unavailable for this scan.",
    file_path_invalid: "File refused: select one explicit local file on a fixed drive.",
    not_regular_file: "Only one explicit regular file can be analyzed.",
    not_local_fixed_filesystem: "UNC, removable, network, device and special paths are refused.",
    limit_exceeded: "The file exceeds the configured 256 MiB limit.",
    reparse_point_refused: "Links, junctions and reparse paths are refused.",
    target_changed: "Target changed: renew authorization before analysis.",
    url_target_refused: "URL refused by the public-internet and SSRF policy.",
    authorization_expired: "URL authorization expired; preview and confirm it again.",
  };
  return messages[code] ?? fallback;
}

const copy = {
  "pt-BR": {
    product: "EDY VERDICT", edition: "Centro de segurança local", overview: "Visão geral", "new-scan": "Nova análise",
    "web-url": "Web / URL", "installed-apps": "Aplicativos instalados", investigations: "Investigações", progress: "Progresso", findings: "Achados", history: "Histórico", engines: "Engines", reports: "Relatórios",
    settings: "Configurações", foundation: "Fundação Level 0", available: "Infraestrutura disponível",
    unavailable: "Infraestrutura indisponível", checking: "Validando infraestrutura…", noData: "Nenhum dado disponível",
    noDataDetail: "A interface não usa demonstrações silenciosas. Os dados aparecem somente após resposta válida do backend.",
    coverage: "Cobertura", risk: "Risco", confidence: "Confiança", status: "Estado", blocker: "Bloqueio conhecido",
    upstream: "Tauri upstream aguardando release oficial", language: "Idioma", theme: "Tema",
    professional: "Profissional escuro", neon: "Cyberpunk neon", synthetic: "Executar fixture sintética autorizada",
    syntheticNote: "Usa somente o fixture interno determinístico; nenhum arquivo do usuário é analisado.", cancel: "Cancelar",
    executive: "Executivo", technical: "Técnico", developer: "Desenvolvedor", generate: "Gerar relatório",
  },
  en: {
    product: "EDY VERDICT", edition: "Local security center", overview: "Overview", "new-scan": "New Scan",
    "web-url": "Web / URL", "installed-apps": "Installed Apps", investigations: "Investigations", progress: "Scan Progress", findings: "Findings", history: "History", engines: "Engines", reports: "Reports",
    settings: "Settings", foundation: "Level 0 Foundation", available: "Infrastructure available",
    unavailable: "Infrastructure unavailable", checking: "Validating infrastructure…", noData: "No data available",
    noDataDetail: "The interface never uses silent demos. Data appears only after a valid backend response.",
    coverage: "Coverage", risk: "Risk", confidence: "Confidence", status: "Status", blocker: "Known blocker",
    upstream: "Tauri upstream awaiting official release", language: "Language", theme: "Theme",
    professional: "Dark professional", neon: "Cyberpunk neon", synthetic: "Run authorized synthetic fixture",
    syntheticNote: "Uses only the deterministic internal fixture; no user file is scanned.", cancel: "Cancel",
    executive: "Executive", technical: "Technical", developer: "Developer", generate: "Generate report",
  },
} as const;

interface ProductViewProps {
  readonly initialPage?: Page;
  readonly status: FoundationStatus | null;
  readonly failed: boolean;
  readonly engines?: readonly EngineStatus[];
  readonly scans?: readonly ScanSummary[];
  readonly selected?: ScanSummary | null;
  readonly progress?: ScanProgress | null;
  readonly findings?: readonly FindingView[];
  readonly report?: ReportView | null;
  readonly error?: string | null;
  readonly busy?: boolean;
  readonly onStart?: () => void;
  readonly onCancel?: () => void;
  readonly onSelect?: (scan: ScanSummary) => void;
  readonly onReport?: (kind: ReportView["kind"]) => void;
  readonly repositoryAuthorization?: RepositoryAuthorization | null;
  readonly onAuthorizeRepository?: (path:string) => void;
  readonly onStartRepository?: () => void;
  readonly filePreview?: FileTargetPreview | null;
  readonly fileAuthorization?: FileAuthorization | null;
  readonly fileAnalysis?: FileAnalysisView | null;
  readonly onInspectFile?: (path:string) => void;
  readonly onAuthorizeFile?: (previewId:string) => void;
  readonly onStartFile?: () => void;
  readonly installedPreview?: InstalledApplicationPreview | null;
  readonly installedAuthorization?: InstalledApplicationAuthorization | null;
  readonly installedInventory?: InstalledApplicationInventory | null;
  readonly providerStatus?: readonly DatasetStatus[];
  readonly onPreviewInstalled?: (includeSystemComponents:boolean) => void;
  readonly onAuthorizeInstalled?: (previewId:string) => void;
  readonly onStartInstalled?: () => void;
  readonly onRefreshProviders?: () => void;
  readonly urlPreview?: UrlTargetPreview|null;
  readonly urlAuthorization?: UrlTargetAuthorization|null;
  readonly webAnalysis?: WebAnalysisView|null;
  readonly onPreviewUrl?: (url:string, policy:QueryPolicy)=>void;
  readonly onAuthorizeUrl?: (previewId:string)=>void;
  readonly onStartUrl?: ()=>void;
  readonly correlation?: CorrelationSummary|null;
  readonly clusters?: readonly Cluster[];
  readonly cases?: readonly InvestigationCase[];
  readonly investigationGraph?: InvestigationGraph|null;
  readonly investigationReport?: InvestigationReport|null;
  readonly investigationState?: InvestigationUiState;
  readonly onRunCorrelation?: ()=>void;
  readonly onCancelCorrelation?: ()=>void;
  readonly onOpenCase?: (clusterId:string)=>void;
  readonly onAdvanceCase?: (caseId:string)=>void;
  readonly onInvestigationReport?: (caseId:string,kind:InvestigationReport["kind"])=>void;
}

function EmptyState({ title, detail }: { readonly title: string; readonly detail: string }) {
  return <section className="empty-state" data-mode="production-empty"><div className="radar" aria-hidden="true"><span /></div><div><h2>{title}</h2><p>{detail}</p></div></section>;
}

type InvestigationPanelProps={readonly summary:CorrelationSummary|null;readonly state:InvestigationUiState;readonly clusters:readonly Cluster[];readonly cases:readonly InvestigationCase[];readonly graph:InvestigationGraph|null;readonly report:InvestigationReport|null;readonly busy:boolean;readonly onRun:(()=>void)|undefined;readonly onCancel:(()=>void)|undefined;readonly onOpen:((id:string)=>void)|undefined;readonly onAdvance:((id:string)=>void)|undefined;readonly onReport:((id:string,kind:InvestigationReport["kind"])=>void)|undefined};

function InvestigationsPanelComplete({summary,state,clusters,cases,graph,report,busy,onRun,onCancel,onOpen,onAdvance,onReport}:InvestigationPanelProps){
  const [status,setStatus]=useState("all");const [priority,setPriority]=useState("all");const [selected,setSelected]=useState<string|null>(null);
  const visible=cases.filter(item=>(status==="all"||item.status===status)&&(priority==="all"||item.assessment.priority===priority));
  const detail=cases.find(item=>item.case_id===selected)??visible[0]??null;
  if(state!=="complete"||!summary)return <div className="workflow-stack" data-level5-screen={state}><section className="action-panel"><p className="eyebrow">Level 5 · observed evidence only</p><h2>Cross-target investigations</h2>{state==="idle"&&<p>A área não inventa dados. Inicie uma correlação determinística somente sobre observações aprovadas e persistidas.</p>}{state==="running"&&<p role="status">Correlation running — no candidate graph is authoritative until atomic completion.</p>}{state==="cancelled"&&<p className="coverage-warning" role="status">CANCELLED — graph not promoted; persisted state remains consistent.</p>}{state==="partial_correlation"&&<p className="coverage-warning" role="status">LIMIT_REACHED / PARTIAL_CORRELATION — partial graph was not promoted.</p>}{state==="error"&&<p className="coverage-warning" role="alert">Correlation stopped safely. No partial graph was promoted.</p>}<div className="report-actions">{state!=="running"&&<button className="primary" disabled={busy||onRun===undefined} onClick={onRun}>Run correlation</button>}{state==="running"&&<button className="secondary" disabled={onCancel===undefined} onClick={onCancel}>Cancel correlation</button>}</div></section></div>;
  return <div className="workflow-stack" data-level5-screen="investigations"><section className="metric-grid investigation-metrics" aria-label="Investigation overview"><article><span>Nodes</span><strong>{summary.nodes}</strong></article><article><span>Relationships</span><strong>{summary.relationships}</strong></article><article><span>Clusters</span><strong>{summary.clusters}</strong></article><article><span>Cases</span><strong>{summary.cases}</strong></article></section><section className="data-panel"><div className="panel-heading"><div><p className="eyebrow">Level 5 · observed evidence only</p><h2>Cross-target investigations</h2></div><code>{summary.run_id}</code></div><p>Correlation groups exact observed identities. It does not prove causation, compromise, breach or a complete attack chain.</p><div className="filter-bar"><label>Status<select aria-label="Investigation status" value={status} onChange={event=>setStatus(event.target.value)}><option value="all">All</option>{["suggested","open","investigating","remediating","verification_pending","resolved","accepted_risk","ignored"].map(value=><option key={value}>{value}</option>)}</select></label><label>Priority<select aria-label="Investigation priority" value={priority} onChange={event=>setPriority(event.target.value)}><option value="all">All</option>{["Immediate","High","Normal","Low","Review"].map(value=><option key={value}>{value}</option>)}</select></label></div><div className="table-wrap"><table><thead><tr><th>Case</th><th>Status</th><th>Priority</th><th>Risk</th><th>Confidence</th><th>Coverage</th></tr></thead><tbody>{visible.map(item=><tr key={item.case_id} onClick={()=>setSelected(item.case_id)}><td>{item.title_safe}</td><td>{item.status}</td><td>{item.assessment.priority}</td><td>{item.assessment.risk}</td><td>{item.assessment.confidence}</td><td>{item.assessment.coverage}</td></tr>)}</tbody></table></div></section>{detail&&<div className="analysis-grid investigation-detail"><article className="data-panel"><h2>Case detail</h2><code>{detail.case_id}</code><dl><dt>Observed targets</dt><dd>{detail.blast_radius.unique_affected_targets}</dd><dt>Components</dt><dd>{detail.blast_radius.unique_affected_components}</dd><dt>Findings</dt><dd>{detail.finding_ids.length}</dd><dt>Vulnerabilities</dt><dd>{detail.blast_radius.unique_vulnerability_ids}</dd></dl><div className="report-actions">{detail.status==="suggested"&&<button className="primary" disabled={busy||detail.cluster_ids.length===0} onClick={()=>{const clusterId=detail.cluster_ids[0];if(clusterId)onOpen?.(clusterId);}}>Open case</button>}{detail.status==="open"&&<button className="secondary" disabled={busy} onClick={()=>onAdvance?.(detail.case_id)}>Start investigation</button>}</div></article><article className="data-panel"><h2>Correlated findings</h2><ul>{detail.finding_ids.map(id=><li key={id}><code>{id}</code></li>)}</ul></article><article className="data-panel"><h2>Affected assets</h2><ul>{detail.entity_ids.map(id=><li key={id}><code>{id}</code></li>)}</ul></article><article className="data-panel"><h2>Score rationale</h2><strong>Risk {detail.assessment.risk} · Confidence {detail.assessment.confidence} · Coverage {detail.assessment.coverage}</strong><ul>{[...detail.assessment.risk_reasons,...detail.assessment.confidence_reasons,...detail.assessment.coverage_reasons,...detail.assessment.priority_reasons].map((reason,index)=><li key={`${index}-${reason}`}>{reason}</li>)}</ul></article><article className="data-panel"><h2>Relationship graph</h2><div className="graph-list">{graph?.edges.filter(edge=>edge.finding_ids.some(id=>detail.finding_ids.includes(id))).slice(0,40).map(edge=><p key={edge.edge_id}><strong>{edge.relationship}</strong><br/><code>{edge.from_entity}</code> → <code>{edge.to_entity}</code></p>)}</div></article><article className="data-panel"><h2>Timeline</h2><ol>{detail.timeline.map(event=><li key={event.sequence}><time>{event.timestamp}</time> · {event.event_type}<p>{event.summary_safe}</p></li>)}</ol></article><article className="data-panel"><h2>Evidence & limitations</h2><p>{detail.evidence_ids.length} redacted evidence references.</p><ul>{detail.evidence_ids.map(id=><li key={id}><code>{id}</code></li>)}</ul><p className="coverage-warning">Observed scope only. Unavailable providers reduce coverage; shared identifiers do not prove a shared incident.</p></article><article className="data-panel"><h2>Reports</h2><div className="report-actions">{(["executive","technical","analyst"] as const).map(kind=><button className="secondary" disabled={busy} key={kind} onClick={()=>onReport?.(detail.case_id,kind)}>{kind}</button>)}</div>{report?.case_id===detail.case_id&&<pre className="report-json" aria-label="Investigation JSON report">{report.json}</pre>}</article></div>}<section className="data-panel"><h2>Clusters</h2>{clusters.map(cluster=><article key={cluster.cluster_id} className="finding-card"><strong>{cluster.cluster_type} · {cluster.target_count} targets</strong><p>{cluster.explanation_safe}</p></article>)}</section></div>;
}

function InvestigationsPanel(props:InvestigationPanelProps){
  const {summary,state,cases,clusters,graph}=props;
  const [risk,setRisk]=useState("all");const [targetType,setTargetType]=useState("all");const [kev,setKev]=useState("all");const [recurrence,setRecurrence]=useState("all");
  if(state!=="complete"||!summary)return <InvestigationsPanelComplete {...props}/>;
  const hasKev=(item:InvestigationCase)=>[...item.assessment.risk_reasons,...item.assessment.priority_reasons].some(reason=>reason.includes("KEV"));
  const hasRecurrence=(item:InvestigationCase)=>item.timeline.some(event=>event.event_type==="finding_reopened");
  const riskMatches=(item:InvestigationCase)=>risk==="all"||(risk==="critical"&&item.assessment.risk>=90)||(risk==="high"&&item.assessment.risk>=75&&item.assessment.risk<90)||(risk==="moderate"&&item.assessment.risk>=50&&item.assessment.risk<75)||(risk==="low"&&item.assessment.risk<50);
  const priorityOrder:Readonly<Record<string,number>>={immediate:0,high:1,normal:2,low:3,review:4};
  const visible=[...cases].filter(item=>riskMatches(item)&&(targetType==="all"||item.blast_radius.target_types_affected.includes(targetType))&&(kev==="all"||(kev==="yes")===hasKev(item))&&(recurrence==="all"||(recurrence==="yes")===hasRecurrence(item))).sort((a,b)=>(priorityOrder[a.assessment.priority]??5)-(priorityOrder[b.assessment.priority]??5)||b.assessment.risk-a.assessment.risk||b.assessment.confidence-a.assessment.confidence||(b.timeline.at(-1)?.timestamp??"").localeCompare(a.timeline.at(-1)?.timestamp??"")||a.case_id.localeCompare(b.case_id));
  const activeCases=cases.filter(item=>["open","investigating","remediating","verification_pending"].includes(item.status)).length;
  const observedTargets=graph?.nodes.filter(node=>node.kind==="scan_target").length??0;
  return <div className="investigation-v2"><section className="metric-grid investigation-metrics" aria-label="Investigation overview"><article><span>Open Cases</span><strong>{activeCases}</strong></article><article><span>Immediate Priority</span><strong>{cases.filter(item=>item.assessment.priority==="immediate").length}</strong></article><article><span>High Priority</span><strong>{cases.filter(item=>item.assessment.priority==="high").length}</strong></article><article><span>Correlated Findings</span><strong>{graph?.findings_preserved??0}</strong></article><article><span>Observed Affected Targets</span><strong>{observedTargets}</strong></article></section><section className="data-panel"><div className="panel-heading"><div><p className="eyebrow">Level 5 · bounded case index</p><h2>Investigation cases</h2></div><code>{summary.run_id}</code></div><div className="filter-bar"><label>Risk<select aria-label="Investigation risk" value={risk} onChange={event=>setRisk(event.target.value)}>{["all","critical","high","moderate","low"].map(value=><option key={value}>{value}</option>)}</select></label><label>Target type<select aria-label="Investigation target type" value={targetType} onChange={event=>setTargetType(event.target.value)}>{["all","repository","file","installed_application","web_url"].map(value=><option key={value}>{value}</option>)}</select></label><label>KEV<select aria-label="Investigation KEV" value={kev} onChange={event=>setKev(event.target.value)}><option value="all">all</option><option value="yes">yes</option><option value="no">no</option></select></label><label>Recurrence<select aria-label="Investigation recurrence" value={recurrence} onChange={event=>setRecurrence(event.target.value)}><option value="all">all</option><option value="yes">yes</option><option value="no">no</option></select></label></div><div className="table-wrap"><table><thead><tr><th>Case</th><th>Status</th><th>Priority</th><th>Risk</th><th>Confidence</th><th>Coverage</th><th>Affected Targets</th><th>Last Activity</th></tr></thead><tbody>{visible.map(item=><tr key={item.case_id}><td>{item.title_safe}</td><td>{item.status}</td><td>{item.assessment.priority}</td><td>{item.assessment.risk}</td><td>{item.assessment.confidence}</td><td>{item.assessment.coverage}</td><td>{item.blast_radius.unique_affected_targets}</td><td>{item.timeline.at(-1)?.timestamp??"—"}</td></tr>)}</tbody></table></div>{visible.length===0&&<p>No cases match the bounded filters.</p>}</section><InvestigationsPanelComplete {...props} cases={visible}/><section className="data-panel"><h2>Cluster detail</h2>{clusters.map(cluster=><article className="finding-card" key={`detail-${cluster.cluster_id}`}><h3>{cluster.cluster_type}</h3><p>{cluster.explanation_safe}</p><dl><dt>Member findings</dt><dd>{cluster.member_findings.join(", ")}</dd><dt>Affected targets</dt><dd>{cluster.target_count}</dd><dt>Evidence references</dt><dd>{cluster.evidence_count}</dd></dl>{cluster.supporting_edges.map(edgeId=>{const edge=graph?.edges.find(item=>item.edge_id===edgeId);return edge&&<div key={edgeId} className="relationship-explanation"><strong>Why correlated?</strong><p>{edge.reasoning_safe}</p><dl><dt>Rule</dt><dd>{edge.rule_id} v{edge.rule_version}</dd><dt>Strength</dt><dd>{edge.confidence}</dd><dt>Evidence</dt><dd>{edge.evidence_ids.join(", ")}</dd><dt>Source scans</dt><dd>{edge.source_scans.join(", ")}</dd></dl></div>})}</article>)}</section></div>;
}

function InstalledAppsPanel({preview,authorization,inventory,providers,busy,onPreview,onAuthorize,onStart,onRefresh}:{readonly preview:InstalledApplicationPreview|null;readonly authorization:InstalledApplicationAuthorization|null;readonly inventory:InstalledApplicationInventory|null;readonly providers:readonly DatasetStatus[];readonly busy:boolean;readonly onPreview:((include:boolean)=>void)|undefined;readonly onAuthorize:((id:string)=>void)|undefined;readonly onStart:(()=>void)|undefined;readonly onRefresh:(()=>void)|undefined}) {
  const [includeSystem,setIncludeSystem]=useState(false); const [search,setSearch]=useState(""); const [priority,setPriority]=useState("all"); const [identity,setIdentity]=useState("all"); const [selectedApp,setSelectedApp]=useState<string|null>(null);
  const applications=inventory?.snapshot.applications.filter(app=>(includeSystem||!app.system_component)&&(search===""||`${app.name} ${app.publisher??""}`.toLowerCase().includes(search.toLowerCase()))&&(identity==="all"||app.identity.state===identity))??[];
  const findings=inventory?.findings.filter(finding=>priority==="all"||finding.priority===priority)??[]; const detail=inventory?.snapshot.applications.find(app=>app.application_id===selectedApp)??applications[0]??null;
  return <div className="workflow-stack" data-level3-screen={inventory?"inventory":preview?"preview":"start"}>
    <section className="action-panel"><div className="panel-heading"><div><p className="eyebrow">Level 3 · Windows inventory</p><h2>Installed Application Security</h2></div><button className="secondary" disabled={busy||onRefresh===undefined} onClick={onRefresh}>Refresh public data</button></div><p>Read-only inventory from standard uninstall registry views and current-user MSIX. Portable apps, other users and filesystem crawling are outside coverage.</p><label><input type="checkbox" checked={includeSystem} onChange={event=>setIncludeSystem(event.target.checked)} /> Include system components</label><button className="secondary" disabled={busy||onPreview===undefined} onClick={()=>onPreview?.(includeSystem)}>Preview inventory</button>{preview&&<div className="confirmation-panel"><strong>{preview.application_count} applications in preview</strong><p>{preview.system_component_count} system components · explicit confirmation required.</p><button className="secondary" disabled={busy||onAuthorize===undefined} onClick={()=>onAuthorize?.(preview.preview_id)}>Authorize this snapshot</button></div>}{authorization&&<div className="confirmation-panel"><strong>Snapshot authorized</strong><p>{authorization.application_count} applications. Public providers receive no host inventory.</p><button className="primary" disabled={busy||onStart===undefined} onClick={onStart}>Confirm installed-app analysis</button></div>}</section>
    <section className="data-panel" data-level3-screen="provider-status"><h2>Provider status</h2><div className="engine-grid">{providers.map(provider=><article key={provider.provider}><span className={`status-dot ${provider.state==="ready"?"ready":""}`} /><div><strong>{provider.provider}</strong><p>{provider.state} · {provider.freshness}</p><small>{provider.dataset_version??"No validated local dataset"}</small></div></article>)}</div><p>NVD uses only an approved fixed public development query. CISA KEV and EPSS enrich validated CVEs; neither proves host exploitation.</p></section>
    {inventory&&<><section className="data-panel" data-level3-screen="coverage"><h2>Inventory coverage</h2><p>{inventory.state} · {inventory.snapshot.applications.length} normalized applications · {inventory.findings.length} validated affected findings.</p><p className="coverage-warning">No finding does not mean clean. Unknown identity, unparseable versions and unavailable data never become vulnerability findings.</p><ul>{inventory.snapshot.coverage.limitations.map(item=><li key={item}>{item}</li>)}</ul></section><section className="findings-workspace"><div className="filter-bar"><label>Search<input aria-label="Application search" value={search} onChange={event=>setSearch(event.target.value)} /></label><label>Identity<select aria-label="Identity filter" value={identity} onChange={event=>setIdentity(event.target.value)}><option value="all">All</option>{["exact","curated","strong","heuristic","unmapped","conflicting"].map(value=><option key={value}>{value}</option>)}</select></label><label>Priority<select aria-label="Priority filter" value={priority} onChange={event=>setPriority(event.target.value)}><option value="all">All</option>{["immediate","high","normal","low","review"].map(value=><option key={value}>{value}</option>)}</select></label></div><div className="finding-layout"><div className="table-wrap"><table><thead><tr><th>Application</th><th>Version</th><th>Publisher</th><th>Identity</th></tr></thead><tbody>{applications.map(app=><tr key={app.application_id} onClick={()=>setSelectedApp(app.application_id)}><td>{app.name}</td><td>{app.version.raw??"Unknown"}</td><td>{app.publisher??"Unknown"}</td><td>{app.identity.state}</td></tr>)}</tbody></table></div>{detail&&<article className="data-panel finding-detail" data-level3-screen="application-detail"><h2>{detail.name}</h2><dl><dt>Version</dt><dd>{detail.version.raw??"Unknown"} ({detail.version.kind})</dd><dt>Publisher</dt><dd>{detail.publisher??"Unknown"}</dd><dt>Identity</dt><dd>{detail.identity.state} · {detail.identity.reason}</dd><dt>CPE / PURL</dt><dd>{detail.identity.cpe??detail.identity.purl??"Unmapped"}</dd><dt>Sources</dt><dd>{detail.sources.map(source=>`${source.kind}/${source.scope}/${source.view}`).join(", ")}</dd><dt>Install date</dt><dd>{detail.install_date_reported??"Unavailable"} (publisher-reported)</dd></dl></article>}</div></section><section className="data-panel" data-level3-screen="vulnerabilities"><h2>Validated affected findings</h2>{findings.length===0?<p>No validated affected finding from available datasets. This is not a clean guarantee.</p>:findings.map(finding=><article key={finding.fingerprint} className="finding-card"><span className={`severity severity-${finding.priority==="immediate"?"critical":finding.priority==="high"?"high":"medium"}`}>{finding.priority}</span><strong>{finding.cve} · {finding.application_name}</strong><p>Installed {finding.installed_version} · CVSS {finding.cvss_score??"unavailable"} · KEV {finding.kev?"yes":"no"} · EPSS {finding.epss?.probability??"unavailable"}</p><small>{finding.priority_reasons.join(" ")} Fixed version: {finding.fixed_version??"not documented"}; availability on this host is not established.</small></article>)}</section></>}
  </div>;
}

export function FoundationView({
  status, failed, engines = [], scans = [], selected = null, progress = null, findings = [], report = null,
  error = null, busy = false, onStart, onCancel, onSelect, onReport, repositoryAuthorization = null, onAuthorizeRepository, onStartRepository,
  filePreview = null, fileAuthorization = null, fileAnalysis = null, onInspectFile, onAuthorizeFile, onStartFile, installedPreview=null, installedAuthorization=null, installedInventory=null, providerStatus=[], onPreviewInstalled, onAuthorizeInstalled, onStartInstalled, onRefreshProviders, urlPreview=null, urlAuthorization=null, webAnalysis=null, onPreviewUrl, onAuthorizeUrl, onStartUrl, correlation=null, clusters=[], cases=[], investigationGraph=null, investigationReport=null, investigationState="idle", onRunCorrelation, onCancelCorrelation, onOpenCase, onAdvanceCase, onInvestigationReport, initialPage = "overview",
}: ProductViewProps) {
  const [page, setPage] = useState<Page>(initialPage);
  const [locale, setLocale] = useState<Locale>("pt-BR");
  const [theme, setTheme] = useState<Theme>("professional");
  const [repositoryPath, setRepositoryPath] = useState("");
  const [filePath, setFilePath] = useState(filePreview?.requested_path ?? "");
  const [urlInput,setUrlInput]=useState("");
  const [queryPolicy,setQueryPolicy]=useState<QueryPolicy>("strip");
  const [dismissedWebTerminal,setDismissedWebTerminal]=useState<string|null>(null);
  useEffect(()=>{if(urlPreview)setUrlInput(urlPreview.target.display_url);},[urlPreview]);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const text = copy[locale];
  const ready = status !== null;
  const scan = selected ?? scans[0] ?? null;
  const coverage = scan === null || scan.coverage.total === 0 ? "—" : `${scan.coverage.completed}/${scan.coverage.total}`;
  const visibleFindings = findings.filter((finding) =>
    (categoryFilter === "all" || finding.category === categoryFilter)
    && (severityFilter === "all" || finding.severity === severityFilter)
    && (statusFilter === "all" || finding.status === statusFilter)
    && (confidenceFilter === "all" || finding.confidence === confidenceFilter));
  const findingDetail = findings.find((finding) => finding.id === selectedFindingId) ?? visibleFindings[0] ?? null;

  const content = (() => {
    if(page==="investigations") return <InvestigationsPanel summary={correlation} state={investigationState} clusters={clusters} cases={cases} graph={investigationGraph} report={investigationReport} busy={busy} onRun={onRunCorrelation} onCancel={onCancelCorrelation} onOpen={onOpenCase} onAdvance={onAdvanceCase} onReport={onInvestigationReport}/>;
    if(page==="web-url"&&dismissedWebTerminal!==scan?.id&&(webAnalysis?.state==="cancelled"||scan?.state==="cancelled")) return <section className="data-panel" data-level4-screen="cancelled"><h2>Passive URL analysis cancelled</h2><p className="coverage-warning">No final security verdict was generated.</p><p>Late worker results cannot replace this terminal state.</p><button className="secondary" onClick={()=>setDismissedWebTerminal(scan?.id??null)}>Analyze another URL</button></section>;
    if(page==="web-url"&&dismissedWebTerminal!==scan?.id&&(webAnalysis?.terminal_error||(scan?.state==="failed"&&progress?.phase==="failed"))) return <section className="data-panel" data-level4-screen="error"><h2>Passive URL analysis stopped safely</h2><p className="coverage-warning">{webAnalysis?.terminal_error??"DNS or transport policy rejected the target before completion."}</p><p>No request is retried and no final security verdict is generated.</p><button className="secondary" onClick={()=>setDismissedWebTerminal(scan?.id??null)}>Analyze another URL</button></section>;
    if(page==="web-url") return <div className="workflow-stack" data-level4-screen={webAnalysis?.analysis?"analysis":urlAuthorization?"confirmation":urlPreview?"preview":"authorization"}><section className="action-panel"><h2>Web / URL Security</h2><p>Passive checks only: public DNS, validated TLS, bounded redirects, selected headers, cookie attributes and optional exact-match reputation. No body, JavaScript, crawler, form or exploit probe.</p><label>Explicit URL<input aria-label="Web URL" value={urlInput} disabled={busy} onChange={event=>setUrlInput(event.target.value)} /></label><label>Query policy<select aria-label="Query policy" value={queryPolicy} disabled={busy} onChange={event=>setQueryPolicy(event.target.value as QueryPolicy)}><option value="strip">Strip values before network request</option><option value="send">Send values once, never retain them</option></select></label><button className="secondary" disabled={!ready||busy||urlInput.length<10||onPreviewUrl===undefined} onClick={()=>onPreviewUrl?.(urlInput,queryPolicy)}>Validate target</button>{urlPreview&&<div className="data-panel"><h3>Sanitized preview</h3><code>{urlPreview.target.display_url}</code><dl><dt>Host</dt><dd>{urlPreview.target.canonical_host}</dd><dt>Scheme / port</dt><dd>{urlPreview.target.scheme} / {urlPreview.target.port}</dd><dt>Query</dt><dd>{urlPreview.target.query_present?`${urlPreview.target.query_parameter_names.join(", ")} · values redacted`:"absent or stripped"}</dd><dt>Fragment</dt><dd>{urlPreview.target.fragment_present?"removed":"absent"}</dd></dl><button className="secondary" disabled={busy||onAuthorizeUrl===undefined} onClick={()=>onAuthorizeUrl?.(urlPreview.preview_id)}>Authorize this exact sanitized target</button></div>}{urlAuthorization&&<div className="confirmation-panel"><strong>URL authorization captured</strong><code>{urlAuthorization.target.display_url}</code><p>One bounded passive request chain will be attempted. Proxies are bypassed and every hop is DNS-validated and IP-pinned.</p><button className="primary" disabled={busy||onStartUrl===undefined} onClick={onStartUrl}>Confirm passive URL analysis</button></div>}</section>{webAnalysis?.analysis&&<section className="analysis-grid"><article className="data-panel"><h2>DNS / Target</h2><code>{webAnalysis.analysis.target.display_url}</code><p>{webAnalysis.analysis.dns.map(item=>`${item.canonical_host}: ${item.public_addresses.join(", ")}`).join(" · ")}</p></article><article className="data-panel"><h2>TLS</h2><p>{webAnalysis.analysis.tls.map(item=>`${item.certificate_state}; validation=${item.validation_enabled}; hostname=${item.hostname_validation_enabled}`).join(" · ")||"Not applicable"}</p></article><article className="data-panel"><h2>Redirects</h2><p>{webAnalysis.analysis.redirects.map(item=>`${item.status} ${item.source_host} → ${item.destination_host} (${item.outcome})`).join(" · ")||"No redirect observed"}</p></article><article className="data-panel"><h2>Security headers</h2>{webAnalysis.analysis.headers.map(item=><p key={item.name}><strong>{item.name}</strong>: {item.state} — {item.interpretation}</p>)}</article><article className="data-panel"><h2>Cookie attributes</h2>{webAnalysis.analysis.cookies.map(item=><p key={item.safe_identifier}><strong>{item.safe_identifier}</strong>: Secure={String(item.secure)}, HttpOnly={String(item.http_only)}, SameSite={item.same_site}. Value never retained.</p>)}</article><article className="data-panel"><h2>Reputation</h2><p>{webAnalysis.analysis.reputation.state}: {webAnalysis.analysis.reputation.explanation}</p></article><article className="data-panel"><h2>Coverage</h2><dl>{Object.entries(webAnalysis.analysis.coverage).filter(([key])=>key!=="limitations").map(([key,value])=><><dt>{key}</dt><dd>{String(value)}</dd></>)}</dl><p className="coverage-warning">{webAnalysis.analysis.coverage.limitations.join(" ")}</p></article></section>}</div>;
    if(page==="installed-apps") return <InstalledAppsPanel preview={installedPreview} authorization={installedAuthorization} inventory={installedInventory} providers={providerStatus} busy={busy} onPreview={onPreviewInstalled} onAuthorize={onAuthorizeInstalled} onStart={onStartInstalled} onRefresh={onRefreshProviders}/>;
    if (page === "new-scan") return <div className="workflow-stack"><section className="action-panel"><h2>File / Binary Security</h2><p>One explicit local file only. Preview never starts analysis.</p><label>File path<input aria-label="File path" value={filePath} disabled={busy} onChange={(event)=>setFilePath(event.target.value)} /></label><button className="secondary" disabled={!ready||busy||filePath.length===0||onInspectFile===undefined} onClick={()=>onInspectFile?.(filePath)}>Preview file</button>{filePreview && filePreview.requested_path === filePath && <div className="data-panel" data-level2-screen="file-authorization"><h3>File preview</h3><dl><dt>File name</dt><dd>{filePreview.file_name}</dd><dt>Resolved location</dt><dd><code>{filePreview.canonical_path}</code></dd><dt>Size</dt><dd>{filePreview.identity.size} bytes</dd><dt>Detected type</dt><dd>{filePreview.detected_type}</dd><dt>Proposed checks</dt><dd>{filePreview.proposed_checks.join(", ")}</dd><dt>Policy limitations</dt><dd>{filePreview.policy_limitations.join(" ")}</dd></dl><button className="secondary" disabled={busy||onAuthorizeFile===undefined} onClick={()=>onAuthorizeFile?.(filePreview.preview_id)}>Authorize this exact file</button></div>}{fileAuthorization && filePreview?.requested_path === filePath && <div className="confirmation-panel"><strong>Authorization captured</strong><code>{fileAuthorization.canonical_path}</code><p>Analysis still requires explicit confirmation. YARA-X is unavailable by execution policy; reputation will be Not checked.</p><button className="primary" disabled={busy||onStartFile===undefined} onClick={onStartFile}>Confirm file analysis</button></div>}</section><section className="action-panel"><h2>Repository Security</h2><p>Repository inventory available. Some security checks are unavailable until execution policy requirements are satisfied.</p><label>Repository path<input aria-label="Repository path" value={repositoryPath} onChange={(event)=>setRepositoryPath(event.target.value)} /></label><button className="secondary" disabled={!ready||busy||repositoryPath.length===0||onAuthorizeRepository===undefined} onClick={()=>onAuthorizeRepository?.(repositoryPath)}>Authorize and inspect</button>{repositoryAuthorization && <div className="data-panel"><h3>Authorization preview</h3><code>{repositoryAuthorization.canonical_root}</code><dl><dt>Estimated files</dt><dd>{repositoryAuthorization.estimated_files}</dd><dt>Estimated bytes</dt><dd>{repositoryAuthorization.estimated_bytes}</dd><dt>Exclusions</dt><dd>{repositoryAuthorization.exclusions.join(", ")}</dd><dt>Readiness</dt><dd>{repositoryAuthorization.readiness}</dd></dl><button className="primary" disabled={busy||onStartRepository===undefined} onClick={onStartRepository}>Confirm repository scan</button></div>}</section><section className="action-panel"><h2>{text.synthetic}</h2><p>{text.syntheticNote}</p><button className="primary" disabled={!ready || busy || onStart === undefined} onClick={onStart}>{busy ? "…" : text.synthetic}</button></section></div>;
    if (page === "progress") return progress === null
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="data-panel"><div className="panel-heading"><div><h2>{progress.phase}</h2><code>{progress.scan_id}</code></div><strong>{progress.percent === null ? "—" : `${progress.percent}%`}</strong></div><progress max="100" value={progress.percent ?? 0} /><dl><dt>{text.status}</dt><dd>{progress.status}</dd><dt>Engine</dt><dd>{progress.current_engine ?? "—"}</dd><dt>Tasks</dt><dd>{progress.completed_tasks}/{progress.total_tasks}</dd><dt>Elapsed</dt><dd>{progress.elapsed_ms} ms</dd></dl>{!terminalStates.has(progress.status) && <button className="secondary" onClick={onCancel} disabled={busy || onCancel === undefined}>{text.cancel}</button>}</section>;
    if (page === "findings") return findings.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="findings-workspace"><div className="filter-bar" aria-label="Finding filters"><label>Category<select aria-label="Category filter" value={categoryFilter} onChange={(event)=>setCategoryFilter(event.target.value)}><option value="all">All</option><option value="secret">Secrets</option><option value="vulnerable_dependency">Vulnerabilities</option><option value="misconfiguration">Misconfiguration</option><option value="supply_chain">Supply Chain</option><option value="license">License</option><option value="digital_signature">Signature</option><option value="yara_match">YARA</option><option value="executable_metadata">PE Indicators</option><option value="file_reputation">Reputation</option><option value="suspicious_binary_indicator">Binary Indicators</option></select></label><label>Severity<select aria-label="Severity filter" value={severityFilter} onChange={(event)=>setSeverityFilter(event.target.value)}><option value="all">All</option>{["info","low","medium","high","critical"].map(value=><option key={value} value={value}>{value}</option>)}</select></label><label>Status<select aria-label="Status filter" value={statusFilter} onChange={(event)=>setStatusFilter(event.target.value)}><option value="all">All</option><option value="open">open</option><option value="resolved">resolved</option></select></label><label>Confidence<select aria-label="Confidence filter" value={confidenceFilter} onChange={(event)=>setConfidenceFilter(event.target.value)}><option value="all">All</option>{["low","medium","high"].map(value=><option key={value} value={value}>{value}</option>)}</select></label></div><div className="finding-layout"><div className="card-list">{visibleFindings.map((finding) => <button className="finding-card" key={finding.id} onClick={()=>setSelectedFindingId(finding.id)}><span className={`severity severity-${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><small>{finding.category} · {finding.status}</small></button>)}</div>{findingDetail && <article className="data-panel finding-detail" aria-label="Finding detail"><h2>{findingDetail.title}</h2><dl><dt>Category</dt><dd>{findingDetail.category}</dd><dt>Severity</dt><dd>{findingDetail.severity}</dd><dt>{text.risk}</dt><dd>{findingDetail.risk}</dd><dt>{text.confidence}</dt><dd>{findingDetail.confidence}</dd><dt>{text.status}</dt><dd>{findingDetail.status}</dd><dt>Affected component</dt><dd><code>{findingDetail.affected_component}</code></dd><dt>Rule / ID</dt><dd>{findingDetail.rule_ids.join(", ")}</dd><dt>Evidence</dt><dd>{findingDetail.evidence_ids.join(", ")}</dd><dt>Supporting sources</dt><dd>{findingDetail.sources.join(", ")}</dd><dt>Remediation guidance</dt><dd>{findingDetail.remediation_guidance}</dd><dt>Limitations</dt><dd>{findingDetail.limitations.join(" ")}</dd></dl>{findingDetail.category === "secret" && <p className="redaction-notice">Secret value: [REDACTED] · reveal is unavailable</p>}</article>}</div></section>;
    if (page === "history") return scans.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="table-wrap"><table><thead><tr><th>ID</th><th>{text.status}</th><th>{text.risk}</th><th>{text.confidence}</th><th>{text.coverage}</th></tr></thead><tbody>{scans.map((item) => <tr key={item.id} onClick={() => onSelect?.(item)}><td><code>{item.id}</code></td><td>{item.state}</td><td>{item.risk ?? "—"}</td><td>{item.confidence ?? "—"}</td><td>{item.coverage.completed}/{item.coverage.total}</td></tr>)}</tbody></table></section>;
    if (page === "engines") return engines.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="engine-grid">{engines.map((engine) => <article key={engine.id}><span className={`status-dot ${engine.state === "ready" ? "ready" : ""}`} /><div><h2>{engine.id}</h2><p>{engine.version} · {engine.state}</p><small>{engine.detail_safe}</small></div></article>)}</section>;
    if (page === "reports") return scan === null
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="data-panel"><div className="report-actions">{(["executive", "technical", "developer"] as const).map((kind) => <button className="secondary" disabled={busy || onReport === undefined} key={kind} onClick={() => onReport?.(kind)}>{text.generate}: {text[kind]}</button>)}</div>{report && <pre className="report-json" aria-label="JSON report">{report.json}</pre>}</section>;
    if (page === "overview" && fileAnalysis?.analysis) { const analysis=fileAnalysis.analysis; return <section className="level2-analysis" data-level2-screen="analysis"><div className="data-panel"><div className="panel-heading"><div><p className="eyebrow">File / Binary Security</p><h2>{analysis.verdict.disposition}</h2></div><span className={`severity severity-${analysis.verdict.risk}`}>{analysis.verdict.risk}</span></div><p>No safety guarantee is made. Coverage limitations remain visible.</p></div><div className="analysis-grid"><article className="data-panel"><h2>File Identity</h2><dl><dt>Location</dt><dd><code>{analysis.target.canonical_path}</code></dd><dt>Volume ID</dt><dd>{analysis.target.identity.volume_id}</dd><dt>File ID</dt><dd>{analysis.target.identity.file_id}</dd><dt>Size</dt><dd>{analysis.target.identity.size}</dd></dl></article><article className="data-panel" data-level2-screen="hashes"><h2>Hashes</h2><dl><dt>SHA-256</dt><dd><code>{analysis.hashes.sha256}</code></dd><dt>SHA-512</dt><dd><code>{analysis.hashes.sha512}</code></dd><dt>Bytes hashed</dt><dd>{analysis.hashes.bytes_hashed}</dd></dl></article><article className="data-panel" data-level2-screen="pe"><h2>PE Metadata</h2><dl><dt>Classification</dt><dd>{analysis.classification}</dd><dt>Architecture</dt><dd>{analysis.pe?.architecture ?? "Not applicable"}</dd><dt>Subsystem</dt><dd>{analysis.pe?.subsystem ?? "—"}</dd><dt>Entry point RVA</dt><dd>{analysis.pe?.entry_point_rva ?? "—"}</dd><dt>Image base</dt><dd>{analysis.pe?.image_base ?? "—"}</dd><dt>Sections</dt><dd>{analysis.pe?.sections.map(section => `${section.name}: virtual=${section.virtual_size}, raw=${section.raw_size}`).join("; ") ?? "—"}</dd><dt>Parser</dt><dd>{analysis.pe_error ?? "completed"}</dd></dl></article><article className="data-panel" data-level2-screen="signature"><h2>Digital Signature</h2><dl><dt>Presence</dt><dd>{analysis.authenticode.signature_present ? "Present" : "Unsigned"}</dd><dt>Cryptographic status</dt><dd>{analysis.authenticode.cryptographic_status}</dd><dt>Trust chain</dt><dd>{analysis.authenticode.trust_chain_status}</dd><dt>Publisher</dt><dd>{analysis.authenticode.publisher?.subject ?? "Unavailable"}</dd><dt>Issuer</dt><dd>{analysis.authenticode.publisher?.issuer ?? "Unavailable"}</dd><dt>Signing time (signer assertion)</dt><dd>{analysis.authenticode.publisher?.signing_time ?? "Absent"}</dd><dt>Countersignature present</dt><dd>{analysis.authenticode.publisher?.timestamp_present === true ? "Present" : analysis.authenticode.publisher?.timestamp_present === false ? "Absent" : "Unknown"}</dd><dt>Trusted timestamp</dt><dd>{analysis.authenticode.publisher?.trusted_timestamp_present === true ? "Validated offline" : analysis.authenticode.publisher?.trusted_timestamp_present === false ? "Absent" : "Not established offline"}</dd><dt>Network</dt><dd>Offline / cache-only; revocation not checked</dd></dl></article><article className="data-panel"><h2>YARA</h2><p className="coverage-warning">Unavailable by execution policy</p></article><article className="data-panel"><h2>Reputation</h2><p className="coverage-warning">Not checked — no upload and no network lookup</p></article><article className="data-panel"><h2>Findings</h2>{analysis.findings.length===0?<p>No findings from available checks. This is not a clean guarantee.</p>:analysis.findings.map(finding=><div key={finding.id}><strong>{finding.title}</strong><p>{finding.category} · {finding.severity}</p></div>)}</article><article className="data-panel" data-level2-screen="coverage"><h2>Coverage</h2><dl><dt>Hashing</dt><dd>{analysis.coverage.hashing}</dd><dt>Classification</dt><dd>{analysis.coverage.classification}</dd><dt>PE</dt><dd>{analysis.coverage.pe_inspection}</dd><dt>Authenticode</dt><dd>{analysis.coverage.authenticode}</dd><dt>YARA</dt><dd>{analysis.coverage.yara}</dd><dt>Reputation</dt><dd>{analysis.coverage.reputation}</dd></dl></article></div></section>; }
    if (page === "overview" && fileAnalysis?.terminal_error) return <section className="data-panel" data-level2-screen={fileAnalysis.progress.phase}><h2>{fileAnalysis.progress.phase}</h2><p className="coverage-warning">{fileAnalysis.terminal_error}</p><p>No final file verdict was generated.</p></section>;
    if (page === "settings") return <section className="data-panel"><h2>Local-first</h2><p>{text.syntheticNote}</p><dl><dt>Operating system</dt><dd>Windows 10</dd><dt>Network providers</dt><dd>Disabled by default</dd><dt>Defender provider</dt><dd>Optional / disabled</dd></dl></section>;
    return scan === null ? <EmptyState title={text.noData} detail={text.noDataDetail} /> : <section className="data-panel"><div className="panel-heading"><div><h2>{scan.verdict ?? scan.state}</h2><code>{scan.id}</code></div><span className={`severity severity-${scan.risk ?? "info"}`}>{scan.risk ?? "pending"}</span></div><dl><dt>{text.status}</dt><dd>{scan.state}</dd><dt>{text.coverage}</dt><dd>{coverage}</dd><dt>Planned</dt><dd>{scan.coverage.total}</dd><dt>Executed / passed</dt><dd>{scan.coverage.completed}</dd><dt>Failed</dt><dd>{scan.coverage.failed}</dd><dt>Unavailable</dt><dd>{scan.coverage.unavailable}</dd><dt>Skipped</dt><dd>{scan.coverage.skipped}</dd><dt>{text.risk}</dt><dd>{scan.risk ?? "—"}</dd><dt>{text.confidence}</dt><dd>{scan.confidence ?? "—"}</dd></dl>{scan.state === "partial" && <p className="coverage-warning">Partial coverage: unavailable checks are recorded and are not treated as a security pass.</p>}{scan.state === "cancelled" && <p className="coverage-warning">Cancelled: no final verdict was generated.</p>}</section>;
  })();

  return <div className={`app-shell theme-${theme}`} lang={locale}>
    <aside className="sidebar" aria-label="Primary navigation"><div className="brand"><span className="brand-mark" aria-hidden="true">EV</span><div><strong>{text.product}</strong><small>{text.edition}</small></div></div><nav>{pages.map((item) => <button key={item} className={page === item ? "active" : ""} aria-current={page === item ? "page" : undefined} onClick={() => setPage(item)}>{text[item]}</button>)}</nav><div className="sidebar-footer"><span className="status-dot" aria-hidden="true" />Windows 10 · Local-first</div></aside>
    <main aria-labelledby="title"><header className="topbar"><div><p className="eyebrow">{text.foundation}</p><h1 id="title">{text[page]}</h1></div><div className="controls"><label>{text.language}<select aria-label={text.language} value={locale} onChange={(event) => setLocale(event.target.value as Locale)}><option value="pt-BR">PT-BR</option><option value="en">EN</option></select></label><label>{text.theme}<select aria-label={text.theme} value={theme} onChange={(event) => setTheme(event.target.value as Theme)}><option value="professional">{text.professional}</option><option value="neon">{text.neon}</option></select></label></div></header>
      <section className="status-strip" aria-label="Infrastructure status" aria-live="polite" aria-atomic="true"><span className={ready ? "status-dot ready" : "status-dot"} aria-hidden="true" /><strong>{ready ? text.available : failed ? text.unavailable : text.checking}</strong><span>{ready ? "Core · Storage · IPC restricted" : "Fail closed"}</span></section>
      {error && <div className="safe-error" role="alert">{error}</div>}
      <section className="metric-grid" aria-label="Verdict dimensions"><article><span>{text.coverage}</span><strong>{coverage}</strong><small>{scan?.state ?? text.noData}</small></article><article><span>{text.risk}</span><strong>{scan?.risk ?? "—"}</strong><small>{text.risk}</small></article><article><span>{text.confidence}</span><strong>{scan?.confidence ?? "—"}</strong><small>{text.confidence}</small></article><article><span>{text.status}</span><strong>{scan?.state ?? "—"}</strong><small>{scan?.verdict ?? text.noData}</small></article></section>
      {content}<footer><strong>{text.blocker}:</strong> {text.upstream}</footer>
    </main>
  </div>;
}

export default function App() {
  const [status, setStatus] = useState<FoundationStatus | null>(null);
  const [failed, setFailed] = useState(false);
  const [engines, setEngines] = useState<readonly EngineStatus[]>([]);
  const [scans, setScans] = useState<readonly ScanSummary[]>([]);
  const [selected, setSelected] = useState<ScanSummary | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [findings, setFindings] = useState<readonly FindingView[]>([]);
  const [report, setReport] = useState<ReportView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [repositoryAuthorization,setRepositoryAuthorization]=useState<RepositoryAuthorization|null>(null);
  const [filePreview,setFilePreview]=useState<FileTargetPreview|null>(null);
  const [fileAuthorization,setFileAuthorization]=useState<FileAuthorization|null>(null);
  const [fileAnalysis,setFileAnalysis]=useState<FileAnalysisView|null>(null);
  const [installedPreview,setInstalledPreview]=useState<InstalledApplicationPreview|null>(null);
  const [installedAuthorization,setInstalledAuthorization]=useState<InstalledApplicationAuthorization|null>(null);
  const [installedInventory,setInstalledInventory]=useState<InstalledApplicationInventory|null>(null);
  const [providerStatus,setProviderStatus]=useState<readonly DatasetStatus[]>([]);
  const [urlPreview,setUrlPreview]=useState<UrlTargetPreview|null>(null);
  const [urlAuthorization,setUrlAuthorization]=useState<UrlTargetAuthorization|null>(null);
  const [webAnalysis,setWebAnalysis]=useState<WebAnalysisView|null>(null);
  const [correlation,setCorrelation]=useState<CorrelationSummary|null>(null);
  const [clusters,setClusters]=useState<readonly Cluster[]>([]);
  const [cases,setCases]=useState<readonly InvestigationCase[]>([]);
  const [investigationGraph,setInvestigationGraph]=useState<InvestigationGraph|null>(null);
  const [investigationReport,setInvestigationReport]=useState<InvestigationReport|null>(null);
  const [investigationState,setInvestigationState]=useState<InvestigationUiState>("idle");
  const selectedId = useRef<string | null>(null);

  useEffect(() => { selectedId.current = selected?.id ?? null; }, [selected?.id]);

  useEffect(() => {
    let active = true;
    void Promise.allSettled([level0Api.foundation(), level0Api.engines(), level0Api.listScans(),level0Api.vulnerabilityProviderStatus()]).then((results) => {
      if (!active) return;
      if (results[0].status === "fulfilled") setStatus(results[0].value); else setFailed(true);
      if (results[1].status === "fulfilled") setEngines(results[1].value);
      if (results[2].status === "fulfilled") { setScans(results[2].value); setSelected(results[2].value[0] ?? null); }
      if (results[3].status === "fulfilled") setProviderStatus(results[3].value);
      if (results.some((result) => result.status === "rejected")) setError("Some backend data is unavailable");
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (selected === null) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setProgress(null);
    setFileAnalysis(null);
    setWebAnalysis(null);
    setFindings([]);
    setReport(null);
    const poll = async () => {
      try {
        const next = await level0Api.progress(selected.id);
        if (!active) return;
        setProgress(next);
        if (terminalStates.has(next.status)) {
          const scanResult = await level0Api.getScan(selected.id);
          let findingResult: readonly FindingView[] = [];
          try { findingResult = await level0Api.findings(selected.id); } catch { findingResult = []; }
          if (active) {
            setSelected(scanResult);
            setFindings(findingResult);
            setScans((current) => [scanResult, ...current.filter((item) => item.id !== scanResult.id)]);
            try { const result = await level0Api.getFileAnalysis(selected.id); if (active) setFileAnalysis(result); } catch { if (active) setFileAnalysis(null); }
            try { const result=await level0Api.getInstalledApplicationInventory(selected.id);if(active){setInstalledInventory(result);setProviderStatus(result.provider_status);}} catch { if(active)setInstalledInventory(null); }
            try { const result=await level0Api.getUrlScanAnalysis(selected.id);if(active)setWebAnalysis(result);} catch {if(active)setWebAnalysis(null);}
          }
        } else {
          timer = setTimeout(() => { void poll(); }, 750);
        }
      } catch (cause) { if (active) setError(safeUiError(cause, "Backend response rejected or unavailable")); }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [selected?.id]);

  const start = async () => {
    setBusy(true); setError(null); setReport(null); setFindings([]);
    try { const scan = await level0Api.createSyntheticScan(); setSelected(scan); setScans((current) => [scan, ...current]); }
    catch (cause) { setError(safeUiError(cause, "Synthetic scan could not be created safely")); }
    finally { setBusy(false); }
  };
  const cancel = async () => {
    if (selected === null) return;
    const scanId = selected.id;
    setBusy(true);
    try { const result = await level0Api.cancel(scanId); if (selectedId.current === scanId) setProgress(result); }
    catch (cause) { setError(safeUiError(cause, "Cancellation request failed safely")); } finally { setBusy(false); }
  };
  const authorizeRepository = async(path:string)=>{setBusy(true);setError(null);try{setRepositoryAuthorization(await level0Api.authorizeRepository(path));}catch(cause){setError(safeUiError(cause,"Repository path was refused safely"));}finally{setBusy(false);}};
  const startRepository = async()=>{if(!repositoryAuthorization)return;setBusy(true);setError(null);try{const scan=await level0Api.createRepositoryScan(repositoryAuthorization.authorization_id);setSelected(scan);setScans(current=>[scan,...current]);}catch(cause){setError(safeUiError(cause,"Repository scan could not be created safely"));}finally{setBusy(false);}};
  const inspectFile=async(path:string)=>{setBusy(true);setError(null);setFileAuthorization(null);try{setFilePreview(await level0Api.inspectFile(path));}catch(cause){setFilePreview(null);setError(safeUiError(cause,"File preview was refused safely"));}finally{setBusy(false);}};
  const authorizeFile=async(previewId:string)=>{setBusy(true);setError(null);try{setFileAuthorization(await level0Api.authorizeFile(previewId));}catch(cause){setFileAuthorization(null);setError(safeUiError(cause,"File authorization was refused safely"));}finally{setBusy(false);}};
  const startFile=async()=>{if(!fileAuthorization)return;setBusy(true);setError(null);setFileAnalysis(null);try{const scan=await level0Api.createFileScan(fileAuthorization.authorization_id);setSelected(scan);setScans(current=>[scan,...current]);}catch(cause){setError(safeUiError(cause,"File analysis could not be created safely"));}finally{setBusy(false);}};
  const previewInstalled=async(include:boolean)=>{setBusy(true);setError(null);setInstalledAuthorization(null);setInstalledInventory(null);try{setInstalledPreview(await level0Api.previewInstalledApplications(include));}catch(cause){setError(safeUiError(cause,"Installed application preview failed safely"));}finally{setBusy(false);}};
  const authorizeInstalled=async(previewId:string)=>{setBusy(true);setError(null);try{setInstalledAuthorization(await level0Api.authorizeInstalledApplications(previewId));}catch(cause){setError(safeUiError(cause,"Installed application authorization failed safely"));}finally{setBusy(false);}};
  const startInstalled=async()=>{if(!installedAuthorization)return;setBusy(true);setError(null);try{const scan=await level0Api.createInstalledApplicationScan(installedAuthorization.authorization_id);setSelected(scan);setScans(current=>[scan,...current]);setInstalledInventory(await level0Api.getInstalledApplicationInventory(scan.id));}catch(cause){setError(safeUiError(cause,"Installed application analysis failed safely"));}finally{setBusy(false);}};
  const refreshProviders=async()=>{setBusy(true);setError(null);try{const result=await level0Api.refreshPublicVulnerabilityData();setProviderStatus(result.provider_status);}catch(cause){setError(safeUiError(cause,"Public vulnerability datasets remain unavailable; prior validated cache was preserved"));}finally{setBusy(false);}};
  const previewUrl=async(url:string,policy:QueryPolicy)=>{setBusy(true);setError(null);setUrlAuthorization(null);setWebAnalysis(null);try{setUrlPreview(await level0Api.previewUrlTarget(url,policy));}catch(cause){setUrlPreview(null);setError(safeUiError(cause,"URL target was refused safely"));}finally{setBusy(false);}};
  const authorizeUrl=async(previewId:string)=>{setBusy(true);setError(null);try{setUrlAuthorization(await level0Api.authorizeUrlTarget(previewId));}catch(cause){setUrlAuthorization(null);setError(safeUiError(cause,"URL authorization was refused safely"));}finally{setBusy(false);}};
  const startUrl=async()=>{if(!urlAuthorization)return;setBusy(true);setError(null);setWebAnalysis(null);try{const scan=await level0Api.createUrlScan(urlAuthorization.authorization_id);setSelected(scan);setScans(current=>[scan,...current]);}catch(cause){setError(safeUiError(cause,"Passive URL analysis could not be created safely"));}finally{setBusy(false);}};
  const generateReport = async (kind: ReportView["kind"]) => {
    if (selected === null) return;
    const scanId = selected.id;
    setBusy(true);
    try { const result = await level0Api.report(scanId, kind); if (selectedId.current === scanId) setReport(result); }
    catch (cause) { setError(safeUiError(cause, "Report generation failed safely")); } finally { setBusy(false); }
  };
  const runCorrelation=async()=>{setInvestigationState("running");setCorrelation(null);setClusters([]);setCases([]);setInvestigationGraph(null);setInvestigationReport(null);try{const summary=await level5Api.run();setCorrelation(summary);setInvestigationState(summary.state);if(summary.state==="complete"){const [clusterItems,caseItems,graph]=await Promise.all([level5Api.clusters(summary.run_id),level5Api.cases(summary.run_id),level5Api.graph(summary.run_id)]);setClusters(clusterItems);setCases(caseItems);setInvestigationGraph(graph);}}catch(cause){setInvestigationState("error");setError(safeUiError(cause,"Correlation stopped safely"));}};
  const cancelCorrelation=async()=>{try{await level5Api.cancel();}catch(cause){setError(safeUiError(cause,"Correlation cancellation failed safely"));}};
  const openCase=async(clusterId:string)=>{if(!correlation)return;setBusy(true);try{const value=await level5Api.createCase(correlation.run_id,clusterId);setCases(current=>current.map(item=>item.case_id===value.case_id?value:item));}catch(cause){setError(safeUiError(cause,"Case creation was refused safely"));}finally{setBusy(false);}};
  const advanceCase=async(caseId:string)=>{if(!correlation)return;setBusy(true);try{const value=await level5Api.transition(correlation.run_id,caseId,"investigating");setCases(current=>current.map(item=>item.case_id===value.case_id?value:item));}catch(cause){setError(safeUiError(cause,"Case lifecycle transition was refused safely"));}finally{setBusy(false);}};
  const investigationReportAction=async(caseId:string,kind:InvestigationReport["kind"])=>{if(!correlation)return;setBusy(true);try{setInvestigationReport(await level5Api.report(correlation.run_id,caseId,kind));}catch(cause){setError(safeUiError(cause,"Investigation report failed safely"));}finally{setBusy(false);}};
  return <FoundationView status={status} failed={failed} engines={engines} scans={scans} selected={selected} progress={progress} findings={findings} report={report} error={error} busy={busy} repositoryAuthorization={repositoryAuthorization} onAuthorizeRepository={(path)=>{void authorizeRepository(path);}} onStartRepository={()=>{void startRepository();}} filePreview={filePreview} fileAuthorization={fileAuthorization} fileAnalysis={fileAnalysis} onInspectFile={(path)=>{void inspectFile(path);}} onAuthorizeFile={(path)=>{void authorizeFile(path);}} onStartFile={()=>{void startFile();}} installedPreview={installedPreview} installedAuthorization={installedAuthorization} installedInventory={installedInventory} providerStatus={providerStatus} onPreviewInstalled={include=>{void previewInstalled(include);}} onAuthorizeInstalled={id=>{void authorizeInstalled(id);}} onStartInstalled={()=>{void startInstalled();}} onRefreshProviders={()=>{void refreshProviders();}} urlPreview={urlPreview} urlAuthorization={urlAuthorization} webAnalysis={webAnalysis} onPreviewUrl={(url,policy)=>{void previewUrl(url,policy);}} onAuthorizeUrl={id=>{void authorizeUrl(id);}} onStartUrl={()=>{void startUrl();}} correlation={correlation} clusters={clusters} cases={cases} investigationGraph={investigationGraph} investigationReport={investigationReport} investigationState={investigationState} onRunCorrelation={()=>{void runCorrelation();}} onCancelCorrelation={()=>{void cancelCorrelation();}} onOpenCase={id=>{void openCase(id);}} onAdvanceCase={id=>{void advanceCase(id);}} onInvestigationReport={(id,kind)=>{void investigationReportAction(id,kind);}} onStart={() => { void start(); }} onCancel={() => { void cancel(); }} onSelect={(scan) => { if (!busy) setSelected(scan); }} onReport={(kind) => { void generateReport(kind); }} />;
}
