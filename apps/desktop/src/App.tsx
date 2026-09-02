import { useEffect, useRef, useState } from "react";
import type { FoundationStatus } from "./foundation";
import { level0Api } from "./level0-api";
import type { EngineStatus, FileAnalysisView, FileAuthorization, FileTargetPreview, FindingView, ReportView, ScanProgress, ScanSummary, RepositoryAuthorization } from "./level0-api";

type Locale = "pt-BR" | "en";
type Theme = "professional" | "neon";
type Page = "overview" | "new-scan" | "progress" | "findings" | "history" | "engines" | "reports" | "settings";

const pages: readonly Page[] = ["overview", "new-scan", "progress", "findings", "history", "engines", "reports", "settings"];
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
  };
  return messages[code] ?? fallback;
}

const copy = {
  "pt-BR": {
    product: "EDY VERDICT", edition: "Centro de segurança local", overview: "Visão geral", "new-scan": "Nova análise",
    progress: "Progresso", findings: "Achados", history: "Histórico", engines: "Engines", reports: "Relatórios",
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
    progress: "Scan Progress", findings: "Findings", history: "History", engines: "Engines", reports: "Reports",
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
}

function EmptyState({ title, detail }: { readonly title: string; readonly detail: string }) {
  return <section className="empty-state" data-mode="production-empty"><div className="radar" aria-hidden="true"><span /></div><div><h2>{title}</h2><p>{detail}</p></div></section>;
}

export function FoundationView({
  status, failed, engines = [], scans = [], selected = null, progress = null, findings = [], report = null,
  error = null, busy = false, onStart, onCancel, onSelect, onReport, repositoryAuthorization = null, onAuthorizeRepository, onStartRepository,
  filePreview = null, fileAuthorization = null, fileAnalysis = null, onInspectFile, onAuthorizeFile, onStartFile, initialPage = "overview",
}: ProductViewProps) {
  const [page, setPage] = useState<Page>(initialPage);
  const [locale, setLocale] = useState<Locale>("pt-BR");
  const [theme, setTheme] = useState<Theme>("professional");
  const [repositoryPath, setRepositoryPath] = useState("");
  const [filePath, setFilePath] = useState(filePreview?.requested_path ?? "");
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
    if (page === "overview" && fileAnalysis?.analysis) { const analysis=fileAnalysis.analysis; return <section className="level2-analysis" data-level2-screen="analysis"><div className="data-panel"><div className="panel-heading"><div><p className="eyebrow">File / Binary Security</p><h2>{analysis.verdict.disposition}</h2></div><span className={`severity severity-${analysis.verdict.risk}`}>{analysis.verdict.risk}</span></div><p>No safety guarantee is made. Coverage limitations remain visible.</p></div><div className="analysis-grid"><article className="data-panel"><h2>File Identity</h2><dl><dt>Location</dt><dd><code>{analysis.target.canonical_path}</code></dd><dt>Volume ID</dt><dd>{analysis.target.identity.volume_id}</dd><dt>File ID</dt><dd>{analysis.target.identity.file_id}</dd><dt>Size</dt><dd>{analysis.target.identity.size}</dd></dl></article><article className="data-panel" data-level2-screen="hashes"><h2>Hashes</h2><dl><dt>SHA-256</dt><dd><code>{analysis.hashes.sha256}</code></dd><dt>SHA-512</dt><dd><code>{analysis.hashes.sha512}</code></dd><dt>Bytes hashed</dt><dd>{analysis.hashes.bytes_hashed}</dd></dl></article><article className="data-panel" data-level2-screen="pe"><h2>PE Metadata</h2><dl><dt>Classification</dt><dd>{analysis.classification}</dd><dt>Architecture</dt><dd>{analysis.pe?.architecture ?? "Not applicable"}</dd><dt>Subsystem</dt><dd>{analysis.pe?.subsystem ?? "—"}</dd><dt>Entry point RVA</dt><dd>{analysis.pe?.entry_point_rva ?? "—"}</dd><dt>Image base</dt><dd>{analysis.pe?.image_base ?? "—"}</dd><dt>Sections</dt><dd>{analysis.pe?.sections.map(section => `${section.name}: virtual=${section.virtual_size}, raw=${section.raw_size}`).join("; ") ?? "—"}</dd><dt>Parser</dt><dd>{analysis.pe_error ?? "completed"}</dd></dl></article><article className="data-panel" data-level2-screen="signature"><h2>Digital Signature</h2><dl><dt>Presence</dt><dd>{analysis.authenticode.signature_present ? "Present" : "Unsigned"}</dd><dt>Cryptographic status</dt><dd>{analysis.authenticode.cryptographic_status}</dd><dt>Trust chain</dt><dd>{analysis.authenticode.trust_chain_status}</dd><dt>Publisher</dt><dd>{analysis.authenticode.publisher?.subject ?? "Unavailable"}</dd><dt>Issuer</dt><dd>{analysis.authenticode.publisher?.issuer ?? "Unavailable"}</dd><dt>Network</dt><dd>Offline / cache-only</dd></dl></article><article className="data-panel"><h2>YARA</h2><p className="coverage-warning">Unavailable by execution policy</p></article><article className="data-panel"><h2>Reputation</h2><p className="coverage-warning">Not checked — no upload and no network lookup</p></article><article className="data-panel"><h2>Findings</h2>{analysis.findings.length===0?<p>No findings from available checks. This is not a clean guarantee.</p>:analysis.findings.map(finding=><div key={finding.id}><strong>{finding.title}</strong><p>{finding.category} · {finding.severity}</p></div>)}</article><article className="data-panel" data-level2-screen="coverage"><h2>Coverage</h2><dl><dt>Hashing</dt><dd>{analysis.coverage.hashing}</dd><dt>Classification</dt><dd>{analysis.coverage.classification}</dd><dt>PE</dt><dd>{analysis.coverage.pe_inspection}</dd><dt>Authenticode</dt><dd>{analysis.coverage.authenticode}</dd><dt>YARA</dt><dd>{analysis.coverage.yara}</dd><dt>Reputation</dt><dd>{analysis.coverage.reputation}</dd></dl></article></div></section>; }
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
  const selectedId = useRef<string | null>(null);

  useEffect(() => { selectedId.current = selected?.id ?? null; }, [selected?.id]);

  useEffect(() => {
    let active = true;
    void Promise.allSettled([level0Api.foundation(), level0Api.engines(), level0Api.listScans()]).then((results) => {
      if (!active) return;
      if (results[0].status === "fulfilled") setStatus(results[0].value); else setFailed(true);
      if (results[1].status === "fulfilled") setEngines(results[1].value);
      if (results[2].status === "fulfilled") { setScans(results[2].value); setSelected(results[2].value[0] ?? null); }
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
    setFindings([]);
    setReport(null);
    const poll = async () => {
      try {
        const next = await level0Api.progress(selected.id);
        if (!active) return;
        setProgress(next);
        if (terminalStates.has(next.status)) {
          const [scanResult, findingResult] = await Promise.all([level0Api.getScan(selected.id), level0Api.findings(selected.id)]);
          if (active) { setSelected(scanResult); setFindings(findingResult); setScans((current) => [scanResult, ...current.filter((item) => item.id !== scanResult.id)]); try { const result = await level0Api.getFileAnalysis(selected.id); if (active) setFileAnalysis(result); } catch { if (active) setFileAnalysis(null); } }
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
  const generateReport = async (kind: ReportView["kind"]) => {
    if (selected === null) return;
    const scanId = selected.id;
    setBusy(true);
    try { const result = await level0Api.report(scanId, kind); if (selectedId.current === scanId) setReport(result); }
    catch (cause) { setError(safeUiError(cause, "Report generation failed safely")); } finally { setBusy(false); }
  };
  return <FoundationView status={status} failed={failed} engines={engines} scans={scans} selected={selected} progress={progress} findings={findings} report={report} error={error} busy={busy} repositoryAuthorization={repositoryAuthorization} onAuthorizeRepository={(path)=>{void authorizeRepository(path);}} onStartRepository={()=>{void startRepository();}} filePreview={filePreview} fileAuthorization={fileAuthorization} fileAnalysis={fileAnalysis} onInspectFile={(path)=>{void inspectFile(path);}} onAuthorizeFile={(path)=>{void authorizeFile(path);}} onStartFile={()=>{void startFile();}} onStart={() => { void start(); }} onCancel={() => { void cancel(); }} onSelect={(scan) => { if (!busy) setSelected(scan); }} onReport={(kind) => { void generateReport(kind); }} />;
}
