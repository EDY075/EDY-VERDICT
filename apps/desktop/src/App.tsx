import { useEffect, useRef, useState } from "react";
import type { FoundationStatus } from "./foundation";
import { level0Api } from "./level0-api";
import type { EngineStatus, FindingView, ReportView, ScanProgress, ScanSummary, RepositoryAuthorization } from "./level0-api";

type Locale = "pt-BR" | "en";
type Theme = "professional" | "neon";
type Page = "overview" | "new-scan" | "progress" | "findings" | "history" | "engines" | "reports" | "settings";

const pages: readonly Page[] = ["overview", "new-scan", "progress", "findings", "history", "engines", "reports", "settings"];
const terminalStates = new Set(["cancelled", "completed", "partial", "failed"]);

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
}

function EmptyState({ title, detail }: { readonly title: string; readonly detail: string }) {
  return <section className="empty-state" data-mode="production-empty"><div className="radar" aria-hidden="true"><span /></div><div><h2>{title}</h2><p>{detail}</p></div></section>;
}

export function FoundationView({
  status, failed, engines = [], scans = [], selected = null, progress = null, findings = [], report = null,
  error = null, busy = false, onStart, onCancel, onSelect, onReport, repositoryAuthorization = null, onAuthorizeRepository, onStartRepository,
}: ProductViewProps) {
  const [page, setPage] = useState<Page>("overview");
  const [locale, setLocale] = useState<Locale>("pt-BR");
  const [theme, setTheme] = useState<Theme>("professional");
  const [repositoryPath, setRepositoryPath] = useState("");
  const text = copy[locale];
  const ready = status !== null;
  const scan = selected ?? scans[0] ?? null;
  const coverage = scan === null || scan.coverage.total === 0 ? "—" : `${scan.coverage.completed}/${scan.coverage.total}`;

  const content = (() => {
    if (page === "new-scan") return <section className="action-panel"><h2>Repository Security</h2><p>Repository inventory available. Some security checks are unavailable until execution policy requirements are satisfied.</p><label>Repository path<input aria-label="Repository path" value={repositoryPath} onChange={(event)=>setRepositoryPath(event.target.value)} /></label><button className="secondary" disabled={!ready||busy||repositoryPath.length===0||onAuthorizeRepository===undefined} onClick={()=>onAuthorizeRepository?.(repositoryPath)}>Authorize and inspect</button>{repositoryAuthorization && <div className="data-panel"><h3>Authorization preview</h3><code>{repositoryAuthorization.canonical_root}</code><dl><dt>Estimated files</dt><dd>{repositoryAuthorization.estimated_files}</dd><dt>Estimated bytes</dt><dd>{repositoryAuthorization.estimated_bytes}</dd><dt>Exclusions</dt><dd>{repositoryAuthorization.exclusions.join(", ")}</dd><dt>Readiness</dt><dd>{repositoryAuthorization.readiness}</dd></dl><button className="primary" disabled={busy||onStartRepository===undefined} onClick={onStartRepository}>Confirm repository scan</button></div>}<hr/><h2>{text.synthetic}</h2><p>{text.syntheticNote}</p><button className="primary" disabled={!ready || busy || onStart === undefined} onClick={onStart}>{busy ? "…" : text.synthetic}</button></section>;
    if (page === "progress") return progress === null
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="data-panel"><div className="panel-heading"><div><h2>{progress.phase}</h2><code>{progress.scan_id}</code></div><strong>{progress.percent === null ? "—" : `${progress.percent}%`}</strong></div><progress max="100" value={progress.percent ?? 0} /><dl><dt>{text.status}</dt><dd>{progress.status}</dd><dt>Engine</dt><dd>{progress.current_engine ?? "—"}</dd><dt>Tasks</dt><dd>{progress.completed_tasks}/{progress.total_tasks}</dd><dt>Elapsed</dt><dd>{progress.elapsed_ms} ms</dd></dl>{!terminalStates.has(progress.status) && <button className="secondary" onClick={onCancel} disabled={busy || onCancel === undefined}>{text.cancel}</button>}</section>;
    if (page === "findings") return findings.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="card-list">{findings.map((finding) => <article key={finding.id}><div><span className={`severity severity-${finding.severity}`}>{finding.severity}</span><h2>{finding.title}</h2><p>{finding.category} · {finding.status}</p></div><dl><dt>{text.risk}</dt><dd>{finding.risk}</dd><dt>{text.confidence}</dt><dd>{finding.confidence}</dd><dt>Sources</dt><dd>{finding.sources.join(", ")}</dd></dl></article>)}</section>;
    if (page === "history") return scans.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="table-wrap"><table><thead><tr><th>ID</th><th>{text.status}</th><th>{text.risk}</th><th>{text.confidence}</th><th>{text.coverage}</th></tr></thead><tbody>{scans.map((item) => <tr key={item.id} onClick={() => onSelect?.(item)}><td><code>{item.id}</code></td><td>{item.state}</td><td>{item.risk ?? "—"}</td><td>{item.confidence ?? "—"}</td><td>{item.coverage.completed}/{item.coverage.total}</td></tr>)}</tbody></table></section>;
    if (page === "engines") return engines.length === 0
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="engine-grid">{engines.map((engine) => <article key={engine.id}><span className={`status-dot ${engine.state === "ready" ? "ready" : ""}`} /><div><h2>{engine.id}</h2><p>{engine.version} · {engine.state}</p><small>{engine.detail_safe}</small></div></article>)}</section>;
    if (page === "reports") return scan === null
      ? <EmptyState title={text.noData} detail={text.noDataDetail} />
      : <section className="data-panel"><div className="report-actions">{(["executive", "technical", "developer"] as const).map((kind) => <button className="secondary" disabled={busy || onReport === undefined} key={kind} onClick={() => onReport?.(kind)}>{text.generate}: {text[kind]}</button>)}</div>{report && <pre className="report-json" aria-label="JSON report">{report.json}</pre>}</section>;
    if (page === "settings") return <section className="data-panel"><h2>Local-first</h2><p>{text.syntheticNote}</p><dl><dt>Operating system</dt><dd>Windows 10</dd><dt>Network providers</dt><dd>Disabled by default</dd><dt>Defender provider</dt><dd>Optional / disabled</dd></dl></section>;
    return scan === null ? <EmptyState title={text.noData} detail={text.noDataDetail} /> : <section className="data-panel"><div className="panel-heading"><div><h2>{scan.verdict ?? scan.state}</h2><code>{scan.id}</code></div><span className={`severity severity-${scan.risk ?? "info"}`}>{scan.risk ?? "pending"}</span></div><dl><dt>{text.status}</dt><dd>{scan.state}</dd><dt>{text.coverage}</dt><dd>{coverage}</dd><dt>{text.risk}</dt><dd>{scan.risk ?? "—"}</dd><dt>{text.confidence}</dt><dd>{scan.confidence ?? "—"}</dd></dl></section>;
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
    setFindings([]);
    setReport(null);
    const poll = async () => {
      try {
        const next = await level0Api.progress(selected.id);
        if (!active) return;
        setProgress(next);
        if (terminalStates.has(next.status)) {
          const [scanResult, findingResult] = await Promise.all([level0Api.getScan(selected.id), level0Api.findings(selected.id)]);
          if (active) { setSelected(scanResult); setFindings(findingResult); setScans((current) => [scanResult, ...current.filter((item) => item.id !== scanResult.id)]); }
        } else {
          timer = setTimeout(() => { void poll(); }, 750);
        }
      } catch { if (active) setError("Backend response rejected or unavailable"); }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [selected?.id]);

  const start = async () => {
    setBusy(true); setError(null); setReport(null); setFindings([]);
    try { const scan = await level0Api.createSyntheticScan(); setSelected(scan); setScans((current) => [scan, ...current]); }
    catch { setError("Synthetic scan could not be created safely"); }
    finally { setBusy(false); }
  };
  const cancel = async () => {
    if (selected === null) return;
    const scanId = selected.id;
    setBusy(true);
    try { const result = await level0Api.cancel(scanId); if (selectedId.current === scanId) setProgress(result); }
    catch { setError("Cancellation request failed safely"); } finally { setBusy(false); }
  };
  const authorizeRepository = async(path:string)=>{setBusy(true);setError(null);try{setRepositoryAuthorization(await level0Api.authorizeRepository(path));}catch{setError("Repository path was refused safely");}finally{setBusy(false);}};
  const startRepository = async()=>{if(!repositoryAuthorization)return;setBusy(true);setError(null);try{const scan=await level0Api.createRepositoryScan(repositoryAuthorization.authorization_id);setSelected(scan);setScans(current=>[scan,...current]);}catch{setError("Repository scan could not be created safely");}finally{setBusy(false);}};
  const generateReport = async (kind: ReportView["kind"]) => {
    if (selected === null) return;
    const scanId = selected.id;
    setBusy(true);
    try { const result = await level0Api.report(scanId, kind); if (selectedId.current === scanId) setReport(result); }
    catch { setError("Report generation failed safely"); } finally { setBusy(false); }
  };
  return <FoundationView status={status} failed={failed} engines={engines} scans={scans} selected={selected} progress={progress} findings={findings} report={report} error={error} busy={busy} repositoryAuthorization={repositoryAuthorization} onAuthorizeRepository={(path)=>{void authorizeRepository(path);}} onStartRepository={()=>{void startRepository();}} onStart={() => { void start(); }} onCancel={() => { void cancel(); }} onSelect={(scan) => { if (!busy) setSelected(scan); }} onReport={(kind) => { void generateReport(kind); }} />;
}
