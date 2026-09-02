import { useEffect, useState } from "react";
import { readFoundationStatus } from "./foundation";
import type { FoundationStatus } from "./foundation";

type Locale = "pt-BR" | "en";
type Theme = "professional" | "neon";
type Page = "overview" | "new-scan" | "progress" | "findings" | "finding-detail" | "history" | "engines" | "reports" | "settings";

const pages: readonly Page[] = [
  "overview", "new-scan", "progress", "findings", "finding-detail",
  "history", "engines", "reports", "settings",
];

const copy = {
  "pt-BR": {
    product: "EDY VERDICT",
    edition: "Centro de segurança local",
    overview: "Visão geral",
    "new-scan": "Nova análise",
    progress: "Progresso",
    findings: "Achados",
    "finding-detail": "Detalhe do achado",
    history: "Histórico",
    engines: "Engines",
    reports: "Relatórios",
    settings: "Configurações",
    foundation: "Fundação Level 0",
    available: "Infraestrutura disponível",
    unavailable: "Infraestrutura indisponível",
    checking: "Validando infraestrutura…",
    noData: "Nenhum dado disponível",
    noDataDetail: "A interface não usa demonstrações silenciosas. Os dados aparecerão quando o backend autorizado fornecer um contrato válido.",
    coverage: "Cobertura",
    risk: "Risco",
    confidence: "Confiança",
    status: "Estado",
    blocker: "Bloqueio conhecido",
    upstream: "Tauri upstream aguardando release oficial",
    language: "Idioma",
    theme: "Tema",
    professional: "Profissional escuro",
    neon: "Cyberpunk neon",
  },
  en: {
    product: "EDY VERDICT",
    edition: "Local security center",
    overview: "Overview",
    "new-scan": "New Scan",
    progress: "Scan Progress",
    findings: "Findings",
    "finding-detail": "Finding Detail",
    history: "History",
    engines: "Engines",
    reports: "Reports",
    settings: "Settings",
    foundation: "Level 0 Foundation",
    available: "Infrastructure available",
    unavailable: "Infrastructure unavailable",
    checking: "Validating infrastructure…",
    noData: "No data available",
    noDataDetail: "The interface never uses silent production demos. Data appears only when the authorized backend provides a valid contract.",
    coverage: "Coverage",
    risk: "Risk",
    confidence: "Confidence",
    status: "Status",
    blocker: "Known blocker",
    upstream: "Tauri upstream awaiting official release",
    language: "Language",
    theme: "Theme",
    professional: "Dark professional",
    neon: "Cyberpunk neon",
  },
} as const;

export function FoundationView({ status, failed }: {
  readonly status: FoundationStatus | null;
  readonly failed: boolean;
}) {
  const [page, setPage] = useState<Page>("overview");
  const [locale, setLocale] = useState<Locale>("pt-BR");
  const [theme, setTheme] = useState<Theme>("professional");
  const text = copy[locale];
  const ready = status !== null;
  return (
    <div className={`app-shell theme-${theme}`} lang={locale}>
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand"><span className="brand-mark" aria-hidden="true">EV</span><div><strong>{text.product}</strong><small>{text.edition}</small></div></div>
        <nav>
          {pages.map((item) => <button key={item} className={page === item ? "active" : ""} aria-current={page === item ? "page" : undefined} onClick={() => setPage(item)}>{text[item]}</button>)}
        </nav>
        <div className="sidebar-footer"><span className="status-dot" aria-hidden="true" />Windows 10 · Local-first</div>
      </aside>
      <main aria-labelledby="title">
        <header className="topbar">
          <div><p className="eyebrow">{text.foundation}</p><h1 id="title">{text[page]}</h1></div>
          <div className="controls">
            <label>{text.language}<select aria-label={text.language} value={locale} onChange={(event) => setLocale(event.target.value as Locale)}><option value="pt-BR">PT-BR</option><option value="en">EN</option></select></label>
            <label>{text.theme}<select aria-label={text.theme} value={theme} onChange={(event) => setTheme(event.target.value as Theme)}><option value="professional">{text.professional}</option><option value="neon">{text.neon}</option></select></label>
          </div>
        </header>
        <section className="status-strip" aria-label="Infrastructure status" aria-live="polite" aria-atomic="true">
          <span className={ready ? "status-dot ready" : "status-dot"} aria-hidden="true" />
          <strong>{ready ? text.available : failed ? text.unavailable : text.checking}</strong>
          <span>{ready ? "Core · Storage · IPC restricted" : "Fail closed"}</span>
        </section>
        <section className="metric-grid" aria-label="Verdict dimensions">
          {[text.coverage, text.risk, text.confidence, text.status].map((label) => <article key={label}><span>{label}</span><strong>—</strong><small>{text.noData}</small></article>)}
        </section>
        <section className="empty-state" data-mode="production-empty">
          <div className="radar" aria-hidden="true"><span /></div>
          <div><h2>{text.noData}</h2><p>{text.noDataDetail}</p></div>
        </section>
        <footer><strong>{text.blocker}:</strong> {text.upstream}</footer>
      </main>
    </div>
  );
}

export default function App() {
  const [status, setStatus] = useState<FoundationStatus | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    void readFoundationStatus().then(
      (result) => { if (active) setStatus(result); },
      () => { if (active) setFailed(true); },
    );
    return () => { active = false; };
  }, []);
  return <FoundationView status={status} failed={failed} />;
}
