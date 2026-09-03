import type { FoundationStatus } from "./foundation";
import type { DatasetStatus, EngineStatus, ScanSummary } from "./level0-api";
import {
  PRODUCT_NAME, PRODUCT_VERSION, SUPPORTED_OS, TAURI_PIN, TAURI_UPSTREAM_STATE,
  type Locale, type Theme,
} from "./product";
import { CAPABILITIES } from "./capabilities";

type Text = Readonly<{
  settings: string; appearance: string; language: string; theme: string;
  privacy: string; diagnostics: string; about: string; localOnly: string;
  noTelemetry: string; noUpload: string; byok: string; notConfigured: string;
  defender: string; disabledChoice: string; system: string; professional: string; neon: string;
  runtime: string; storage: string; ipc: string; engines: string; providers: string;
  recentScans: string; supportBundle: string; supportUnavailable: string;
  version: string; platform: string; upstream: string; license: string; licensePending: string;
  limitations: string; backToSettings: string; resetOnboarding: string;
}>;

const words: Record<Locale, Text> = {
  "pt-BR": {
    settings: "Configurações", appearance: "Aparência e idioma", language: "Idioma", theme: "Tema",
    privacy: "Privacidade", diagnostics: "Diagnóstico", about: "Sobre", localOnly: "Local-first por padrão",
    noTelemetry: "Telemetria: nenhuma. O aplicativo não envia métricas de uso.",
    noUpload: "Arquivos, segredos, inventário e relatórios não são enviados automaticamente.",
    byok: "Chaves BYOK", notConfigured: "Não configuradas. Quando usadas, pertencem ao Windows Credential Manager e nunca são exibidas.",
    defender: "Microsoft Defender", disabledChoice: "Provider opcional e desativado por decisão do usuário.",
    system: "Seguir o sistema", professional: "Profissional escuro", neon: "Cyberpunk neon",
    runtime: "Core", storage: "Armazenamento", ipc: "IPC", engines: "Engines locais", providers: "Datasets públicos",
    recentScans: "Análises locais registradas", supportBundle: "Bundle de suporte", supportUnavailable: "Não gerado automaticamente nesta release candidate; copie apenas este resumo sanitizado se precisar de suporte.",
    version: "Versão", platform: "Plataforma", upstream: "Gate upstream", license: "Licença do produto", licensePending: "Decisão do titular pendente; distribuição pública continua bloqueada.",
    limitations: "Limitações", backToSettings: "Voltar às configurações", resetOnboarding: "Mostrar introdução novamente",
  },
  en: {
    settings: "Settings", appearance: "Appearance and language", language: "Language", theme: "Theme",
    privacy: "Privacy", diagnostics: "Diagnostics", about: "About", localOnly: "Local-first by default",
    noTelemetry: "Telemetry: none. The application sends no usage metrics.",
    noUpload: "Files, secrets, inventory, and reports are never uploaded automatically.",
    byok: "BYOK keys", notConfigured: "Not configured. When used, they belong in Windows Credential Manager and are never displayed.",
    defender: "Microsoft Defender", disabledChoice: "Optional provider, disabled by user decision.",
    system: "Follow system", professional: "Dark professional", neon: "Cyberpunk neon",
    runtime: "Core", storage: "Storage", ipc: "IPC", engines: "Local engines", providers: "Public datasets",
    recentScans: "Recorded local scans", supportBundle: "Support bundle", supportUnavailable: "Not generated automatically in this release candidate; copy only this sanitized summary when requesting support.",
    version: "Version", platform: "Platform", upstream: "Upstream gate", license: "Product license", licensePending: "Rights-holder decision pending; public distribution remains blocked.",
    limitations: "Limitations", backToSettings: "Back to settings", resetOnboarding: "Show introduction again",
  },
};

export function SettingsPage({ locale, theme, onLocale, onTheme, onOpen, onResetOnboarding }: {
  readonly locale: Locale; readonly theme: Theme;
  readonly onLocale: (value: Locale) => void; readonly onTheme: (value: Theme) => void;
  readonly onOpen: (page: "privacy" | "diagnostics" | "about") => void;
  readonly onResetOnboarding: () => void;
}) {
  const t = words[locale];
  return <div className="workflow-stack" data-level7-screen="settings">
    <section className="data-panel"><h2>{t.appearance}</h2><div className="settings-grid">
      <label>{t.language}<select value={locale} onChange={event => onLocale(event.target.value as Locale)}><option value="pt-BR">Português (Brasil)</option><option value="en">English</option></select></label>
      <label>{t.theme}<select value={theme} onChange={event => onTheme(event.target.value as Theme)}><option value="system">{t.system}</option><option value="professional">{t.professional}</option><option value="neon">{t.neon}</option></select></label>
    </div></section>
    <section className="data-panel"><h2>{t.localOnly}</h2><dl><dt>{t.byok}</dt><dd>{t.notConfigured}</dd><dt>{t.defender}</dt><dd>{t.disabledChoice}</dd><dt>Network providers</dt><dd>Opt-in actions only; no background refresh.</dd></dl></section>
    <section className="data-panel"><h2>{t.settings}</h2><div className="report-actions"><button className="secondary" onClick={() => onOpen("privacy")}>{t.privacy}</button><button className="secondary" onClick={() => onOpen("diagnostics")}>{t.diagnostics}</button><button className="secondary" onClick={() => onOpen("about")}>{t.about}</button><button className="secondary" onClick={onResetOnboarding}>{t.resetOnboarding}</button></div></section>
  </div>;
}

export function PrivacyPage({ locale }: { readonly locale: Locale }) {
  const t=words[locale];
  return <div className="workflow-stack" data-level7-screen="privacy"><section className="data-panel"><p className="eyebrow">{PRODUCT_NAME}</p><h2>{t.privacy}</h2><p>{t.noTelemetry}</p><p>{t.noUpload}</p><dl><dt>Local database</dt><dd>SQLite under the application data directory.</dd><dt>{t.byok}</dt><dd>{t.notConfigured}</dd><dt>URL checks</dt><dd>Only after preview and explicit confirmation; query values are stripped or never retained.</dd><dt>Reports</dt><dd>Generated locally and redacted before serialization.</dd></dl></section></div>;
}

export function DiagnosticsPage({ locale, status, engines, providers, scans }: {
  readonly locale: Locale; readonly status: FoundationStatus | null; readonly engines: readonly EngineStatus[];
  readonly providers: readonly DatasetStatus[]; readonly scans: readonly ScanSummary[];
}) {
  const t=words[locale];
  return <div className="workflow-stack" data-level7-screen="diagnostics"><section className="data-panel"><div className="panel-heading"><div><p className="eyebrow">Read-only</p><h2>{t.diagnostics}</h2></div><span className="severity severity-info">SANITIZED</span></div><dl><dt>{t.version}</dt><dd>{PRODUCT_VERSION}</dd><dt>{t.runtime}</dt><dd>{status?.core ?? "unavailable"}</dd><dt>{t.storage}</dt><dd>{status?.storage ?? "unavailable"}</dd><dt>{t.ipc}</dt><dd>{status?.ipc ?? "unavailable"}</dd><dt>{t.engines}</dt><dd>{engines.map(item => `${item.id}@${item.version}:${item.state}`).join(", ") || "unavailable"}</dd><dt>{t.providers}</dt><dd>{providers.map(item => `${item.provider}:${item.state}/${item.freshness}`).join(", ") || "not loaded"}</dd><dt>{t.recentScans}</dt><dd>{scans.length}</dd><dt>{t.upstream}</dt><dd>{TAURI_UPSTREAM_STATE}</dd></dl><p className="coverage-warning">{t.supportBundle}: {t.supportUnavailable}</p></section></div>;
}

export function AboutPage({ locale }: { readonly locale: Locale }) {
  const t=words[locale];
  return <div className="workflow-stack" data-level7-screen="about"><section className="data-panel"><p className="eyebrow">Release candidate</p><h2>{PRODUCT_NAME}</h2><dl><dt>{t.version}</dt><dd>{PRODUCT_VERSION}</dd><dt>{t.platform}</dt><dd>{SUPPORTED_OS}</dd><dt>Tauri</dt><dd>{TAURI_PIN} (pinned)</dd><dt>{t.upstream}</dt><dd>{TAURI_UPSTREAM_STATE}</dd><dt>{t.license}</dt><dd>{t.licensePending}</dd></dl><h3>{t.limitations}</h3><ul><li>Public release and distribution are blocked until the Tauri upstream gate passes.</li><li>Local engine execution remains policy-gated; unavailable checks reduce coverage and never imply a clean result.</li><li>Microsoft Defender remains optional and disabled by user decision.</li><li>SMBIOS identity remains USER_MODIFIED / UNTRUSTED and is not used as a security assertion.</li></ul></section><section className="data-panel" data-level7-screen="capability-matrix"><h2>Capability matrix</h2><div className="table-wrap"><table><thead><tr><th>Target</th><th>Capability</th><th>State</th><th>Boundary</th></tr></thead><tbody>{CAPABILITIES.map(item=><tr key={`${item.target}/${item.capability}`}><td>{item.target}</td><td>{item.capability}</td><td><span className="severity severity-info">{item.state}</span></td><td>{item.explanation}</td></tr>)}</tbody></table></div></section></div>;
}
