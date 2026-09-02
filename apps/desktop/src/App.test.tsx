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
});
