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
});
