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
});
