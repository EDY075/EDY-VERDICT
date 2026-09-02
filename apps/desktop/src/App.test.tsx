import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FoundationView } from "./App";
import { parseFoundationStatus } from "./foundation";

describe("minimal technical screen", () => {
  it("renders only infrastructure labels after a validated backend response", () => {
    const status = parseFoundationStatus({ core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 });
    const html = renderToStaticMarkup(<FoundationView status={status} failed={false} />);
    for (const label of ["EDY VERDICT", "Foundation Build", "Core Ready", "Storage Ready", "IPC Restricted"]) {
      expect(html).toContain(label);
    }
    expect(html).not.toContain("<button");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("<a ");
  });

  it("never claims readiness while pending or failed", () => {
    for (const failed of [false, true]) {
      const html = renderToStaticMarkup(<FoundationView status={null} failed={failed} />);
      expect(html).not.toContain("Core Ready");
      expect(html).not.toContain("Storage Ready");
      expect(html).not.toContain("IPC Restricted");
    }
    expect(renderToStaticMarkup(<FoundationView status={null} failed />)).toContain('role="alert"');
  });
});
