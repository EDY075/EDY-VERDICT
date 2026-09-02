import { describe, expect, it } from "vitest";
import { parseEngineStatus, parseFinding, parseReport, parseScanProgress, parseScanSummary } from "./level0-api";

const scanId = "018f4c2a-1d3b-7abc-8def-0123456789ab";

describe("Level 0 IPC response validation", () => {
  it("accepts exact bounded contracts", () => {
    expect(parseEngineStatus({ id: "yara-x", version: "1.20.0", state: "ready", detail_safe: "Integrity verified" }).state).toBe("ready");
    expect(parseScanSummary({ id: scanId, state: "partial", verdict: "needs_review", risk: "high", confidence: "low", coverage: { total: 4, completed: 2, failed: 1, unavailable: 1, skipped: 0 } }).confidence).toBe("low");
    expect(parseScanProgress({ scan_id: scanId, phase: "engine", completed_tasks: 1, total_tasks: 4, percent: 25, elapsed_ms: 10, current_engine: "yara-x", status: "running" }).percent).toBe(25);
    expect(parseFinding({ id: "018f4c2a-1d3b-7abc-8def-0123456789ac", scan_id: scanId, title: "Synthetic", category: "fixture", severity: "high", risk: "high", confidence: "medium", status: "open", sources: ["yara-x"] }).sources).toEqual(["yara-x"]);
    expect(parseReport({ scan_id: scanId, kind: "technical", schema: "REPORT_SCHEMA_V2", json: "{}" }).kind).toBe("technical");
  });

  it("rejects invalid ids, oversized progress and malformed report JSON", () => {
    expect(() => parseScanSummary({ id: "../../etc", state: "completed", verdict: null, risk: null, confidence: null, coverage: { total: 0, completed: 0, failed: 0, unavailable: 0, skipped: 0 } })).toThrow();
    expect(() => parseScanProgress({ scan_id: scanId, phase: "x", completed_tasks: 2, total_tasks: 1, percent: 101, elapsed_ms: 0, current_engine: null, status: "running" })).toThrow();
    expect(() => parseReport({ scan_id: scanId, kind: "technical", schema: "REPORT_SCHEMA_V2", json: "<script>" })).toThrow();
    expect(() => parseEngineStatus({ id: "yara-x", version: "1.20.0", state: "ready", detail_safe: "ok", secret: "unexpected" })).toThrow();
    expect(() => parseScanSummary({ id: scanId, state: "completed", verdict: null, risk: null, confidence: null, coverage: { total: 0, completed: 0, failed: 0, unavailable: 0, skipped: 0, clean: true } })).toThrow();
  });

  it("keeps risk confidence and coverage as distinct dimensions", () => {
    const scan = parseScanSummary({ id: scanId, state: "partial", verdict: "needs_review", risk: "critical", confidence: "low", coverage: { total: 4, completed: 1, failed: 1, unavailable: 2, skipped: 0 } });
    expect(scan.risk).toBe("critical");
    expect(scan.confidence).toBe("low");
    expect(scan.coverage.completed).toBe(1);
  });
});
