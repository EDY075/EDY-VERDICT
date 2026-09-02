import { invoke } from "@tauri-apps/api/core";
import { parseFoundationStatus } from "./foundation";
import type { FoundationStatus } from "./foundation";

export type EngineState = "ready" | "unavailable" | "tampered" | "policy_blocked";
export type ScanState = "queued" | "preparing" | "running" | "cancellation_requested" | "cancelled" | "completed" | "partial" | "failed";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface EngineStatus {
  readonly id: "yara-x" | "gitleaks" | "trivy" | "osv-scanner";
  readonly version: string;
  readonly state: EngineState;
  readonly detail_safe: string;
}

export interface CoverageView {
  readonly total: number;
  readonly completed: number;
  readonly failed: number;
  readonly unavailable: number;
  readonly skipped: number;
}

export interface ScanSummary {
  readonly id: string;
  readonly state: ScanState;
  readonly verdict: string | null;
  readonly risk: Severity | null;
  readonly confidence: Confidence | null;
  readonly coverage: CoverageView;
}

export interface ScanProgress {
  readonly scan_id: string;
  readonly phase: string;
  readonly completed_tasks: number;
  readonly total_tasks: number;
  readonly percent: number | null;
  readonly elapsed_ms: number;
  readonly current_engine: string | null;
  readonly status: ScanState;
}

export interface FindingView {
  readonly id: string;
  readonly scan_id: string;
  readonly title: string;
  readonly category: string;
  readonly severity: Severity;
  readonly risk: Severity;
  readonly confidence: Confidence;
  readonly status: string;
  readonly sources: readonly string[];
}

export interface ReportView {
  readonly scan_id: string;
  readonly kind: "executive" | "technical" | "developer";
  readonly schema: "REPORT_SCHEMA_V2";
  readonly json: string;
}

export interface SafeIpcError {
  readonly code: string;
  readonly message_safe: string;
  readonly correlation_id: string;
}

const ENGINE_IDS = ["yara-x", "gitleaks", "trivy", "osv-scanner"] as const;
const ENGINE_STATES = ["ready", "unavailable", "tampered", "policy_blocked"] as const;
const SCAN_STATES = ["queued", "preparing", "running", "cancellation_requested", "cancelled", "completed", "partial", "failed"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const CONFIDENCES = ["low", "medium", "high"] as const;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Backend response rejected");
  return value as Record<string, unknown>;
}

function exact(item: Record<string, unknown>, keys: readonly string[]): void {
  const observed = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (observed.length !== expected.length || observed.some((key, index) => key !== expected[index])) {
    throw new Error("Backend response rejected");
  }
}

function text(value: unknown, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("Backend response rejected");
  return value;
}

function member<const T extends readonly string[]>(value: unknown, values: T): T[number] {
  if (typeof value !== "string" || !values.includes(value)) throw new Error("Backend response rejected");
  return value as T[number];
}

function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) throw new Error("Backend response rejected");
  return value;
}

function nullable<T>(value: unknown, parse: (input: unknown) => T): T | null {
  return value === null ? null : parse(value);
}

function uuid(value: unknown): string {
  const result = text(value, 36);
  if (!UUID_V7.test(result)) throw new Error("Backend response rejected");
  return result;
}

function coverage(value: unknown): CoverageView {
  const item = record(value);
  exact(item, ["total", "completed", "failed", "unavailable", "skipped"]);
  const result = {
    total: integer(item.total, 1024), completed: integer(item.completed, 1024),
    failed: integer(item.failed, 1024), unavailable: integer(item.unavailable, 1024),
    skipped: integer(item.skipped, 1024),
  };
  if (result.completed + result.failed + result.unavailable + result.skipped > result.total) throw new Error("Backend response rejected");
  return Object.freeze(result);
}

export function parseEngineStatus(value: unknown): EngineStatus {
  const item = record(value);
  exact(item, ["id", "version", "state", "detail_safe"]);
  return Object.freeze({
    id: member(item.id, ENGINE_IDS), version: text(item.version, 32),
    state: member(item.state, ENGINE_STATES), detail_safe: text(item.detail_safe, 256),
  });
}

export function parseScanSummary(value: unknown): ScanSummary {
  const item = record(value);
  exact(item, ["id", "state", "verdict", "risk", "confidence", "coverage"]);
  return Object.freeze({
    id: uuid(item.id), state: member(item.state, SCAN_STATES),
    verdict: nullable(item.verdict, (input) => text(input, 64)),
    risk: nullable(item.risk, (input) => member(input, SEVERITIES)),
    confidence: nullable(item.confidence, (input) => member(input, CONFIDENCES)),
    coverage: coverage(item.coverage),
  });
}

export function parseScanProgress(value: unknown): ScanProgress {
  const item = record(value);
  exact(item, ["scan_id", "phase", "completed_tasks", "total_tasks", "percent", "elapsed_ms", "current_engine", "status"]);
  const percent = nullable(item.percent, (input) => integer(input, 100));
  const result = {
    scan_id: uuid(item.scan_id), phase: text(item.phase, 64),
    completed_tasks: integer(item.completed_tasks, 1024), total_tasks: integer(item.total_tasks, 1024),
    percent, elapsed_ms: integer(item.elapsed_ms),
    current_engine: nullable(item.current_engine, (input) => text(input, 64)),
    status: member(item.status, SCAN_STATES),
  };
  if (result.completed_tasks > result.total_tasks) throw new Error("Backend response rejected");
  return Object.freeze(result);
}

export function parseFinding(value: unknown): FindingView {
  const item = record(value);
  exact(item, ["id", "scan_id", "title", "category", "severity", "risk", "confidence", "status", "sources"]);
  if (!Array.isArray(item.sources) || item.sources.length > 16) throw new Error("Backend response rejected");
  return Object.freeze({
    id: uuid(item.id), scan_id: uuid(item.scan_id), title: text(item.title, 256),
    category: text(item.category, 64), severity: member(item.severity, SEVERITIES),
    risk: member(item.risk, SEVERITIES), confidence: member(item.confidence, CONFIDENCES),
    status: text(item.status, 64), sources: Object.freeze(item.sources.map((source) => text(source, 64))),
  });
}

export function parseReport(value: unknown): ReportView {
  const item = record(value);
  exact(item, ["scan_id", "kind", "schema", "json"]);
  const json = text(item.json, 2 * 1024 * 1024);
  JSON.parse(json);
  if (item.schema !== "REPORT_SCHEMA_V2") throw new Error("Backend response rejected");
  return Object.freeze({
    scan_id: uuid(item.scan_id), kind: member(item.kind, ["executive", "technical", "developer"] as const),
    schema: "REPORT_SCHEMA_V2", json,
  });
}

async function call<T>(command: string, args: Record<string, unknown>, parse: (value: unknown) => T, timeoutMs: number | null = 8000): Promise<T> {
  if (timeoutMs === null) return parse(await invoke(command, args));
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const value = await Promise.race([
      invoke(command, args),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Backend unavailable")), timeoutMs); }),
    ]);
    return parse(value);
  } finally {
    clearTimeout(timer);
  }
}

export const level0Api = Object.freeze({
  foundation: (): Promise<FoundationStatus> => call("get_foundation_status", {}, parseFoundationStatus),
  engines: (): Promise<readonly EngineStatus[]> => call("get_engine_status", {}, (value) => {
    if (!Array.isArray(value) || value.length !== 4) throw new Error("Backend response rejected");
    const engines = value.map(parseEngineStatus);
    if (new Set(engines.map((engine) => engine.id)).size !== ENGINE_IDS.length
      || ENGINE_IDS.some((id) => !engines.some((engine) => engine.id === id))) throw new Error("Backend response rejected");
    return Object.freeze(engines);
  }),
  createSyntheticScan: (): Promise<ScanSummary> => call("create_synthetic_scan", { request: { fixture_id: "synthetic-target-a" } }, parseScanSummary, null),
  getScan: (scanId: string): Promise<ScanSummary> => {
    const expected = uuid(scanId);
    return call("get_scan", { request: { scan_id: expected } }, (value) => {
      const scan = parseScanSummary(value);
      if (scan.id !== expected) throw new Error("Backend response rejected");
      return scan;
    });
  },
  listScans: (): Promise<readonly ScanSummary[]> => call("list_scans", { request: { offset: 0, limit: 50 } }, (value) => {
    if (!Array.isArray(value) || value.length > 50) throw new Error("Backend response rejected");
    const scans = value.map(parseScanSummary);
    if (new Set(scans.map((scan) => scan.id)).size !== scans.length) throw new Error("Backend response rejected");
    return Object.freeze(scans);
  }),
  progress: (scanId: string): Promise<ScanProgress> => {
    const expected = uuid(scanId);
    return call("get_scan_progress", { request: { scan_id: expected } }, (value) => {
      const progress = parseScanProgress(value);
      if (progress.scan_id !== expected) throw new Error("Backend response rejected");
      return progress;
    });
  },
  cancel: (scanId: string): Promise<ScanProgress> => {
    const expected = uuid(scanId);
    return call("cancel_scan", { request: { scan_id: expected } }, (value) => {
      const progress = parseScanProgress(value);
      if (progress.scan_id !== expected) throw new Error("Backend response rejected");
      return progress;
    }, null);
  },
  findings: (scanId: string): Promise<readonly FindingView[]> => {
    const expected = uuid(scanId);
    return call("list_findings", { request: { scan_id: expected, offset: 0, limit: 100 } }, (value) => {
    if (!Array.isArray(value) || value.length > 100) throw new Error("Backend response rejected");
    const findings = value.map(parseFinding);
    if (findings.some((finding) => finding.scan_id !== expected)
      || new Set(findings.map((finding) => finding.id)).size !== findings.length) throw new Error("Backend response rejected");
    return Object.freeze(findings);
    });
  },
  getFinding: (findingId: string): Promise<FindingView> => {
    const expected = uuid(findingId);
    return call("get_finding", { request: { finding_id: expected } }, (value) => {
      const finding = parseFinding(value);
      if (finding.id !== expected) throw new Error("Backend response rejected");
      return finding;
    });
  },
  report: (scanId: string, kind: ReportView["kind"]): Promise<ReportView> => {
    const expected = uuid(scanId);
    return call("generate_report", { request: { scan_id: expected, kind } }, (value) => {
      const report = parseReport(value);
      if (report.scan_id !== expected || report.kind !== kind) throw new Error("Backend response rejected");
      return report;
    });
  },
});
