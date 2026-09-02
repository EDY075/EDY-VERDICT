// Explicit dev-only visual fixtures. Never imported by the production entrypoint;
// no backend calls, target I/O, engine execution, or network providers.
import { useState } from "react";
import type { ComponentProps } from "react";
import { createRoot } from "react-dom/client";
import { FoundationView } from "./App";
import type { FileAnalysisView, FindingView, ScanProgress, ScanSummary } from "./level0-api";
import "./styles.css";

const id = "018f4c2a-1d3b-7abc-8def-0123456789ab";
const identity = { volume_id: "123", file_id: "456", size: 512, last_write_time: "134000000000000000", attributes: 32 };
const scan: ScanSummary = { id, state: "partial", verdict: "insufficient_coverage", risk: "info", confidence: "medium", coverage: { total: 6, completed: 4, failed: 0, unavailable: 2, skipped: 0 } };
const progress: ScanProgress = { scan_id: id, phase: "reporting", completed_tasks: 8, total_tasks: 8, percent: 100, elapsed_ms: 29, current_engine: null, status: "partial" };
const finding: FindingView = { id: "018f4c2a-1d3b-7abc-8def-0123456789ac", scan_id: id, title: "Synthetic malformed PE requires review", category: "executable_metadata", severity: "medium", risk: "medium", confidence: "high", status: "open", sources: ["first-party-pe-parser"], affected_component: "synthetic-fixture.bin", rule_ids: ["pe_parser_rejected"], evidence_ids: [], remediation_guidance: "Review synthetic metadata only", limitations: ["Visual fixture — not real scan evidence"] };
const file: FileAnalysisView = { scan_id: id, state: "partial", progress, terminal_error: null, analysis: {
  target: { canonical_path: "D:/synthetic-visual-fixture.bin", identity },
  hashes: { sha256: "a".repeat(64), sha512: "b".repeat(128), bytes_hashed: 512 },
  classification: "pe_executable", pe: { machine: 34404, architecture: "x86_64", subsystem: 3, timestamp: 0, image_base: 5368709120, entry_point_rva: 4096, is_dll: false, signature_present: false, sections: [{ name: ".text", virtual_size: 4096, raw_size: 512, characteristics: 0x60000020 }] }, pe_error: null,
  authenticode: { signature_present: false, cryptographic_status: "unsigned", trust_chain_status: "unsigned", offline_cache_only: true },
  yara_observations: [], reputation: { privacy_mode: "local_only", availability: "not_configured", provider: null, known: null, malicious_count: null, suspicious_count: null, status: "not_checked" }, findings: [],
  coverage: { hashing: "completed", classification: "completed", pe_inspection: "completed", authenticode: "completed", yara: "policy_blocked", reputation: "not_checked", target_stable: true, unavailable_checks: ["yara", "reputation"] },
  verdict: { disposition: "insufficient_coverage", risk_score: 0, risk: "info", confidence_score: 66, confidence: "medium", reasons: ["Synthetic visual fixture — missing checks are not a clean guarantee"] },
} };
const scenarios = ["authorization", "progress", "analysis", "signature-valid", "signature-invalid", "trust-unavailable", "indeterminate", "findings", "reports", "error", "cancelled", "target-changed"] as const;
type Scenario = typeof scenarios[number];

export function visualFixture(scenario: Scenario): ComponentProps<typeof FoundationView> {
  const base: ComponentProps<typeof FoundationView> = { status: { core: "ready", storage: "ready", ipc: "restricted", schema_version: 1 }, failed: false, selected: scan, scans: [scan] };
  if (scenario === "authorization") return { ...base, initialPage: "new-scan", filePreview: { preview_id: id, requested_path: "D:/synthetic-visual-fixture.bin", canonical_path: "D:/synthetic-visual-fixture.bin", file_name: "synthetic-visual-fixture.bin", identity, detected_type: "pe_executable", proposed_checks: ["streaming_sha256", "streaming_sha512", "bounded_pe_inspection", "offline_authenticode"], policy_limitations: ["YARA unavailable by execution policy", "Reputation not checked"], max_file_size: 268435456 } };
  if (scenario === "progress") return { ...base, initialPage: "progress", progress: { ...progress, status: "running", phase: "streaming_hashes", percent: 25, completed_tasks: 2 } };
  if (scenario === "findings") return { ...base, initialPage: "findings", findings: [finding] };
  if (scenario === "reports") return { ...base, initialPage: "reports", report: { scan_id: id, kind: "technical", schema: "REPORT_SCHEMA_V2", json: JSON.stringify({ fixture: "SYNTHETIC_ONLY", sha256: "a".repeat(64), signature: "unsigned", yara: "policy_blocked", reputation: "not_checked", findings: [] }, null, 2) } };
  if (scenario === "error" || scenario === "cancelled" || scenario === "target-changed") {
    const state = scenario === "cancelled" ? "cancelled" : "failed";
    const phase = scenario === "target-changed" ? "target_changed" : scenario;
    return { ...base, fileAnalysis: { scan_id: id, state, analysis: null, terminal_error: phase.toUpperCase(), progress: { ...progress, state, status: state, phase, percent: null } as ScanProgress } };
  }
  if (scenario !== "analysis" && file.analysis) {
    const crypto = scenario === "signature-valid" ? "signed_valid_offline" : scenario === "signature-invalid" ? "signed_invalid" : "indeterminate";
    const trust = scenario === "signature-valid" ? "trust_chain_valid_offline" : scenario === "trust-unavailable" ? "trust_chain_unavailable_offline" : "indeterminate";
    return { ...base, fileAnalysis: { ...file, analysis: { ...file.analysis, authenticode: { signature_present: true, cryptographic_status: crypto, trust_chain_status: trust, offline_cache_only: true } } } };
  }
  return { ...base, fileAnalysis: file };
}

function VisualQa() {
  const [scenario, setScenario] = useState<Scenario>("authorization");
  return <><div role="note" style={{ padding: 12, background: "#523000", color: "#fff" }}>SYNTHETIC VISUAL QA ONLY — backend disconnected. <label>Scenario <select aria-label="Scenario" value={scenario} onChange={event => setScenario(event.target.value as Scenario)}>{scenarios.map(name => <option key={name}>{name}</option>)}</select></label></div><FoundationView key={scenario} {...visualFixture(scenario)} /></>;
}

// Separate development entrypoint, absent from index.html and production bundle.
if (location.hostname === "127.0.0.1" || location.hostname === "localhost") {
  const root = document.getElementById("root");
  if (root) createRoot(root).render(<VisualQa />);
}
