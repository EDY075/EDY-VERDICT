export type CapabilityState = "AVAILABLE" | "OPTIONAL" | "POLICY_BLOCKED" | "NOT_CONFIGURED" | "COVERAGE_LIMITED" | "UNAVAILABLE";

export interface Capability {
  readonly target: string;
  readonly capability: string;
  readonly state: CapabilityState;
  readonly explanation: string;
}

export const CAPABILITIES: readonly Capability[] = Object.freeze([
  {target:"Repository",capability:"Local inventory, authorization, correlation and reporting",state:"AVAILABLE",explanation:"Explicit local path only; unavailable external checks reduce coverage."},
  {target:"Repository",capability:"Gitleaks, Trivy and OSV-Scanner real execution",state:"POLICY_BLOCKED",explanation:"Adapters and pinned artifacts are ready, but execution remains denied by the frozen policy."},
  {target:"File / Binary",capability:"Identity, streaming hashes, PE metadata and offline Authenticode",state:"AVAILABLE",explanation:"One explicit regular file on a fixed local volume."},
  {target:"File / Binary",capability:"YARA-X real execution",state:"POLICY_BLOCKED",explanation:"Adapter and YARA-X 1.20.0 are ready; execution remains policy blocked."},
  {target:"File / Binary",capability:"Cloud reputation",state:"NOT_CONFIGURED",explanation:"No upload; BYOK is optional and absent by default."},
  {target:"Installed Applications",capability:"Read-only Windows inventory and exact vulnerability matching",state:"COVERAGE_LIMITED",explanation:"Current-user and standard registry/MSIX views only; portable apps and other users are outside coverage."},
  {target:"Web / URL",capability:"Bounded passive DNS, TLS, redirect, header and cookie-attribute checks",state:"AVAILABLE",explanation:"Requires sanitized preview and explicit confirmation; no body, script, crawler or exploit probe."},
  {target:"Web / URL",capability:"URLhaus / VirusTotal reputation",state:"OPTIONAL",explanation:"Exact-match provider coverage is optional and does not establish safety."},
  {target:"Investigations",capability:"Deterministic cross-target graph, cases and timeline",state:"AVAILABLE",explanation:"Observed evidence only; correlation never proves causation or compromise."},
  {target:"Remediation",capability:"Guidance, manual verification, rescan and persistence",state:"AVAILABLE",explanation:"User performs any target change outside EDY VERDICT."},
  {target:"Remediation",capability:"Automatic target mutation and rollback",state:"POLICY_BLOCKED",explanation:"Production write capability was removed; no hidden executor exists."},
]);
