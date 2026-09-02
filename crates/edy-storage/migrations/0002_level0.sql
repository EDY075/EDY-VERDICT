CREATE TABLE scans (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  state TEXT NOT NULL CHECK (state IN ('queued','preparing','running','cancellation_requested','cancelled','completed','partial','failed')),
  partial INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0,1)),
  created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) BETWEEN 1 AND 64),
  started_at_utc TEXT CHECK (started_at_utc IS NULL OR length(started_at_utc) BETWEEN 1 AND 64),
  completed_at_utc TEXT CHECK (completed_at_utc IS NULL OR length(completed_at_utc) BETWEEN 1 AND 64),
  CHECK (state NOT IN ('cancelled','completed','partial','failed') OR completed_at_utc IS NOT NULL),
  CHECK ((state = 'partial' AND partial = 1) OR (state != 'partial' AND partial = 0))
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  reference TEXT NOT NULL CHECK (length(reference) BETWEEN 1 AND 4096),
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64 AND fingerprint = lower(fingerprint) AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
  UNIQUE (scan_id, id),
  UNIQUE (scan_id, fingerprint)
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 37 AND substr(fingerprint,1,5) = 'ffp1-' AND substr(fingerprint,6) = lower(substr(fingerprint,6)) AND substr(fingerprint,6) NOT GLOB '*[^0-9a-f]*'),
  category TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 128),
  location_reference TEXT NOT NULL CHECK (length(location_reference) BETWEEN 1 AND 4096),
  severity TEXT NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
  confidence TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
  lifecycle TEXT NOT NULL CHECK (lifecycle IN ('open','investigating','remediating','verification_pending','resolved','ignored','accepted_risk')),
  first_observed_at_utc TEXT NOT NULL CHECK (length(first_observed_at_utc) BETWEEN 1 AND 64),
  last_observed_at_utc TEXT NOT NULL CHECK (length(last_observed_at_utc) BETWEEN 1 AND 64),
  FOREIGN KEY (scan_id, target_id) REFERENCES targets(scan_id, id) ON DELETE CASCADE,
  UNIQUE (scan_id, id),
  UNIQUE (scan_id, fingerprint)
);

CREATE TABLE evidence (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 128),
  observed_at_utc TEXT NOT NULL CHECK (length(observed_at_utc) BETWEEN 1 AND 64),
  redacted_summary TEXT NOT NULL CHECK (length(redacted_summary) BETWEEN 1 AND 4096),
  integrity_sha256 TEXT NOT NULL CHECK (length(integrity_sha256) = 64 AND integrity_sha256 = lower(integrity_sha256) AND integrity_sha256 NOT GLOB '*[^0-9a-f]*'),
  redacted INTEGER NOT NULL CHECK (redacted IN (0,1)),
  FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
  UNIQUE (scan_id, id)
);

CREATE TABLE scan_events (
  id INTEGER PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  at_utc TEXT NOT NULL CHECK (length(at_utc) BETWEEN 1 AND 64),
  kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  redacted_detail TEXT CHECK (redacted_detail IS NULL OR length(redacted_detail) <= 4096)
);

CREATE TABLE engine_runs (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  engine_id TEXT NOT NULL CHECK (length(engine_id) BETWEEN 1 AND 64),
  engine_version TEXT NOT NULL CHECK (length(engine_version) BETWEEN 1 AND 64),
  state TEXT NOT NULL CHECK (state IN ('running','passed','failed','skipped','cancelled')),
  partial INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0,1)),
  started_at_utc TEXT CHECK (started_at_utc IS NULL OR length(started_at_utc) BETWEEN 1 AND 64),
  completed_at_utc TEXT CHECK (completed_at_utc IS NULL OR length(completed_at_utc) BETWEEN 1 AND 64),
  exit_code INTEGER CHECK (exit_code IS NULL OR exit_code BETWEEN 0 AND 4294967295),
  error_summary TEXT CHECK (error_summary IS NULL OR length(error_summary) <= 2048),
  FOREIGN KEY (scan_id, target_id) REFERENCES targets(scan_id, id) ON DELETE CASCADE,
  UNIQUE (scan_id, id),
  CHECK (state = 'running' OR completed_at_utc IS NOT NULL)
);

CREATE TABLE remediation_actions (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested','completed','verification_pending','rescan_running','resolved','still_present','regression','failed')),
  proposal_summary TEXT NOT NULL CHECK (length(proposal_summary) BETWEEN 1 AND 4096),
  requires_authorization INTEGER NOT NULL CHECK (requires_authorization IN (0,1)),
  created_at_utc TEXT NOT NULL CHECK (length(created_at_utc) BETWEEN 1 AND 64),
  updated_at_utc TEXT NOT NULL CHECK (length(updated_at_utc) BETWEEN 1 AND 64),
  FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
  UNIQUE (scan_id, id)
);

CREATE TABLE verification_runs (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  scan_id TEXT NOT NULL,
  remediation_action_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('running','resolved','still_present','regression','inconclusive')),
  started_at_utc TEXT CHECK (started_at_utc IS NULL OR length(started_at_utc) BETWEEN 1 AND 64),
  completed_at_utc TEXT CHECK (completed_at_utc IS NULL OR length(completed_at_utc) BETWEEN 1 AND 64),
  redacted_result TEXT CHECK (redacted_result IS NULL OR length(redacted_result) <= 4096),
  FOREIGN KEY (scan_id, remediation_action_id) REFERENCES remediation_actions(scan_id, id) ON DELETE CASCADE,
  CHECK (state = 'running' OR completed_at_utc IS NOT NULL)
);

CREATE INDEX idx_targets_scan ON targets(scan_id);
CREATE INDEX idx_findings_target ON findings(scan_id, target_id);
CREATE INDEX idx_findings_lifecycle ON findings(scan_id, lifecycle);
CREATE INDEX idx_evidence_finding ON evidence(scan_id, finding_id);
CREATE INDEX idx_scan_events_scan_time ON scan_events(scan_id, at_utc);
CREATE INDEX idx_engine_runs_target ON engine_runs(scan_id, target_id);
CREATE INDEX idx_remediation_finding ON remediation_actions(scan_id, finding_id);
CREATE INDEX idx_verification_action ON verification_runs(scan_id, remediation_action_id);
