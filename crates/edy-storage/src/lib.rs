//! Project-local SQLite persistence and native secret storage.
//! Secrets remain exclusively in the native credential adapter, never in SQL.
pub mod secrets;

pub use edy_core::{
    EngineRunState, FindingStatus, RemediationWorkflowState, ScanState, VerificationOutcome,
};
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path, time::Duration};

const MIGRATION_1: &str = include_str!("../migrations/0001_infrastructure.sql");
const MIGRATION_2: &str = include_str!("../migrations/0002_level0.sql");
const VERSION: u32 = 2;
const MIGRATIONS: &[(u32, &str)] = &[(1, MIGRATION_1), (2, MIGRATION_2)];

#[derive(Debug)]
pub enum StorageError {
    Sql(rusqlite::Error),
    UnsafeState(&'static str),
    InvalidInput(&'static str),
    NotFound(&'static str),
    Io(std::io::Error),
}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sql(_) => write!(f, "SQLite storage operation failed"),
            Self::UnsafeState(s) | Self::InvalidInput(s) | Self::NotFound(s) => f.write_str(s),
            Self::Io(_) => f.write_str("Storage filesystem operation failed"),
        }
    }
}
impl std::error::Error for StorageError {}

pub struct NewTarget<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub kind: &'a str,
    pub reference: &'a str,
    pub fingerprint: &'a str,
}
pub struct NewFinding<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub target_id: &'a str,
    pub fingerprint: &'a str,
    pub category: &'a str,
    pub location_reference: &'a str,
    pub severity: &'a str,
    pub confidence: &'a str,
    pub observed_at_utc: &'a str,
}
pub struct NewEvidence<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub finding_id: &'a str,
    pub source: &'a str,
    pub observed_at_utc: &'a str,
    /// Safe summary only; raw secrets and raw scanner output are forbidden.
    pub redacted_summary: &'a str,
    pub integrity_sha256: &'a str,
    pub redacted: bool,
}
pub struct NewEngineRun<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub target_id: &'a str,
    pub engine_id: &'a str,
    pub engine_version: &'a str,
    pub started_at_utc: &'a str,
}
pub struct NewRemediationAction<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub finding_id: &'a str,
    /// Redacted, reviewable description; never a credential or transcript.
    pub proposal_summary: &'a str,
    pub requires_authorization: bool,
    pub at_utc: &'a str,
}
pub struct NewVerificationRun<'a> {
    pub id: &'a str,
    pub scan_id: &'a str,
    pub remediation_action_id: &'a str,
    pub started_at_utc: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScanRecord {
    pub id: String,
    pub state: String,
    pub partial: bool,
    pub created_at_utc: String,
    pub started_at_utc: Option<String>,
    pub completed_at_utc: Option<String>,
}

pub struct Storage {
    connection: Connection,
}
impl Storage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if !path.is_absolute() {
            return Err(StorageError::UnsafeState("Absolute database path required"));
        }
        let existed = path.exists();
        let mut initial_version = 0;
        if existed {
            let check = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            check.busy_timeout(Duration::from_secs(5))?;
            if check.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
                return Err(StorageError::UnsafeState(
                    "Corrupt database preserved; explicit restore required",
                ));
            }
            initial_version = check.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if initial_version > VERSION {
                return Err(StorageError::UnsafeState("Newer schema refused"));
            }
            if initial_version == 0 {
                let tables: u32 = check.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'", [], |r| r.get(0))?;
                if tables != 0 {
                    return Err(StorageError::UnsafeState("Unrecognized schema refused"));
                }
            } else {
                verify_schema(&check, initial_version)?;
            }
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        if existed && initial_version < VERSION {
            reserve_backup(
                &connection,
                &path.with_extension(format!("pre-v{}.sqlite3", initial_version + 1)),
            )?;
        }
        let current: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (version, sql) in MIGRATIONS.iter().copied().filter(|(v, _)| *v > current) {
            apply_migration(&mut connection, version, sql)?;
        }
        verify_schema(&connection, VERSION)?;
        Ok(Self { connection })
    }
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        Ok(self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }
    pub fn backup(&self, path: &Path) -> Result<(), StorageError> {
        if !path.is_absolute() {
            return Err(StorageError::UnsafeState("Absolute backup path required"));
        }
        reserve_backup(&self.connection, path)
    }
    pub fn create_scan(&self, id: &str, created_at_utc: &str) -> Result<(), StorageError> {
        validate_text(id, 128, "Invalid scan id")?;
        validate_text(created_at_utc, 64, "Invalid scan timestamp")?;
        self.connection.execute(
            "INSERT INTO scans(id,state,created_at_utc) VALUES (?1,'queued',?2)",
            (id, created_at_utc),
        )?;
        Ok(())
    }
    pub fn get_scan(&self, id: &str) -> Result<ScanRecord, StorageError> {
        self.connection.query_row("SELECT id,state,partial,created_at_utc,started_at_utc,completed_at_utc FROM scans WHERE id=?1", [id], |row| Ok(ScanRecord { id: row.get(0)?, state: row.get(1)?, partial: row.get::<_, i64>(2)? != 0, created_at_utc: row.get(3)?, started_at_utc: row.get(4)?, completed_at_utc: row.get(5)? })).map_err(|error| match error { rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("Scan not found"), other => StorageError::Sql(other) })
    }
    /// Persists lifecycle state and its audit event atomically.
    pub fn transition_scan(
        &mut self,
        id: &str,
        state: ScanState,
        at_utc: &str,
    ) -> Result<(), StorageError> {
        validate_text(at_utc, 64, "Invalid scan timestamp")?;
        let transaction = self.connection.transaction()?;
        let current = transaction
            .query_row("SELECT state FROM scans WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("Scan not found"),
                other => StorageError::Sql(other),
            })?;
        parse_scan_state(&current)?
            .transition(state)
            .map_err(|_| StorageError::InvalidInput("Invalid scan state transition"))?;
        let state_name = scan_state_name(state);
        let completed = scan_state_terminal(state).then_some(at_utc);
        let changed = transaction.execute("UPDATE scans SET state=?2,partial=?3,started_at_utc=CASE WHEN ?2='running' THEN coalesce(started_at_utc,?4) ELSE started_at_utc END,completed_at_utc=?5 WHERE id=?1", params![id, state_name, state == ScanState::Partial, at_utc, completed])?;
        require_changed(changed, "Scan not found")?;
        transaction.execute(
            "INSERT INTO scan_events(scan_id,at_utc,kind,redacted_detail) VALUES (?1,?2,?3,NULL)",
            (id, at_utc, state_name),
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub fn delete_scan(&self, id: &str) -> Result<(), StorageError> {
        require_changed(
            self.connection
                .execute("DELETE FROM scans WHERE id=?1", [id])?,
            "Scan not found",
        )
    }
    pub fn add_target(&self, target: &NewTarget<'_>) -> Result<(), StorageError> {
        validate_text(target.id, 128, "Invalid target id")?;
        validate_text(target.kind, 64, "Invalid target kind")?;
        validate_text(target.reference, 4096, "Invalid target reference")?;
        validate_hash(target.fingerprint, "Invalid target fingerprint")?;
        self.connection.execute(
            "INSERT INTO targets(id,scan_id,kind,reference,fingerprint) VALUES (?1,?2,?3,?4,?5)",
            params![
                target.id,
                target.scan_id,
                target.kind,
                target.reference,
                target.fingerprint
            ],
        )?;
        Ok(())
    }
    /// Deduplicates within a scan by the caller's normalized SHA-256 fingerprint.
    pub fn upsert_finding(&mut self, finding: &NewFinding<'_>) -> Result<String, StorageError> {
        validate_finding_fingerprint(finding.fingerprint)?;
        for (value, max, message) in [
            (finding.id, 128, "Invalid finding id"),
            (finding.category, 128, "Invalid finding category"),
            (finding.location_reference, 4096, "Invalid finding location"),
            (finding.observed_at_utc, 64, "Invalid finding timestamp"),
        ] {
            validate_text(value, max, message)?;
        }
        if !matches!(
            finding.severity,
            "informational" | "low" | "medium" | "high" | "critical"
        ) || !matches!(finding.confidence, "low" | "medium" | "high")
        {
            return Err(StorageError::InvalidInput("Invalid finding classification"));
        }
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO findings(id,scan_id,target_id,fingerprint,category,location_reference,severity,confidence,lifecycle,first_observed_at_utc,last_observed_at_utc) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'open',?9,?9) ON CONFLICT(scan_id,fingerprint) DO UPDATE SET last_observed_at_utc=excluded.last_observed_at_utc", params![finding.id,finding.scan_id,finding.target_id,finding.fingerprint,finding.category,finding.location_reference,finding.severity,finding.confidence,finding.observed_at_utc])?;
        let id = transaction.query_row(
            "SELECT id FROM findings WHERE scan_id=?1 AND fingerprint=?2",
            (finding.scan_id, finding.fingerprint),
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(id)
    }
    pub fn set_finding_lifecycle(
        &self,
        id: &str,
        lifecycle: FindingStatus,
    ) -> Result<(), StorageError> {
        let current = self
            .connection
            .query_row("SELECT lifecycle FROM findings WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound("Finding not found"),
                other => StorageError::Sql(other),
            })?;
        parse_finding_status(&current)?
            .transition(lifecycle)
            .map_err(|_| StorageError::InvalidInput("Invalid finding lifecycle transition"))?;
        require_changed(
            self.connection.execute(
                "UPDATE findings SET lifecycle=?2 WHERE id=?1",
                (id, finding_status_name(lifecycle)),
            )?,
            "Finding not found",
        )
    }
    pub fn add_evidence(&self, evidence: &NewEvidence<'_>) -> Result<(), StorageError> {
        for (value, max, message) in [
            (evidence.id, 128, "Invalid evidence id"),
            (evidence.source, 128, "Invalid evidence source"),
            (evidence.observed_at_utc, 64, "Invalid evidence timestamp"),
            (evidence.redacted_summary, 4096, "Invalid evidence summary"),
        ] {
            validate_text(value, max, message)?;
        }
        validate_hash(evidence.integrity_sha256, "Invalid evidence hash")?;
        self.connection.execute("INSERT INTO evidence(id,scan_id,finding_id,source,observed_at_utc,redacted_summary,integrity_sha256,redacted) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![evidence.id,evidence.scan_id,evidence.finding_id,evidence.source,evidence.observed_at_utc,evidence.redacted_summary,evidence.integrity_sha256,evidence.redacted])?;
        Ok(())
    }
    pub fn record_event(
        &self,
        scan_id: &str,
        at_utc: &str,
        kind: &str,
        redacted_detail: Option<&str>,
    ) -> Result<(), StorageError> {
        validate_text(at_utc, 64, "Invalid event timestamp")?;
        validate_text(kind, 64, "Invalid event kind")?;
        validate_optional_text(redacted_detail, 4096, "Invalid event detail")?;
        self.connection.execute(
            "INSERT INTO scan_events(scan_id,at_utc,kind,redacted_detail) VALUES (?1,?2,?3,?4)",
            params![scan_id, at_utc, kind, redacted_detail],
        )?;
        Ok(())
    }
    pub fn begin_engine_run(&self, run: &NewEngineRun<'_>) -> Result<(), StorageError> {
        for (value, max, message) in [
            (run.id, 128, "Invalid engine run id"),
            (run.engine_id, 64, "Invalid engine id"),
            (run.engine_version, 64, "Invalid engine version"),
            (run.started_at_utc, 64, "Invalid engine timestamp"),
        ] {
            validate_text(value, max, message)?;
        }
        self.connection.execute("INSERT INTO engine_runs(id,scan_id,target_id,engine_id,engine_version,state,started_at_utc) VALUES (?1,?2,?3,?4,?5,'running',?6)",params![run.id,run.scan_id,run.target_id,run.engine_id,run.engine_version,run.started_at_utc])?;
        Ok(())
    }
    pub fn finish_engine_run(
        &self,
        id: &str,
        state: EngineRunState,
        partial: bool,
        completed_at_utc: &str,
        exit_code: Option<u32>,
        error_summary: Option<&str>,
    ) -> Result<(), StorageError> {
        validate_text(completed_at_utc, 64, "Invalid engine timestamp")?;
        validate_optional_text(error_summary, 2048, "Invalid engine error summary")?;
        require_changed(self.connection.execute("UPDATE engine_runs SET state=?2,partial=?3,completed_at_utc=?4,exit_code=?5,error_summary=?6 WHERE id=?1",params![id,engine_run_state_name(state),partial,completed_at_utc,exit_code,error_summary])?,"Engine run not found")
    }
    pub fn add_remediation_action(
        &self,
        action: &NewRemediationAction<'_>,
    ) -> Result<(), StorageError> {
        for (value, max, message) in [
            (action.id, 128, "Invalid remediation id"),
            (action.proposal_summary, 4096, "Invalid remediation summary"),
            (action.at_utc, 64, "Invalid remediation timestamp"),
        ] {
            validate_text(value, max, message)?;
        }
        self.connection.execute("INSERT INTO remediation_actions(id,scan_id,finding_id,state,proposal_summary,requires_authorization,created_at_utc,updated_at_utc) VALUES (?1,?2,?3,'requested',?4,?5,?6,?6)",params![action.id,action.scan_id,action.finding_id,action.proposal_summary,action.requires_authorization,action.at_utc])?;
        Ok(())
    }
    pub fn set_remediation_state(
        &self,
        id: &str,
        state: RemediationWorkflowState,
        updated_at_utc: &str,
    ) -> Result<(), StorageError> {
        validate_text(updated_at_utc, 64, "Invalid remediation timestamp")?;
        require_changed(
            self.connection.execute(
                "UPDATE remediation_actions SET state=?2,updated_at_utc=?3 WHERE id=?1",
                (id, remediation_state_name(state), updated_at_utc),
            )?,
            "Remediation action not found",
        )
    }
    pub fn begin_verification(&self, run: &NewVerificationRun<'_>) -> Result<(), StorageError> {
        validate_text(run.id, 128, "Invalid verification id")?;
        validate_text(run.started_at_utc, 64, "Invalid verification timestamp")?;
        self.connection.execute("INSERT INTO verification_runs(id,scan_id,remediation_action_id,state,started_at_utc) VALUES (?1,?2,?3,'running',?4)",params![run.id,run.scan_id,run.remediation_action_id,run.started_at_utc])?;
        Ok(())
    }
    pub fn finish_verification(
        &self,
        id: &str,
        outcome: VerificationOutcome,
        completed_at_utc: &str,
        redacted_result: Option<&str>,
    ) -> Result<(), StorageError> {
        validate_text(completed_at_utc, 64, "Invalid verification timestamp")?;
        validate_optional_text(redacted_result, 4096, "Invalid verification result")?;
        require_changed(self.connection.execute("UPDATE verification_runs SET state=?2,completed_at_utc=?3,redacted_result=?4 WHERE id=?1",params![id,verification_outcome_name(outcome),completed_at_utc,redacted_result])?,"Verification run not found")
    }
}

fn reserve_backup(source: &Connection, path: &Path) -> Result<(), StorageError> {
    let reserved = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    drop(reserved);
    let mut destination = Connection::open(path)?;
    rusqlite::backup::Backup::new(source, &mut destination)?.run_to_completion(
        32,
        Duration::from_millis(5),
        None,
    )?;
    if destination.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
        return Err(StorageError::UnsafeState("Backup verification failed"));
    }
    Ok(())
}
fn migration_hash(sql: &str) -> String {
    format!("{:x}", Sha256::digest(sql.as_bytes()))
}
fn apply_migration(
    connection: &mut Connection,
    version: u32,
    sql: &str,
) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(sql)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version,checksum) VALUES (?1,?2)",
        (version, migration_hash(sql)),
    )?;
    transaction.pragma_update(None, "user_version", version)?;
    transaction.commit()?;
    Ok(())
}
fn verify_schema(connection: &Connection, version: u32) -> Result<(), StorageError> {
    if version == 0 || version > VERSION {
        return Err(StorageError::UnsafeState("Unsupported schema version"));
    }
    let history: Vec<(u32, String)> = connection
        .prepare("SELECT version,checksum FROM schema_migrations ORDER BY version")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let expected_history: Vec<_> = MIGRATIONS
        .iter()
        .filter(|(v, _)| *v <= version)
        .map(|(v, sql)| (*v, migration_hash(sql)))
        .collect();
    if history != expected_history {
        return Err(StorageError::UnsafeState("Unexpected migration history"));
    }
    let expected = Connection::open_in_memory()?;
    for (_, sql) in MIGRATIONS.iter().filter(|(v, _)| *v <= version) {
        expected.execute_batch(sql)?;
    }
    fn schema(c: &Connection) -> Result<Vec<(String, String, String)>, rusqlite::Error> {
        c.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect()
    }
    if schema(connection)? != schema(&expected)? {
        return Err(StorageError::UnsafeState("Unexpected database structure"));
    }
    if connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        return Err(StorageError::UnsafeState("Foreign-key corruption refused"));
    }
    Ok(())
}
fn scan_state_name(state: ScanState) -> &'static str {
    match state {
        ScanState::Queued => "queued",
        ScanState::Preparing => "preparing",
        ScanState::Running => "running",
        ScanState::CancellationRequested => "cancellation_requested",
        ScanState::Cancelled => "cancelled",
        ScanState::Completed => "completed",
        ScanState::Partial => "partial",
        ScanState::Failed => "failed",
    }
}
fn parse_scan_state(value: &str) -> Result<ScanState, StorageError> {
    match value {
        "queued" => Ok(ScanState::Queued),
        "preparing" => Ok(ScanState::Preparing),
        "running" => Ok(ScanState::Running),
        "cancellation_requested" => Ok(ScanState::CancellationRequested),
        "cancelled" => Ok(ScanState::Cancelled),
        "completed" => Ok(ScanState::Completed),
        "partial" => Ok(ScanState::Partial),
        "failed" => Ok(ScanState::Failed),
        _ => Err(StorageError::UnsafeState("Unknown persisted scan state")),
    }
}
fn scan_state_terminal(state: ScanState) -> bool {
    matches!(
        state,
        ScanState::Cancelled | ScanState::Completed | ScanState::Partial | ScanState::Failed
    )
}
fn finding_status_name(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "open",
        FindingStatus::Investigating => "investigating",
        FindingStatus::Remediating => "remediating",
        FindingStatus::VerificationPending => "verification_pending",
        FindingStatus::Resolved => "resolved",
        FindingStatus::AcceptedRisk => "accepted_risk",
        FindingStatus::Ignored => "ignored",
    }
}
fn parse_finding_status(value: &str) -> Result<FindingStatus, StorageError> {
    match value {
        "open" => Ok(FindingStatus::Open),
        "investigating" => Ok(FindingStatus::Investigating),
        "remediating" => Ok(FindingStatus::Remediating),
        "verification_pending" => Ok(FindingStatus::VerificationPending),
        "resolved" => Ok(FindingStatus::Resolved),
        "accepted_risk" => Ok(FindingStatus::AcceptedRisk),
        "ignored" => Ok(FindingStatus::Ignored),
        _ => Err(StorageError::UnsafeState(
            "Unknown persisted finding lifecycle",
        )),
    }
}
fn engine_run_state_name(state: EngineRunState) -> &'static str {
    match state {
        EngineRunState::Passed => "passed",
        EngineRunState::Failed => "failed",
        EngineRunState::Skipped => "skipped",
        EngineRunState::Cancelled => "cancelled",
    }
}
fn remediation_state_name(state: RemediationWorkflowState) -> &'static str {
    match state {
        RemediationWorkflowState::Requested => "requested",
        RemediationWorkflowState::Completed => "completed",
        RemediationWorkflowState::VerificationPending => "verification_pending",
        RemediationWorkflowState::RescanRunning => "rescan_running",
        RemediationWorkflowState::Resolved => "resolved",
        RemediationWorkflowState::StillPresent => "still_present",
        RemediationWorkflowState::Regression => "regression",
        RemediationWorkflowState::Failed => "failed",
    }
}
fn verification_outcome_name(outcome: VerificationOutcome) -> &'static str {
    match outcome {
        VerificationOutcome::Resolved => "resolved",
        VerificationOutcome::StillPresent => "still_present",
        VerificationOutcome::Regression => "regression",
        VerificationOutcome::Inconclusive => "inconclusive",
    }
}
fn validate_text(value: &str, max: usize, message: &'static str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        Err(StorageError::InvalidInput(message))
    } else {
        Ok(())
    }
}
fn validate_optional_text(
    value: Option<&str>,
    max: usize,
    message: &'static str,
) -> Result<(), StorageError> {
    match value {
        Some(value) => validate_text(value, max, message),
        None => Ok(()),
    }
}
fn validate_hash(value: &str, message: &'static str) -> Result<(), StorageError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(StorageError::InvalidInput(message))
    }
}
fn validate_finding_fingerprint(value: &str) -> Result<(), StorageError> {
    if value.len() == 37
        && value.starts_with("ffp1-")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("Invalid finding fingerprint"))
    }
}
fn require_changed(changed: usize, message: &'static str) -> Result<(), StorageError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StorageError::NotFound(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const AT: &str = "2026-09-02T03:00:00Z";
    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FINDING_FINGERPRINT: &str = "ffp1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "edy-storage-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn seeded(path: &Path) -> Storage {
        let mut s = Storage::open(path).unwrap();
        s.create_scan("scan-1", AT).unwrap();
        s.transition_scan("scan-1", ScanState::Preparing, AT)
            .unwrap();
        s.transition_scan("scan-1", ScanState::Running, AT).unwrap();
        s.add_target(&NewTarget {
            id: "target-1",
            scan_id: "scan-1",
            kind: "synthetic",
            reference: "fixture/benign",
            fingerprint: HASH_A,
        })
        .unwrap();
        s
    }

    #[test]
    fn creates_level0_schema_and_reopens_with_pragmas() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let s = Storage::open(&p).unwrap();
        assert_eq!(s.schema_version().unwrap(), 2);
        for t in [
            "scans",
            "targets",
            "findings",
            "evidence",
            "scan_events",
            "engine_runs",
            "remediation_actions",
            "verification_runs",
        ] {
            assert_eq!(
                s.connection
                    .query_row(
                        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                        [t],
                        |r| r.get::<_, u32>(0)
                    )
                    .unwrap(),
                1
            );
        }
        for (pragma, expected) in [
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("synchronous", 2),
            ("busy_timeout", 5000),
        ] {
            assert_eq!(
                s.connection
                    .pragma_query_value(None, pragma, |r| r.get::<_, i64>(0))
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            s.connection
                .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        drop(s);
        assert_eq!(Storage::open(&p).unwrap().schema_version().unwrap(), 2);
    }
    #[test]
    fn upgrades_v1_forward_and_preserves_recovery_copy() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let c = Connection::open(&p).unwrap();
        c.execute_batch(MIGRATION_1).unwrap();
        c.execute(
            "INSERT INTO schema_migrations(version,checksum) VALUES (1,?1)",
            [migration_hash(MIGRATION_1)],
        )
        .unwrap();
        c.pragma_update(None, "user_version", 1).unwrap();
        drop(c);
        assert_eq!(Storage::open(&p).unwrap().schema_version().unwrap(), 2);
        let c = Connection::open(p.with_extension("pre-v2.sqlite3")).unwrap();
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn failed_migration_rolls_back_schema_history_and_version() {
        let mut c = Connection::open_in_memory().unwrap();
        apply_migration(&mut c, 1, MIGRATION_1).unwrap();
        assert!(
            apply_migration(
                &mut c,
                2,
                "CREATE TABLE rollback_fixture(id INTEGER); INSERT INTO missing_table VALUES (1);"
            )
            .is_err()
        );
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='rollback_fixture'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM schema_migrations", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn finding_dedup_and_full_lifecycle_survive_reopen() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let mut s = seeded(&p);
        let f = NewFinding {
            id: "finding-1",
            scan_id: "scan-1",
            target_id: "target-1",
            fingerprint: FINDING_FINGERPRINT,
            category: "synthetic",
            location_reference: "fixture/benign:1",
            severity: "low",
            confidence: "high",
            observed_at_utc: AT,
        };
        assert_eq!(s.upsert_finding(&f).unwrap(), "finding-1");
        let duplicate = NewFinding {
            id: "finding-duplicate",
            ..f
        };
        assert_eq!(s.upsert_finding(&duplicate).unwrap(), "finding-1");
        s.set_finding_lifecycle("finding-1", FindingStatus::Investigating)
            .unwrap();
        s.add_evidence(&NewEvidence {
            id: "evidence-1",
            scan_id: "scan-1",
            finding_id: "finding-1",
            source: "synthetic-fixture",
            observed_at_utc: AT,
            redacted_summary: "benign synthetic observation",
            integrity_sha256: HASH_A,
            redacted: true,
        })
        .unwrap();
        s.begin_engine_run(&NewEngineRun {
            id: "engine-run-1",
            scan_id: "scan-1",
            target_id: "target-1",
            engine_id: "fixture-engine",
            engine_version: "0.0.0",
            started_at_utc: AT,
        })
        .unwrap();
        s.finish_engine_run(
            "engine-run-1",
            EngineRunState::Failed,
            true,
            AT,
            Some(1),
            Some("synthetic failure without raw output"),
        )
        .unwrap();
        s.add_remediation_action(&NewRemediationAction {
            id: "action-1",
            scan_id: "scan-1",
            finding_id: "finding-1",
            proposal_summary: "review synthetic condition",
            requires_authorization: true,
            at_utc: AT,
        })
        .unwrap();
        s.set_remediation_state("action-1", RemediationWorkflowState::Completed, AT)
            .unwrap();
        s.begin_verification(&NewVerificationRun {
            id: "verification-1",
            scan_id: "scan-1",
            remediation_action_id: "action-1",
            started_at_utc: AT,
        })
        .unwrap();
        s.finish_verification(
            "verification-1",
            VerificationOutcome::Resolved,
            AT,
            Some("synthetic verification passed"),
        )
        .unwrap();
        s.transition_scan("scan-1", ScanState::Partial, AT).unwrap();
        drop(s);
        let s = Storage::open(&p).unwrap();
        let scan = s.get_scan("scan-1").unwrap();
        assert_eq!(scan.state, "partial");
        assert!(scan.partial);
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM findings", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM evidence", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn foreign_keys_and_cascade_delete_are_enforced() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let s = Storage::open(&p).unwrap();
        assert!(
            s.add_target(&NewTarget {
                id: "orphan",
                scan_id: "missing",
                kind: "synthetic",
                reference: "fixture",
                fingerprint: HASH_A
            })
            .is_err()
        );
        s.create_scan("scan-delete", AT).unwrap();
        s.add_target(&NewTarget {
            id: "target-delete",
            scan_id: "scan-delete",
            kind: "synthetic",
            reference: "fixture",
            fingerprint: HASH_A,
        })
        .unwrap();
        s.delete_scan("scan-delete").unwrap();
        assert_eq!(
            s.connection
                .query_row("SELECT count(*) FROM targets", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            0
        );
        assert!(s.get_scan("scan-delete").is_err());
    }
    #[test]
    fn invalid_hashes_and_errors_do_not_echo_input() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let mut s = seeded(&p);
        assert!(
            s.add_target(&NewTarget {
                id: "bad-hash",
                scan_id: "scan-1",
                kind: "synthetic",
                reference: "fixture",
                fingerprint: "NOT-A-HASH"
            })
            .is_err()
        );
        assert!(
            s.upsert_finding(&NewFinding {
                id: "bad-finding",
                scan_id: "scan-1",
                target_id: "target-1",
                fingerprint: HASH_A,
                category: "synthetic",
                location_reference: "fixture",
                severity: "low",
                confidence: "low",
                observed_at_utc: AT,
            })
            .is_err()
        );
        assert_eq!(
            s.get_scan("missing").unwrap_err().to_string(),
            "Scan not found"
        );
    }
    #[test]
    fn backup_reopens_and_tampered_schema_fails_closed() {
        let d = Directory::new();
        let p = d.0.join("db.sqlite3");
        let s = Storage::open(&p).unwrap();
        let b = d.0.join("backup.sqlite3");
        s.backup(&b).unwrap();
        assert!(
            s.backup(&b).is_err(),
            "existing backup must not be replaced"
        );
        assert_eq!(Storage::open(&b).unwrap().schema_version().unwrap(), 2);
        s.connection.execute_batch("DROP TABLE evidence").unwrap();
        drop(s);
        assert!(Storage::open(&p).is_err());
    }
    #[test]
    fn corruption_is_preserved_and_newer_schema_is_refused() {
        let d = Directory::new();
        let bad = d.0.join("bad.sqlite3");
        let bytes = b"harmless simulated corrupt database";
        std::fs::write(&bad, bytes).unwrap();
        assert!(Storage::open(&bad).is_err());
        assert_eq!(std::fs::read(&bad).unwrap(), bytes);
        let p = d.0.join("newer.sqlite3");
        let s = Storage::open(&p).unwrap();
        s.connection
            .pragma_update(None, "user_version", 99)
            .unwrap();
        drop(s);
        assert!(Storage::open(&p).is_err());
    }
    #[test]
    fn migration_history_and_unexpected_user_objects_fail_closed() {
        let d = Directory::new();
        let checksum_path = d.0.join("checksum.sqlite3");
        let s = Storage::open(&checksum_path).unwrap();
        s.connection
            .execute(
                "UPDATE schema_migrations SET checksum='tampered' WHERE version=2",
                [],
            )
            .unwrap();
        drop(s);
        assert!(Storage::open(&checksum_path).is_err());

        let object_path = d.0.join("object.sqlite3");
        let s = Storage::open(&object_path).unwrap();
        s.connection
            .execute_batch("CREATE TABLE sqliteXunexpected(id INTEGER)")
            .unwrap();
        drop(s);
        assert!(Storage::open(&object_path).is_err());
    }
}
