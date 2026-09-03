//! Opaque, integrity-checked Level 0 aggregate snapshots.
//!
//! This is deliberately separate from the frozen relational schema. The application service owns
//! the typed payload; this module provides only atomic SQLite durability and optimistic revisions.

use edy_core::{
    CorrelationFinding, CorrelationResult, CorrelationRunState, FindingCluster, GraphLimits,
    IdentifierKind, InvestigationCase, correlate_investigation,
};
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const LEVEL0_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level0_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
";

const LEVEL1_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level1_repository_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  target_id TEXT NOT NULL CHECK(length(target_id) = 36),
  authorization_id TEXT NOT NULL CHECK(length(authorization_id) = 36),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  UNIQUE(target_id, authorization_id)
);
CREATE INDEX IF NOT EXISTS idx_level1_target ON level1_repository_snapshots(target_id);
";

const LEVEL2_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level2_file_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  target_id TEXT NOT NULL CHECK(length(target_id) = 36),
  authorization_id TEXT NOT NULL CHECK(length(authorization_id) = 36),
  canonical_target_id TEXT NOT NULL CHECK(length(canonical_target_id) = 64 AND canonical_target_id = lower(canonical_target_id) AND canonical_target_id NOT GLOB '*[^0-9a-f]*'),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  UNIQUE(target_id, authorization_id)
);
CREATE INDEX IF NOT EXISTS idx_level2_file_target ON level2_file_snapshots(target_id);
";

const LEVEL3_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level3_installed_app_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  authorization_id TEXT NOT NULL CHECK(length(authorization_id) = 36),
  inventory_fingerprint TEXT NOT NULL CHECK(length(inventory_fingerprint) = 64 AND inventory_fingerprint = lower(inventory_fingerprint) AND inventory_fingerprint NOT GLOB '*[^0-9a-f]*'),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  UNIQUE(authorization_id)
);
CREATE INDEX IF NOT EXISTS idx_level3_inventory_fingerprint ON level3_installed_app_snapshots(inventory_fingerprint);
";

const LEVEL4_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level4_web_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  authorization_id TEXT NOT NULL CHECK(length(authorization_id) = 36),
  target_fingerprint TEXT NOT NULL CHECK(length(target_fingerprint) = 64 AND target_fingerprint = lower(target_fingerprint) AND target_fingerprint NOT GLOB '*[^0-9a-f]*'),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  UNIQUE(authorization_id)
);
CREATE INDEX IF NOT EXISTS idx_level4_target_fingerprint ON level4_web_snapshots(target_fingerprint);
";

const LEVEL5_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level5_investigation_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
CREATE INDEX IF NOT EXISTS idx_level5_revision ON level5_investigation_snapshots(revision);
CREATE TABLE IF NOT EXISTS level5_correlation_runs (
  run_id TEXT PRIMARY KEY CHECK(length(run_id) = 36),
  state TEXT NOT NULL CHECK(state IN ('complete','partial_correlation','cancelled')),
  observations_json BLOB NOT NULL CHECK(length(observations_json) BETWEEN 2 AND 8388608),
  observations_sha256 TEXT NOT NULL CHECK(length(observations_sha256) = 64),
  result_json BLOB NOT NULL CHECK(length(result_json) BETWEEN 2 AND 8388608),
  result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64)
);
CREATE TABLE IF NOT EXISTS level5_entities (
  run_id TEXT NOT NULL,
  entity_id TEXT NOT NULL CHECK(length(entity_id) BETWEEN 16 AND 128),
  kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
  identity_kind TEXT NOT NULL CHECK(length(identity_kind) BETWEEN 1 AND 64),
  identity_value TEXT NOT NULL CHECK(length(identity_value) BETWEEN 1 AND 2048),
  label_safe TEXT NOT NULL CHECK(length(label_safe) BETWEEN 1 AND 160),
  PRIMARY KEY(run_id,entity_id),
  FOREIGN KEY(run_id) REFERENCES level5_correlation_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS level5_findings (
  run_id TEXT NOT NULL,
  finding_id TEXT NOT NULL CHECK(length(finding_id) BETWEEN 1 AND 128),
  entity_id TEXT NOT NULL,
  vulnerability_id TEXT,
  artifact_sha256 TEXT,
  purl TEXT,
  cpe TEXT,
  PRIMARY KEY(run_id,finding_id),
  UNIQUE(run_id,entity_id),
  FOREIGN KEY(run_id,entity_id) REFERENCES level5_entities(run_id,entity_id)
);
CREATE TABLE IF NOT EXISTS level5_evidence (
  run_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL CHECK(length(evidence_id) BETWEEN 1 AND 128),
  entity_id TEXT NOT NULL,
  PRIMARY KEY(run_id,evidence_id),
  UNIQUE(run_id,entity_id),
  FOREIGN KEY(run_id,entity_id) REFERENCES level5_entities(run_id,entity_id)
);
CREATE TABLE IF NOT EXISTS level5_relationships (
  run_id TEXT NOT NULL,
  edge_id TEXT NOT NULL CHECK(length(edge_id) BETWEEN 16 AND 128),
  relationship TEXT NOT NULL CHECK(length(relationship) BETWEEN 1 AND 64),
  from_entity TEXT NOT NULL,
  to_entity TEXT NOT NULL,
  rule_id TEXT NOT NULL CHECK(length(rule_id) BETWEEN 1 AND 128),
  rule_version INTEGER NOT NULL CHECK(rule_version >= 1),
  confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
  payload_json BLOB NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  PRIMARY KEY(run_id,edge_id),
  FOREIGN KEY(run_id,from_entity) REFERENCES level5_entities(run_id,entity_id),
  FOREIGN KEY(run_id,to_entity) REFERENCES level5_entities(run_id,entity_id)
);
CREATE TABLE IF NOT EXISTS level5_relationship_findings (
  run_id TEXT NOT NULL, edge_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  PRIMARY KEY(run_id,edge_id,finding_id),
  FOREIGN KEY(run_id,edge_id) REFERENCES level5_relationships(run_id,edge_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,finding_id) REFERENCES level5_findings(run_id,finding_id)
);
CREATE TABLE IF NOT EXISTS level5_relationship_evidence (
  run_id TEXT NOT NULL, edge_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
  PRIMARY KEY(run_id,edge_id,evidence_id),
  FOREIGN KEY(run_id,edge_id) REFERENCES level5_relationships(run_id,edge_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,evidence_id) REFERENCES level5_evidence(run_id,evidence_id)
);
CREATE TABLE IF NOT EXISTS level5_clusters (
  run_id TEXT NOT NULL,
  cluster_id TEXT NOT NULL CHECK(length(cluster_id) BETWEEN 16 AND 128),
  cluster_type TEXT NOT NULL CHECK(length(cluster_type) BETWEEN 1 AND 64),
  payload_json BLOB NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  PRIMARY KEY(run_id,cluster_id),
  FOREIGN KEY(run_id) REFERENCES level5_correlation_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS level5_cluster_entities (
  run_id TEXT NOT NULL, cluster_id TEXT NOT NULL, entity_id TEXT NOT NULL,
  PRIMARY KEY(run_id,cluster_id,entity_id),
  FOREIGN KEY(run_id,cluster_id) REFERENCES level5_clusters(run_id,cluster_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,entity_id) REFERENCES level5_entities(run_id,entity_id)
);
CREATE TABLE IF NOT EXISTS level5_cluster_findings (
  run_id TEXT NOT NULL, cluster_id TEXT NOT NULL, finding_id TEXT NOT NULL CHECK(length(finding_id) BETWEEN 1 AND 128),
  PRIMARY KEY(run_id,cluster_id,finding_id),
  FOREIGN KEY(run_id,cluster_id) REFERENCES level5_clusters(run_id,cluster_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,finding_id) REFERENCES level5_findings(run_id,finding_id)
);
CREATE TABLE IF NOT EXISTS level5_cases (
  run_id TEXT NOT NULL,
  case_id TEXT NOT NULL CHECK(length(case_id) BETWEEN 16 AND 128),
  status TEXT NOT NULL CHECK(length(status) BETWEEN 1 AND 32),
  risk INTEGER NOT NULL CHECK(risk BETWEEN 0 AND 100),
  confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
  coverage INTEGER NOT NULL CHECK(coverage BETWEEN 0 AND 100),
  priority TEXT NOT NULL CHECK(length(priority) BETWEEN 1 AND 32),
  payload_json BLOB NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
  PRIMARY KEY(run_id,case_id),
  FOREIGN KEY(run_id) REFERENCES level5_correlation_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS level5_case_clusters (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, cluster_id TEXT NOT NULL,
  PRIMARY KEY(run_id,case_id,cluster_id),
  FOREIGN KEY(run_id,case_id) REFERENCES level5_cases(run_id,case_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,cluster_id) REFERENCES level5_clusters(run_id,cluster_id)
);
CREATE TABLE IF NOT EXISTS level5_case_entities (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, entity_id TEXT NOT NULL,
  PRIMARY KEY(run_id,case_id,entity_id),
  FOREIGN KEY(run_id,case_id) REFERENCES level5_cases(run_id,case_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,entity_id) REFERENCES level5_entities(run_id,entity_id)
);
CREATE TABLE IF NOT EXISTS level5_case_findings (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  PRIMARY KEY(run_id,case_id,finding_id),
  FOREIGN KEY(run_id,case_id) REFERENCES level5_cases(run_id,case_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,finding_id) REFERENCES level5_findings(run_id,finding_id)
);
CREATE TABLE IF NOT EXISTS level5_case_evidence (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
  PRIMARY KEY(run_id,case_id,evidence_id),
  FOREIGN KEY(run_id,case_id) REFERENCES level5_cases(run_id,case_id) ON DELETE CASCADE,
  FOREIGN KEY(run_id,evidence_id) REFERENCES level5_evidence(run_id,evidence_id)
);
CREATE TABLE IF NOT EXISTS level5_case_timeline (
  run_id TEXT NOT NULL, case_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence >= 1),
  timestamp TEXT NOT NULL CHECK(length(timestamp) BETWEEN 1 AND 40),
  event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 80),
  summary_safe TEXT NOT NULL CHECK(length(summary_safe) BETWEEN 1 AND 512),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 80),
  PRIMARY KEY(run_id,case_id,sequence),
  FOREIGN KEY(run_id,case_id) REFERENCES level5_cases(run_id,case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_level5_relationship_from ON level5_relationships(run_id,from_entity);
CREATE INDEX IF NOT EXISTS idx_level5_relationship_to ON level5_relationships(run_id,to_entity);
CREATE INDEX IF NOT EXISTS idx_level5_entity_kind ON level5_entities(run_id,kind,entity_id);
CREATE INDEX IF NOT EXISTS idx_level5_entity_identity ON level5_entities(run_id,identity_kind,identity_value);
CREATE INDEX IF NOT EXISTS idx_level5_finding_vulnerability ON level5_findings(run_id,vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_level5_finding_hash ON level5_findings(run_id,artifact_sha256);
CREATE INDEX IF NOT EXISTS idx_level5_finding_purl ON level5_findings(run_id,purl);
CREATE INDEX IF NOT EXISTS idx_level5_finding_cpe ON level5_findings(run_id,cpe);
CREATE INDEX IF NOT EXISTS idx_level5_relationship_finding ON level5_relationship_findings(run_id,finding_id,edge_id);
CREATE INDEX IF NOT EXISTS idx_level5_cluster_type ON level5_clusters(run_id,cluster_type);
CREATE INDEX IF NOT EXISTS idx_level5_case_status ON level5_cases(run_id,status,priority,risk DESC);
CREATE INDEX IF NOT EXISTS idx_level5_timeline ON level5_case_timeline(run_id,case_id,sequence);
";

#[derive(Debug)]
pub enum SnapshotError {
    Sql(rusqlite::Error),
    Io(std::io::Error),
    InvalidInput,
    Conflict,
    NotFound,
    Integrity,
}

impl From<rusqlite::Error> for SnapshotError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sql(value)
    }
}

impl From<std::io::Error> for SnapshotError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Sql(_) => "Snapshot database operation failed",
            Self::Io(_) => "Snapshot filesystem operation failed",
            Self::InvalidInput => "Snapshot input was refused",
            Self::Conflict => "Snapshot changed concurrently",
            Self::NotFound => "Snapshot was not found",
            Self::Integrity => "Snapshot integrity verification failed",
        })
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBlob {
    pub revision: u64,
    pub payload: Vec<u8>,
}

pub struct Level0SnapshotStore {
    connection: Connection,
}

impl Level0SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() {
            return Err(SnapshotError::InvalidInput);
        }
        if let Some(parent) = path.parent()
            && !parent.is_dir()
        {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        connection.execute_batch(LEVEL0_SCHEMA)?;
        if version == 0 {
            connection.execute_batch("PRAGMA user_version=1;")?;
        }
        verify_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn create(&mut self, scan_id: &str, payload: &[u8]) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO level0_snapshots(scan_id,revision,payload,payload_sha256) VALUES(?1,1,?2,?3)",
            params![scan_id, payload, digest(payload)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(SnapshotError::InvalidInput);
        }
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE level0_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",
            params![scan_id, expected_revision as i64, payload, digest(payload)],
        )?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        transaction.commit()?;
        Ok(expected_revision + 1)
    }

    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision, payload, expected): (i64, Vec<u8>, String) = self
            .connection
            .query_row(
                "SELECT revision,payload,payload_sha256 FROM level0_snapshots WHERE scan_id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => SnapshotError::NotFound,
                other => SnapshotError::Sql(other),
            })?;
        validate(scan_id, &payload)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        let revision = u64::try_from(revision).map_err(|_| SnapshotError::Integrity)?;
        Ok(SnapshotBlob { revision, payload })
    }

    pub fn list_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=50).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT scan_id FROM level0_snapshots ORDER BY scan_id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(params![limit, offset], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::with_capacity(limit as usize);
        for row in rows {
            let id = row?;
            validate_scan_id(&id)?;
            ids.push(id);
        }
        Ok(ids)
    }

    pub fn count(&self) -> Result<u32, SnapshotError> {
        let count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM level0_snapshots", [], |row| {
                    row.get(0)
                })?;
        u32::try_from(count).map_err(|_| SnapshotError::Integrity)
    }
}

/// Forward-only Level 0 -> Level 1 snapshot migration and sanitized Level 1 payload store.
pub struct Level1SnapshotStore {
    connection: Connection,
}

impl Level1SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(LEVEL0_SCHEMA)?;
        transaction.execute_batch(LEVEL1_SCHEMA)?;
        if version < 2 {
            transaction.execute_batch("PRAGMA user_version=2;")?;
        }
        transaction.commit()?;
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        scan_id: &str,
        target_id: &str,
        authorization_id: &str,
        payload: &[u8],
    ) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        validate_uuid(target_id)?;
        validate_uuid(authorization_id)?;
        reject_fixture_secret(payload)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO level1_repository_snapshots(scan_id,target_id,authorization_id,revision,payload,payload_sha256) VALUES(?1,?2,?3,1,?4,?5)",
            params![scan_id, target_id, authorization_id, payload, digest(payload)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision, payload, expected): (i64, Vec<u8>, String) = self.connection.query_row(
            "SELECT revision,payload,payload_sha256 FROM level1_repository_snapshots WHERE scan_id=?1",
            [scan_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => SnapshotError::NotFound,
            other => SnapshotError::Sql(other),
        })?;
        validate(scan_id, &payload)?;
        reject_fixture_secret(&payload)?;
        if expected != digest(&payload) {
            return Err(SnapshotError::Integrity);
        }
        Ok(SnapshotBlob {
            revision: revision.try_into().map_err(|_| SnapshotError::Integrity)?,
            payload,
        })
    }

    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(SnapshotError::InvalidInput);
        }
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE level1_repository_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",
            params![scan_id, expected_revision as i64, payload, digest(payload)],
        )?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        transaction.commit()?;
        Ok(expected_revision + 1)
    }

    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM level1_repository_snapshots")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if row?.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=50).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT scan_id FROM level1_repository_snapshots ORDER BY scan_id DESC LIMIT ?1 OFFSET ?2"
        )?;
        let rows = statement.query_map(params![limit, offset], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SnapshotError::Sql)
    }
}

/// Forward-only Level 2 file-analysis snapshots. Payloads are sanitized summaries only: file
/// bytes, certificate blobs, raw engine output and provider credentials are outside the contract.
pub struct Level2SnapshotStore {
    connection: Connection,
}

impl Level2SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(LEVEL0_SCHEMA)?;
        transaction.execute_batch(LEVEL1_SCHEMA)?;
        transaction.execute_batch(LEVEL2_SCHEMA)?;
        if version < 3 {
            transaction.execute_batch("PRAGMA user_version=3;")?;
        }
        transaction.commit()?;
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        verify_level2_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        scan_id: &str,
        target_id: &str,
        authorization_id: &str,
        canonical_target_id: &str,
        payload: &[u8],
    ) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        validate_uuid(target_id)?;
        validate_uuid(authorization_id)?;
        validate_digest(canonical_target_id)?;
        reject_fixture_secret(payload)?;
        let transaction = self.connection.transaction()?;
        let count: u32 =
            transaction.query_row("SELECT count(*) FROM level2_file_snapshots", [], |row| {
                row.get(0)
            })?;
        if count >= 256 {
            return Err(SnapshotError::InvalidInput);
        }
        transaction.execute(
            "INSERT INTO level2_file_snapshots(scan_id,target_id,authorization_id,canonical_target_id,revision,payload,payload_sha256) VALUES(?1,?2,?3,?4,1,?5,?6)",
            params![scan_id, target_id, authorization_id, canonical_target_id, payload, digest(payload)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(SnapshotError::InvalidInput);
        }
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE level2_file_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",
            params![scan_id, expected_revision as i64, payload, digest(payload)],
        )?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        transaction.commit()?;
        Ok(expected_revision + 1)
    }

    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision, payload, expected): (i64, Vec<u8>, String) = self
            .connection
            .query_row(
                "SELECT revision,payload,payload_sha256 FROM level2_file_snapshots WHERE scan_id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => SnapshotError::NotFound,
                other => SnapshotError::Sql(other),
            })?;
        validate(scan_id, &payload)?;
        reject_fixture_secret(&payload)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        Ok(SnapshotBlob {
            revision: revision.try_into().map_err(|_| SnapshotError::Integrity)?,
            payload,
        })
    }

    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM level2_file_snapshots")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if row?.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=50).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT scan_id FROM level2_file_snapshots ORDER BY scan_id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(params![limit, offset], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(SnapshotError::Sql)
    }
}

/// Forward-only Level 3 installed-application snapshots. The payload may contain local product
/// names and versions, but never uninstall commands, secrets, raw registry exports or file bytes.
pub struct Level3SnapshotStore {
    connection: Connection,
}

impl Level3SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(LEVEL0_SCHEMA)?;
        transaction.execute_batch(LEVEL1_SCHEMA)?;
        transaction.execute_batch(LEVEL2_SCHEMA)?;
        transaction.execute_batch(LEVEL3_SCHEMA)?;
        if version < 4 {
            transaction.execute_batch("PRAGMA user_version=4;")?;
        }
        transaction.commit()?;
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        verify_level2_schema(&connection)?;
        verify_level3_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        scan_id: &str,
        authorization_id: &str,
        inventory_fingerprint: &str,
        payload: &[u8],
    ) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        validate_uuid(authorization_id)?;
        validate_digest(inventory_fingerprint)?;
        reject_fixture_secret(payload)?;
        let transaction = self.connection.transaction()?;
        let count: u32 = transaction.query_row(
            "SELECT count(*) FROM level3_installed_app_snapshots",
            [],
            |row| row.get(0),
        )?;
        if count >= 256 {
            return Err(SnapshotError::InvalidInput);
        }
        transaction.execute("INSERT INTO level3_installed_app_snapshots(scan_id,authorization_id,inventory_fingerprint,revision,payload,payload_sha256) VALUES(?1,?2,?3,1,?4,?5)",params![scan_id,authorization_id,inventory_fingerprint,payload,digest(payload)])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(SnapshotError::InvalidInput);
        }
        let transaction = self.connection.transaction()?;
        let changed=transaction.execute("UPDATE level3_installed_app_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",params![scan_id,expected_revision as i64,payload,digest(payload)])?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        transaction.commit()?;
        Ok(expected_revision + 1)
    }

    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision,payload,expected):(i64,Vec<u8>,String)=self.connection.query_row("SELECT revision,payload,payload_sha256 FROM level3_installed_app_snapshots WHERE scan_id=?1",[scan_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|error|match error{rusqlite::Error::QueryReturnedNoRows=>SnapshotError::NotFound,other=>SnapshotError::Sql(other)})?;
        validate(scan_id, &payload)?;
        reject_fixture_secret(&payload)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        Ok(SnapshotBlob {
            revision: revision.try_into().map_err(|_| SnapshotError::Integrity)?,
            payload,
        })
    }

    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM level3_installed_app_snapshots")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if row?.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=50).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement=self.connection.prepare("SELECT scan_id FROM level3_installed_app_snapshots ORDER BY scan_id DESC LIMIT ?1 OFFSET ?2")?;
        statement
            .query_map(params![limit, offset], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SnapshotError::Sql)
    }
}

/// Forward-only Level 4 passive web snapshots. Payloads are sanitized analysis only: raw query
/// values, cookie values, credentials, response bodies and unrestricted headers are forbidden.
pub struct Level4SnapshotStore {
    connection: Connection,
}

impl Level4SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(LEVEL0_SCHEMA)?;
        transaction.execute_batch(LEVEL1_SCHEMA)?;
        transaction.execute_batch(LEVEL2_SCHEMA)?;
        transaction.execute_batch(LEVEL3_SCHEMA)?;
        transaction.execute_batch(LEVEL4_SCHEMA)?;
        if version < 5 {
            transaction.execute_batch("PRAGMA user_version=5;")?;
        }
        transaction.commit()?;
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        verify_level2_schema(&connection)?;
        verify_level3_schema(&connection)?;
        verify_level4_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        scan_id: &str,
        authorization_id: &str,
        target_fingerprint: &str,
        payload: &[u8],
    ) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        validate_uuid(authorization_id)?;
        validate_digest(target_fingerprint)?;
        reject_fixture_secret(payload)?;
        let transaction = self.connection.transaction()?;
        let count: u32 =
            transaction.query_row("SELECT count(*) FROM level4_web_snapshots", [], |row| {
                row.get(0)
            })?;
        if count >= 256 {
            return Err(SnapshotError::InvalidInput);
        }
        transaction.execute(
            "INSERT INTO level4_web_snapshots(scan_id,authorization_id,target_fingerprint,revision,payload,payload_sha256) VALUES(?1,?2,?3,1,?4,?5)",
            params![scan_id, authorization_id, target_fingerprint, payload, digest(payload)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        if expected_revision == 0 || expected_revision >= i64::MAX as u64 {
            return Err(SnapshotError::InvalidInput);
        }
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE level4_web_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",
            params![scan_id, expected_revision as i64, payload, digest(payload)],
        )?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        transaction.commit()?;
        Ok(expected_revision + 1)
    }

    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision, payload, expected): (i64, Vec<u8>, String) = self
            .connection
            .query_row(
                "SELECT revision,payload,payload_sha256 FROM level4_web_snapshots WHERE scan_id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => SnapshotError::NotFound,
                other => SnapshotError::Sql(other),
            })?;
        validate(scan_id, &payload)?;
        reject_fixture_secret(&payload)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        Ok(SnapshotBlob {
            revision: revision.try_into().map_err(|_| SnapshotError::Integrity)?,
            payload,
        })
    }

    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM level4_web_snapshots")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if row?.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=50).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT scan_id FROM level4_web_snapshots ORDER BY scan_id DESC LIMIT ?1 OFFSET ?2",
        )?;
        statement
            .query_map(params![limit, offset], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SnapshotError::Sql)
    }
}

/// Forward-only, integrity-checked Level 5 graph/case snapshot. The typed domain owns the
/// schema; this boundary atomically persists only redacted normalized observations/results.
pub struct Level5SnapshotStore {
    pub(crate) connection: Connection,
}

impl Level5SnapshotStore {
    pub fn open_read_only(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || !path.is_file() {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if !(6..=8).contains(&version) {
            return Err(SnapshotError::Integrity);
        }
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        verify_level2_schema(&connection)?;
        verify_level3_schema(&connection)?;
        verify_level4_schema(&connection)?;
        verify_level5_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 8 {
            return Err(SnapshotError::Integrity);
        }
        let tx = connection.unchecked_transaction()?;
        for schema in [
            LEVEL0_SCHEMA,
            LEVEL1_SCHEMA,
            LEVEL2_SCHEMA,
            LEVEL3_SCHEMA,
            LEVEL4_SCHEMA,
            LEVEL5_SCHEMA,
        ] {
            tx.execute_batch(schema)?;
        }
        if version < 6 {
            tx.execute_batch("PRAGMA user_version=6;")?;
        }
        tx.commit()?;
        verify_schema(&connection)?;
        verify_level1_schema(&connection)?;
        verify_level2_schema(&connection)?;
        verify_level3_schema(&connection)?;
        verify_level4_schema(&connection)?;
        verify_level5_schema(&connection)?;
        Ok(Self { connection })
    }
    pub fn create(&mut self, scan_id: &str, payload: &[u8]) -> Result<(), SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        reject_level5_secret(payload)?;
        let tx = self.connection.transaction()?;
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM level5_investigation_snapshots",
            [],
            |r| r.get(0),
        )?;
        if count >= 256 {
            return Err(SnapshotError::InvalidInput);
        }
        tx.execute("INSERT INTO level5_investigation_snapshots(scan_id,revision,payload,payload_sha256) VALUES(?1,1,?2,?3)",params![scan_id,payload,digest(payload)])?;
        tx.commit()?;
        Ok(())
    }
    pub fn replace(
        &mut self,
        scan_id: &str,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<u64, SnapshotError> {
        validate(scan_id, payload)?;
        reject_fixture_secret(payload)?;
        reject_level5_secret(payload)?;
        if expected_revision == 0 {
            return Err(SnapshotError::InvalidInput);
        }
        let tx = self.connection.transaction()?;
        let changed=tx.execute("UPDATE level5_investigation_snapshots SET revision=revision+1,payload=?3,payload_sha256=?4 WHERE scan_id=?1 AND revision=?2",params![scan_id,expected_revision as i64,payload,digest(payload)])?;
        if changed != 1 {
            return Err(SnapshotError::Conflict);
        }
        tx.commit()?;
        Ok(expected_revision + 1)
    }
    pub fn load(&self, scan_id: &str) -> Result<SnapshotBlob, SnapshotError> {
        validate_scan_id(scan_id)?;
        let (revision,payload,expected):(i64,Vec<u8>,String)=self.connection.query_row("SELECT revision,payload,payload_sha256 FROM level5_investigation_snapshots WHERE scan_id=?1",[scan_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|if matches!(e,rusqlite::Error::QueryReturnedNoRows){SnapshotError::NotFound}else{SnapshotError::Sql(e)})?;
        validate(scan_id, &payload)?;
        reject_level5_secret(&payload)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        Ok(SnapshotBlob {
            revision: revision.try_into().map_err(|_| SnapshotError::Integrity)?,
            payload,
        })
    }
    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        let mut s = self
            .connection
            .prepare("SELECT payload FROM level5_investigation_snapshots")?;
        for row in s.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            if row?.windows(needle.len()).any(|w| w == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Atomically promotes only a complete, redacted correlation result. Cancelled or bounded
    /// partial runs never become authoritative graph state.
    pub fn promote(
        &mut self,
        run_id: &str,
        observations: &[CorrelationFinding],
        result: &CorrelationResult,
    ) -> Result<(), SnapshotError> {
        validate_scan_id(run_id)?;
        if result.state != CorrelationRunState::Complete || result.limit_reached {
            return Err(SnapshotError::InvalidInput);
        }
        let replay =
            correlate_investigation(observations.to_vec(), GraphLimits::default(), || false)
                .map_err(|_| SnapshotError::InvalidInput)?;
        if replay != *result {
            return Err(SnapshotError::Integrity);
        }
        let observations_json =
            serde_json::to_vec(observations).map_err(|_| SnapshotError::InvalidInput)?;
        let result_json = serde_json::to_vec(result).map_err(|_| SnapshotError::InvalidInput)?;
        validate(run_id, &result_json)?;
        reject_fixture_secret(&observations_json)?;
        reject_level5_secret(&observations_json)?;
        reject_fixture_secret(&result_json)?;
        reject_level5_secret(&result_json)?;
        let node_ids = result
            .nodes
            .iter()
            .map(|node| node.entity_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if result.edges.iter().any(|edge| {
            !node_ids.contains(edge.from_entity.as_str())
                || !node_ids.contains(edge.to_entity.as_str())
        }) {
            return Err(SnapshotError::Integrity);
        }
        let tx = self.connection.transaction()?;
        tx.execute("INSERT INTO level5_correlation_runs(run_id,state,observations_json,observations_sha256,result_json,result_sha256) VALUES(?1,'complete',?2,?3,?4,?5)", params![run_id,observations_json,digest(&observations_json),result_json,digest(&result_json)])?;
        for node in &result.nodes {
            tx.execute("INSERT INTO level5_entities(run_id,entity_id,kind,identity_kind,identity_value,label_safe) VALUES(?1,?2,?3,?4,?5,?6)", params![run_id,node.entity_id,format!("{:?}",node.kind),format!("{:?}",node.identity.kind),node.identity.canonical_value,node.label_safe])?;
        }
        for finding in observations {
            let finding_entity = result
                .nodes
                .iter()
                .find(|node| {
                    node.identity.kind == IdentifierKind::StableFinding
                        && node.identity.canonical_value == finding.finding_id
                })
                .ok_or(SnapshotError::Integrity)?;
            tx.execute("INSERT INTO level5_findings(run_id,finding_id,entity_id,vulnerability_id,artifact_sha256,purl,cpe) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![run_id,finding.finding_id,finding_entity.entity_id,finding.vulnerability_id,finding.artifact_sha256,finding.purl,finding.cpe])?;
            for evidence_id in &finding.evidence_ids {
                let evidence_entity = result
                    .nodes
                    .iter()
                    .find(|node| {
                        node.identity.kind == IdentifierKind::StableEvidence
                            && node.identity.canonical_value == *evidence_id
                    })
                    .ok_or(SnapshotError::Integrity)?;
                tx.execute("INSERT OR IGNORE INTO level5_evidence(run_id,evidence_id,entity_id) VALUES(?1,?2,?3)",params![run_id,evidence_id,evidence_entity.entity_id])?;
            }
        }
        for edge in &result.edges {
            let payload = serde_json::to_vec(edge).map_err(|_| SnapshotError::InvalidInput)?;
            tx.execute("INSERT INTO level5_relationships(run_id,edge_id,relationship,from_entity,to_entity,rule_id,rule_version,confidence,payload_json,payload_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![run_id,edge.edge_id,format!("{:?}",edge.relationship),edge.from_entity,edge.to_entity,edge.rule_id,edge.rule_version,edge.confidence,payload,digest(&payload)])?;
            for finding_id in &edge.finding_ids {
                tx.execute("INSERT INTO level5_relationship_findings(run_id,edge_id,finding_id) VALUES(?1,?2,?3)",params![run_id,edge.edge_id,finding_id])?;
            }
            for evidence_id in &edge.evidence_ids {
                tx.execute("INSERT INTO level5_relationship_evidence(run_id,edge_id,evidence_id) VALUES(?1,?2,?3)",params![run_id,edge.edge_id,evidence_id])?;
            }
        }
        for cluster in &result.clusters {
            let payload = serde_json::to_vec(cluster).map_err(|_| SnapshotError::InvalidInput)?;
            tx.execute("INSERT INTO level5_clusters(run_id,cluster_id,cluster_type,payload_json,payload_sha256) VALUES(?1,?2,?3,?4,?5)",params![run_id,cluster.cluster_id,format!("{:?}",cluster.cluster_type),payload,digest(&payload)])?;
            for entity in &cluster.member_entities {
                tx.execute("INSERT INTO level5_cluster_entities(run_id,cluster_id,entity_id) VALUES(?1,?2,?3)",params![run_id,cluster.cluster_id,entity])?;
            }
            for finding in &cluster.member_findings {
                tx.execute("INSERT INTO level5_cluster_findings(run_id,cluster_id,finding_id) VALUES(?1,?2,?3)",params![run_id,cluster.cluster_id,finding])?;
            }
        }
        for case in &result.suggested_cases {
            let payload = serde_json::to_vec(case).map_err(|_| SnapshotError::InvalidInput)?;
            tx.execute("INSERT INTO level5_cases(run_id,case_id,status,risk,confidence,coverage,priority,payload_json,payload_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![run_id,case.case_id,format!("{:?}",case.status),case.assessment.risk,case.assessment.confidence,case.assessment.coverage,format!("{:?}",case.assessment.priority),payload,digest(&payload)])?;
            for cluster in &case.cluster_ids {
                tx.execute(
                    "INSERT INTO level5_case_clusters(run_id,case_id,cluster_id) VALUES(?1,?2,?3)",
                    params![run_id, case.case_id, cluster],
                )?;
            }
            for entity in &case.entity_ids {
                tx.execute(
                    "INSERT INTO level5_case_entities(run_id,case_id,entity_id) VALUES(?1,?2,?3)",
                    params![run_id, case.case_id, entity],
                )?;
            }
            for finding in &case.finding_ids {
                tx.execute(
                    "INSERT INTO level5_case_findings(run_id,case_id,finding_id) VALUES(?1,?2,?3)",
                    params![run_id, case.case_id, finding],
                )?;
            }
            for evidence in &case.evidence_ids {
                tx.execute(
                    "INSERT INTO level5_case_evidence(run_id,case_id,evidence_id) VALUES(?1,?2,?3)",
                    params![run_id, case.case_id, evidence],
                )?;
            }
            for event in &case.timeline {
                tx.execute("INSERT INTO level5_case_timeline(run_id,case_id,sequence,timestamp,event_type,summary_safe,source) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![run_id,case.case_id,event.sequence,event.timestamp,event.event_type,event.summary_safe,event.source])?;
            }
        }
        tx.execute("INSERT INTO level5_investigation_snapshots(scan_id,revision,payload,payload_sha256) VALUES(?1,1,?2,?3)",params![run_id,result_json,digest(&result_json)])?;
        tx.commit()?;
        Ok(())
    }

    pub fn load_result(&self, run_id: &str) -> Result<CorrelationResult, SnapshotError> {
        validate_scan_id(run_id)?;
        let (payload, expected): (Vec<u8>, String) = self
            .connection
            .query_row(
                "SELECT result_json,result_sha256 FROM level5_correlation_runs WHERE run_id=?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    SnapshotError::NotFound
                } else {
                    SnapshotError::Sql(error)
                }
            })?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        serde_json::from_slice(&payload).map_err(|_| SnapshotError::Integrity)
    }

    pub fn load_observations(
        &self,
        run_id: &str,
    ) -> Result<Vec<CorrelationFinding>, SnapshotError> {
        validate_scan_id(run_id)?;
        let (payload, expected): (Vec<u8>, String) = self
            .connection
            .query_row(
                "SELECT observations_json,observations_sha256 FROM level5_correlation_runs WHERE run_id=?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    SnapshotError::NotFound
                } else {
                    SnapshotError::Sql(error)
                }
            })?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        serde_json::from_slice(&payload).map_err(|_| SnapshotError::Integrity)
    }

    pub fn list_run_ids(&self, offset: u32, limit: u32) -> Result<Vec<String>, SnapshotError> {
        if offset > 10_000 || !(1..=100).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT run_id FROM level5_correlation_runs ORDER BY run_id DESC LIMIT ?1 OFFSET ?2",
        )?;
        statement
            .query_map(params![limit, offset], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SnapshotError::Sql)
    }

    pub fn list_clusters(
        &self,
        run_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<FindingCluster>, SnapshotError> {
        paged_json(
            &self.connection,
            "SELECT payload_json,payload_sha256 FROM level5_clusters WHERE run_id=?1 ORDER BY cluster_id LIMIT ?2 OFFSET ?3",
            run_id,
            offset,
            limit,
        )
    }

    pub fn list_cases(
        &self,
        run_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<InvestigationCase>, SnapshotError> {
        paged_json(
            &self.connection,
            "SELECT payload_json,payload_sha256 FROM level5_cases WHERE run_id=?1 ORDER BY CASE priority WHEN 'Immediate' THEN 0 WHEN 'High' THEN 1 WHEN 'Normal' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,risk DESC,confidence DESC,case_id LIMIT ?2 OFFSET ?3",
            run_id,
            offset,
            limit,
        )
    }

    pub fn get_cluster(
        &self,
        run_id: &str,
        cluster_id: &str,
    ) -> Result<FindingCluster, SnapshotError> {
        one_json(
            &self.connection,
            "SELECT payload_json,payload_sha256 FROM level5_clusters WHERE run_id=?1 AND cluster_id=?2",
            run_id,
            cluster_id,
        )
    }

    pub fn get_case(
        &self,
        run_id: &str,
        case_id: &str,
    ) -> Result<InvestigationCase, SnapshotError> {
        one_json(
            &self.connection,
            "SELECT payload_json,payload_sha256 FROM level5_cases WHERE run_id=?1 AND case_id=?2",
            run_id,
            case_id,
        )
    }

    pub fn replace_case(
        &mut self,
        run_id: &str,
        case: &InvestigationCase,
    ) -> Result<(), SnapshotError> {
        validate_scan_id(run_id)?;
        if case.case_id.len() < 16 || case.case_id.len() > 128 {
            return Err(SnapshotError::InvalidInput);
        }
        let previous = self.get_case(run_id, &case.case_id)?;
        if previous.title_safe != case.title_safe
            || previous.suggested != case.suggested
            || previous.finding_ids != case.finding_ids
            || previous.cluster_ids != case.cluster_ids
            || previous.entity_ids != case.entity_ids
            || previous.evidence_ids != case.evidence_ids
            || previous.blast_radius != case.blast_radius
            || previous.assessment != case.assessment
            || case.transitions.len() != previous.transitions.len() + 1
            || case.timeline.len() != previous.timeline.len() + 1
            || !case.transitions.starts_with(&previous.transitions)
            || !case.timeline.starts_with(&previous.timeline)
        {
            return Err(SnapshotError::Integrity);
        }
        let transition = case.transitions.last().ok_or(SnapshotError::Integrity)?;
        let event = case.timeline.last().ok_or(SnapshotError::Integrity)?;
        if transition.from != previous.status
            || transition.to != case.status
            || event.sequence != case.timeline.len() as u32
            || event.timestamp != transition.timestamp
        {
            return Err(SnapshotError::Integrity);
        }
        let payload = serde_json::to_vec(case).map_err(|_| SnapshotError::InvalidInput)?;
        reject_fixture_secret(&payload)?;
        reject_level5_secret(&payload)?;
        let tx = self.connection.transaction()?;
        let changed=tx.execute("UPDATE level5_cases SET status=?3,risk=?4,confidence=?5,coverage=?6,priority=?7,payload_json=?8,payload_sha256=?9 WHERE run_id=?1 AND case_id=?2",params![run_id,case.case_id,format!("{:?}",case.status),case.assessment.risk,case.assessment.confidence,case.assessment.coverage,format!("{:?}",case.assessment.priority),payload,digest(&payload)])?;
        if changed != 1 {
            return Err(SnapshotError::NotFound);
        }
        tx.execute(
            "DELETE FROM level5_case_timeline WHERE run_id=?1 AND case_id=?2",
            params![run_id, case.case_id],
        )?;
        for event in &case.timeline {
            tx.execute("INSERT INTO level5_case_timeline(run_id,case_id,sequence,timestamp,event_type,summary_safe,source) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![run_id,case.case_id,event.sequence,event.timestamp,event.event_type,event.summary_safe,event.source])?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn paged_json<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    run_id: &str,
    offset: u32,
    limit: u32,
) -> Result<Vec<T>, SnapshotError> {
    validate_scan_id(run_id)?;
    if offset > 10_000 || !(1..=100).contains(&limit) {
        return Err(SnapshotError::InvalidInput);
    }
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params![run_id, limit, offset], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (payload, expected) = row?;
        if digest(&payload) != expected {
            return Err(rusqlite::Error::InvalidQuery);
        }
        serde_json::from_slice(&payload).map_err(|_| rusqlite::Error::InvalidQuery)
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(SnapshotError::Sql)
}

fn one_json<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    run_id: &str,
    id: &str,
) -> Result<T, SnapshotError> {
    validate_scan_id(run_id)?;
    if id.len() < 16 || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(SnapshotError::InvalidInput);
    }
    let (payload, expected): (Vec<u8>, String) = connection
        .query_row(sql, params![run_id, id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|error| {
            if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                SnapshotError::NotFound
            } else {
                SnapshotError::Sql(error)
            }
        })?;
    if digest(&payload) != expected {
        return Err(SnapshotError::Integrity);
    }
    serde_json::from_slice(&payload).map_err(|_| SnapshotError::Integrity)
}

fn validate(scan_id: &str, payload: &[u8]) -> Result<(), SnapshotError> {
    validate_scan_id(scan_id)?;
    if payload.len() < 2 || payload.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::InvalidInput);
    }
    Ok(())
}

fn validate_scan_id(scan_id: &str) -> Result<(), SnapshotError> {
    edy_core::ScanId::new(scan_id)
        .map(|_| ())
        .map_err(|_| SnapshotError::InvalidInput)
}

fn validate_uuid(value: &str) -> Result<(), SnapshotError> {
    edy_core::TargetId::new(value)
        .map(|_| ())
        .map_err(|_| SnapshotError::InvalidInput)
}

fn validate_digest(value: &str) -> Result<(), SnapshotError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(SnapshotError::InvalidInput);
    }
    Ok(())
}

fn reject_fixture_secret(payload: &[u8]) -> Result<(), SnapshotError> {
    for marker in [
        b"EDY_FAKE_TEST_TOKEN_".as_slice(),
        b"EDY_FAKE_QUERY_SECRET_LEVEL4".as_slice(),
        b"EDY_FAKE_COOKIE_SECRET_LEVEL4".as_slice(),
    ] {
        if payload
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
        {
            return Err(SnapshotError::InvalidInput);
        }
    }
    Ok(())
}

fn reject_level5_secret(payload: &[u8]) -> Result<(), SnapshotError> {
    for marker in [
        b"EDY_FAKE_SECRET_LEVEL5".as_slice(),
        b"EDY_FAKE_COOKIE_LEVEL5".as_slice(),
        b"EDY_FAKE_QUERY_LEVEL5".as_slice(),
    ] {
        if payload
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
        {
            return Err(SnapshotError::InvalidInput);
        }
    }
    Ok(())
}

fn digest(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

fn verify_schema(connection: &Connection) -> Result<(), SnapshotError> {
    let sql: String = connection.query_row(
        "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name='level0_snapshots'",
        [],
        |row| row.get(0),
    )?;
    if !sql.contains("payload_sha256") || !sql.contains("revision") {
        return Err(SnapshotError::Integrity);
    }
    if connection
        .prepare("PRAGMA quick_check")?
        .query_row([], |row| row.get::<_, String>(0))?
        != "ok"
    {
        return Err(SnapshotError::Integrity);
    }
    Ok(())
}

fn verify_level1_schema(connection: &Connection) -> Result<(), SnapshotError> {
    let sql: String = connection.query_row(
        "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name='level1_repository_snapshots'",
        [], |row| row.get(0),
    )?;
    if !sql.contains("authorization_id") || !sql.contains("payload_sha256") {
        return Err(SnapshotError::Integrity);
    }
    Ok(())
}

fn verify_level2_schema(connection: &Connection) -> Result<(), SnapshotError> {
    let sql: String = connection.query_row(
        "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name='level2_file_snapshots'",
        [],
        |row| row.get(0),
    )?;
    if !sql.contains("canonical_target_id") || !sql.contains("payload_sha256") {
        return Err(SnapshotError::Integrity);
    }
    Ok(())
}

fn verify_level3_schema(connection: &Connection) -> Result<(), SnapshotError> {
    let sql: String = connection.query_row(
        "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name='level3_installed_app_snapshots'",
        [], |row| row.get(0),
    )?;
    for required in [
        "authorization_id",
        "inventory_fingerprint",
        "payload_sha256",
        "UNIQUE(authorization_id)",
    ] {
        if !sql.contains(required) {
            return Err(SnapshotError::Integrity);
        }
    }
    Ok(())
}

fn verify_level4_schema(connection: &Connection) -> Result<(), SnapshotError> {
    let sql: String = connection.query_row(
        "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name='level4_web_snapshots'",
        [],
        |row| row.get(0),
    )?;
    for required in [
        "authorization_id",
        "target_fingerprint",
        "payload_sha256",
        "UNIQUE(authorization_id)",
    ] {
        if !sql.contains(required) {
            return Err(SnapshotError::Integrity);
        }
    }
    Ok(())
}

fn verify_level5_schema(connection: &Connection) -> Result<(), SnapshotError> {
    for (table, required) in [
        (
            "level5_investigation_snapshots",
            &["payload_sha256", "revision", "PRIMARY KEY"][..],
        ),
        (
            "level5_correlation_runs",
            &["observations_sha256", "result_sha256", "PRIMARY KEY"][..],
        ),
        (
            "level5_entities",
            &["identity_kind", "identity_value", "FOREIGN KEY"][..],
        ),
        (
            "level5_findings",
            &["vulnerability_id", "artifact_sha256", "FOREIGN KEY"][..],
        ),
        (
            "level5_evidence",
            &["evidence_id", "entity_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_relationships",
            &[
                "from_entity",
                "to_entity",
                "rule_version",
                "payload_sha256",
                "FOREIGN KEY",
            ][..],
        ),
        (
            "level5_relationship_findings",
            &["edge_id", "finding_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_relationship_evidence",
            &["edge_id", "evidence_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_clusters",
            &[
                "cluster_type",
                "payload_json",
                "payload_sha256",
                "FOREIGN KEY",
            ][..],
        ),
        (
            "level5_cluster_entities",
            &["cluster_id", "entity_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_cluster_findings",
            &["cluster_id", "finding_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_cases",
            &[
                "status",
                "priority",
                "payload_json",
                "payload_sha256",
                "FOREIGN KEY",
            ][..],
        ),
        (
            "level5_case_clusters",
            &["case_id", "cluster_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_case_entities",
            &["case_id", "entity_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_case_findings",
            &["case_id", "finding_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_case_evidence",
            &["case_id", "evidence_id", "FOREIGN KEY"][..],
        ),
        (
            "level5_case_timeline",
            &["sequence", "timestamp", "FOREIGN KEY"][..],
        ),
    ] {
        let sql: String = connection
            .query_row(
                "SELECT coalesce(sql,'') FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| SnapshotError::Integrity)?;
        if required.iter().any(|fragment| !sql.contains(fragment)) {
            return Err(SnapshotError::Integrity);
        }
    }
    for index in [
        "idx_level5_entity_kind",
        "idx_level5_entity_identity",
        "idx_level5_finding_vulnerability",
        "idx_level5_finding_hash",
        "idx_level5_finding_purl",
        "idx_level5_finding_cpe",
        "idx_level5_relationship_from",
        "idx_level5_relationship_to",
        "idx_level5_relationship_finding",
        "idx_level5_cluster_type",
        "idx_level5_case_status",
        "idx_level5_timeline",
    ] {
        let count: u32 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name=?1",
            [index],
            |row| row.get(0),
        )?;
        if count != 1 {
            return Err(SnapshotError::Integrity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "edy-level0-snapshot-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn snapshot_survives_reopen_and_conflicts_fail_closed() {
        let directory = TempDir::new();
        let path = directory.0.join("snapshots.sqlite3");
        let scan = "018f4c2a-1d3b-7abc-8def-0123456789a1";
        let mut store = Level0SnapshotStore::open(&path).unwrap();
        store.create(scan, br#"{"state":"queued"}"#).unwrap();
        let first = store.load(scan).unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(store.list_ids(0, 10).unwrap(), vec![scan]);
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(
            store
                .replace(scan, first.revision, br#"{"state":"running"}"#)
                .unwrap(),
            2
        );
        assert!(matches!(
            store.replace(scan, 1, br#"{"state":"failed"}"#),
            Err(SnapshotError::Conflict)
        ));
        drop(store);
        let reopened = Level0SnapshotStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(scan).unwrap().payload,
            br#"{"state":"running"}"#
        );
    }

    #[test]
    fn invalid_ids_relative_paths_and_oversized_payloads_are_refused() {
        let directory = TempDir::new();
        assert!(matches!(
            Level0SnapshotStore::open(Path::new("relative.sqlite3")),
            Err(SnapshotError::InvalidInput)
        ));
        let mut store = Level0SnapshotStore::open(&directory.0.join("db.sqlite3")).unwrap();
        assert!(store.create("not-a-scan", b"{}").is_err());
        assert!(
            store
                .create(
                    "018f4c2a-1d3b-7abc-8def-0123456789a1",
                    &vec![b'x'; MAX_SNAPSHOT_BYTES + 1]
                )
                .is_err()
        );
    }

    #[test]
    fn level0_database_migrates_forward_and_preserves_snapshots() {
        let directory = TempDir::new();
        let path = directory.0.join("upgrade.sqlite3");
        let scan0 = "018f4c2a-1d3b-7abc-8def-0123456789a1";
        let scan1 = "018f4c2a-1d3b-7abc-8def-0123456789a2";
        let target = "018f4c2a-1d3b-7abc-8def-0123456789a3";
        let auth = "018f4c2a-1d3b-7abc-8def-0123456789a4";
        let mut level0 = Level0SnapshotStore::open(&path).unwrap();
        level0.create(scan0, br#"{"state":"completed"}"#).unwrap();
        drop(level0);
        let mut level1 = Level1SnapshotStore::open(&path).unwrap();
        level1
            .create(
                scan1,
                target,
                auth,
                br#"{"state":"partial","secret_preview":"EDY_************"}"#,
            )
            .unwrap();
        assert_eq!(level1.load(scan1).unwrap().revision, 1);
        drop(level1);
        let level0 = Level0SnapshotStore::open(&path).unwrap();
        assert_eq!(
            level0.load(scan0).unwrap().payload,
            br#"{"state":"completed"}"#
        );
    }

    #[test]
    fn level1_database_rejects_and_never_contains_fixture_secret_plaintext() {
        let directory = TempDir::new();
        let path = directory.0.join("redaction.sqlite3");
        let mut store = Level1SnapshotStore::open(&path).unwrap();
        let scan = "018f4c2a-1d3b-7abc-8def-0123456789a1";
        let target = "018f4c2a-1d3b-7abc-8def-0123456789a2";
        let auth = "018f4c2a-1d3b-7abc-8def-0123456789a3";
        let full_secret = ["EDY_FAKE_TEST_TOKEN_", "REPOSITORY_A_ONLY"].concat();
        let unsafe_payload = format!(r#"{{"value":"{full_secret}"}}"#);
        assert!(
            store
                .create(scan, target, auth, unsafe_payload.as_bytes())
                .is_err()
        );
        store
            .create(scan, target, auth, br#"{"value":"EDY_************"}"#)
            .unwrap();
        assert!(!store.contains_bytes(b"EDY_FAKE_TEST_TOKEN_").unwrap());
    }

    #[test]
    fn level2_migrates_fresh_level0_and_level1_databases_and_reloads_safely() {
        for seed in [0_u8, 1, 2] {
            let directory = TempDir::new();
            let path = directory.0.join(format!("upgrade-{seed}.sqlite3"));
            let scan0 = "018f4c2a-1d3b-7abc-8def-0123456789a1";
            let scan1 = "018f4c2a-1d3b-7abc-8def-0123456789a2";
            let scan2 = "018f4c2a-1d3b-7abc-8def-0123456789a3";
            let target = "018f4c2a-1d3b-7abc-8def-0123456789a4";
            let auth = "018f4c2a-1d3b-7abc-8def-0123456789a5";
            if seed >= 1 {
                let mut level0 = Level0SnapshotStore::open(&path).unwrap();
                level0.create(scan0, br#"{"state":"completed"}"#).unwrap();
            }
            if seed >= 2 {
                let mut level1 = Level1SnapshotStore::open(&path).unwrap();
                level1
                    .create(scan1, target, auth, br#"{"state":"partial"}"#)
                    .unwrap();
            }
            let mut level2 = Level2SnapshotStore::open(&path).unwrap();
            level2
                .create(
                    scan2,
                    target,
                    auth,
                    &"a".repeat(64),
                    br#"{"state":"partial","hashes":{"sha256":"safe"}}"#,
                )
                .unwrap();
            assert_eq!(level2.load(scan2).unwrap().revision, 1);
            drop(level2);
            assert_eq!(
                Level2SnapshotStore::open(&path)
                    .unwrap()
                    .load(scan2)
                    .unwrap()
                    .revision,
                1
            );
            assert_eq!(
                Connection::open(&path)
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                3
            );
        }
    }

    #[test]
    fn level2_snapshot_contains_no_raw_file_bytes_or_fixture_secrets() {
        let directory = TempDir::new();
        let path = directory.0.join("level2.sqlite3");
        let mut store = Level2SnapshotStore::open(&path).unwrap();
        store
            .create(
                "018f4c2a-1d3b-7abc-8def-0123456789a1",
                "018f4c2a-1d3b-7abc-8def-0123456789a2",
                "018f4c2a-1d3b-7abc-8def-0123456789a3",
                &"b".repeat(64),
                br#"{"classification":"generic_file","bytes_persisted":false}"#,
            )
            .unwrap();
        assert!(!store.contains_bytes(b"EDY_LEVEL2_RAW_FILE_BYTES").unwrap());
        assert!(
            store
                .create(
                    "018f4c2a-1d3b-7abc-8def-0123456789a4",
                    "018f4c2a-1d3b-7abc-8def-0123456789a5",
                    "018f4c2a-1d3b-7abc-8def-0123456789a6",
                    &"c".repeat(64),
                    br#"{"raw":"EDY_FAKE_TEST_TOKEN_FORBIDDEN"}"#,
                )
                .is_err()
        );
    }

    #[test]
    fn level3_migrates_fresh_and_levels_zero_one_two_without_losing_prior_snapshots() {
        for seed in [0_u8, 1, 2, 3] {
            let directory = TempDir::new();
            let path = directory.0.join(format!("level3-upgrade-{seed}.sqlite3"));
            let ids = [
                "018f4c2a-1d3b-7abc-8def-0123456789b0",
                "018f4c2a-1d3b-7abc-8def-0123456789b1",
                "018f4c2a-1d3b-7abc-8def-0123456789b2",
                "018f4c2a-1d3b-7abc-8def-0123456789b3",
                "018f4c2a-1d3b-7abc-8def-0123456789b4",
                "018f4c2a-1d3b-7abc-8def-0123456789b5",
            ];
            if seed >= 1 {
                let mut store = Level0SnapshotStore::open(&path).unwrap();
                store.create(ids[0], br#"{"level":0}"#).unwrap();
            }
            if seed >= 2 {
                let mut store = Level1SnapshotStore::open(&path).unwrap();
                store
                    .create(ids[1], ids[4], ids[5], br#"{"level":1}"#)
                    .unwrap();
            }
            if seed >= 3 {
                let mut store = Level2SnapshotStore::open(&path).unwrap();
                store
                    .create(ids[2], ids[4], ids[5], &"a".repeat(64), br#"{"level":2}"#)
                    .unwrap();
            }
            let mut store = Level3SnapshotStore::open(&path).unwrap();
            store.create(ids[3],ids[4],&"b".repeat(64),br#"{"schema":"INSTALLED_APPLICATION_SNAPSHOT_V1","uninstall_strings_persisted":false}"#).unwrap();
            assert_eq!(store.load(ids[3]).unwrap().revision, 1);
            assert_eq!(
                Connection::open(&path)
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                4
            );
            if seed >= 1 {
                assert_eq!(
                    Level0SnapshotStore::open(&path)
                        .unwrap()
                        .load(ids[0])
                        .unwrap()
                        .revision,
                    1
                )
            }
            if seed >= 2 {
                assert_eq!(
                    Level1SnapshotStore::open(&path)
                        .unwrap()
                        .load(ids[1])
                        .unwrap()
                        .revision,
                    1
                )
            }
            if seed >= 3 {
                assert_eq!(
                    Level2SnapshotStore::open(&path)
                        .unwrap()
                        .load(ids[2])
                        .unwrap()
                        .revision,
                    1
                )
            }
        }
    }

    #[test]
    fn level3_snapshot_rejects_secret_marker_and_detects_integrity_tampering() {
        let directory = TempDir::new();
        let path = directory.0.join("level3.sqlite3");
        let mut store = Level3SnapshotStore::open(&path).unwrap();
        assert!(
            store
                .create(
                    "018f4c2a-1d3b-7abc-8def-0123456789c0",
                    "018f4c2a-1d3b-7abc-8def-0123456789c1",
                    &"c".repeat(64),
                    br#"{"token":"EDY_FAKE_TEST_TOKEN_FORBIDDEN"}"#
                )
                .is_err()
        );
        store
            .create(
                "018f4c2a-1d3b-7abc-8def-0123456789c0",
                "018f4c2a-1d3b-7abc-8def-0123456789c1",
                &"c".repeat(64),
                br#"{"safe":true}"#,
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE level3_installed_app_snapshots SET payload_sha256=?1",
                ["d".repeat(64)],
            )
            .unwrap();
        assert!(matches!(
            store.load("018f4c2a-1d3b-7abc-8def-0123456789c0"),
            Err(SnapshotError::Integrity)
        ));
    }

    #[test]
    fn level4_migrates_v0_through_v4_and_rejects_query_and_cookie_secrets() {
        for seed in [0_u8, 1, 2, 3, 4] {
            let directory = TempDir::new();
            let path = directory.0.join(format!("level4-upgrade-{seed}.sqlite3"));
            let ids = [
                "018f4c2a-1d3b-7abc-8def-0123456789d0",
                "018f4c2a-1d3b-7abc-8def-0123456789d1",
                "018f4c2a-1d3b-7abc-8def-0123456789d2",
                "018f4c2a-1d3b-7abc-8def-0123456789d3",
                "018f4c2a-1d3b-7abc-8def-0123456789d4",
                "018f4c2a-1d3b-7abc-8def-0123456789d5",
                "018f4c2a-1d3b-7abc-8def-0123456789d6",
            ];
            if seed >= 1 {
                Level0SnapshotStore::open(&path).unwrap();
            }
            if seed >= 2 {
                Level1SnapshotStore::open(&path).unwrap();
            }
            if seed >= 3 {
                Level2SnapshotStore::open(&path).unwrap();
            }
            if seed >= 4 {
                Level3SnapshotStore::open(&path).unwrap();
            }
            let mut store = Level4SnapshotStore::open(&path).unwrap();
            assert!(
                store
                    .create(
                        ids[0],
                        ids[1],
                        &"a".repeat(64),
                        br#"{"query":"EDY_FAKE_QUERY_SECRET_LEVEL4"}"#
                    )
                    .is_err()
            );
            assert!(
                store
                    .create(
                        ids[2],
                        ids[3],
                        &"b".repeat(64),
                        br#"{"cookie":"EDY_FAKE_COOKIE_SECRET_LEVEL4"}"#
                    )
                    .is_err()
            );
            store.create(ids[4],ids[5],&"c".repeat(64),br#"{"target":"https://example.com/?token=[REDACTED]","cookie_value_retained":false}"#).unwrap();
            assert_eq!(store.load(ids[4]).unwrap().revision, 1);
            assert!(
                !store
                    .contains_bytes(b"EDY_FAKE_QUERY_SECRET_LEVEL4")
                    .unwrap()
            );
            assert!(
                !store
                    .contains_bytes(b"EDY_FAKE_COOKIE_SECRET_LEVEL4")
                    .unwrap()
            );
            assert_eq!(
                Connection::open(&path)
                    .unwrap()
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                5
            );
        }
    }

    #[test]
    fn level5_migrates_level4_persists_atomically_and_rejects_all_plaintext_markers() {
        let d = TempDir::new();
        let p = d.0.join("level5.sqlite3");
        Level4SnapshotStore::open(&p).unwrap();
        let mut s = Level5SnapshotStore::open(&p).unwrap();
        let id = "018f4c2a-1d3b-7abc-8def-0123456789e0";
        for marker in [
            "EDY_FAKE_SECRET_LEVEL5",
            "EDY_FAKE_COOKIE_LEVEL5",
            "EDY_FAKE_QUERY_LEVEL5",
        ] {
            assert!(
                s.create(id, format!("{{\"unsafe\":\"{marker}\"}}").as_bytes())
                    .is_err()
            );
        }
        s.create(
            id,
            br#"{"schema":"LEVEL5_INVESTIGATION_V1","redacted":true}"#,
        )
        .unwrap();
        assert_eq!(s.load(id).unwrap().revision, 1);
        assert_eq!(
            s.replace(
                id,
                1,
                br#"{"schema":"LEVEL5_INVESTIGATION_V1","redacted":true,"revision":2}"#
            )
            .unwrap(),
            2
        );
        assert!(matches!(
            s.replace(id, 1, br#"{"safe":true}"#),
            Err(SnapshotError::Conflict)
        ));
        assert_eq!(
            Connection::open(&p)
                .unwrap()
                .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            6
        );
    }

    fn level5_finding(id: &str, target: &str, cve: &str) -> CorrelationFinding {
        use edy_core::{IdentifierKind, StrongIdentity, TargetType};
        CorrelationFinding {
            finding_id: id.into(),
            target_id: target.into(),
            target_type: TargetType::Repository,
            target_identity: StrongIdentity::new(IdentifierKind::StableTarget, target).unwrap(),
            affected_identity: StrongIdentity::new(
                IdentifierKind::Purl,
                format!("pkg:npm/{target}@1.0.0"),
            )
            .unwrap(),
            vulnerability_id: Some(cve.into()),
            artifact_sha256: None,
            purl: Some(format!("pkg:npm/{target}@1.0.0")),
            cpe: None,
            web_origin: None,
            web_domain: None,
            evidence_ids: vec![format!("evidence-{id}")],
            source_scans: vec![format!("scan-{id}")],
            severity_points: 70,
            kev: true,
            epss_basis_points: Some(8000),
            provider_available: true,
            parser_certain: true,
            conflicting_evidence: false,
            first_seen: "2099-01-01T00:00:00Z".into(),
            last_seen: "2099-01-02T00:00:00Z".into(),
            occurrence_count: 1,
            reopened: false,
        }
    }

    #[test]
    fn level5_relational_promotion_reload_and_replay_are_atomic_and_deterministic() {
        use edy_core::{GraphLimits, correlate_investigation};
        let d = TempDir::new();
        let p = d.0.join("level5-relational.sqlite3");
        Level0SnapshotStore::open(&p).unwrap();
        let mut s = Level5SnapshotStore::open(&p).unwrap();
        let run_id = "018f4c2a-1d3b-7abc-8def-0123456789e1";
        let observations = vec![
            level5_finding("finding-a", "package-a", "CVE-2099-1001"),
            level5_finding("finding-b", "package-b", "CVE-2099-1001"),
        ];
        let result =
            correlate_investigation(observations.clone(), GraphLimits::default(), || false)
                .unwrap();
        s.promote(run_id, &observations, &result).unwrap();
        assert_eq!(s.load_result(run_id).unwrap(), result);
        assert_eq!(s.list_run_ids(0, 10).unwrap(), vec![run_id]);
        assert_eq!(s.list_clusters(run_id, 0, 10).unwrap(), result.clusters);
        assert_eq!(s.list_cases(run_id, 0, 10).unwrap(), result.suggested_cases);
        let replay = correlate_investigation(
            s.load_observations(run_id).unwrap(),
            GraphLimits::default(),
            || false,
        )
        .unwrap();
        assert_eq!(replay, result);
        let foreign_keys: u32 = s
            .connection
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        let dangling: u32 = s.connection.query_row("SELECT count(*) FROM level5_relationships r LEFT JOIN level5_entities e ON e.run_id=r.run_id AND e.entity_id=r.from_entity WHERE e.entity_id IS NULL", [], |r| r.get(0)).unwrap();
        assert_eq!(dangling, 0);
        let relationship_finding_rows: u32 = s
            .connection
            .query_row(
                "SELECT count(*) FROM level5_relationship_findings",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let relationship_evidence_rows: u32 = s
            .connection
            .query_row(
                "SELECT count(*) FROM level5_relationship_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            relationship_finding_rows,
            result
                .edges
                .iter()
                .map(|edge| edge.finding_ids.len() as u32)
                .sum::<u32>()
        );
        assert_eq!(
            relationship_evidence_rows,
            result
                .edges
                .iter()
                .map(|edge| edge.evidence_ids.len() as u32)
                .sum::<u32>()
        );
        assert!(
            s.connection
                .execute(
                    "INSERT INTO level5_relationship_evidence(run_id,edge_id,evidence_id) VALUES(?1,?2,?3)",
                    params![run_id, result.edges[0].edge_id, "missing-evidence"]
                )
                .is_err()
        );
        let foreign_key_violations: u32 = s
            .connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_violations, 0);
        let mut case = s.list_cases(run_id, 0, 10).unwrap().remove(0);
        case.transition(
            edy_core::CaseStatus::Open,
            "2099-01-03T00:00:00Z",
            "user",
            "Review approved",
        )
        .unwrap();
        s.replace_case(run_id, &case).unwrap();
        assert_eq!(s.get_case(run_id, &case.case_id).unwrap(), case);
        let mut forged = case.clone();
        forged.finding_ids.push("foreign-finding".into());
        assert!(matches!(
            s.replace_case(run_id, &forged),
            Err(SnapshotError::Integrity)
        ));
        assert!(s.promote(run_id, &observations, &result).is_err());
    }

    #[test]
    fn level5_promotion_rejects_a_result_not_derived_from_its_observations() {
        use edy_core::{GraphLimits, correlate_investigation};
        let d = TempDir::new();
        let p = d.0.join("level5-forged.sqlite3");
        let mut s = Level5SnapshotStore::open(&p).unwrap();
        let observations = vec![level5_finding("finding-a", "package-a", "CVE-2099-1001")];
        let mut result =
            correlate_investigation(observations.clone(), GraphLimits::default(), || false)
                .unwrap();
        result.findings_preserved = 999;
        assert!(matches!(
            s.promote(
                "018f4c2a-1d3b-7abc-8def-0123456789e3",
                &observations,
                &result
            ),
            Err(SnapshotError::Integrity)
        ));
        assert!(s.list_run_ids(0, 10).unwrap().is_empty());
    }

    #[test]
    fn level5_partial_and_cancelled_results_never_promote() {
        use edy_core::{GraphLimits, correlate_investigation};
        let d = TempDir::new();
        let p = d.0.join("level5-no-partial.sqlite3");
        let mut s = Level5SnapshotStore::open(&p).unwrap();
        let observations = vec![level5_finding("finding-a", "package-a", "CVE-2099-1001")];
        let cancelled =
            correlate_investigation(observations.clone(), GraphLimits::default(), || true).unwrap();
        assert!(
            s.promote(
                "018f4c2a-1d3b-7abc-8def-0123456789e2",
                &observations,
                &cancelled
            )
            .is_err()
        );
        assert!(s.list_run_ids(0, 10).unwrap().is_empty());
    }

    #[test]
    fn level5_migrates_fresh_and_every_prior_schema_without_losing_level0_data() {
        for seed in 0_u8..=5 {
            let directory = TempDir::new();
            let path = directory.0.join(format!("level5-upgrade-{seed}.sqlite3"));
            let scan_id = "018f4c2a-1d3b-7abc-8def-0123456789ef";
            if seed >= 1 {
                let mut level0 = Level0SnapshotStore::open(&path).unwrap();
                level0.create(scan_id, br#"{"state":"complete"}"#).unwrap();
            }
            if seed >= 2 {
                Level1SnapshotStore::open(&path).unwrap();
            }
            if seed >= 3 {
                Level2SnapshotStore::open(&path).unwrap();
            }
            if seed >= 4 {
                Level3SnapshotStore::open(&path).unwrap();
            }
            if seed >= 5 {
                Level4SnapshotStore::open(&path).unwrap();
            }
            let store = Level5SnapshotStore::open(&path).unwrap();
            let version: u32 = store
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            let violations: u32 = store
                .connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(version, 6);
            assert_eq!(violations, 0);
            drop(store);
            if seed >= 1 {
                assert_eq!(
                    Level0SnapshotStore::open(&path)
                        .unwrap()
                        .load(scan_id)
                        .unwrap()
                        .payload,
                    br#"{"state":"complete"}"#
                );
            }
        }
    }

    #[test]
    fn level5_six_hundred_findings_promote_and_retrieve_in_bounded_pages() {
        use edy_core::{GraphLimits, correlate_investigation};
        let directory = TempDir::new();
        let path = directory.0.join("level5-scale.sqlite3");
        let observations = (0..600)
            .map(|index| {
                level5_finding(
                    &format!("finding-{index:03}"),
                    &format!("package-{index:03}"),
                    &format!("CVE-2099-{:04}", 1000 + index / 2),
                )
            })
            .collect::<Vec<_>>();
        let result =
            correlate_investigation(observations.clone(), GraphLimits::default(), || false)
                .unwrap();
        assert_eq!(result.findings_preserved, 600);
        assert_eq!(result.clusters.len(), 300);
        let run_id = "018f4c2a-1d3b-7abc-8def-0123456789ed";
        let mut store = Level5SnapshotStore::open(&path).unwrap();
        store.promote(run_id, &observations, &result).unwrap();
        assert_eq!(store.list_clusters(run_id, 0, 100).unwrap().len(), 100);
        assert_eq!(store.list_clusters(run_id, 100, 100).unwrap().len(), 100);
        assert_eq!(store.list_cases(run_id, 0, 100).unwrap().len(), 100);
        assert_eq!(store.list_cases(run_id, 200, 100).unwrap().len(), 100);
        assert_eq!(store.load_result(run_id).unwrap(), result);
    }
}
