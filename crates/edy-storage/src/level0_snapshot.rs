//! Opaque, integrity-checked Level 0 aggregate snapshots.
//!
//! This is deliberately separate from the frozen relational schema. The application service owns
//! the typed payload; this module provides only atomic SQLite durability and optimistic revisions.

use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS level0_snapshots (
  scan_id TEXT PRIMARY KEY CHECK(length(scan_id) = 36),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  payload BLOB NOT NULL CHECK(length(payload) BETWEEN 2 AND 8388608),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
PRAGMA user_version=1;
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
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 1 {
            return Err(SnapshotError::Integrity);
        }
        connection.execute_batch(SCHEMA)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "edy-level0-snapshot-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
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
}
