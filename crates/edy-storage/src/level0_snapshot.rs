//! Opaque, integrity-checked Level 0 aggregate snapshots.
//!
//! This is deliberately separate from the frozen relational schema. The application service owns
//! the typed payload; this module provides only atomic SQLite durability and optimistic revisions.

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
        if version > 5 {
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
        if version > 5 {
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
        if version > 5 {
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
        if version > 5 {
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
        if version > 5 {
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
}
