//! Integrity-checked Level 6 persistence. Backup bytes stay in the controlled filesystem store.

use crate::level0_snapshot::{Level5SnapshotStore, SnapshotError};
use edy_remediation::{RemediationSnapshot, valid_sha256, validate_plan};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const MAX_PAYLOAD: usize = 2 * 1024 * 1024;
const LEVEL6_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS level6_remediation_plans (
  action_id TEXT PRIMARY KEY CHECK(length(action_id) = 71 AND substr(action_id,1,7) = 'rma-v1-'),
  plan_id TEXT NOT NULL CHECK(length(plan_id) BETWEEN 1 AND 128),
  plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
  state TEXT NOT NULL CHECK(length(state) BETWEEN 1 AND 64),
  payload_json BLOB NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 2097152),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
CREATE INDEX IF NOT EXISTS idx_level6_plan_id ON level6_remediation_plans(plan_id);
CREATE TABLE IF NOT EXISTS level6_authorizations (
  authorization_id TEXT PRIMARY KEY CHECK(length(authorization_id) = 36),
  action_id TEXT NOT NULL REFERENCES level6_remediation_plans(action_id) ON DELETE CASCADE,
  token_sha256 TEXT NOT NULL CHECK(length(token_sha256) = 64),
  plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
  expires_at_unix INTEGER NOT NULL,
  used INTEGER NOT NULL CHECK(used IN (0,1))
);
CREATE TABLE IF NOT EXISTS level6_action_receipts (
  action_id TEXT PRIMARY KEY REFERENCES level6_remediation_plans(action_id) ON DELETE CASCADE,
  payload_json BLOB NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 2097152),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
CREATE TABLE IF NOT EXISTS level6_verification_results (
  action_id TEXT PRIMARY KEY REFERENCES level6_remediation_plans(action_id) ON DELETE CASCADE,
  payload_json BLOB NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 2097152),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
CREATE TABLE IF NOT EXISTS level6_rollback_receipts (
  action_id TEXT PRIMARY KEY REFERENCES level6_remediation_plans(action_id) ON DELETE CASCADE,
  payload_json BLOB NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 2097152),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
CREATE TABLE IF NOT EXISTS level6_recovery_journal (
  action_id TEXT PRIMARY KEY REFERENCES level6_remediation_plans(action_id) ON DELETE CASCADE,
  payload_json BLOB NOT NULL CHECK(length(payload_json) BETWEEN 2 AND 2097152),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
);
"#;

pub struct Level6SnapshotStore {
    connection: Connection,
}

impl Level6SnapshotStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        if !path.is_absolute() || path.parent().is_some_and(|parent| !parent.is_dir()) {
            return Err(SnapshotError::InvalidInput);
        }
        let version = if path.exists() {
            let check = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            check.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?
        } else {
            0
        };
        if version > 7 {
            return Err(SnapshotError::Integrity);
        }
        if version < 7 {
            // Reuse the verified forward-only Level 0–5 schema promotion before adding v7.
            drop(Level5SnapshotStore::open(path)?);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(LEVEL6_SCHEMA)?;
        transaction.execute_batch("PRAGMA user_version=7;")?;
        transaction.commit()?;
        verify(&connection)?;
        Ok(Self { connection })
    }

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
        verify(&connection)?;
        Ok(Self { connection })
    }

    pub fn save(&mut self, snapshot: &RemediationSnapshot) -> Result<(), SnapshotError> {
        validate_snapshot(snapshot)?;
        let action_id = &snapshot.plan.actions[0].action_id;
        let payload = bounded_json(snapshot)?;
        reject_secret(&payload)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO level6_remediation_plans(action_id,plan_id,plan_sha256,state,payload_json,payload_sha256) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(action_id) DO UPDATE SET plan_id=excluded.plan_id,plan_sha256=excluded.plan_sha256,state=excluded.state,payload_json=excluded.payload_json,payload_sha256=excluded.payload_sha256",
            params![action_id, snapshot.plan.plan_id, snapshot.plan.plan_sha256, format!("{:?}", snapshot.state), payload, digest(&payload)],
        )?;
        transaction.execute(
            "DELETE FROM level6_authorizations WHERE action_id=?1",
            [action_id],
        )?;
        for authorization in &snapshot.authorizations {
            if !valid_sha256(&authorization.token_sha256) {
                return Err(SnapshotError::InvalidInput);
            }
            transaction.execute("INSERT INTO level6_authorizations(authorization_id,action_id,token_sha256,plan_sha256,expires_at_unix,used) VALUES(?1,?2,?3,?4,?5,?6)", params![authorization.authorization_id,action_id,authorization.token_sha256,authorization.plan_sha256,authorization.expires_at_unix,authorization.used])?;
        }
        persist_optional(
            &transaction,
            "level6_action_receipts",
            action_id,
            snapshot.receipt.as_ref(),
        )?;
        persist_optional(
            &transaction,
            "level6_verification_results",
            action_id,
            snapshot.verification.as_ref(),
        )?;
        persist_optional(
            &transaction,
            "level6_rollback_receipts",
            action_id,
            snapshot.rollback_receipt.as_ref(),
        )?;
        persist_optional(
            &transaction,
            "level6_recovery_journal",
            action_id,
            snapshot.journal.as_ref(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get(&self, action_id: &str) -> Result<RemediationSnapshot, SnapshotError> {
        validate_action_id(action_id)?;
        let row = self.connection.query_row("SELECT payload_json,payload_sha256 FROM level6_remediation_plans WHERE action_id=?1", [action_id], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,String>(1)?))).optional()?;
        let (payload, expected) = row.ok_or(SnapshotError::NotFound)?;
        if digest(&payload) != expected {
            return Err(SnapshotError::Integrity);
        }
        let snapshot: RemediationSnapshot =
            serde_json::from_slice(&payload).map_err(|_| SnapshotError::Integrity)?;
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    pub fn list(&self, offset: u32, limit: u32) -> Result<Vec<RemediationSnapshot>, SnapshotError> {
        if offset > 10_000 || !(1..=100).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement = self.connection.prepare("SELECT action_id FROM level6_remediation_plans ORDER BY plan_id DESC,action_id LIMIT ?1 OFFSET ?2")?;
        let ids = statement
            .query_map(params![limit, offset], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.get(id)).collect()
    }

    pub fn contains_bytes(&self, needle: &[u8]) -> Result<bool, SnapshotError> {
        if needle.is_empty() || needle.len() > 4096 {
            return Err(SnapshotError::InvalidInput);
        }
        for table in [
            "level6_remediation_plans",
            "level6_action_receipts",
            "level6_verification_results",
            "level6_rollback_receipts",
            "level6_recovery_journal",
        ] {
            let sql = format!("SELECT payload_json FROM {table}");
            let mut statement = self.connection.prepare(&sql)?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                if row?.windows(needle.len()).any(|window| window == needle) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn persist_optional<T: serde::Serialize>(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    action_id: &str,
    value: Option<&T>,
) -> Result<(), SnapshotError> {
    let Some(value) = value else {
        return Ok(());
    };
    let payload = bounded_json(value)?;
    reject_secret(&payload)?;
    let sql = format!(
        "INSERT INTO {table}(action_id,payload_json,payload_sha256) VALUES(?1,?2,?3) ON CONFLICT(action_id) DO UPDATE SET payload_json=excluded.payload_json,payload_sha256=excluded.payload_sha256"
    );
    transaction.execute(&sql, params![action_id, payload, digest(&payload)])?;
    Ok(())
}

fn bounded_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, SnapshotError> {
    let payload = serde_json::to_vec(value).map_err(|_| SnapshotError::InvalidInput)?;
    if !(2..=MAX_PAYLOAD).contains(&payload.len()) {
        return Err(SnapshotError::InvalidInput);
    }
    Ok(payload)
}
fn validate_snapshot(snapshot: &RemediationSnapshot) -> Result<(), SnapshotError> {
    validate_plan(&snapshot.plan).map_err(|_| SnapshotError::Integrity)?;
    if snapshot.plan.actions.len() != 1 || snapshot.timeline_safe.len() > 128 {
        return Err(SnapshotError::InvalidInput);
    }
    if snapshot
        .timeline_safe
        .iter()
        .any(|value| value.len() > 512 || value.chars().any(char::is_control))
    {
        return Err(SnapshotError::InvalidInput);
    }
    Ok(())
}
fn validate_action_id(value: &str) -> Result<(), SnapshotError> {
    let suffix = value
        .strip_prefix("rma-v1-")
        .ok_or(SnapshotError::InvalidInput)?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(SnapshotError::InvalidInput);
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn reject_secret(payload: &[u8]) -> Result<(), SnapshotError> {
    let lower = String::from_utf8_lossy(payload).to_ascii_lowercase();
    if [
        "edy_fake_secret_level6",
        "edy_fake_cookie_level6",
        "edy_fake_query_level6",
        "authorization: bearer",
        "private key-----",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        Err(SnapshotError::InvalidInput)
    } else {
        Ok(())
    }
}
fn verify(connection: &Connection) -> Result<(), SnapshotError> {
    if connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))? != 7
        || connection.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))? != "ok"
    {
        return Err(SnapshotError::Integrity);
    }
    for table in [
        "level6_remediation_plans",
        "level6_authorizations",
        "level6_action_receipts",
        "level6_verification_results",
        "level6_rollback_receipts",
        "level6_recovery_journal",
    ] {
        let found: u32 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if found != 1 {
            return Err(SnapshotError::Integrity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_remediation::*;
    use std::fs;

    fn path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "edy-level6-storage-{label}-{}-{}.sqlite3",
            std::process::id(),
            uuid::Uuid::now_v7()
        ))
    }
    fn sample() -> RemediationSnapshot {
        let edit = ExactTextEdit::contract(sha256_hex(b"before"), sha256_hex(b"after"), 1, 1);
        let mut action = RemediationAction {
            action_id: String::new(),
            finding_id: "finding".into(),
            case_id: None,
            target_id: "target".into(),
            kind: RemediationActionKind::ExactTextConfigPatch,
            safety_class: RemediationSafetyClass::TestOnlyReversible,
            rule_id: EXACT_TEXT_CONFIG_RULE_ID.into(),
            rule_version: 1,
            explanation_safe: "safe".into(),
            precondition: RemediationPrecondition {
                canonical_path: "D:/synthetic/security-config.toml".into(),
                stable_identity: "file-v1".into(),
                expected_sha256: sha256_hex(b"file"),
                expected_size: 4,
                expected_anchor_sha256: sha256_hex(b"before"),
            },
            edit: Some(edit),
            verification: VerificationPlan {
                scanner_id: "scanner".into(),
                original_fingerprint: "finding".into(),
                required_checks: vec!["check".into()],
                expected_post_sha256: sha256_hex(b"patched"),
                coverage_required: true,
                manual_scope: None,
            },
            rollback: RollbackPlan {
                eligible: true,
                required_post_sha256: sha256_hex(b"patched"),
                explanation_safe: "bounded".into(),
            },
        };
        action.action_id = deterministic_action_id(&action).unwrap();
        let mut plan = RemediationPlan {
            plan_id: uuid::Uuid::now_v7().to_string(),
            plan_sha256: String::new(),
            finding_id: "finding".into(),
            case_id: None,
            created_at_utc: "2099-01-01T00:00:00Z".into(),
            actions: vec![action],
        };
        plan.plan_sha256 = calculate_plan_sha256(&plan).unwrap();
        RemediationSnapshot {
            plan,
            state: RemediationActionState::Planned,
            finding_lifecycle: RemediationFindingLifecycle::Investigating,
            case_lifecycle: None,
            preview: None,
            authorizations: vec![],
            receipt: None,
            verification: None,
            rollback_receipt: None,
            journal: None,
            timeline_safe: vec!["plan_created".into()],
        }
    }

    #[test]
    fn fresh_and_v1_through_v6_migrate_to_v7() {
        for version in 0..=6 {
            let path = path(&format!("v{version}"));
            if version > 0 {
                let connection = Connection::open(&path).unwrap();
                connection
                    .pragma_update(None, "user_version", version)
                    .unwrap();
            }
            let store = Level6SnapshotStore::open(&path).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                7
            );
            drop(store);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn snapshots_round_trip_without_raw_authority_or_secret_markers() {
        let path = path("roundtrip");
        let mut store = Level6SnapshotStore::open(&path).unwrap();
        let snapshot = sample();
        let id = snapshot.plan.actions[0].action_id.clone();
        store.save(&snapshot).unwrap();
        assert_eq!(store.get(&id).unwrap(), snapshot);
        assert!(!store.contains_bytes(b"EDY_FAKE_SECRET_LEVEL6").unwrap());
        drop(store);
        fs::remove_file(path).unwrap();
    }
}
