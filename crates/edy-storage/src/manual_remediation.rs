//! Production plans/rescan metadata. No file backup, rollback or write-recovery state.
use crate::level0_snapshot::{Level5SnapshotStore, SnapshotError};
use edy_core::{CaseStatus, CorrelationFinding, InvestigationCase, TimelineEvent};
use edy_remediation::{ManualSnapshot, sha256_hex};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS level6_manual_plans(
 action_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL, finding_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), state TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload)<=131072), sha256 TEXT NOT NULL CHECK(length(sha256)=64),
 UNIQUE(run_id,case_id,finding_id),
 FOREIGN KEY(run_id,case_id,finding_id) REFERENCES level5_case_findings(run_id,case_id,finding_id)
);
CREATE TABLE IF NOT EXISTS level6_manual_events(
 action_id TEXT NOT NULL REFERENCES level6_manual_plans(action_id), sequence INTEGER NOT NULL,
 event_type TEXT NOT NULL, at_utc TEXT NOT NULL, PRIMARY KEY(action_id,sequence)
);
"#;

pub struct ManualRemediationStore {
    pub investigation: Level5SnapshotStore,
}
impl ManualRemediationStore {
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        let mut investigation = Level5SnapshotStore::open(path)?;
        let tx = investigation
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch("PRAGMA user_version=8;")?;
        tx.commit()?;
        Ok(Self { investigation })
    }
    pub fn open_read_only(path: &Path) -> Result<Self, SnapshotError> {
        let investigation = Level5SnapshotStore::open_read_only(path)?;
        let version: u32 = investigation
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 8 {
            return Err(SnapshotError::Integrity);
        }
        Ok(Self { investigation })
    }
    pub fn finding(
        &self,
        run: &str,
        case: &str,
        finding: &str,
    ) -> Result<CorrelationFinding, SnapshotError> {
        let case = self.investigation.get_case(run, case)?;
        if !case.finding_ids.iter().any(|id| id == finding) {
            return Err(SnapshotError::InvalidInput);
        }
        self.investigation
            .load_observations(run)?
            .into_iter()
            .find(|f| f.finding_id == finding)
            .ok_or(SnapshotError::NotFound)
    }
    pub fn get(&self, id: &str) -> Result<ManualSnapshot, SnapshotError> {
        if id.len() != 71 || !id.starts_with("rma-v1-") {
            return Err(SnapshotError::InvalidInput);
        }
        let data = self
            .investigation
            .connection
            .query_row(
                "SELECT payload,sha256 FROM level6_manual_plans WHERE action_id=?1",
                [id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(SnapshotError::NotFound)?;
        decode(&data.0, &data.1)
    }
    pub fn find_for_member(
        &self,
        run: &str,
        case: &str,
        finding: &str,
    ) -> Result<Option<ManualSnapshot>, SnapshotError> {
        let id=self.investigation.connection.query_row("SELECT action_id FROM level6_manual_plans WHERE run_id=?1 AND case_id=?2 AND finding_id=?3",params![run,case,finding],|r|r.get::<_,String>(0)).optional()?;
        id.map(|id| self.get(&id)).transpose()
    }
    pub fn list(
        &self,
        case: Option<&str>,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ManualSnapshot>, SnapshotError> {
        if offset > 10000 || !(1..=100).contains(&limit) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut statement=self.investigation.connection.prepare("SELECT payload,sha256 FROM level6_manual_plans WHERE (?1 IS NULL OR case_id=?1) ORDER BY rowid DESC LIMIT ?2 OFFSET ?3")?;
        let rows = statement.query_map(params![case, limit, offset], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|r| {
            let (p, h) = r?;
            decode(&p, &h)
        })
        .collect()
    }
    /// Revision CAS, verification-authority consumption and case timeline share one transaction.
    /// Caller publishes the returned state only after COMMIT succeeds.
    pub fn save(&mut self, snapshot: &mut ManualSnapshot) -> Result<(), SnapshotError> {
        snapshot.validate().map_err(|_| SnapshotError::Integrity)?;
        let id = &snapshot.plan.actions[0].action_id;
        let case_id = snapshot
            .plan
            .case_id
            .as_ref()
            .ok_or(SnapshotError::InvalidInput)?;
        let tx = self
            .investigation
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = tx
            .query_row(
                "SELECT payload,sha256 FROM level6_manual_plans WHERE action_id=?1",
                [id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        let previous = previous.map(|(p, h)| decode(&p, &h)).transpose()?;
        let old_len = if let Some(previous) = &previous {
            if snapshot.revision != previous.revision
                || snapshot.plan != previous.plan
                || snapshot.run_id != previous.run_id
                || !snapshot.timeline.starts_with(&previous.timeline)
            {
                return Err(SnapshotError::Integrity);
            }
            previous.timeline.len()
        } else {
            if snapshot.revision != 0 {
                return Err(SnapshotError::Integrity);
            }
            0
        };
        let case_data = tx.query_row(
            "SELECT payload_json,payload_sha256 FROM level5_cases WHERE run_id=?1 AND case_id=?2",
            params![snapshot.run_id, case_id],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
        )?;
        if sha256_hex(&case_data.0) != case_data.1 {
            return Err(SnapshotError::Integrity);
        }
        let mut case: InvestigationCase =
            serde_json::from_slice(&case_data.0).map_err(|_| SnapshotError::Integrity)?;
        if !case.finding_ids.contains(&snapshot.plan.finding_id) {
            return Err(SnapshotError::InvalidInput);
        }
        let mut next = snapshot.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SnapshotError::Integrity)?;
        let payload = serde_json::to_vec(&next).map_err(|_| SnapshotError::InvalidInput)?;
        tx.execute("INSERT INTO level6_manual_plans(action_id,run_id,case_id,finding_id,revision,state,payload,sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(action_id) DO UPDATE SET revision=excluded.revision,state=excluded.state,payload=excluded.payload,sha256=excluded.sha256",params![id,next.run_id,case_id,next.plan.finding_id,next.revision,format!("{:?}",next.state),payload,sha256_hex(&payload)])?;
        for event in &next.timeline[old_len..] {
            tx.execute("INSERT INTO level6_manual_events(action_id,sequence,event_type,at_utc) VALUES(?1,?2,?3,?4)",params![id,event.sequence,event.event_type,event.at_utc])?;
            // Never regress timeline time when a synthetic/historical case is future-dated.
            let at = case
                .timeline
                .last()
                .map(|e| e.timestamp.clone())
                .filter(|s| s > &event.at_utc)
                .unwrap_or_else(|| event.at_utc.clone());
            case.timeline.push(TimelineEvent {
                sequence: case.timeline.len() as u32 + 1,
                timestamp: at,
                event_type: event.event_type.clone(),
                summary_safe: format!("{}; action {}", event.event_type, id),
                source: "EDY Level 6 manual verification".into(),
            });
        }
        // Only current persisted results for every case member can resolve a case.
        let resolved:i64=tx.query_row("SELECT count(*) FROM level5_case_findings f WHERE f.run_id=?1 AND f.case_id=?2 AND EXISTS(SELECT 1 FROM level6_manual_plans p WHERE p.run_id=f.run_id AND p.case_id=f.case_id AND p.finding_id=f.finding_id AND p.state='Resolved')",params![next.run_id,case_id],|r|r.get(0))?;
        let all = resolved as usize == case.finding_ids.len() && !case.finding_ids.is_empty();
        let at = case
            .timeline
            .last()
            .ok_or(SnapshotError::Integrity)?
            .timestamp
            .clone();
        if case.status == CaseStatus::Resolved && !all {
            case.transition(
                CaseStatus::Open,
                &at,
                "Level 6",
                "Verification no longer resolves every member",
            )
            .map_err(|_| SnapshotError::Integrity)?;
        }
        if case.status == CaseStatus::Suggested {
            case.transition(CaseStatus::Open, &at, "Level 6", "Guidance requested")
                .map_err(|_| SnapshotError::Integrity)?;
        }
        if case.status == CaseStatus::Open {
            case.transition(
                CaseStatus::Investigating,
                &at,
                "Level 6",
                "Manual verification workflow",
            )
            .map_err(|_| SnapshotError::Integrity)?;
        }
        if all
            && matches!(
                case.status,
                CaseStatus::Investigating | CaseStatus::VerificationPending
            )
        {
            case.transition(
                CaseStatus::Resolved,
                &at,
                "Level 6",
                "Every member verified for its required checks",
            )
            .map_err(|_| SnapshotError::Integrity)?;
        }
        let case_payload = serde_json::to_vec(&case).map_err(|_| SnapshotError::Integrity)?;
        tx.execute("UPDATE level5_cases SET status=?3,payload_json=?4,payload_sha256=?5 WHERE run_id=?1 AND case_id=?2",params![next.run_id,case_id,format!("{:?}",case.status),case_payload,sha256_hex(&case_payload)])?;
        tx.execute(
            "DELETE FROM level5_case_timeline WHERE run_id=?1 AND case_id=?2",
            params![next.run_id, case_id],
        )?;
        for e in &case.timeline {
            tx.execute("INSERT INTO level5_case_timeline(run_id,case_id,sequence,timestamp,event_type,summary_safe,source) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![next.run_id,case_id,e.sequence,e.timestamp,e.event_type,e.summary_safe,e.source])?;
        }
        tx.commit()?;
        *snapshot = next;
        Ok(())
    }
    pub fn recover_verifications(&mut self) -> Result<u32, SnapshotError> {
        // Fixed ordered IDs; updates cannot shift pagination or duplicate events.
        let ids = {
            let mut q=self.investigation.connection.prepare("SELECT action_id FROM level6_manual_plans WHERE state IN ('VerificationPending','Verifying') ORDER BY action_id")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for id in &ids {
            let mut s = self.get(id)?;
            if s.interrupt_on_restart()
                .map_err(|_| SnapshotError::Integrity)?
            {
                self.save(&mut s)?;
            }
        }
        Ok(ids.len() as u32)
    }
}
fn decode(payload: &[u8], hash: &str) -> Result<ManualSnapshot, SnapshotError> {
    if payload.len() > 131072 || sha256_hex(payload) != hash {
        return Err(SnapshotError::Integrity);
    }
    let s: ManualSnapshot =
        serde_json::from_slice(payload).map_err(|_| SnapshotError::Integrity)?;
    s.validate().map_err(|_| SnapshotError::Integrity)?;
    Ok(s)
}

#[cfg(test)]
#[path = "manual_remediation_tests.rs"]
mod tests;
