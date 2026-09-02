use super::*;
use edy_core::{ScanId, ScanState, Timestamp};
use edy_storage::level0_snapshot::Level0SnapshotStore;
use std::path::Path;

pub struct SqliteScanRepository {
    store: Level0SnapshotStore,
}

impl SqliteScanRepository {
    pub fn open(path: &Path) -> Result<Self, ServiceError> {
        Level0SnapshotStore::open(path)
            .map(|store| Self { store })
            .map_err(storage_error)
    }

    fn update(
        &mut self,
        scan_id: &ScanId,
        mutate: impl FnOnce(&mut StoredScan) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        let blob = self.store.load(scan_id.as_str()).map_err(storage_error)?;
        let mut scan: StoredScan = serde_json::from_slice(&blob.payload).map_err(|_| {
            ServiceError::new(
                "storage_snapshot_invalid",
                "Persisted scan snapshot is invalid",
            )
        })?;
        if scan.scan_id != *scan_id {
            return Err(ServiceError::new(
                "storage_snapshot_invalid",
                "Persisted scan snapshot is incoherent",
            ));
        }
        mutate(&mut scan)?;
        let payload = serde_json::to_vec(&scan).map_err(|_| {
            ServiceError::new(
                "storage_snapshot_invalid",
                "Scan snapshot could not be serialized",
            )
        })?;
        self.store
            .replace(scan_id.as_str(), blob.revision, &payload)
            .map_err(storage_error)?;
        Ok(())
    }
}

impl ScanRepository for SqliteScanRepository {
    fn create(&mut self, scan: StoredScan) -> Result<(), ServiceError> {
        let payload = serde_json::to_vec(&scan).map_err(|_| {
            ServiceError::new(
                "storage_snapshot_invalid",
                "Scan snapshot could not be serialized",
            )
        })?;
        self.store
            .create(scan.scan_id.as_str(), &payload)
            .map_err(storage_error)
    }

    fn transition(
        &mut self,
        scan_id: &ScanId,
        next: ScanState,
        at: &Timestamp,
    ) -> Result<(), ServiceError> {
        self.update(scan_id, |scan| {
            scan.state = scan.state.transition(next).map_err(|_| {
                ServiceError::new(
                    "invalid_scan_transition",
                    "Scan state transition was refused",
                )
            })?;
            if next == ScanState::Running {
                scan.started_at = Some(at.clone());
            }
            if next.is_terminal() {
                scan.finished_at = Some(at.clone());
            }
            Ok(())
        })
    }

    fn persist_event(&mut self, event: PipelineEvent) -> Result<(), ServiceError> {
        let scan_id = event.scan_id.clone();
        self.update(&scan_id, |scan| {
            if event.sequence != scan.events.len() as u32 {
                return Err(ServiceError::new(
                    "event_sequence_invalid",
                    "Event sequence is incoherent",
                ));
            }
            scan.events.push(event);
            Ok(())
        })
    }

    fn persist_engine_run(
        &mut self,
        scan_id: &ScanId,
        run: StoredEngineRun,
    ) -> Result<(), ServiceError> {
        self.update(scan_id, |scan| {
            if scan
                .engine_runs
                .iter()
                .any(|item| item.engine.id == run.engine.id)
            {
                return Err(ServiceError::new(
                    "engine_run_duplicate",
                    "Engine run was already persisted",
                ));
            }
            scan.engine_runs.push(run);
            Ok(())
        })
    }

    fn persist_finding_with_evidence(
        &mut self,
        scan_id: &ScanId,
        finding: edy_core::Finding,
        evidence: Vec<edy_core::Evidence>,
    ) -> Result<(), ServiceError> {
        self.update(scan_id, |scan| {
            if evidence.is_empty()
                || evidence
                    .iter()
                    .any(|item| !finding.evidence_ids().contains(item.id()))
            {
                return Err(ServiceError::new(
                    "finding_evidence_invalid",
                    "Finding evidence transaction is incoherent",
                ));
            }
            for item in evidence {
                scan.evidence.insert(item.id().as_str().to_owned(), item);
            }
            if let Some(existing) = scan
                .findings
                .iter_mut()
                .find(|item| item.fingerprint() == finding.fingerprint())
            {
                if finding.id() == existing.id() && finding.last_seen() >= existing.last_seen() {
                    *existing = finding;
                }
            } else {
                scan.findings.push(finding);
                scan.findings
                    .sort_by(|left, right| left.fingerprint().cmp(right.fingerprint()));
            }
            Ok(())
        })
    }

    fn finalize(
        &mut self,
        scan_id: &ScanId,
        finalization: FinalSnapshot,
    ) -> Result<(), ServiceError> {
        self.update(scan_id, |scan| {
            let terminal = scan.state.transition(finalization.state).map_err(|_| {
                ServiceError::new("invalid_scan_transition", "Scan finalization was refused")
            })?;
            if matches!(terminal, ScanState::Completed | ScanState::Partial)
                && (finalization.coverage.is_none()
                    || finalization.verdict.is_none()
                    || finalization.report_json.is_none())
            {
                return Err(ServiceError::new(
                    "final_snapshot_incomplete",
                    "Completed scan snapshot is incomplete",
                ));
            }
            if matches!(terminal, ScanState::Failed | ScanState::Cancelled)
                && (finalization.verdict.is_some() || finalization.report_json.is_some())
            {
                return Err(ServiceError::new(
                    "unsafe_terminal_result",
                    "Failed or cancelled scan cannot expose a final verdict",
                ));
            }
            if finalization.event.scan_id != *scan_id
                || finalization.event.sequence != scan.events.len() as u32
                || finalization.event.at != finalization.at
            {
                return Err(ServiceError::new(
                    "event_sequence_invalid",
                    "Final event is incoherent",
                ));
            }
            scan.state = terminal;
            scan.finished_at = Some(finalization.at);
            scan.coverage = finalization.coverage;
            scan.verdict = finalization.verdict;
            scan.report_json = finalization.report_json;
            scan.events.push(finalization.event);
            Ok(())
        })
    }

    fn load(&self, scan_id: &ScanId) -> Result<StoredScan, ServiceError> {
        let blob = self.store.load(scan_id.as_str()).map_err(storage_error)?;
        let scan: StoredScan = serde_json::from_slice(&blob.payload).map_err(|_| {
            ServiceError::new(
                "storage_snapshot_invalid",
                "Persisted scan snapshot is invalid",
            )
        })?;
        if scan.scan_id != *scan_id {
            return Err(ServiceError::new(
                "storage_snapshot_invalid",
                "Persisted scan snapshot is incoherent",
            ));
        }
        Ok(scan)
    }

    fn list(&self, offset: u32, limit: u32) -> Result<Vec<StoredScan>, ServiceError> {
        self.store
            .list_ids(offset, limit)
            .map_err(storage_error)?
            .into_iter()
            .map(|id| {
                let id = ScanId::new(id).map_err(|_| {
                    ServiceError::new(
                        "storage_snapshot_invalid",
                        "Persisted scan identifier is invalid",
                    )
                })?;
                self.load(&id)
            })
            .collect()
    }

    fn count(&self) -> Result<u32, ServiceError> {
        self.store.count().map_err(storage_error)
    }
}

fn storage_error(_: edy_storage::level0_snapshot::SnapshotError) -> ServiceError {
    ServiceError::new("storage_unavailable", "Scan storage is unavailable")
}
