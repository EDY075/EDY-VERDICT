use super::*;
use edy_core::{
    Confidence, EngineId, EvidenceDraft, EvidenceId, EvidenceKind, EvidenceProvenance,
    EvidenceStrength, ObservationSignal, Severity, Sha256Digest, StructuredFact, TargetId,
    TargetKind, TargetLocator, Timestamp,
};

const SCAN_A: &str = "018f4c2a-1d3b-7abc-8def-0123456789a1";
const SCAN_B: &str = "018f4c2a-1d3b-7abc-8def-0123456789a2";
const TARGET: &str = "018f4c2a-1d3b-7abc-8def-0123456789b1";
const EVIDENCE_A: &str = "018f4c2a-1d3b-7abc-8def-0123456789c1";
const EVIDENCE_B: &str = "018f4c2a-1d3b-7abc-8def-0123456789c2";
const AT: &str = "2026-09-02T04:00:00Z";

fn timestamp() -> Timestamp {
    Timestamp::new(AT).unwrap()
}

fn clock() -> FakeClock {
    FakeClock::new(std::iter::repeat_n(timestamp(), 64))
}

fn target() -> edy_core::Target {
    edy_core::Target::new(
        TargetId::new(TARGET).unwrap(),
        TargetKind::Repository,
        TargetLocator::new_local_path("D:/EDY-Projects/EDY-VERDICT/_intake/synthetic-target-A")
            .unwrap(),
    )
    .unwrap()
}

fn engine(id: &str, available: bool) -> EngineDescriptor {
    EngineDescriptor {
        id: EngineId::new(id).unwrap(),
        version: "0.0.0-synthetic".into(),
        available,
    }
}

fn bundle(engine_id: &str, evidence_id: &str, semantic_key: &str) -> ObservationBundle {
    let engine = EngineId::new(engine_id).unwrap();
    let evidence_id = EvidenceId::new(evidence_id).unwrap();
    let evidence = edy_core::Evidence::new(EvidenceDraft {
        id: evidence_id.clone(),
        kind: EvidenceKind::EngineOutput,
        source: format!("{engine_id}-synthetic-fixture"),
        timestamp: timestamp(),
        digest: Sha256Digest::new("a".repeat(64)).unwrap(),
        summary: "redacted synthetic observation".into(),
        structured_payload: vec![StructuredFact::new("fixture", "benign", true).unwrap()],
        raw_reference: None,
        provenance: EvidenceProvenance {
            producer: engine_id.into(),
            producer_version: "0.0.0-synthetic".into(),
            observed_at: timestamp(),
        },
        redacted: true,
    })
    .unwrap();
    ObservationBundle {
        observation: edy_core::EngineObservation {
            engine,
            engine_version: "0.0.0-synthetic".into(),
            target_id: TargetId::new(TARGET).unwrap(),
            rule_id: format!("{engine_id}-synthetic-rule"),
            semantic_key: semantic_key.into(),
            category: "synthetic".into(),
            severity: Severity::Low,
            location: "fixture/benign.txt:1".into(),
            message: "synthetic marker observed".into(),
            evidence_id,
            signal: ObservationSignal::Informational,
            evidence_strength: EvidenceStrength::Strong,
            parser_confidence: Confidence::High,
        },
        evidence,
    }
}

fn request(scan_id: &str, cancellation: CancellationToken) -> SyntheticScanRequest {
    SyntheticScanRequest::target_a(
        edy_core::ScanId::new(scan_id).unwrap(),
        TargetId::new(TARGET).unwrap(),
        std::path::Path::new("D:/EDY-Projects/EDY-VERDICT"),
        5_000,
        cancellation,
    )
    .unwrap()
}

fn success(bundle: ObservationBundle) -> ExecutionResult {
    ExecutionResult::Completed {
        bundles: vec![bundle],
        elapsed_ms: 10,
    }
}

fn kinds(events: &[PipelineEvent]) -> Vec<PipelineEventKind> {
    events.iter().map(|event| event.kind).collect()
}

#[test]
fn all_success_is_deterministic_and_reloads_complete_snapshot() {
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let sink = InMemoryEventSink::default();
    let mut service = ScanService::new(
        clock(),
        sink,
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true), engine("fixture-b", true)]),
        ScriptedExecutor::new([
            success(bundle("fixture-a", EVIDENCE_A, "marker-a")),
            success(bundle("fixture-b", EVIDENCE_B, "marker-b")),
        ]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );

    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Completed);
    assert!(outcome.verdict.is_some());
    assert!(outcome.report_json.is_some());

    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Completed);
    assert_eq!(stored.findings.len(), 2);
    assert_eq!(stored.evidence.len(), 2);
    assert_eq!(stored.engine_runs.len(), 2);
    assert_eq!(stored.coverage, outcome.coverage);
    assert_eq!(stored.verdict, outcome.verdict);
    assert_eq!(stored.report_json, outcome.report_json);
    assert_eq!(
        kinds(&stored.events),
        vec![
            PipelineEventKind::ScanCreated,
            PipelineEventKind::ScanStarted,
            PipelineEventKind::EngineStarted,
            PipelineEventKind::EngineProgress,
            PipelineEventKind::FindingObserved,
            PipelineEventKind::EngineCompleted,
            PipelineEventKind::EngineStarted,
            PipelineEventKind::EngineProgress,
            PipelineEventKind::FindingObserved,
            PipelineEventKind::EngineCompleted,
            PipelineEventKind::ScanCompleted,
        ]
    );
    assert!(
        stored
            .events
            .iter()
            .enumerate()
            .all(|(index, event)| event.sequence == index as u32)
    );
}

#[test]
fn cross_engine_dedup_preserves_identity_sources_and_evidence_history() {
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true), engine("fixture-b", true)]),
        ScriptedExecutor::new([
            success(bundle("fixture-a", EVIDENCE_A, "same-marker")),
            success(bundle("fixture-b", EVIDENCE_B, "same-marker")),
        ]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.findings.len(), 1);
    assert_eq!(stored.findings[0].source_engines().len(), 2);
    assert_eq!(stored.findings[0].evidence_ids().len(), 2);
    assert_eq!(stored.evidence.len(), 2);
}

#[test]
fn one_engine_failure_continues_and_finishes_partial() {
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true), engine("fixture-b", true)]),
        ScriptedExecutor::new([
            ExecutionResult::Failed {
                safe_reason: "synthetic engine failure".into(),
                elapsed_ms: 5,
            },
            success(bundle("fixture-b", EVIDENCE_B, "marker-b")),
        ]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Partial);
    assert!(outcome.verdict.is_some());
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert!(kinds(&stored.events).contains(&PipelineEventKind::EngineFailed));
    assert_eq!(
        stored.events.last().unwrap().kind,
        PipelineEventKind::ScanPartial
    );
}

#[test]
fn multiple_failures_and_timeout_fail_closed_without_verdict() {
    for outcomes in [
        vec![
            ExecutionResult::Failed {
                safe_reason: "synthetic a".into(),
                elapsed_ms: 1,
            },
            ExecutionResult::Failed {
                safe_reason: "synthetic b".into(),
                elapsed_ms: 1,
            },
        ],
        vec![
            ExecutionResult::TimedOut { elapsed_ms: 5_001 },
            ExecutionResult::TimedOut { elapsed_ms: 5_001 },
        ],
    ] {
        let repository = InMemoryScanRepository::default();
        let reopened = repository.reopen();
        let mut service = ScanService::new(
            clock(),
            InMemoryEventSink::default(),
            repository,
            StaticEngineRegistry::new(vec![engine("fixture-a", true), engine("fixture-b", true)]),
            ScriptedExecutor::new(outcomes),
            CoreCorrelation::default(),
            DeterministicJsonReportGenerator::default(),
        );
        let outcome = service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .unwrap();
        assert_eq!(outcome.state, edy_core::ScanState::Failed);
        assert!(outcome.verdict.is_none());
        assert!(outcome.report_json.is_none());
        let stored = reopened
            .load(&edy_core::ScanId::new(SCAN_A).unwrap())
            .unwrap();
        assert_eq!(stored.state, edy_core::ScanState::Failed);
        assert!(stored.verdict.is_none());
    }
}

#[test]
fn cancellation_before_start_prevents_every_engine() {
    let cancellation = CancellationToken::default();
    cancellation.request();
    let executor = ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]);
    let observer = executor.clone();
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        executor,
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, cancellation))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Cancelled);
    assert!(observer.executed().is_empty());
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Cancelled);
    assert!(stored.verdict.is_none());
}

#[test]
fn cancellation_during_engine_confirms_cleanup_and_cancels_remaining() {
    let executor = ScriptedExecutor::new([ExecutionResult::Cancelled {
        elapsed_ms: 12,
        cleanup_confirmed: true,
    }]);
    let observer = executor.clone();
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true), engine("fixture-b", true)]),
        executor,
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Cancelled);
    assert!(outcome.cleanup_confirmed);
    assert_eq!(observer.executed(), vec!["fixture-a"]);
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.engine_runs.len(), 2);
    assert!(
        stored
            .engine_runs
            .iter()
            .all(|run| run.state == edy_core::EngineRunState::Cancelled)
    );
    assert!(stored.verdict.is_none());
}

#[test]
fn unconfirmed_cancellation_cleanup_is_structural_failure() {
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([ExecutionResult::Cancelled {
            elapsed_ms: 12,
            cleanup_confirmed: false,
        }]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Failed);
    assert!(!outcome.cleanup_confirmed);
    assert!(
        reopened
            .load(&edy_core::ScanId::new(SCAN_A).unwrap())
            .unwrap()
            .verdict
            .is_none()
    );
}

#[test]
fn unavailable_engine_reduces_coverage_and_never_claims_clean() {
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![
            engine("fixture-a", true),
            engine("fixture-unavailable", false),
        ]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Partial);
    let verdict = outcome.verdict.unwrap();
    assert_ne!(verdict.kind, edy_core::VerdictKind::NoKnownIndicators);
    assert!(verdict.confidence.score.value() < 75);
    assert!(
        !reopened
            .load(&edy_core::ScanId::new(SCAN_A).unwrap())
            .unwrap()
            .report_json
            .unwrap()
            .to_ascii_lowercase()
            .contains("completely secure")
    );
}

#[test]
fn storage_correlation_report_and_event_failures_are_fail_closed() {
    // Atomic finding/evidence persistence failure.
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    repository.fail_next(RepositoryFailurePoint::FindingEvidence);
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    assert!(
        service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .is_err()
    );
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Failed);
    assert!(stored.findings.is_empty());
    assert!(stored.evidence.is_empty());
    assert!(stored.verdict.is_none());

    // Final snapshot transaction failure is retried only as a failed state without verdict.
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    repository.fail_next(RepositoryFailurePoint::Finalize);
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    assert!(
        service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .is_err()
    );
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Failed);
    assert!(stored.verdict.is_none());
    assert!(stored.report_json.is_none());

    // Correlation failure.
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::failing(),
        DeterministicJsonReportGenerator::default(),
    );
    assert!(
        service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .is_err()
    );
    assert_eq!(
        reopened
            .load(&edy_core::ScanId::new(SCAN_A).unwrap())
            .unwrap()
            .state,
        edy_core::ScanState::Failed
    );

    // Report generation failure after correlation.
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator { fail: true },
    );
    assert!(
        service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .is_err()
    );
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Failed);
    assert!(stored.verdict.is_none());
    assert!(stored.report_json.is_none());

    // Event delivery failure is terminal in storage, never successful.
    let repository = InMemoryScanRepository::default();
    let reopened = repository.reopen();
    let sink = InMemoryEventSink::default();
    sink.fail_next();
    let mut service = ScanService::new(
        clock(),
        sink,
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    assert!(
        service
            .run_synthetic(request(SCAN_A, CancellationToken::default()))
            .is_err()
    );
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Failed);
    assert!(stored.verdict.is_none());
}

#[test]
fn identical_inputs_have_identical_event_order_and_report_shape() {
    fn execute(scan_id: &str) -> (Vec<PipelineEventKind>, serde_json::Value) {
        let repository = InMemoryScanRepository::default();
        let reopened = repository.reopen();
        let mut service = ScanService::new(
            clock(),
            InMemoryEventSink::default(),
            repository,
            StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
            ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
            CoreCorrelation::default(),
            DeterministicJsonReportGenerator::default(),
        );
        service
            .run_synthetic(request(scan_id, CancellationToken::default()))
            .unwrap();
        let stored = reopened
            .load(&edy_core::ScanId::new(scan_id).unwrap())
            .unwrap();
        let mut report: serde_json::Value =
            serde_json::from_str(stored.report_json.as_ref().unwrap()).unwrap();
        report["scan_id"] = serde_json::Value::String("normalized".into());
        for event in report["events"].as_array_mut().unwrap() {
            event["scan_id"] = serde_json::Value::String("normalized".into());
        }
        for finding in report["findings"].as_array_mut().unwrap() {
            finding["scan_id"] = serde_json::Value::String("normalized".into());
        }
        (kinds(&stored.events), report)
    }
    let first = execute(SCAN_A);
    let second = execute(SCAN_B);
    assert_eq!(first, second);
}

#[test]
fn storage_event_sink_and_system_clock_contracts_are_usable() {
    let repository = InMemoryScanRepository::default();
    let scan_id = edy_core::ScanId::new(SCAN_A).unwrap();
    let mut seed = repository.clone();
    seed.create(StoredScan::queued(scan_id.clone(), target(), timestamp()))
        .unwrap();
    let mut sink = StorageEventSink::new(repository);
    sink.emit(&PipelineEvent {
        sequence: 0,
        scan_id: scan_id.clone(),
        at: timestamp(),
        kind: PipelineEventKind::ScanCreated,
        engine: None,
        safe_detail: None,
    })
    .unwrap();
    assert_eq!(sink.into_inner().load(&scan_id).unwrap().events.len(), 1);
    assert!(SystemClock.now().is_ok());
}

#[test]
fn sqlite_repository_reopens_exact_completed_snapshot() {
    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = TempDir(std::env::temp_dir().join(format!(
        "edy-level0-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let database = directory.0.join("level0.sqlite3");
    let repository = SqliteScanRepository::open(&database).unwrap();
    let mut service = ScanService::new(
        clock(),
        InMemoryEventSink::default(),
        repository,
        StaticEngineRegistry::new(vec![engine("fixture-a", true)]),
        ScriptedExecutor::new([success(bundle("fixture-a", EVIDENCE_A, "marker-a"))]),
        CoreCorrelation::default(),
        DeterministicJsonReportGenerator::default(),
    );
    let outcome = service
        .run_synthetic(request(SCAN_A, CancellationToken::default()))
        .unwrap();
    assert_eq!(outcome.state, edy_core::ScanState::Completed);
    drop(service);

    let reopened = SqliteScanRepository::open(&database).unwrap();
    let stored = reopened
        .load(&edy_core::ScanId::new(SCAN_A).unwrap())
        .unwrap();
    assert_eq!(stored.state, edy_core::ScanState::Completed);
    assert_eq!(stored.findings.len(), 1);
    assert_eq!(stored.evidence.len(), 1);
    assert_eq!(stored.engine_runs.len(), 1);
    assert!(stored.coverage.is_some());
    assert!(stored.verdict.is_some());
    assert!(stored.report_json.is_some());
    assert_eq!(
        stored.events.last().unwrap().kind,
        PipelineEventKind::ScanCompleted
    );
}
