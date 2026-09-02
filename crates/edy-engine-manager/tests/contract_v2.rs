use edy_engine_manager::manifest::*;
use edy_engine_manager::receipt::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GIT_D: &str = "dddddddddddddddddddddddddddddddddddddddd";
const ENTRYPOINT_BYTES: &[u8] = b"fixture-engine-v2";
const LICENSE_BYTES: &[u8] = b"fixture-license";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verified(kind: ProvenanceType, digest: EvidenceDigest) -> ProvenanceEvidence {
    let subject = match kind {
        ProvenanceType::PublishedChecksum
        | ProvenanceType::Sigstore
        | ProvenanceType::Slsa
        | ProvenanceType::InToto
        | ProvenanceType::ReproducibleBuild => "fixture.zip",
        ProvenanceType::Authenticode => "fixture.exe",
        _ => GIT_D,
    };
    ProvenanceEvidence {
        evidence_type: kind,
        status: EvidenceStatus::Verified,
        source: "https://example.invalid/evidence".into(),
        subject: subject.into(),
        digest: Some(digest),
        verifier: Some("fixture-verifier-1.0".into()),
        verified_at: Some("2026-09-02T00:00:00Z".into()),
    }
}

fn present(kind: ProvenanceType) -> ProvenanceEvidence {
    ProvenanceEvidence {
        evidence_type: kind,
        status: EvidenceStatus::PresentUnverified,
        source: "https://example.invalid/evidence".into(),
        subject: "fixture.zip".into(),
        digest: Some(EvidenceDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: SHA_A.into(),
        }),
        verifier: None,
        verified_at: None,
    }
}

fn fixture(id: &str, entrypoint: &str, evidence: Vec<ProvenanceEvidence>) -> EngineManifest {
    EngineManifest {
        schema_version: 2,
        identity: EngineIdentity {
            id: id.into(),
            version: "1.2.3".into(),
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
        },
        source: EngineSource {
            official_source: "https://example.invalid/project".into(),
            release_url: "https://example.invalid/releases/v1.2.3".into(),
            asset_url: "https://example.invalid/releases/v1.2.3/fixture.zip".into(),
            asset_name: "fixture.zip".into(),
            asset_size: 2048,
            archive_sha256: SHA_A.into(),
        },
        artifact: EngineArtifact {
            format: ArtifactFormat::Zip,
            entrypoint: entrypoint.into(),
            entrypoint_size: ENTRYPOINT_BYTES.len() as u64,
            executable_sha256: sha(ENTRYPOINT_BYTES),
            auxiliary_hashes: vec![AuxiliaryHash {
                relative_path: "LICENSE.txt".into(),
                sha256: sha(LICENSE_BYTES),
                size: LICENSE_BYTES.len() as u64,
            }],
            closed_set: true,
        },
        provenance: Provenance { evidence },
        license: EngineLicense {
            spdx: "MIT".into(),
            source: "https://example.invalid/project/LICENSE".into(),
            redistribution_policy: RedistributionPolicy::ReviewRequired,
            notice_required: true,
        },
        extraction: ExtractionPolicy::secure_defaults(ArtifactFormat::Zip),
        process: ProcessPolicy {
            timeout_ms: 10_000,
            stdout_limit_bytes: 64 * 1024,
            stderr_limit_bytes: 64 * 1024,
            stdin_limit_bytes: 0,
            kill_process_tree: true,
            shell: false,
            network_policy: NetworkPolicy::Deny,
        },
        version_probe: VersionProbe {
            args: vec!["--version".into()],
            expected_exit_codes: vec![0],
            expected_output: "fixture".into(),
            output_stream: OutputStream::Stdout,
            network: false,
            timeout_ms: 2_000,
        },
        review: ContractReview {
            reviewed_at: "2026-09-02T00:00:00Z".into(),
            reviewed_by_role: ReviewerRole::JrOrchestrator,
            policy_version: "engine-policy-v2".into(),
        },
    }
}

fn checksum() -> ProvenanceEvidence {
    verified(
        ProvenanceType::PublishedChecksum,
        EvidenceDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: SHA_A.into(),
        },
    )
}

fn source_commit() -> ProvenanceEvidence {
    verified(
        ProvenanceType::SourceCommit,
        EvidenceDigest {
            algorithm: DigestAlgorithm::GitSha1,
            value: GIT_D.into(),
        },
    )
}

#[test]
fn positive_yara_like_checksum_and_commit() {
    fixture(
        "fixture-yara-x-like",
        "yara-x.exe",
        vec![checksum(), source_commit()],
    )
    .validate()
    .unwrap();
}

#[test]
fn positive_gitleaks_like_checksum_only() {
    fixture("fixture-gitleaks-like", "gitleaks.exe", vec![checksum()])
        .validate()
        .unwrap();
}

#[test]
fn positive_trivy_like_checksum_and_unverified_sigstore() {
    fixture(
        "fixture-trivy-like",
        "trivy.exe",
        vec![checksum(), present(ProvenanceType::Sigstore)],
    )
    .validate()
    .unwrap();
}

#[test]
fn positive_osv_like_checksum_and_unverified_in_toto() {
    fixture(
        "fixture-osv-like",
        "osv-scanner.exe",
        vec![checksum(), present(ProvenanceType::InToto)],
    )
    .validate()
    .unwrap();
}

#[test]
fn v1_is_explicitly_superseded() {
    let error = EngineManifest::parse(br#"{"schema_version":1}"#).unwrap_err();
    assert!(matches!(
        error,
        ContractError::ManifestVersionUnsupported {
            found: Some(1),
            supported: 2
        }
    ));
    assert!(error.to_string().contains("migrate to V2"));
}

#[test]
fn unknown_field_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["unknown"] = json!(true);
    assert!(EngineManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn duplicate_json_key_is_rejected_before_deserialization() {
    assert!(EngineManifest::parse(br#"{"schema_version":2,"schema_version":2}"#).is_err());
}

#[test]
fn invalid_sha256_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.source.archive_sha256 = "A".repeat(64);
    assert!(manifest.validate().is_err());
}

#[test]
fn duplicate_auxiliary_path_is_rejected_case_insensitively() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.artifact.auxiliary_hashes.push(AuxiliaryHash {
        relative_path: "license.TXT".into(),
        sha256: SHA_A.into(),
        size: 1,
    });
    assert!(manifest.validate().is_err());
}

#[test]
fn traversal_path_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.artifact.auxiliary_hashes[0].relative_path = "../outside".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn absolute_path_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.artifact.entrypoint = "C:\\engine.exe".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn invalid_url_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.source.asset_url = "http://example.invalid/fixture.zip".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn missing_entrypoint_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["artifact"]
        .as_object_mut()
        .unwrap()
        .remove("entrypoint");
    assert!(EngineManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn zero_timeout_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.process.timeout_ms = 0;
    assert!(manifest.validate().is_err());
}

#[test]
fn absurd_archive_limit_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.extraction.max_archive_bytes = u64::MAX;
    assert!(manifest.validate().is_err());
}

#[test]
fn unsupported_architecture_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["identity"]["architecture"] = json!("mips64");
    assert!(EngineManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn unknown_provenance_type_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["provenance"]["evidence"][0]["type"] = json!("magic_trust");
    assert!(EngineManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn failed_provenance_parses_but_policy_blocks() {
    let mut failed = checksum();
    failed.status = EvidenceStatus::Failed;
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![failed]);
    manifest.validate().unwrap();
    let policy = EngineTrustPolicy::new(vec![ProvenanceType::PublishedChecksum], 1).unwrap();
    assert!(matches!(
        policy.evaluate(&manifest),
        Err(ContractError::PolicyBlocked(_))
    ));
}

#[test]
fn hash_pinned_and_source_commit_policy_can_allow() {
    let manifest = fixture(
        "fixture-yara-x-like",
        "yara-x.exe",
        vec![checksum(), source_commit()],
    );
    let policy = EngineTrustPolicy::new(
        vec![
            ProvenanceType::PublishedChecksum,
            ProvenanceType::SourceCommit,
        ],
        2,
    )
    .unwrap();
    assert_eq!(policy.evaluate(&manifest), Ok(PolicyDecision::Allowed));
}

#[test]
fn sigstore_required_and_unverified_is_policy_blocked() {
    let manifest = fixture(
        "fixture-trivy-like",
        "trivy.exe",
        vec![checksum(), present(ProvenanceType::Sigstore)],
    );
    let policy = EngineTrustPolicy::new(vec![ProvenanceType::Sigstore], 1).unwrap();
    assert!(matches!(
        policy.evaluate(&manifest),
        Err(ContractError::PolicyBlocked(_))
    ));
}

#[test]
fn empty_or_zero_trust_policy_is_rejected() {
    assert!(EngineTrustPolicy::new(vec![], 0).is_err());
    assert!(EngineTrustPolicy::new(vec![ProvenanceType::PublishedChecksum], 0).is_err());
}

#[test]
fn malformed_https_authority_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.source.asset_url = "https:///asset.zip".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn non_ascii_windows_path_is_rejected_to_close_casefold_ambiguity() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.artifact.auxiliary_hashes[0].relative_path = "É.txt".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn nonexistent_calendar_date_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.review.reviewed_at = "2026-02-31T00:00:00Z".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn asset_size_must_fit_extraction_limit_and_format_must_be_exact() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.source.asset_size = manifest.extraction.max_archive_bytes + 1;
    assert!(manifest.validate().is_err());
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.extraction.allowed_formats = vec![ArtifactFormat::RawExecutable];
    assert!(manifest.validate().is_err());
}

#[test]
fn unsupported_spdx_expression_is_rejected() {
    let mut manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    manifest.license.spdx = "MIT OR".into();
    assert!(manifest.validate().is_err());
}

fn ready_receipt(manifest: &EngineManifest) -> EngineReceipt {
    EngineReceipt {
        schema_version: 2,
        engine_id: manifest.identity.id.clone(),
        version: manifest.identity.version.clone(),
        manifest_sha256: manifest.canonical_sha256().unwrap(),
        entrypoint_sha256: manifest.artifact.executable_sha256.clone(),
        artifact_set_sha256: manifest.declared_artifact_set_sha256().unwrap(),
        promoted_at: NullableTimestamp(Some("2026-09-02T00:00:00Z".into())),
        state: ReceiptState::Ready,
    }
}

fn observation(manifest: &EngineManifest, entrypoint: &[u8]) -> IntegrityObservation {
    IntegrityObservation::from_bytes(
        manifest,
        entrypoint,
        &[ObservedArtifact {
            relative_path: "LICENSE.txt",
            bytes: LICENSE_BYTES,
        }],
    )
    .unwrap()
}

#[test]
fn receipt_matches_manifest_and_observed_hashes() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let receipt = ready_receipt(&manifest);
    receipt
        .verify_against(&manifest, &observation(&manifest, ENTRYPOINT_BYTES))
        .unwrap();
}

#[test]
fn receipt_manifest_hash_mismatch_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let mut receipt = ready_receipt(&manifest);
    receipt.manifest_sha256 = SHA_A.into();
    assert!(
        receipt
            .verify_against(&manifest, &observation(&manifest, ENTRYPOINT_BYTES))
            .is_err()
    );
}

#[test]
fn receipt_executable_hash_mismatch_is_rejected() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let receipt = ready_receipt(&manifest);
    assert!(
        receipt
            .verify_against(&manifest, &observation(&manifest, b"tampered-engine"))
            .is_err()
    );
}

#[test]
fn acquisition_remains_policy_blocked() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let paths = EnginePaths::from_root(Path::new("D:/fixture-tools"), &manifest).unwrap();
    assert!(matches!(
        DisabledAcquisition.acquire(&manifest, &paths),
        Err(ContractError::PolicyBlocked(_))
    ));
}

#[test]
fn round_trip_and_canonical_order_are_deterministic() {
    let mut manifest = fixture(
        "fixture-yara-x-like",
        "yara-x.exe",
        vec![source_commit(), checksum()],
    );
    manifest.version_probe.expected_exit_codes = vec![1, 0];
    let first = manifest.canonical_bytes().unwrap();
    let parsed = EngineManifest::parse(&first).unwrap();
    let second = parsed.canonical_bytes().unwrap();
    assert_eq!(
        manifest.canonical_sha256().unwrap(),
        "8faf70764428da85c8f3872b2a0721a457b93ecbab7b161042aba8b317ae3f56"
    );
    assert_eq!(
        manifest.declared_artifact_set_sha256().unwrap(),
        "8655fc826a0c53cc4d5a7f04b889189dceb709f06f4c91c41e12d8ca492f16b5"
    );
    assert_eq!(first, second);
    assert_eq!(manifest.canonical_sha256(), parsed.canonical_sha256());
}

#[test]
fn receipt_absent_denies_execution_as_unverified() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let policy = EngineTrustPolicy::new(vec![ProvenanceType::PublishedChecksum], 1).unwrap();
    assert_eq!(
        verify_execution_ready(
            &manifest,
            None,
            &policy,
            &observation(&manifest, ENTRYPOINT_BYTES),
        ),
        Err(EngineState::Unverified)
    );
}

#[test]
fn current_runner_never_claims_network_enforced_execution_ready() {
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let policy = EngineTrustPolicy::new(vec![ProvenanceType::PublishedChecksum], 1).unwrap();
    let receipt = ready_receipt(&manifest);
    assert_eq!(
        verify_execution_ready(
            &manifest,
            Some(&receipt),
            &policy,
            &observation(&manifest, ENTRYPOINT_BYTES),
        ),
        Err(EngineState::PolicyBlocked)
    );
}

fn assert_schema_shape(value: &Value, schema: &Value) {
    match value {
        Value::Object(object) => {
            assert_eq!(schema["additionalProperties"], json!(false));
            let properties = schema["properties"].as_object().unwrap();
            let required: BTreeSet<_> = schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap())
                .collect();
            for key in object.keys() {
                assert!(
                    properties.contains_key(key),
                    "Rust field {key} absent from schema"
                );
            }
            for key in required {
                assert!(
                    object.contains_key(key),
                    "schema-required field {key} absent from Rust"
                );
            }
            for (key, child) in object {
                if child.is_object() {
                    assert_schema_shape(child, &properties[key]);
                } else if let Value::Array(items) = child
                    && let Some(first) = items.first()
                    && first.is_object()
                {
                    assert_schema_shape(first, &properties[key]["items"]);
                }
            }
        }
        _ => panic!("shape gate expects an object"),
    }
}

use std::collections::BTreeSet;

#[test]
fn json_schema_and_rust_contract_shape_do_not_drift() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("tools/manifests/engine-manifest.schema.json")).unwrap(),
    )
    .unwrap();
    let receipt_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("tools/manifests/engine-receipt.schema.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest_schema["$id"], "urn:edy-verdict:engine-manifest:v2");
    assert_eq!(receipt_schema["$id"], "urn:edy-verdict:engine-receipt:v2");
    let manifest = fixture("fixture-yara-x-like", "yara-x.exe", vec![checksum()]);
    let receipt = ready_receipt(&manifest);
    assert_schema_shape(&serde_json::to_value(manifest).unwrap(), &manifest_schema);
    assert_schema_shape(&serde_json::to_value(receipt).unwrap(), &receipt_schema);
    assert_eq!(
        manifest_schema["properties"]["identity"]["properties"]["architecture"]["enum"],
        json!(["x86_64", "aarch64"])
    );
    assert_eq!(
        manifest_schema["properties"]["provenance"]["properties"]["evidence"]["items"]["properties"]
            ["status"]["enum"],
        json!(["verified", "present_unverified", "unavailable", "failed"])
    );
}
