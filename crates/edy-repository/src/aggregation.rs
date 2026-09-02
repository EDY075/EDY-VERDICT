use crate::{
    AuthorizedRepositoryTarget, RepositoryDocumentKind, RepositoryFindingCategory,
    RepositoryInventory, RepositoryObservation, finding_fingerprint,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    Detected,
    Unknown,
    Conflicting,
    PolicyReview,
}

impl LicenseState {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Unknown => "unknown",
            Self::Conflicting => "conflicting",
            Self::PolicyReview => "policy_review",
        }
    }
}

pub fn aggregate_repository_posture(
    target: &AuthorizedRepositoryTarget,
    inventory: &RepositoryInventory,
    analyzed_ecosystems: &BTreeSet<String>,
    vulnerability_data_available: bool,
) -> Vec<RepositoryObservation> {
    let mut observations = Vec::new();
    for ecosystem in &inventory.ecosystems {
        let documents = inventory
            .documents
            .iter()
            .filter(|doc| &doc.ecosystem == ecosystem)
            .collect::<Vec<_>>();
        let has_manifest = documents
            .iter()
            .any(|doc| doc.kind == RepositoryDocumentKind::Manifest);
        let has_lock = documents
            .iter()
            .any(|doc| doc.kind == RepositoryDocumentKind::Lockfile);
        for lockfile in documents
            .iter()
            .filter(|doc| doc.kind == RepositoryDocumentKind::Lockfile && doc.size == 0)
        {
            observations.push(supply_observation(
                target,
                "malformed-lockfile",
                ecosystem,
                &format!(
                    "Recognized lockfile is empty and cannot provide deterministic dependency data: {}",
                    lockfile.relative_path
                ),
                "medium",
            ));
        }
        if has_manifest && !has_lock {
            observations.push(supply_observation(
                target,
                "missing-lockfile",
                ecosystem,
                "Repository manifest has no recognized lockfile",
                "medium",
            ));
        }
        if !analyzed_ecosystems.contains(ecosystem) {
            observations.push(supply_observation(
                target,
                "unsupported-ecosystem",
                ecosystem,
                "Detected ecosystem is not covered by the current vulnerability plan",
                "info",
            ));
        } else if !vulnerability_data_available {
            observations.push(supply_observation(
                target,
                "vulnerability-data-unavailable",
                ecosystem,
                "Vulnerability data is unavailable; dependency coverage is incomplete",
                "info",
            ));
        }
    }
    observations.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    observations
}

pub fn normalize_license_state(
    observation: &mut RepositoryObservation,
    state: LicenseState,
    sources: &[&str],
) {
    observation.category = RepositoryFindingCategory::License;
    observation
        .metadata
        .insert("license_status".into(), state.token().into());
    let mut sources = sources
        .iter()
        .map(|source| (*source).to_owned())
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    observation
        .metadata
        .insert("license_sources".into(), sources.join(","));
    observation.description = match state {
        LicenseState::Detected => "License metadata detected; legal review is separate",
        LicenseState::Unknown => "License metadata was not determined; review is required",
        LicenseState::Conflicting => {
            "License sources conflict; technical and legal review is required"
        }
        LicenseState::PolicyReview => "License was detected and requires policy review",
    }
    .into();
}

fn supply_observation(
    target: &AuthorizedRepositoryTarget,
    rule: &str,
    ecosystem: &str,
    description: &str,
    severity: &str,
) -> RepositoryObservation {
    RepositoryObservation {
        engine_id: "edy-inventory".into(),
        engine_version: "0.1.0".into(),
        category: RepositoryFindingCategory::SupplyChain,
        rule_id: rule.into(),
        description: description.into(),
        location: "<repository>".into(),
        line: None,
        severity: severity.into(),
        confidence: "high".into(),
        fingerprint_version: "SUPPLY_CHAIN_FINDING_V1".into(),
        fingerprint: finding_fingerprint("SUPPLY_CHAIN_FINDING_V1", target, &[rule, ecosystem]),
        package: Some(ecosystem.into()),
        installed_version: None,
        vulnerability_id: None,
        aliases: vec![],
        affected_range: None,
        fixed_version: None,
        source: Some("repository-inventory".into()),
        secret_class: None,
        secret_preview: None,
        secret_digest: None,
        license: None,
        metadata: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RepositoryLimits, inspect};
    use edy_core::TargetId;
    use std::{fs, path::PathBuf};
    fn target() -> AuthorizedRepositoryTarget {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/aggregation-fixture");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package.json"), "{}").unwrap();
        let canonical = fs::canonicalize(root).unwrap();
        let text = canonical.to_string_lossy();
        AuthorizedRepositoryTarget::authorize(
            text.strip_prefix(r"\\?\").unwrap_or(&text),
            TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap(),
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            RepositoryLimits::default(),
        )
        .unwrap()
    }
    #[test]
    fn missing_lock_is_supply_chain_not_critical_vulnerability() {
        let t = target();
        let inventory = inspect(&t).unwrap();
        let result =
            aggregate_repository_posture(&t, &inventory, &BTreeSet::from(["node".into()]), false);
        assert_eq!(result.len(), 2);
        assert!(
            result
                .iter()
                .all(|item| item.category == RepositoryFindingCategory::SupplyChain)
        );
        assert!(result.iter().all(|item| item.severity != "critical"));
    }
    #[test]
    fn license_states_are_technical_and_preserve_sources() {
        let t = target();
        let mut item = supply_observation(&t, "license", "node", "placeholder", "info");
        normalize_license_state(
            &mut item,
            LicenseState::Conflicting,
            &["manifest", "engine", "manifest"],
        );
        assert_eq!(item.metadata["license_status"], "conflicting");
        assert_eq!(item.metadata["license_sources"], "engine,manifest");
        assert!(!item.description.contains("illegal"));
        assert!(!item.description.contains("unlawful"));
        for state in [
            LicenseState::Detected,
            LicenseState::Unknown,
            LicenseState::Conflicting,
            LicenseState::PolicyReview,
        ] {
            normalize_license_state(&mut item, state, &["license file"]);
            assert_eq!(item.metadata["license_status"], state.token());
        }
    }

    #[test]
    fn empty_lockfile_is_a_supply_chain_concern_not_a_vulnerability() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/aggregation-empty-lock-fixture");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        let canonical = fs::canonicalize(root).unwrap();
        let text = canonical.to_string_lossy();
        let target = AuthorizedRepositoryTarget::authorize(
            text.strip_prefix(r"\\?\").unwrap_or(&text),
            TargetId::new("018f4c2a-1d3b-7abc-8def-0123456789b1").unwrap(),
            "018f4c2a-1d3b-7abc-8def-0123456789b2",
            "2026-09-02T13:00:00Z",
            RepositoryLimits::default(),
        )
        .unwrap();
        let inventory = inspect(&target).unwrap();
        let result = aggregate_repository_posture(
            &target,
            &inventory,
            &BTreeSet::from(["rust".into()]),
            true,
        );
        assert!(
            result
                .iter()
                .any(|item| item.rule_id == "malformed-lockfile")
        );
        assert!(result.iter().all(|item| {
            item.category == RepositoryFindingCategory::SupplyChain && item.severity != "critical"
        }));
        fs::remove_dir_all(canonical).unwrap();
    }
}
