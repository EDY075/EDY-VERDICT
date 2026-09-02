use crate::manifest::{
    ArtifactSetRecord, ContractError, EngineManifest, EngineTrustPolicy, artifact_set_sha256,
    canonical_token, parse_unique_json, safe_relative, sha256_hex, sha256_valid,
    utc_timestamp_valid, version_token,
};
use serde::{Deserialize, Serialize};

pub const ENGINE_RECEIPT_SCHEMA_VERSION: u32 = 2;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineReceipt {
    pub schema_version: u32,
    pub engine_id: String,
    pub version: String,
    pub manifest_sha256: String,
    pub entrypoint_sha256: String,
    pub artifact_set_sha256: String,
    pub promoted_at: NullableTimestamp,
    pub state: ReceiptState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct NullableTimestamp(pub Option<String>);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Staged,
    Ready,
    Revoked,
    Tampered,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Ready,
    InvalidManifest,
    Unverified,
    Tampered,
    PolicyBlocked,
}

pub struct ObservedArtifact<'a> {
    pub relative_path: &'a str,
    pub bytes: &'a [u8],
}

pub struct IntegrityObservation {
    entrypoint_sha256: String,
    artifact_set_sha256: String,
}

impl IntegrityObservation {
    pub fn from_bytes(
        manifest: &EngineManifest,
        entrypoint_bytes: &[u8],
        auxiliary_files: &[ObservedArtifact<'_>],
    ) -> Result<Self, ContractError> {
        manifest.validate()?;
        if entrypoint_bytes.is_empty()
            || auxiliary_files.len() != manifest.artifact.auxiliary_hashes.len()
        {
            return Err(ContractError::InvalidManifest(
                "incomplete observed artifact set",
            ));
        }
        let entrypoint_sha256 = sha256_hex(entrypoint_bytes);
        let mut records = vec![ArtifactSetRecord {
            relative_path: manifest.artifact.entrypoint.clone(),
            sha256: entrypoint_sha256.clone(),
            size: entrypoint_bytes.len() as u64,
        }];
        let mut paths = std::collections::BTreeSet::new();
        for file in auxiliary_files {
            if file.bytes.is_empty()
                || !safe_relative(file.relative_path)
                || !paths.insert(file.relative_path.to_ascii_lowercase())
            {
                return Err(ContractError::InvalidManifest(
                    "invalid observed artifact set",
                ));
            }
            records.push(ArtifactSetRecord {
                relative_path: file.relative_path.to_owned(),
                sha256: sha256_hex(file.bytes),
                size: file.bytes.len() as u64,
            });
        }
        Ok(Self {
            entrypoint_sha256,
            artifact_set_sha256: artifact_set_sha256(records)?,
        })
    }
}

impl EngineReceipt {
    pub fn parse(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(ContractError::InvalidManifest("receipt exceeds 64 KiB"));
        }
        let value = parse_unique_json(bytes)?;
        let found = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64);
        if found != Some(u64::from(ENGINE_RECEIPT_SCHEMA_VERSION)) {
            return Err(ContractError::ManifestVersionUnsupported {
                found,
                supported: ENGINE_RECEIPT_SCHEMA_VERSION,
            });
        }
        let receipt: Self = serde_json::from_value(value)
            .map_err(|_| ContractError::InvalidManifest("JSON does not match Receipt V2"))?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != ENGINE_RECEIPT_SCHEMA_VERSION
            || !canonical_token(&self.engine_id)
            || !version_token(&self.version)
            || !sha256_valid(&self.manifest_sha256)
            || !sha256_valid(&self.entrypoint_sha256)
            || !sha256_valid(&self.artifact_set_sha256)
        {
            return Err(ContractError::InvalidManifest(
                "invalid receipt identity or hash",
            ));
        }
        match (&self.state, &self.promoted_at.0) {
            (ReceiptState::Staged, None) => {}
            (ReceiptState::Staged, Some(_)) | (_, None) => {
                return Err(ContractError::InvalidManifest(
                    "receipt state and promoted_at disagree",
                ));
            }
            (_, Some(timestamp)) if !utc_timestamp_valid(timestamp) => {
                return Err(ContractError::InvalidManifest("invalid receipt timestamp"));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn verify_against(
        &self,
        manifest: &EngineManifest,
        observation: &IntegrityObservation,
    ) -> Result<(), ContractError> {
        self.validate()?;
        manifest.validate()?;
        if self.engine_id != manifest.identity.id
            || self.version != manifest.identity.version
            || self.manifest_sha256 != manifest.canonical_sha256()?
            || self.entrypoint_sha256 != manifest.artifact.executable_sha256
            || self.entrypoint_sha256 != observation.entrypoint_sha256
            || self.artifact_set_sha256 != manifest.declared_artifact_set_sha256()?
            || self.artifact_set_sha256 != observation.artifact_set_sha256
        {
            return Err(ContractError::InvalidManifest("receipt integrity mismatch"));
        }
        Ok(())
    }
}

pub fn verify_execution_ready(
    manifest: &EngineManifest,
    receipt: Option<&EngineReceipt>,
    policy: &EngineTrustPolicy,
    observation: &IntegrityObservation,
) -> Result<EngineState, EngineState> {
    if manifest.validate().is_err() {
        return Err(EngineState::InvalidManifest);
    }
    let Some(receipt) = receipt else {
        return Err(EngineState::Unverified);
    };
    if policy.evaluate(manifest).is_err() {
        return Err(EngineState::PolicyBlocked);
    }
    if receipt.state != ReceiptState::Ready {
        return Err(EngineState::Unverified);
    }
    if receipt.verify_against(manifest, observation).is_err() {
        return Err(EngineState::Tampered);
    }
    Err(EngineState::PolicyBlocked)
}
