use edy_remediation::{GuidanceAction, RemediationSnapshot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ManualRemediationReport {
    pub schema: &'static str,
    pub product_version: String,
    pub action_id: String,
    pub case_id: Option<String>,
    pub finding_id: String,
    pub status: String,
    pub guidance: Vec<String>,
    pub suggested_diff: Option<String>,
    pub limitations: Vec<String>,
    pub timeline: Vec<edy_remediation::ManualEvent>,
    pub automatic_mutation: &'static str,
    pub verification: Option<edy_remediation::ManualVerificationResult>,
}
impl ManualRemediationReport {
    pub fn from_snapshot(s: &edy_remediation::ManualSnapshot) -> Self {
        Self {
            schema: "EDY_MANUAL_VERIFICATION_REPORT_V1",
            product_version: crate::PRODUCT_VERSION.into(),
            action_id: s.plan.actions[0].action_id.clone(),
            case_id: s.plan.case_id.clone(),
            finding_id: s.plan.finding_id.clone(),
            status: edy_remediation::manual_wording(s.state).into(),
            guidance: s.guidance.clone(),
            suggested_diff: s.suggested_diff.clone(),
            limitations: s.limitations.clone(),
            timeline: s.timeline.clone(),
            automatic_mutation: "POLICY_BLOCKED",
            verification: s.verification.clone(),
        }
    }
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    pub fn html(&self) -> String {
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Manual verification</title></head><body><h1>Remediation guidance generated</h1><p>{}</p><p>Manual action required — not applied by EDY VERDICT</p><pre>{}</pre><pre>{}</pre><p>{}</p></body></html>",
            escape(&self.status),
            escape(&self.guidance.join("\n")),
            escape(
                self.suggested_diff
                    .as_deref()
                    .unwrap_or("No suggested diff")
            ),
            escape(&self.limitations.join(" "))
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAudience {
    Executive,
    Technical,
    Analyst,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemediationReport {
    pub schema: String,
    pub product_version: String,
    pub audience: RemediationAudience,
    pub action_id: String,
    pub finding_id: String,
    pub case_id: Option<String>,
    pub safety_class: String,
    pub action_kind: String,
    pub execution_status: String,
    pub verification_status: String,
    pub rollback_status: String,
    pub residual_risk: String,
    pub details_safe: Vec<(String, String)>,
}

impl RemediationReport {
    pub fn from_snapshot(snapshot: &RemediationSnapshot, audience: RemediationAudience) -> Self {
        let action = &snapshot.plan.actions[0];
        let verification = snapshot.verification.as_ref().map_or_else(
            || "not_run".into(),
            |value| format!("{:?}", value.outcome).to_ascii_lowercase(),
        );
        let rollback = snapshot.rollback_receipt.as_ref().map_or_else(
            || {
                if snapshot.receipt.is_some() && action.rollback.eligible {
                    "available".into()
                } else {
                    "not_available".into()
                }
            },
            |_| "rolled_back".into(),
        );
        let mut details = vec![
            (
                "rule".into(),
                format!("{} v{}", action.rule_id, action.rule_version),
            ),
            ("plan_id".into(), snapshot.plan.plan_id.clone()),
            ("plan_sha256".into(), snapshot.plan.plan_sha256.clone()),
            ("target".into(), action.precondition.canonical_path.clone()),
            (
                "precondition_sha256".into(),
                action.precondition.expected_sha256.clone(),
            ),
            (
                "verification_scanner".into(),
                action.verification.scanner_id.clone(),
            ),
            (
                "coverage".into(),
                snapshot
                    .verification
                    .as_ref()
                    .map_or("pending", |value| {
                        if value.coverage_sufficient {
                            "sufficient"
                        } else {
                            "insufficient"
                        }
                    })
                    .into(),
            ),
        ];
        if audience != RemediationAudience::Executive {
            if let Some(preview) = &snapshot.preview
                && let Some(diff) = &preview.sanitized_unified_diff
            {
                details.push(("sanitized_diff".into(), diff.clone()));
            }
            if let Some(receipt) = &snapshot.receipt {
                details.push(("original_sha256".into(), receipt.original_sha256.clone()));
                details.push(("resulting_sha256".into(), receipt.resulting_sha256.clone()));
                details.push(("backup_id".into(), receipt.backup_id.clone()));
            }
            details.push(("timeline".into(), snapshot.timeline_safe.join(" -> ")));
        }
        Self {
            schema: "EDY_REMEDIATION_REPORT_V1".into(),
            product_version: crate::PRODUCT_VERSION.into(),
            audience,
            action_id: action.action_id.clone(),
            finding_id: action.finding_id.clone(),
            case_id: action.case_id.clone(),
            safety_class: format!("{:?}", action.safety_class).to_ascii_lowercase(),
            action_kind: format!("{:?}", action.kind).to_ascii_lowercase(),
            execution_status: format!("{:?}", snapshot.state).to_ascii_lowercase(),
            verification_status: verification,
            rollback_status: rollback,
            residual_risk:
                "Verification applies only to the checks shown; remediation is not proof of safety."
                    .into(),
            details_safe: details,
        }
    }

    pub fn from_guidance(action: &GuidanceAction, audience: RemediationAudience) -> Self {
        Self {
            schema: "EDY_REMEDIATION_REPORT_V1".into(),
            product_version: crate::PRODUCT_VERSION.into(),
            audience,
            action_id: action.action_id.clone(),
            finding_id: action.finding_id.clone(),
            case_id: action.case_id.clone(),
            safety_class: "guidance_only".into(),
            action_kind: format!("{:?}", action.kind).to_ascii_lowercase(),
            execution_status: "NOT EXECUTED BY EDY VERDICT".into(),
            verification_status: "manual_verification_required".into(),
            rollback_status: "not_applicable".into(),
            residual_risk: "Manual action and rescan remain required.".into(),
            details_safe: vec![
                ("target".into(), action.affected_target_safe.clone()),
                ("guidance".into(), action.guidance_safe.join(" | ")),
                (
                    "verification_steps".into(),
                    action.verification_steps_safe.join(" | "),
                ),
            ],
        }
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn html(&self) -> String {
        let details = self
            .details_safe
            .iter()
            .map(|(key, value)| format!("<dt>{}</dt><dd>{}</dd>", escape(key), escape(value)))
            .collect::<String>();
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>EDY VERDICT remediation</title></head><body><main><h1>Remediation status</h1><p>{}</p><dl><dt>Finding</dt><dd>{}</dd><dt>Action</dt><dd>{}</dd><dt>Safety class</dt><dd>{}</dd><dt>Verification</dt><dd>{}</dd><dt>Rollback</dt><dd>{}</dd>{}</dl><p>{}</p></main></body></html>",
            escape(&self.execution_status),
            escape(&self.finding_id),
            escape(&self.action_id),
            escape(&self.safety_class),
            escape(&self.verification_status),
            escape(&self.rollback_status),
            details,
            escape(&self.residual_risk)
        )
    }
}

fn escape(value: &str) -> String {
    value
        .chars()
        .take(8192)
        .fold(String::new(), |mut output, value| {
            output.push_str(match value {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '\"' => "&quot;",
                '\'' => "&#39;",
                _ => {
                    output.push(value);
                    return output;
                }
            });
            output
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edy_remediation::{RemediationActionKind, RemediationSafetyClass};

    #[test]
    fn guidance_reports_disclose_non_execution_and_escape_injection() {
        let guidance = GuidanceAction {
            action_id: "guidance".into(),
            finding_id: "finding".into(),
            case_id: None,
            kind: RemediationActionKind::RemoteWebConfiguration,
            safety_class: RemediationSafetyClass::GuidanceOnly,
            affected_target_safe: "<script>alert(1)</script>".into(),
            guidance_safe: vec!["Review server configuration.".into()],
            verification_steps_safe: vec!["Rescan the URL.".into()],
            execution_disclosure: "NOT EXECUTED BY EDY VERDICT".into(),
        };
        let report = RemediationReport::from_guidance(&guidance, RemediationAudience::Technical);
        assert!(
            report
                .json()
                .unwrap()
                .contains("NOT EXECUTED BY EDY VERDICT")
        );
        let html = report.html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
