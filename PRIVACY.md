# Privacy

EDY VERDICT stores scan metadata, redacted evidence, reports, investigations and manual-verification history locally in SQLite. UI preferences contain only locale, theme and onboarding state. Telemetry and automatic support uploads are absent.

Repository and file analysis read only explicitly authorized local targets. Installed-application inventory does not send host inventory to public providers. Passive URL checks may contact the explicitly authorized public target and optional reputation providers; query values are stripped or used once according to the selected policy and are never retained. File bytes are never uploaded.

Provider refreshes and future BYOK integrations require explicit action. API secrets are not configured by this candidate. Diagnostic export is manual and must be reviewed before sharing. There is no EDY VERDICT cloud copy of local history.
