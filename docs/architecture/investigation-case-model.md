# Level 5 investigation cases

Cases collect evidence-backed clusters, findings, entities, an observed blast
radius, explainable risk/confidence/coverage/priority and an ordered timeline.
Strong meaningful cross-target correlation can create a `SUGGESTED` case; a user
must open it. A suggestion is not a confirmed incident, breach, compromise or
attack-in-progress claim.

Lifecycle transitions are validated and audited. Level 5 permits classification,
priority, annotations and lifecycle changes only; it performs no remediation.
Risk does not overwrite original severity. Confidence falls for conflicts,
uncertain parsing and unavailable providers. Coverage applies only to associated
analyzed targets. Priority is separately derived and always carries reasons.

Blast radius reports counts of observed targets, components, findings,
vulnerabilities and target types. It never invents an organization-wide percentage
without a real denominator.

Allowed transitions are closed: suggested to open; open to investigating,
accepted-risk or ignored; investigating to remediating, resolved or accepted-risk;
remediating to verification-pending; verification-pending to resolved or back to
investigating; resolved to open for recorded recurrence. Invalid transitions fail
without changing the stored case or timeline.

Temporal correlation keeps a finding stable across observations. A later
observation updates `last_seen` and `occurrence_count` instead of creating a
duplicate finding. When recurrence/reopening is explicitly present in normalized
input, the suggested case receives a deterministic `finding_reopened` event;
this remains an observation and is not an incident claim.
