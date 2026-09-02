# Verdict, risk and confidence model

The model is deterministic and explainable. Every score carries contribution strings suitable for
an audit record. Generated prose or AI inference is not part of the verdict contract.

## Verdict priority

1. `malicious`: at least one malicious signal backed by strong evidence;
2. `vulnerable`: a vulnerability signal was observed;
3. `suspicious`: a suspicious signal or high/critical correlated finding was observed;
4. `needs_review`: other findings remain;
5. `no_known_indicators`: no findings, every planned check passed and no required check/provider is
   unavailable;
6. `insufficient_coverage`: the remaining zero-finding case.

This ordering prevents missing coverage from weakening strong malicious evidence, while preventing
an incomplete zero-finding scan from being described as clean.

## Risk score

Risk is impact/likelihood, bounded to `0..=100`. It starts from maximum finding severity:

| Severity | Base |
|---|---:|
| info | 0 |
| low | 20 |
| medium | 40 |
| high | 70 |
| critical | 90 |

Known exploitation adds 10, exposed attack surface adds 10, persistence adds 5, and broad affected
scope adds 5. A finding confirmed by multiple independent engines adds 5; unrelated single-source
findings do not receive that bonus. The result saturates at 100
and maps back to info `0..9`, low `10..29`, medium `30..59`, high `60..84`, critical `85..100`.
Provider unavailability never changes risk.

## Confidence score

Confidence expresses evidence quality and coverage, not impact. Passed planned tasks contribute up
to 70 points proportionally. Complete planned coverage adds 10. Strongest evidence adds 5/10/15
for weak/moderate/strong. The minimum parser confidence across contributing observations adds
0/5/10 for low/medium/high. Agreement inside one correlated finding adds 5. Each unavailable
external check subtracts 5, capped at 20. The final score is `0..=100`: low `0..39`, medium
`40..74`, high `75..100`.

Examples:

- one of four planned checks passes and finds nothing: low confidence,
  `insufficient_coverage`;
- all four pass and find nothing, with no unavailable providers: high confidence,
  `no_known_indicators`;
- a strong malicious observation with partial coverage: `malicious`; confidence still reflects the
  missing coverage;
- an unavailable provider lowers confidence and makes a zero-finding result insufficient, but does
  not reduce the risk score of existing findings.

## Remediation and rescan

Plans separate manual-only, safe-automatable and confirmation-required steps. A step cannot claim
safe automation while also requiring confirmation. Verification names the expected fingerprint and
required engines. Workflow resolution is allowed only after remediation completion, verification
pending and a rescan. Outcomes distinguish resolved, still present and regression; history is
append-only in the domain object. Real host changes require a separately authorized adapter and are
outside Level 0.
