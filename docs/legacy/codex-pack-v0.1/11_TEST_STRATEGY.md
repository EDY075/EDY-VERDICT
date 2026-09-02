# 11 - TEST STRATEGY

## Test layers

### Unit

- normalization;
- finding fingerprints;
- severity/confidence mapping;
- redaction;
- URI/path normalization;
- report view models;
- retry/backoff calculation.

### Provider contract

Every provider adapter must pass the same behavior contract:

- available/success;
- no findings;
- findings;
- unsupported/not configured;
- timeout;
- cancellation;
- malformed output;
- non-zero process exit;
- rate limited;
- sensitive error redaction.

### Integration

Run against installed official CLIs/services where safe. External API tests should be opt-in and quota-aware; default CI uses recorded/synthetic responses for transport-layer behavior without pretending those are production results.

### Safe security fixtures

- synthetic fake API tokens that match patterns but are not real credentials;
- intentionally vulnerable package locks in isolated fixture directories;
- intentionally weak config/IaC fixtures;
- EICAR only where appropriate to validate antivirus integration;
- custom harmless YARA test files/rules;
- local test HTTP/TLS endpoints where possible.

No live malware repository fixture.

### E2E

From clean app state:

1. scan safe synthetic repo;
2. observe known finding;
3. open evidence;
4. generate report;
5. execute allowed synthetic/manual remediation flow;
6. rescan;
7. verify lifecycle and report update.

## Negative/security tests

- filename containing shell metacharacters;
- extremely long path/name;
- malformed UTF-8/tool output;
- huge stdout/stderr;
- provider process hang;
- provider JSON schema drift;
- API 429/backoff;
- expired/invalid key;
- revoked TLS certificate test endpoint where safe;
- report HTML injection strings;
- symlink/junction traversal fixture;
- secret pattern in exception/log message to prove redaction.

## Quality gates

No level passes with:

- failing tests;
- build warnings newly introduced without disposition;
- Critical/High dependency vulnerability without explicit reviewed exception;
- secret scanner hit in tracked project files;
- unsupported third-party license introduction;
- production mock/fallback path;
- button/action without implementation in a feature declared done.
