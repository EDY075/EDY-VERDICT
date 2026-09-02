# Engine Manifest Contract V2

`engine-manifest.schema.json` is the active V2 contract. The former schema is
retained as `engine-manifest-v1.schema.json` only for historical documentation and
explicit unsupported-version tests. It is not an active acquisition format.

`engine-receipt.schema.json` defines the independent V2 receipt stored outside an
engine installation. Receipt integrity does not replace trust-policy evaluation.

Engine acquisition remains disabled in Level -1D.1. No YARA-X, Gitleaks, Trivy or
OSV-Scanner binaries may be acquired, executed or promoted in this round. Gitleaks
8.30.1 remains blocked. Only project-built benign fixtures may run.
