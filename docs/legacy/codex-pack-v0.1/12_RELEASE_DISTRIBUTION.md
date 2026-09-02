# 12 - RELEASE AND DISTRIBUTION

## External-user objective

A user should be able to obtain EDY VERDICT, install/run it, perform useful local scans without creating an account, and optionally configure free/community providers.

## Windows packaging options

### Option A - Self-contained installer/portable package

Pros: simplest development/release path.
Cons: unsigned/new binaries can trigger SmartScreen or Smart App Control friction.

### Option B - Microsoft Store

Pros: Microsoft documentation states Store apps are signed by Microsoft and avoid SmartScreen download warnings.
Cons: separate publishing requirements/process; decide later.

### Option C - Code signing outside Store

Microsoft currently recommends its Artifact Signing service for non-Store distribution, but it is paid. For an open-source project, evaluate **SignPath Foundation**, which advertises free code signing for qualifying OSS projects.

**Selected release-readiness action:** apply/evaluate SignPath Foundation before public v1.0. If not eligible, document unsigned beta behavior honestly rather than buying a service prematurely.

## Third-party engine delivery

Preferred v0.x:

- EDY app ships independently;
- Engine Manager downloads official pinned tools on demand;
- show source/version/license before acquisition;
- validate integrity/provenance;
- record installation metadata;
- allow engine removal/update.

A later offline/full bundle requires a separate redistribution audit and third-party notices.

## Release artifact set

- Windows installer or portable release chosen by ADR;
- SHA-256 checksums;
- SBOM for EDY app;
- `THIRD_PARTY_NOTICES.md`;
- `SECURITY.md`;
- `PRIVACY.md`;
- `CHANGELOG.md`;
- `RELEASE_NOTES.md`;
- signed artifacts if signing path available;
- clean-machine validation evidence.

## Update policy

No silent self-updater in the first milestone. Updates should be explicit. Engine databases/rules may have an explicit refresh operation with provenance and rollback/version history where feasible.
