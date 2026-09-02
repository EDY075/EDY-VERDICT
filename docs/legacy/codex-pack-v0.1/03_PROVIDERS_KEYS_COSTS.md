# 03 - PROVIDERS, KEYS, COSTS AND PRE-REQUISITES

## A. Works without user API keys

| Capability/provider | Key | Cost to user | Role |
|---|---|---:|---|
| Local SHA-256/SHA-1/MD5 | none | 0 | File identity; SHA-256 is canonical |
| Authenticode/Windows certificate APIs | none | 0 | Signature/publisher evidence |
| Microsoft Defender (when present) | none | 0 | Local AV evidence |
| YARA-X | none | 0 | Local rule matching |
| Gitleaks CLI | none | 0 | Secret detection in repos/files |
| Trivy | none | 0 | Vulnerabilities/misconfig/secrets/licenses/SBOM |
| OSV-Scanner | none | 0 | Dependency vulnerability analysis |
| OSV API | none | 0 | Vulnerability enrichment; current API says no rate limit |
| CISA KEV JSON/CSV | none | 0 | Known exploited status |
| FIRST EPSS | none | 0 | Exploitation probability/percentile |
| DNS/TLS/HTTP checks | none | 0 | Passive web analysis |

## B. Free/community keys recommended

### NVD API key

**Placeholder:** `NVD_API_KEY`
**Required for MVP?** No.
**Recommended?** Yes.

Use NVD as enrichment, not the sole vulnerability database. The implementation must have throttling/backoff/cache and obey current NVD guidance/headers. Key is stored in the platform secret store, never `appsettings.json`.

### abuse.ch Auth-Key

**Placeholder:** `ABUSECH_AUTH_KEY`
Can be used with URLhaus and MalwareBazaar community APIs according to current service terms.

Community use is free under fair-use language, but commercial/for-profit usage may require an enhanced commercial subscription. Therefore abuse.ch providers are optional and policy-tagged.

### VirusTotal Community key - OPTIONAL / RESTRICTED

**Placeholder:** `VIRUSTOTAL_API_KEY`.

The public API currently documents 4 requests/minute and 500/day and explicitly forbids use in commercial products/services. Therefore:

- never make VirusTotal a required product dependency;
- keep it disabled unless the user configures it and accepts provider terms;
- label it `Community / Personal-Lab Only` in the provider UI;
- do not ship Edy's personal key;
- a future commercial product must use a licensed alternative/Premium arrangement or disable this provider.

## C. No-upload policy

Default file workflow:

`file -> local SHA-256 -> local engines -> hash/intel lookup`

Do not upload files to external services automatically. MalwareBazaar submission is not part of the user scan pipeline; their community documentation says submissions should be confirmed/vetted malware only.

## D. Key storage

Development:

- `.NET user-secrets` or process environment variables;
- CI: GitHub Actions encrypted secrets;
- never a checked-in `.env` containing real values.

Installed Windows app:

- Windows Credential Manager or DPAPI-backed secret store through an abstraction;
- store only provider credentials, not raw scan contents;
- expose `Remove key` and `Test connection` operations;
- redact keys from exception messages/logs.

Future non-Windows ports require another secret-store implementation behind the same interface.

## E. Engine Manager manifest

Create a signed/checked-in metadata file with fields such as:

```json
{
  "engineId": "yara-x",
  "version": "PINNED_AT_LEVEL_MINUS_1",
  "source": "official-release-url",
  "license": "BSD-3-Clause",
  "platform": "win-x64",
  "sha256": "UPSTREAM_OR_RELEASE_VERIFIED_VALUE",
  "acquisition": "download-on-demand"
}
```

Never write a fake checksum. If upstream does not publish one, record that limitation and use a stronger acquisition/provenance control where available.

## F. Accounts/checklist before feature work

- [ ] NVD key requested/available or explicit no-key mode accepted.
- [ ] abuse.ch account/Auth-Key available for optional URLhaus/MalwareBazaar tests.
- [ ] VirusTotal Community account/key only if personal-lab provider testing is desired.
- [ ] GitHub repository location decided before CI/release level.
- [ ] SignPath Foundation eligibility/application evaluated before public Windows release.
- [ ] No secret value added to this documentation pack.

## G. Expected mandatory monthly project cost

**MVP core: R$ 0/month.**

Potential future costs:

- code-signing path if free OSS signing is unavailable;
- Microsoft Artifact Signing (Microsoft currently describes paid pricing) if selected;
- commercial threat-intel subscriptions if the project becomes for-profit/enterprise;
- optional hosting/backend only if a later edition needs central services.
