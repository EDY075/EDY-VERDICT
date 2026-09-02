# SOURCES - RESEARCH SNAPSHOT

Checked around 2026-09-01. Always re-verify terms/version-sensitive facts before a public/commercial release.

- **Microsoft .NET Support Policy** - https://dotnet.microsoft.com/en-us/platform/support/policy
  .NET 10 LTS active; support through 2028-11-14; 10.0.11 current patch observed 2026-08-11.
- **Avalonia 12.1 release** - https://avaloniaui.net/blog/release-12-1
  Avalonia 12.1 released July 2026; cross-platform .NET UI; core open source.
- **Avalonia GitHub releases** - https://github.com/AvaloniaUI/Avalonia/releases
  12.1.x stable branch; 12.1.1 visible in August 2026 releases.
- **Avalonia license** - https://github.com/AvaloniaUI/Avalonia/blob/main/licence.md
  Avalonia core is MIT licensed.
- **YARA-X installation** - https://virustotal.github.io/yara-x/docs/intro/installation/
  Official prebuilt binaries exist for Windows/Linux/macOS; Rust not required for consumers.
- **YARA-X repository/license** - https://github.com/VirusTotal/yara-x
  YARA-X is mature/stable, production used by VirusTotal; BSD-3-Clause.
- **Gitleaks repository** - https://github.com/gitleaks/gitleaks
  Gitleaks CLI detects secrets; repository identifies MIT license.
- **Gitleaks CLI license** - https://github.com/gitleaks/gitleaks/blob/master/LICENSE
  CLI license is MIT. Do not confuse with gitleaks-action licensing.
- **Trivy filesystem scanning** - https://trivy.dev/docs/dev/target/filesystem/
  Trivy scans vulnerabilities, misconfigurations, secrets, licenses and can emit SBOM.
- **Trivy repository scanning** - https://trivy.dev/docs/latest/target/repository/
  Trivy scans local/remote code repositories.
- **Trivy license** - https://github.com/aquasecurity/trivy/blob/main/LICENSE
  Apache License 2.0.
- **OSV API** - https://google.github.io/osv.dev/api/
  Public OSV API currently states no rate limit; no API key required.
- **OSV-Scanner installation** - https://google.github.io/osv-scanner/installation/
  Official Windows binaries and WinGet distribution are available.
- **CISA KEV data** - https://github.com/cisagov/kev-data
  Official KEV data mirror publishes JSON/CSV and updates with the canonical catalog.
- **FIRST EPSS API** - https://api.first.org/epss/
  Public EPSS CVE exploitation probability data API.
- **NVD developers** - https://nvd.nist.gov/developers/start-here
  NVD API 2.0; API key recommended. Current published rate guidance commonly states 5 requests/30s without key and 50/30s with key; implementation must obey headers/retry guidance.
- **URLhaus Community API** - https://urlhaus.abuse.ch/api/
  Free under fair use; Auth-Key required; commercial/for-profit use may require enhanced commercial API.
- **MalwareBazaar Community API** - https://bazaar.abuse.ch/api/
  Free under fair use; Auth-Key required; submit confirmed malware only; commercial use may require enhanced API.
- **VirusTotal Public vs Premium API** - https://docs.virustotal.com/reference/public-vs-premium-api
  Public API: 4 requests/minute, 500/day; must not be used in commercial products/services.
- **Microsoft SmartScreen reputation** - https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
  Unsigned downloads can show SmartScreen warnings; Store distribution avoids download warnings; Artifact Signing is paid.
- **SignPath Foundation** - https://signpath.org/
  Free code signing is offered for qualifying open-source projects.
- **Playwright .NET license** - https://github.com/microsoft/playwright-dotnet/blob/main/LICENSE
  Playwright for .NET is MIT licensed.
