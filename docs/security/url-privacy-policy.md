# URL privacy policy

Level 4 is local-first. No target is submitted to URLhaus, VirusTotal or another
reputation service by default. URLhaus is an optional BYOK/community-data
provider. Without configuration, the product reports `Not checked — optional
provider not configured`; it never converts missing coverage into a clean result.

The implemented local reputation contract compares the SHA-256 of the exact
canonical URL against an already validated local dataset. It does not perform URL
submission, hostname expansion or similarity matching. Provider credentials are
not accepted through frontend IPC, bundled in the application, stored in SQLite
or logged. Future BYOK entry must use the existing native secret-store boundary.

Cookie values are discarded during parsing. Only a bounded safe cookie name and
attributes such as Secure, HttpOnly, SameSite, Domain presence, Path, expiry,
Partitioned and prefix consistency may persist. Query values and URL credentials
may not persist. Logs, SQLite, reports, IPC payloads and DOM are covered by
synthetic redaction tests.

DNS, TLS and HTTP observations are point-in-time. Passive checks do not prove that
a website is safe, legitimate, phishing-free, fraud-free or vulnerability-free.
No page JavaScript is executed, no crawler is used and no active vulnerability
exploitation is performed. A missing header does not automatically prove
exploitability; a present header does not automatically prove security.
