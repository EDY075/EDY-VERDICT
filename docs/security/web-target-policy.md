# Web target policy

Level 4 accepts one explicitly entered absolute `http://` or `https://` URL. The
user sees a sanitized preview and must authorize that exact normalized target
before a bounded passive request chain can start. Preview and authorization are
process-local, single-use records.

The parser requires an explicit scheme, a dotted DNS hostname or a public IP
literal, and the default port (80 or 443). It rejects userinfo, single-label hosts,
control characters, whitespace, backslashes, encoded NUL/CR/LF/backslash, malformed
IPv6 zones, non-HTTP schemes, nonstandard ports and inputs over 2,048 bytes. DNS
names are normalized to lowercase IDNA ASCII and one trailing dot is removed.
Fragments are never sent or retained.

Query values have two explicit modes. `strip` removes the entire query before any
request. `send` permits the original query in process memory for that authorized
request chain only. Displays, IPC results, SQLite payloads, findings and reports
retain only parameter names with `[REDACTED]`; values never enter fingerprints.

An authorization permits only normal GET requests with a fixed transparent user
agent and `Accept-Encoding: identity`. No form submission, login, crawler, page
body, JavaScript execution, arbitrary method/header, credential, cookie jar,
referer or raw generic HTTP IPC exists.
