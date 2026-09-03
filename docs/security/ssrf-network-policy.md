# SSRF and network policy

Every initial target and redirect hop is parsed, resolved, normalized and checked
before transport. Empty answers, more than 16 answers, and any set containing a
blocked address fail closed. A public plus private answer is therefore rejected,
not partially accepted.

Blocked IPv4 includes unspecified/current network, RFC1918, CGNAT, loopback,
link-local/metadata, protocol/documentation/benchmark ranges, multicast and
reserved space. Blocked IPv6 includes unspecified, loopback, unique-local,
link-local, multicast, discard/documentation/benchmark ranges. IPv4-mapped IPv6 is
normalized and evaluated by the IPv4 policy.

The validated answer set is recorded, and one address from that exact set is
pinned into a dedicated backend-only reqwest client using hostname-preserving
resolution. Host/SNI and certificate hostname validation remain tied to the URL
hostname. A redirect target is resolved exactly once before the hop is marked as
followed; that prevalidated set is consumed by the next connection. Tests prove a
later private DNS answer cannot replace the pinned address and that a private
redirect answer causes zero second requests.

Redirects are manual. At most five redirects and six total requests are allowed;
loops and malformed locations fail closed. HTTPS-to-HTTP downgrade is recorded and
not followed. Every public redirect is independently revalidated. System proxy,
PAC and environment proxy discovery are bypassed by the client; the frontend has
no HTTP capability.

DNS has a 3-second wait. Connect timeout is 4 seconds and request timeout 8
seconds. Response bodies are never read. Retained response metadata is capped at
64 headers, 32 KiB total, 4 KiB per value and 32 cookies.
