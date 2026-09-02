# Synthetic execution fixtures

These files are fabricated Level 0 inputs only. They contain no user data, malware,
credential, or usable secret. `EDY_FAKE_TEST_TOKEN_IMPOSSIBLE_*` is an intentional,
non-credential marker.

Possession of these fixtures does not authorize engine execution. A smoke test must
still pass the manifest, receipt, artifact, runtime-data, containment, and network-policy
gates. The current Windows Job Object runner is not a network sandbox, so the frozen
`network_policy = deny` contract keeps real engine smoke execution blocked.
