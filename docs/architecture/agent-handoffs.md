# JR integration record — Level -1C

JR created root manifests, structural edy-core contracts and ownership map before
delegation. Core and Engine specialist attempts returned usage-limit failures; no
changes came from them. JR implemented those infrastructure modules locally.

Tauri/Frontend specialist owned only apps/desktop. It delivered source, tests,
security/config/Isolation explanations and no changes to root contracts or locks.
JR inspected main.rs, build.rs, capabilities, CSP, frontend parser, package pins
and test implementation and reran the frontend gates. Its plain deterministic
build icon is not a product identity/design approval. Native app build not run.

The same available specialist then performed read-only QA of the JR's storage,
secret and process code. JR corrected and regression-tested:

1. Cancellation before launch; deadline during hashing; fixed/local regular image
   <=512 MiB; bounded waits when Job assignment/resume fails.
2. Windows path devices, invalid characters, trailing dots/spaces and tool namespace
   collisions. Engine acquisition remains unconditionally PolicyBlocked.
3. SQLite actual-schema verification, missing tables, altered migration history,
   FK validation and sqliteX-prefixed user objects (literal prefix, not SQL LIKE).
4. Wipe of the native Credential Manager blob before CredFree in addition to the
   zeroizing Rust copy. Two fake credential tests always run serially.
5. Canonical working-directory resolution/local-directory checks.

No specialist performed a merge, publication or shared-contract integration.
No failures were silenced with clippy allow or advisory ignore entries.
Residual limitations: cooperative synchronous I/O cancellation; no full OS sandbox;
no assurance against same-user adversarial races on parent directories; no runtime
Tauri/CSP/zero-network claim until the explicitly blocked smoke is authorized.
