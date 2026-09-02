# Packaging readiness — NSIS ready, overall gate waiting upstream

Reviewed 2026-09-01 and updated after the controlled source-build promotion on
2026-09-02.

## NSIS project-local toolchain

`NSIS = READY`.

The project-local kit is promoted at `tools/packaging/nsis/3.12/`. Its trust
anchor is not the SourceForge release ZIP. The approved chain is:

```text
official NSIS source
-> tag v312
-> commit e3f60402bcdf7be822d159b531c6e38ddf32de12
-> frozen 835-file source manifest
-> security fix #1326 present
-> verified SCons 4.11.1 and zlib 1.3.2
-> two clean independent builds
-> 276/276 SHA-256 equality
-> static PE analysis
-> project-local makensis /VERSION = v3.12
```

The bundle contains four LZMA stubs and four required upstream zlib stubs. It
contains no bzip2 and no third-party NSIS plugins. `Bin/zlib1.dll` is the only
expected non-system runtime dependency of `makensis.exe`; zlib uses the static
MSVC CRT, so no VC++ Redistributable is required by this kit.

`AUTHENTICODE = NOT_REQUIRED_FOR_INTERNAL_BUILD_TOOL`. Every use must first run
the closed-set SHA-256 verifier. A mismatch means `TOOL_STATE = TAMPERED` and
execution is denied. This decision does not waive the future Authenticode gate
for EDY VERDICT public executables, installer, uninstaller, or updater.

License notices are bundled and `LICENSE_GATE = PASS`. NSIS is classified as
`BUILD_TOOLING`, not `PRODUCT_RUNTIME` or `EXTERNAL_ENGINES`.

Known residual risk: all eight installer stubs are linked by upstream with
`/FIXED`, so ASLR is disabled. This is recorded as
`KNOWN_UPSTREAM_RESIDUAL_RISK`; NX/DEP passed, imports match installer behavior,
and no network imports or unexpected runtime dependencies were found.

## Overall packaging gate

`PACKAGING_GATE = BLOCKED / WAITING UPSTREAM` because Tauri remains
`WAIT_FOR_OFFICIAL_RELEASE`. No Tauri pin, Cargo lockfile, source, patch, ignore,
bundle, `.nsi`, installer, uninstaller, or product executable was changed or
created by the NSIS promotion.

The former SourceForge metadata review is retained as historical evidence only:
its SHA-1/MD5 values and absent SHA-256/signature were never accepted as trust
for this project. The reproducible source build supersedes that acquisition
path.
