# NSIS 3.12 project-local promotion

Promotion result: `PASS`.

## Scope

- Source: `https://github.com/NSIS-Dev/nsis.git`
- Tag: `v312`
- Commit: `e3f60402bcdf7be822d159b531c6e38ddf32de12`
- Canonical source tree SHA-256:
  `58087810d4c84bc0cfb92b58a3e431ccebc8f8c52649e1ca0ec26b00aad25693`
- Source manifest SHA-256:
  `91fbe1563b39e11f72a70451188325dcb08c01c5cf2809a9252e8324dc08cc54`
- Security fix: issue #1326 present.
- Promoted payload: 276 files from clean `FINAL_BUILD_A`.
- Independent comparison: 276/276 equal to `FINAL_BUILD_B`.
- Entrypoint SHA-256:
  `28c87961d818117bfa4d8becfea2f2ed6aad8d325d62e8ad0ebd9d4dcd9c9f76`.
- zlib1.dll SHA-256:
  `bce51df2cc355ae24ed907aaac47ad58b39069251502166443b43820e2c354ee`.

The source-built payload is stored at `tools/packaging/nsis/3.12/`. The bundle
adds licenses, provenance, a closed-set SHA-256 manifest, and a read-only
integrity verifier. It is `BUILD_TOOLING`; users do not need NSIS installed.

## Verification and probe

The verifier checks every listed file's SHA-256 and size, mandatory files,
missing files, modified files, and unexpected extras. It never repairs data.

```powershell
& tools/packaging/nsis/3.12/Verify-Integrity.ps1
```

Promotion validation results:

| TEST | EXPECTED | RESULT |
|---|---|---|
| Original temporary copy | PASS | PASS |
| Copy with one byte appended to `makensis.exe` | detected | DETECTED |
| Copy missing `zlib1.dll` | detected | DETECTED |

Only after the official kit passed integrity verification was the following
command executed:

```text
tools/packaging/nsis/3.12/Bin/makensis.exe /VERSION
exit code: 0
stdout: v3.12
stderr: empty
hash before = hash after = 28c87961d818117bfa4d8becfea2f2ed6aad8d325d62e8ad0ebd9d4dcd9c9f76
```

No `.nsi`, installer, uninstaller, Tauri bundling, or product executable was
created or executed.

## Security and license decisions

- `THIRD_PARTY_NSIS_PLUGINS = 0`.
- `BZIP2 = NOT_INCLUDED`.
- Four upstream LZMA stubs and four required upstream zlib stubs are included.
- NX/DEP passed for all 21 generated PEs.
- Eight stubs have ASLR disabled by upstream `/FIXED`:
  `KNOWN_UPSTREAM_RESIDUAL_RISK`.
- No network imports, local path leakage, or unexpected runtime dependencies.
- `AUTHENTICODE = NOT_REQUIRED_FOR_INTERNAL_BUILD_TOOL`.
- Public EDY VERDICT Authenticode signing remains a future release gate.
- `LICENSE_GATE = PASS`; applicable notices are inside the promoted kit.

## Remaining state

```text
NSIS = READY
PACKAGING_TOOLCHAIN = READY
TAURI = WAITING_FOR_OFFICIAL_RELEASE
LEVEL -1C = FAIL / WAITING UPSTREAM
OVERALL_PACKAGING_GATE = BLOCKED / WAITING UPSTREAM
```

No Level 0 work is authorized by this promotion.
