# EDY VERDICT — Level 2: encerramento final

Data: 2026-09-02. **EDY VERDICT LEVEL 2 = COMPLETE**.

O escopo File/Binary foi validado no executável Tauri real, WebView2 real, React real,
IPC tipado real, serviços Rust reais, SQLite real e relatório real. Não foram usados
mocks para o aceite nativo. Isto não habilita engines, reputação em rede nem release
de produção.

## Baselines imutáveis

| Referência | Commit |
|---|---|
| Foundation (`level/minus1c/foundation`) | `f4cdd8ec2af4b0ab5c6d80480524b930affcfc15` |
| Level 0 (`level0-synthetic-complete`) | `09dd8b9f93516c346e011123d02bc250341b1edd` |
| Level 1 (`level1-repository-complete`) | `80812be31f65e9bc0a9f065f924b11c99d59f2a3` |
| Branch Level 2 | `work/level2-file-binary-20260902-145722` |
| Commit inicial da rodada | `8d83507d06682dc8e79dafc73fe1eb6b57d13657` |

As referências não foram movidas. O hash final do commit, tree, tag e manifesto fica
no ledger externo para evitar circularidade.

## Harness nativo e isolamento

O harness anterior era `@oai/sky`/Computer Use. A captura chamou
`GraphicsCaptureSession.IsBorderRequired` (`IGraphicsCaptureSession3`) no Windows 10
build 19045. A API foi introduzida no build 20348; a chamada retornou
`0x80004002/E_NOINTERFACE`. A acessibilidade sem captura e o IPC de startup já haviam
passado, portanto isso nunca demonstrou falha do WebView2.

O substituto é o servidor W3C embarcado oficial `tauri-plugin-wdio-webdriver=1.3.0`
e um cliente W3C mínimo, dependency-free, do próprio teste. `webdriverio=9.30.0` foi
avaliado e removido antes da integração porque seu grafo npm apresentou dois
advisories High. O resultado final tem zero dependências npm novas e `pnpm audit=0`.

O plugin Rust é opcional, preso a uma feature `native-e2e`, exige build debug e um
dos três argumentos sintéticos de QA. Compilar `native-e2e` em release produz erro
intencional. O grafo default/release não contém plugin, Axum nem listener. CSP,
Isolation, capabilities, frontend, `withGlobalTauri=false`, devtools, comandos IPC e
configuração de produção permanecem inalterados.

## E2E real

| Viewport | Fluxos reais | Asserções semânticas de tela | Resultado |
|---|---:|---:|---|
| 1366×768 | 7 | 50 | PASS |
| 1920×1080 | 7 | 50 | PASS |
| 2560×1440 | 7 | 50 | PASS |
| **Total** | **21** | **150** | **PASS** |

Cada resolução validou texto, binário genérico, PE mínimo, PE assinado, PE malformado,
TARGET_CHANGED e cancelamento. Os estados verificados incluem vazio, preview,
autorizado, progresso, resultados, assinatura, cobertura, achados, três relatórios,
cancelado, alteração de alvo e erro. Overflow horizontal, ação primária cortada e
campo ilegível: zero na matriz semântica. Screenshot permaneceu uma limitação do
harness antigo e não foi usada como prova.

- Hashes SHA-256/SHA-512 foram recalculados pelo teste e comparados com UI/IPC.
- Payload e SHA do snapshot foram lidos do SQLite real em modo read-only e comparados.
- Relatórios Executive, Technical e Developer foram acionados pela UI e comparados
  ao IPC e à análise persistida.
- TARGET_CHANGED terminou sem análise ou veredito e com erro seguro na UI.
- Cancelamento foi acionado no botão real durante `streaming_hashes`; snapshot terminal
  permaneceu imutável após o worker e não publicou veredito.
- PE malformado produziu erro estruturado sem panic/crash/OOB e a UI continuou ativa.
- YARA exibiu `Unavailable by execution policy`; reputação exibiu `Not checked`.
  Nenhum estado disse Safe, Clean, No threats found, Trusted File ou 100% secure.

O E2E revelou e corrigiu um defeito real: o validador frontend rejeitava o JSON
formatado dos relatórios por conter TAB/CR/LF. Agora somente esses controles válidos
de whitespace JSON são aceitos; os demais C0/DEL continuam bloqueados, com regressão.

## Authenticode

| Gate | Resultado |
|---|---|
| Implementação offline/cache-only | READY |
| Fixture pública assinada | PRESENT / CRYPTO VALID / CHAIN UNTRUSTED |
| SHA-256 da fixture | `2FC5B08550136239E42793EDE57B79EBFFE342DA05B949BA17728C18133D22B5` |
| Tamper de byte coberto | SIGNATURE INVALID / PASS |
| Parser de signingTime | PASS |
| signingTime real | ABSENT — limitação de validação, não da implementação |
| Countersignature/timestamp confiável | ABSENT |
| Store de certificados | UNCHANGED |
| Chave privada/PFX do projeto | NONE |

A fixture foi restaurada do hex público versionado; não foi executada nem reassinada.
Validade criptográfica continua separada de confiança e nunca produz veredito SAFE.

## Segurança e QA

A revisão focal está em [LEVEL_2_SECURITY_REVIEW.md](LEVEL_2_SECURITY_REVIEW.md).
Achados abertos: Critical 0, High 0, Medium 0, Low 1 aceito e documentado,
Informational 2. O Low é a não preempção dentro das APIs WinTrust/SIP síncronas;
controles e gatilho de remediação estão documentados.

| Gate | Resultado |
|---|---|
| `cargo test --workspace --locked` | PASS — 207 passed, 2 ignored |
| Clippy `-D warnings` / fmt check | PASS / PASS |
| Frontend typecheck / lint / build | PASS / PASS / PASS |
| Frontend + arquitetura | PASS — 49 + 5 |
| Native E2E | PASS — 21 fluxos / 150 estados semânticos |
| Production release build / release E2E denial | PASS / PASS |
| `pnpm audit` | PASS — 0 advisory |
| Cargo deny advisories | somente os 5 `unic-*` conhecidos do blocker Tauri |
| Cargo deny licenses / sources / bans | PASS / PASS / PASS |
| Secret scan local | 0 candidatos em 179 arquivos candidatos |

Nova dependência Rust test-only: `tauri-plugin-wdio-webdriver=1.3.0`, MIT, checksum
crates.io verificado, Rust 1.77+, Tauri 2+, 19 nomes de pacote líquidos adicionados ao
lockfile e nenhum advisory novo. Não houve mudança de versão/checksum preexistente.
Impacto no bundle de produção: NONE.

## Estado consolidado

File authorization, path security, file identity, TOCTOU, SHA-256, SHA-512,
classificação, PE, Authenticode, correlação, storage, reporting, IPC e UI: READY.
Backend E2E e Native WebView/IPC/storage/report/UI E2E: PASS.

Permanecem deliberadamente externos ao aceite:

- `YARA REAL EXECUTION = POLICY_BLOCKED`;
- `REPUTATION NETWORK LOOKUP = DISABLED`;
- `PRODUCTION FILE SCANNING READINESS = NOT CLAIMED`;
- `TAURI_UPSTREAM_GATE = WAITING_FOR_OFFICIAL_RELEASE`;
- `LEVEL -1C = FAIL / WAITING UPSTREAM`.

Não houve push, PR, deploy, package, installer, release, scan de arquivo pessoal,
diretório ou malware, upload, consulta reputacional, alteração do Windows/Defender/
Firewall/SMBIOS/PATH global/Rustup global/Certificate Store, nem início do Level 3.

**NEXT ACTION = READY_FOR_LEVEL3_AUDIT. LEVEL 3 = NOT STARTED.**
