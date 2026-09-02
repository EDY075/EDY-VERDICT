# EDY VERDICT — Level 2: remediação final

Data: 2026-09-02. **EDY VERDICT LEVEL 2 = PARTIAL**.

Authenticode positivo/tamper, revisão manual formal e QA de código concluídos. Smokes da infraestrutura nativa passaram nas três resoluções. Fluxos File/Binary e matriz visual no WebView seguem pendentes: a automação disponível não conseguiu capturar a janela nem acionar seus controles.

Isso impede COMPLETE e COMPLETE WITH ACTIONS: a exceção autorizada de aceite era somente para um fixture Authenticode impossível, que agora foi validado. Não houve push, PR, deploy, package, installer, release, scan pessoal, execução de PE fixture, malware, upload, API de reputação, alteração do sistema ou Level 3.

## Baselines

| Referência | Valor |
|---|---|
| Foundation congelada | f4cdd8ec2af4b0ab5c6d80480524b930affcfc15 |
| Level 0 / level0-synthetic-complete | 09dd8b9f93516c346e011123d02bc250341b1edd |
| Level 1 / level1-repository-complete | 80812be31f65e9bc0a9f065f924b11c99d59f2a3 |
| Branch | work/level2-file-binary-20260902-145722 |
| Commit inicial desta rodada | 2276fd9ea01a357d1834f3c813d044c7bae85fec |
| Commits Level 2 anteriores | 3505ae6, 372e8ae, 9f20b81, 2276fd9 |

Referências congeladas verificadas e não movidas. Alterações somente na branch Level 2. Pins, lockfiles, manifests/receipts, NSIS, providers, schema SQLite, Credential Manager, gitignore, config Tauri, CSP, Isolation e capabilities sem alteração nesta rodada. Envelope de infraestrutura permanece schema_version=1 conforme contrato, distinto do SQLite v2 validado por Storage.

Hashes finais dos commits/tree ficam na entrega e no ledger ignorado _intake/level2-final-remediation/LEVEL2_REMEDIATION_CHECKPOINT.json, evitando circularidade de hash neste documento.

## Remediações

- Cadeia não confiável agora distinta da indisponível. Validade matemática exige CMS + digest SIP em caso de falha de cadeia.
- Parser DER de signingTime e campo separado de timestamp confiável; DTO/UI preservam distinções.
- Fixture PE assinada offline, pública/test-only; nenhum material privado exportado ou importado em store.
- Cancelamento/commit serializados no Level 2, terminal imutável, regressão das duas ordens da corrida.
- Extensão de dados de seção PE limitada ao arquivo, 4.096 mutações/truncamentos sem panic.
- Oito blocos unsafe documentados/revisados. Protótipo SIP que causou access violation foi corrigido antes de commit, eliminando cópia de client data transitório.
- Inicialização corrigida: removida exigência obsoleta de banco v1; Storage mantém validação/migração real. Envelope IPC v1 preservado.
- Flags debug-only para três tamanhos e banco/perfil WebView2 de QA separados em .local. Nenhum IPC extra, devtools ou privilégio frontend.

## Authenticode real

| Item | Resultado |
|---|---|
| Tooling | SignTool x64 do Windows SDK 10.0.26100.0 já instalado; sem instalação/download |
| Certificado | EDY VERDICT AUTHENTICODE TEST ONLY; autoassinado RSA-2048/SHA-256, não confiável |
| Chave | RSACng(2048), IsEphemeral=true, nunca exportada; objetos descartados em finally; processo terminou |
| Método | SignTool /dg com CER **público** → RSA.SignHash em memória → SignTool /di |
| Proibições preservadas | Sem PFX, /t, /tr, timestamp server, importação de certificado ou execução do PE |
| Alvo | PE do synthetic.c inerte do projeto; nenhum binário Windows/terceiro como fixture |
| Presença / matemática | PRESENT / VALID |
| Cadeia | UNTRUSTED, não confundida com assinatura inválida |
| Original SHA-256 | 2FC5B08550136239E42793EDE57B79EBFFE342DA05B949BA17728C18133D22B5 |
| Certificado público SHA-256 | 053061031E233A61C8CE55CAAD92D8CF27A3CF213580D6FEC23B65DCC12178EC |
| Tamper | Exatamente um byte na seção coberta, offset 512; SIGNATURE INVALID |
| Tampered SHA-256 | 0B7D4E91CA5D2E71C89A6D9C0451476BD30F29A31A3809512B83181B35F4AE9C |
| SigningTime real | ABSENT; não disponível no fixture gerado |
| SigningTime parser | PASS: UTC/GeneralizedTime, data/bordas/erro/truncamento |
| Timestamp real | Countersignature ABSENT / TRUSTED_TIMESTAMP ABSENT |
| Rede | WinTrust cache-only, revogação desabilitada; CMS/SIP local; sem consulta CRL/OCSP/TSA/API |
| Certificate Store | 213 certificados antes/depois; zero erro de leitura; digest idêntico |
| Private key / PFX restante | NO / NO; nenhum arquivo privado criado |

A mensagem SignTool “Done Adding Additional Store” corresponde à montagem interna de material público, não a uma importação executada em store persistente. CurrentUser e LocalMachine permaneceram idênticos. As tentativas iniciais falharam com segurança pela verificação do tipo RSA e combinação /di com /fd; execução final usou RSACng explícito e /di sem /fd.

Certificado com validade sintética 2020–2100 evita expiração do teste no dia seguinte; não lhe concede confiança. A chave deixou de existir ao encerrar o processo. O PE público versionado em hex está em crates/edy-engine-manager/tests/fixtures/level2/signed-test-only.hex. Testes o decodificam somente em diretório controlado, sem executá-lo.

O método de digest separado é documentado pela [Microsoft: SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool). A chave usa o [.NET RSACng](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacng.-ctor) já disponível. Nenhuma dependência do produto adicionada.

### Matriz de assinatura

| Caso | Resultado |
|---|---|
| Unsigned synthetic PE | PASS |
| PKCS7 malformado | PASS: presente, nunca valid/unsigned por fallback |
| Assinatura real válida | PASS: CMS/SIP + arquivo autorizado |
| Byte coberto alterado | PASS: invalid |
| Signatário não confiável | PASS: matemática valid, cadeia untrusted |
| Cadeia indisponível offline | PASS de mapeamento unitário; não smoke de cadeia remota |
| SigningTime presente | PASS parser unitário; não fixture assinado real |
| SigningTime ausente | PASS fixture real |
| Timestamp ausente | PASS fixture real |
| Erro genérico / estado nulo | PASS: falha conservadora |

## Native WebView E2E

Build: frontend → Rust project-local → runtime nativo, Tauri 2.11.5. Entrada React, invoke e handlers reais. Nenhum mock IPC usado para evidência nativa.

| Dimensões físicas, escala 1 | Inicialização/IPC | File/Binary integrado | Overflow/clipping |
|---|---|---|---|
| 1366×768 | PASS, exit 0 | PENDING | NOT VERIFIED |
| 1920×1080 | PASS, exit 0 | PENDING | NOT VERIFIED |
| 2560×1440 | PASS, exit 0 | PENDING | NOT VERIFIED |

Logs: FOUNDATION_IPC_RECEIVED core=ready storage=ready ipc=restricted schema_version=1. A acessibilidade mostrou “Infraestrutura disponível” e “Core · Storage · IPC restricted”. Banco/perfil ficaram em .local/level2-native-qa-data e .local/level2-native-qa-webview2.

A skill Computer Use orientou a seleção exclusiva da janela EDY VERDICT, observação antes de agir e interrupção diante das falhas. Evidência:

- Captura: SetIsBorderRequired failed: Não há suporte para esta interface (0x80004002).
- Clique em Nova análise: element 23 is not available in cached app state for edy-desktop.exe, mesmo após nova observação.
- Tab/F6: foco continuou no painel hospedeiro. Nenhum caminho de arquivo foi digitado.

Não foram alterados Windows, devtools, remote debugging ou permissões para contornar o mecanismo. Processos de QA encerrados.

| Fluxo | Backend sintético real | WebView integrado |
|---|---|---|
| Texto → preview/auth/hash/classify/correlate/persist/report/UI | PASS; UI testada separadamente | PENDING |
| PE mínimo unsigned → metadata/cobertura/report/UI | PASS; UI testada separadamente | PENDING |
| TARGET_CHANGED sem veredito | PASS | PENDING |
| Cancelamento sem veredito, DB consistente | PASS, inclusive corrida de finalização | PENDING |
| PE malformado fail-closed | PASS | PENDING |
| YARA bloqueado / reputação não consultada | PASS backend/contratos/render | PENDING |

Preview, autorização, progresso, hashes, PE, assinatura, achados, cobertura, relatórios, cancelado, target-changed e erro não têm aceite visual nativo. O harness browser anterior não foi apresentado como evidência nativa.

## Revisão formal e QA

[Revisão formal manual](LEVEL_2_SECURITY_REVIEW.md) concluída no escopo documentado, sem alegar conclusão do serviço externo anterior ou auditoria independente. Resultado: PASS; abertos Critical 0, High 0, Medium 0, Low 1, Informational 3. Low restante: cancelamento não preemptivo dentro de chamada Windows síncrona. UNDOCUMENTED UNSAFE=0.

| Gate | Resultado |
|---|---|
| cargo test --workspace --locked | PASS: 207 passed, 0 failed, 2 ignored |
| Testes Credential Manager ignorados | Não habilitados; nenhuma gravação de credencial |
| clippy --workspace --all-targets --locked -- -D warnings | PASS |
| cargo fmt --all -- --check | PASS |
| Frontend typecheck / lint / build | PASS |
| Frontend / arquitetura | PASS: 49 + 4 |
| Authenticode real direcionado | PASS positivo/tamper/malformado |
| Secret gate local | Zero candidatos nos padrões, sem exclusão de paths do conjunto candidato; sem upload; limite heurístico |
| Cargo.lock / pnpm lock / pins | Sem mudança |
| cargo deny | FAIL esperado: somente cinco advisories conhecidos, zero novos nos dados consultados |
| Licenses / sources / bans | PASS, zero erros; 13 warnings de duplicidade em bans, não suprimidos |

Advisories: RUSTSEC-2025-0081, RUSTSEC-2025-0075, RUSTSEC-2025-0080, RUSTSEC-2025-0100, RUSTSEC-2025-0098. Tauri 2.11.5, tauri-utils 2.9.3 e urlpattern 0.3.0 preservados; nenhuma exceção.

## Higiene

Rust com homes project-local e prevention gate; sysroot local 1.98 confirmado. Inventário global somente no diretório neutro de projetos.

- Global: somente stable-x86_64-pc-windows-msvc; default e hash settings.toml idênticos; 1.98 global ausente.
- PATH persistente User/Machine: hashes idênticos.
- Certificate Store: digest 1CF4D9855F3836D856C23F837ACEE702A2700EFB7D8A769A2872A08090801C59 antes/depois.
- Windows build/boot, serviços Defender, perfis firewall e hash SMBIOS sem diferença nos campos inventariados; nenhuma mudança de configuração executada.
- Engines/manifests/receipts/NSIS não alterados/baixados; Defender opcional desativado, SMBIOS USER_MODIFIED/UNTRUSTED preservados.
- Ledger em _intake/level2-final-remediation: snapshots, evidências públicas, logs QA, bloqueio da automação e smokes. Nenhuma chave privada, senha ou PFX. Builds/caches/fixtures somente no projeto em D:.

## Estado consolidado

| Chave | Resultado |
|---|---|
| EDY VERDICT LEVEL 2 | PARTIAL |
| FOUNDATION UNCHANGED | YES |
| AUTHENTICODE IMPLEMENTATION | READY; positivos/negativos PASS |
| AUTHENTICODE OFFLINE NETWORK | CACHE_ONLY / nenhuma busca de rede solicitada |
| AUTHENTICODE POSITIVE SMOKE | PASS |
| AUTHENTICODE TAMPER TEST | PASS |
| SIGNING TIME PARSER | PASS |
| REAL SIGNING TIME SMOKE | NOT AVAILABLE IN GENERATED FIXTURE — ABSENT |
| CERTIFICATE STORE CHANGED | NO |
| PRIVATE KEY REMAINING | NO — não exportada; objetos efêmeros descartados |
| NATIVE WEBVIEW E2E | PENDING / AUTOMATION BLOCKED |
| NATIVE IPC | STARTUP PASS / FILE FLOWS PENDING |
| NATIVE STORAGE | STARTUP PASS / FILE FLOWS PENDING |
| NATIVE REPORT | PENDING |
| NATIVE UI | STARTUP OBSERVED / STATE MATRIX PENDING |
| TARGET CHANGE NATIVE | PENDING |
| CANCELLATION NATIVE | PENDING |
| FORMAL SECURITY REVIEW | PASS — manual, escopo documentado |
| CRITICAL / HIGH / MEDIUM | 0 / 0 / 0 abertos |
| LOW / INFORMATIONAL | 1 / 3 abertos |
| RUST TESTS | 207 PASS / 2 IGNORED |
| FRONTEND TESTS | 49 PASS + 4 ARCHITECTURE |
| CLIPPY / FMT / TYPECHECK / LINT / BUILD | PASS |
| KNOWN / NEW ADVISORIES | 5 / 0 nos dados consultados |
| GLOBAL 1.98 PRESENT | NO |
| GLOBAL DEFAULT | stable-x86_64-pc-windows-msvc |
| GLOBAL PATH CHANGED | NO |
| WINDOWS CHANGED | NO CONFIGURATION CHANGE |
| DEFENDER / SMBIOS / FIREWALL CHANGED | NO |
| LEVEL 0 % / LEVEL 1 % | 100 / 100 — baselines aprovadas |
| LEVEL 2 % | NOT MEASURED; aceite nativo incompleto |
| TOTAL PROJECT % | NOT MEASURED; sem pesos aprovados |
| PRODUCTION FILE SCANNING READINESS | NOT CLAIMED |
| TAURI_UPSTREAM_GATE | WAITING_FOR_OFFICIAL_RELEASE |
| NEXT ACTION | LEVEL2_REQUIRES_REMEDIATION |
| PUSH | NO |
| LEVEL 3 | NOT STARTED |

Não criar tag complete, tag validation-pending ou freeze de aceite nesta condição. O checkpoint local não é COMPLETE. Próxima ação: validar seis fluxos e matriz visual em automação nativa funcional ou sessão manual observada, preservando as restrições. Encerrar esta rodada sem outra implementação.
