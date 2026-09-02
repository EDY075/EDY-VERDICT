# EDY VERDICT — Level 2: File & Binary Security

Data: 2026-09-02. Resultado consolidado: **PARTIAL — implementação e testes locais concluídos; aceite integral pendente**.

Este relatório substitui o rascunho que declarava COMPLETE prematuramente. Não houve push, deploy, package, installer, scan de arquivo real do usuário ou início do Level 3. Tauri permanece bloqueado por upstream. Passar em testes locais não equivale a prontidão para produção.

## Baselines preservadas

| Referência | Valor |
|---|---|
| Foundation imutável | f4cdd8ec2af4b0ab5c6d80480524b930affcfc15 |
| Level 0 | 09dd8b9f93516c346e011123d02bc250341b1edd |
| Tag Level 0 | level0-synthetic-complete |
| Level 1 / início desta branch | 80812be31f65e9bc0a9f065f924b11c99d59f2a3 |
| Tag Level 1 | level1-repository-complete; anotada, local, não assinada |
| Tree Level 1 | 5341b987abbf27609ab5e462b893655b5d5559c5 |
| Manifesto Level 1 | 169 arquivos; SHA-256 14ced58d4a209f000aff94386f061e8e835ec670c456e9f4cad03a1c948c70ca |
| Branch Level 2 | work/level2-file-binary-20260902-145722 |

FOUNDATION UNCHANGED refere-se ao commit e à branch congelados, não à identidade de todos os arquivos da branch de desenvolvimento, que recebe as alterações autorizadas do Level 2.

## Implementado

- Um arquivo explícito, sem descoberta ou recursão. Preview gera identificador opaco, limitado a 64 sessões. Autorização consome esse identificador, compara a identidade mostrada e gera autorização de uso único. Path cru não autoriza nem inicia análise.
- Limite padrão e máximo conservador de 256 MiB; recusa diretório, UNC, device path, ADS, caminho relativo, caracteres de controle, volume não fixo e componentes reparse.
- Identidade Windows derivada do handle: volume, file ID, tamanho, atributos e last-write time. Caminho final precisa ser obtido com sucesso. Abertura compartilha somente leitura, recusando escritores existentes e impedindo novos handles de escrita/exclusão durante sua vida.
- SHA-256/SHA-512 first-party em chunks de 64 KiB; hex minúsculo; cancellation entre chunks; identidade/tamanho conferidos antes e depois. Nenhum veredito em TARGET_CHANGED ou CANCELLED.
- Classificação por magic/header: generic_file, pe_executable, pe_dll e unknown_binary. Parser PE lê no máximo 1 MiB de cabeçalho, limita 96 seções e valida offsets/tabelas/diretório de certificados. Nunca executa o PE.
- Authenticode por WinVerifyTrust, sem UI, cache-only, sem CRL/OCSP. Presença, resultado criptográfico, cadeia e publisher separados. Falha genérica não é convertida em assinatura inválida; cadeia indisponível não é apresentada como criptografia válida.
- Publisher: subject e issuer limitados/sanitizados, SHA-256 do certificado público e presença de countersigner quando retornados pelo Windows. Estado transitório WinTrust é fechado. Nenhuma escrita no certificate store. Signing time permanece não implementado; verification time não é rotulado como signing time.
- Adapter YARA-X recebe AuthorizedFileTarget e monta argv sem shell/recursão. Processo real permanece bloqueado. Reputação no Core aceita somente hash; provider implementado retorna indisponibilidade sem rede/upload.
- Normalização usa TargetKind::File/Binary e CorrelationEngine existentes do Core. DTOs e fingerprints file-specific são projeções; a política de risco/confiança do Level 2 mantém assinatura como evidência e indisponibilidade como perda de cobertura.
- Persistência SQLite transacional, schema forward-only versão 3, migração Level 0/1 e reload. Limite de 256 snapshots. Estados interrompidos são invalidados ao reabrir; falhas de persistência não publicam resultado válido.
- Relatórios Executive/Technical/Developer, JSON e HTML local escapado. PE completo em resumo textual, hashes, identidade, assinatura, evidências e checks indisponíveis; sem bytes do arquivo nem certificado completo.
- IPC tipado com 18 comandos específicos, Isolation, CSP e capabilities fechadas. Inclusão dos quatro comandos File e reconciliação dos comandos Repository já existentes no backend; nenhum acesso genérico a filesystem/shell.
- UI File/Binary com preview, confirmação, hashes, PE, assinatura/publisher, YARA, reputação, achados/filtros, cobertura e terminais. Preview/autorização são ocultados quando o usuário muda o path exibido.
- Área _intake explicitamente ignorada no Git para fixtures temporárias; nenhum conteúdo dessa área é versionado.

Não foi criada crate nova. As arestas locais adicionais são desktop → sha2 e reporting → engine-manager. Windows-sys 0.61.2 ganhou apenas features das APIs de Cryptography, Catalog, SIP e WinTrust; nenhuma versão de pacote mudou.

## Validado sinteticamente

| Área | Evidência |
|---|---|
| Autorização | Preview obrigatório, desconhecido/reutilizado recusado; identidade alterada após preview recusada |
| Caminhos/handle | Missing, diretório, oversized, UNC, device, ADS, relativo, junction controlada, escrita/delete/rename concorrentes recusados |
| Hashing | Vetores vazio e abc; limites 65.536 e 131.089 bytes comparados com valores pré-computados por .NET; multichunk e cancellation |
| PE | Matriz determinística de truncamentos, assinaturas/offsets inválidos, seções excessivas e diretório de certificados inválido |
| Authenticode | Unsigned sintético; mapeamento mockado valid/invalid/indeterminate/error/chain-unavailable; publisher nulo e sanitização |
| Correlação | Unsigned não malicioso; erro não inventa evidência; múltiplos indicadores; conflitos; deduplicação via Core |
| Pipeline backend | Texto, PE mínimo sintético, PE malformado e binário inofensivo → preview/autorização/análise/SQLite/reports/IPC |
| Terminais | TARGET_CHANGED sem resultado; cancellation sem resultado; reabertura invalida análise interrompida |
| Persistência/HTML | Migrações/reload/integridade, ausência de marcador de bytes brutos, escape de script/img/onerror |
| Frontend | Contratos estritos, rejeição de estados inválidos, renderização dos painéis/terminais e configuração Tauri |

A regra benigna do projeto está em `crates/edy-engine-manager/tests/fixtures/level2/benign-marker.yar`.
Digest dos bytes observados: `D2B9EDA2BAE887872A2AC66D11159775D1E93989C71182A5C139EEF9AC621000`.
Seu output YARA é uma fixture de parser; **a regra não foi executada por YARA-X**. Não houve malware, download de executável ou ruleset externo.

O E2E backend é real sobre fixtures locais; a camada UI foi validada separadamente por contratos/renderização/browser. Não declarar que o percurso completo WebView → IPC nativo → backend → UI foi exercitado nesta rodada.

## QA final

| Gate | Resultado |
|---|---|
| cargo test --workspace --locked | PASS: 203 passed, 0 failed, 2 ignored |
| cargo clippy --workspace --all-targets --locked -- -D warnings | PASS |
| cargo fmt --all -- --check | PASS |
| Frontend typecheck/lint/build | PASS |
| Vitest | PASS: 49 testes |
| Arquitetura | PASS: 4 testes |
| Bundle de produção | Fixture visual ausente |
| Cargo.lock | 460 pacotes antes/depois; 0 mudanças de versões, sources ou checksums |
| cargo deny check | FAIL esperado: cinco advisories unic-* conhecidos; zero novos nos dados consultados |
| Licenças / sources | Zero erros |
| Bans | Zero erros; 13 warnings de duplicidade, não ocultados |
| Secret review local | Zero correspondências nos padrões de chave privada/tokens conhecidos no conjunto alterado; não prova ausência universal |
| Global Rustup | Somente stable-x86_64-pc-windows-msvc; 1.98.0 global ausente; default stable |
| Engines, receipts, NSIS, scripts de ambiente, pnpm lock, config Tauri | Sem alteração nesta branch em relação ao início |

Os dois testes ignorados escrevem credenciais sintéticas no Credential Manager e não foram habilitados.

Advisories herdados: RUSTSEC-2025-0081, RUSTSEC-2025-0075, RUSTSEC-2025-0080, RUSTSEC-2025-0100 e RUSTSEC-2025-0098. Tauri 2.11.5, tauri-utils 2.9.3 e urlpattern 0.3.0 preservados. Não foi criada exceção ao cargo-deny. Não se reivindica atualização independente da base de advisories.

Tentativas auxiliares de cargo-audit não produziram auditoria válida: o wrapper existente não passou o subcomando audit. Ele não foi alterado nem esse resultado apresentado como PASS. O gate solicitado cargo-deny foi executado.

## Conferência visual

A habilidade Browser orientou a criação de um harness explicitamente sintético, separado da entrada de produção e sem backend. Foram verificadas 36 combinações: 12 cenários × 1366×768, 1920×1080 e 2560×1440. Nenhuma apresentou overflow horizontal no DOM. Screenshots de análise, autorização, achados, relatórios e target-changed foram inspecionados. Os demais estados foram conferidos via DOM e render tests.

Cenários: autorização, progresso, análise/painéis, assinatura válida, inválida, cadeia indisponível, indeterminado, achados, relatórios, erro, cancelamento e alvo alterado. Isso não equivale a 36 testes visuais pixel-a-pixel nem a um teste do transporte Tauri. Navegador e servidor de QA foram encerrados e viewport restaurado.

## Revisão de segurança e limites

Três candidatos da revisão anterior foram corrigidos e receberam regressões locais: fallback de caminho final, compartilhamento de escrita/delete no handle e autorização desvinculada do preview. A contagem de confiança, cobertura e classificação de falhas Authenticode também foi corrigida.

A revisão formal iniciada no serviço de segurança **não foi concluída**. Scan ID: `5e014f29-691e-4a77-8345-ba69da018a58`. Ela retrata um snapshot anterior às correções, não o commit final. As ferramentas desse serviço deixaram de estar disponíveis nesta continuação; também havia integração TAC sem login. Não houve instalação/reconexão de plugin, mudança de conta ou alegação de aprovação formal.

O serviço havia criado seu artefato em TEMP do usuário em C:, fora da política preferida de artefatos em D:. Esse artefato preexistente não foi removido nem alterado; os novos logs de QA estão em .local no projeto em D:. Essa exceção deve ser regularizada no mecanismo do serviço antes de uma nova revisão.

SECURITY_REGRESSION: nenhuma regressão observada nos controles e testes locais; **aceite formal permanece pendente**. Não são garantidos resistência a atacante kernel/admin, ausência de toda condição TOCTOU possível ou cobertura completa de todos os formatos de assinatura.

Fontes oficiais consultadas para a integração offline: [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data), [CertGetNameStringW](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw), [CRYPT_PROVIDER_SGNR](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr).

## Bloqueado por política / diferido / upstream

| Classe | Item |
|---|---|
| POLICY BLOCKED | YARA/engines reais, scan de arquivo real do usuário, rede de reputação, uploads, cloud analysis |
| DEFERRED | E2E integrado no WebView/IPC nativo; positivo Authenticode real com fixture assinada previamente aprovada; extração de signing time quando disponível |
| INCOMPLETE EXTERNAL REVIEW | Finalização da revisão formal sobre o diff corrigido |
| UPSTREAM BLOCKED | TAURI_UPSTREAM_GATE = WAITING_FOR_OFFICIAL_RELEASE |
| NOT STARTED | Level 3, packaging, distribuição, publicação, remediação do sistema |

A capacidade para receber um arquivo real futuro existe no código, mas não foi exercitada nem liberada como produção.

## Próximas ações de fechamento do Level 2

1. Revalidar o diff final em revisão de segurança concluída, mantendo artefatos em D:.
2. Exercitar E2E integrado do host nativo com fixtures sintéticas, sob os gates aplicáveis; não contornar o upstream nem a política de engines.
3. Validar publisher/Authenticode positivo com material previamente autorizado; tratar signing time como campo explicitamente ausente até haver implementação/teste específico.
4. Só então reavaliar COMPLETE/COMPLETE WITH ACTIONS. Nenhum avanço automático ao Level 3.

## Estado consolidado

```ini
EDY VERDICT LEVEL 2 = PARTIAL
FOUNDATION = IMMUTABLE
FOUNDATION UNCHANGED = YES (frozen reference)
LEVEL0 TAG = level0-synthetic-complete
LEVEL1 TAG = level1-repository-complete
LEVEL2 BRANCH = work/level2-file-binary-20260902-145722
START COMMIT = 80812be31f65e9bc0a9f065f924b11c99d59f2a3
FILE AUTHORIZATION = READY / SYNTHETICALLY VALIDATED
PATH SECURITY = READY / WINDOWS SYNTHETIC TESTS
FILE IDENTITY = READY
TOCTOU = HARDENED / TESTED / NO UNIVERSAL GUARANTEE
SHA256 = READY
SHA512 = READY
FILE CLASSIFICATION = READY
PE INSPECTION = READY / BOUNDED PARSER
AUTHENTICODE OFFLINE = IMPLEMENTED / POSITIVE SMOKE DEFERRED
YARA ADAPTER = READY / ARGV AND PARSER
YARA REAL EXECUTION = POLICY_BLOCKED
REPUTATION CONTRACT = READY
REPUTATION NETWORK LOOKUP = DISABLED
CORRELATION = READY / CORE INTEGRATED
STORAGE = READY
REPORTING = READY
IPC = IMPLEMENTED / NATIVE E2E PENDING
UI = IMPLEMENTED / SYNTHETIC VISUAL QA
SYNTHETIC FILE E2E = BACKEND PASS / NATIVE UI INTEGRATION PENDING
TARGET CHANGE E2E = PASS (backend)
CANCELLATION E2E = PASS (backend)
RUST TESTS = PASS / 203
FRONTEND TESTS = PASS / 49 + 4 architecture
CLIPPY = PASS
FMT = PASS
TYPECHECK = PASS
LINT = PASS
BUILD = PASS
KNOWN ADVISORIES = 5
NEW ADVISORIES = 0 (consulted database)
SECURITY_REGRESSION = NONE OBSERVED / FORMAL REVIEW INCOMPLETE
REAL_SECRETS = 0 DETECTED / HEURISTIC REVIEW
GLOBAL 1.98 PRESENT = NO
GLOBAL DEFAULT = stable-x86_64-pc-windows-msvc
GLOBAL PATH CHANGED = NO PERSISTENT CHANGE PERFORMED
WINDOWS CHANGED = NO
DEFENDER CHANGED = NO
SMBIOS CHANGED = NO
FOUNDATION % = FROZEN BASELINE / RELEASE GATE BLOCKED
LEVEL 0 % = 100 (approved user baseline)
LEVEL 1 % = 100 (approved user baseline)
LEVEL 2 % = NOT MEASURED; PARTIAL GATES ABOVE
TOTAL PROJECT % = NOT MEASURED; NO APPROVED WEIGHTS
PRODUCTION FILE SCANNING READINESS = NOT CLAIMED
PUSH = NO
LEVEL -1C = FAIL / WAITING UPSTREAM
LEVEL 3 = NOT STARTED
NEXT ACTION = LEVEL2_REQUIRES_FINAL_REMEDIATION
```

Os identificadores dos commits e o estado final do worktree são registrados na entrega desta rodada. Um documento versionado não pode conter o hash de seu próprio commit sem circularidade; as três entregas de código são 3505ae6, 372e8ae e 9f20b81.
