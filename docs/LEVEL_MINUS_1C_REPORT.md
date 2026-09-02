# EDY VERDICT — relatório Level -1C

Data: 2026-09-01. **LEVEL -1C: FAIL.** Fundação parcial materializada; promoção bloqueada.
Não é reprovação da escolha de Windows 10. Não foi iniciado o Nível 0.

> Atualização de 2026-09-02: o bloqueio de aquisição do NSIS foi resolvido por
> build reproduzível a partir do source oficial. NSIS 3.12 foi promovido como
> `BUILD_TOOLING` project-local, com 276/276 hashes A/B iguais e verificador de
> integridade fechado. As afirmações abaixo sobre NSIS não adquirido descrevem
> o estado histórico desta rodada original. O resultado global continua
> **LEVEL -1C: FAIL / WAITING UPSTREAM**, exclusivamente porque Tauri permanece
> `WAIT_FOR_OFFICIAL_RELEASE`. Nenhum Nível 0 foi iniciado.

## Resultado executivo

Foram criados workspace, contratos estruturais, manifests/pins, dois lockfiles,
infraestrutura SQLite, adapter de credenciais, runner de fixtures com Job Object,
fakes, bootstrap frontend, testes e baseline preliminar de supply chain.

Passaram **23 testes Rust de infraestrutura**, **2 testes nativos descartáveis de
credenciais**, **4 gates estruturais** e **29 testes frontend**: 58 verificações.
Clippy da infraestrutura passou com `-D warnings`; rustfmt de todo o workspace passou.
O frontend compilou. Isso NÃO comprova que o executável Tauri compila/inicia.

O gate recusou cinco advisories `unmaintained` efetivos no alvo Windows. Nenhuma
exceção foi adicionada. Portanto, build nativo e smoke Tauri ficaram bloqueados pela
condição expressa do usuário de só avançar após os gates anteriores passarem.

## Ferramentas e pins

| TOOL | REQUESTED VERSION | INSTALLED VERSION | SOURCE | STATUS |
|---|---|---|---|---|
| Rust | 1.98.0 | 1.98.0, 88d9e12ae | static.rust-lang.org, via rustup | READY, project-local |
| Cargo | toolchain 1.98 | 1.98.0, 797e8a9bc | distribuição Rust | READY, project-local |
| Target | x86_64-pc-windows-msvc | instalado | distribuição Rust | READY |
| rustfmt | componente estável | 1.9.0-stable | distribuição Rust | READY |
| Clippy | componente 1.98 | 0.1.98 | distribuição Rust | READY |
| Node, DEV-ONLY | 24.20.0 | 24.20.0 | nodejs.org/dist/v24.20.0 | READY, hash e Authenticode válidos |
| pnpm | 11.25.0 | 11.25.0 | registry.npmjs.org/pnpm/11.25.0 | READY, SHA-512 validado |
| Tauri | 2.11.5 | source/crate 2.11.5 adquirido e locked | crates.io | BLOCKED para build/promoção |
| tauri-build | 2.6.3 | 2.6.3 locked | crates.io | adquirido, build nativo NOT TESTED |
| Tauri API / CLI | 2.11.1 / 2.11.4 | 2.11.1 / 2.11.4 | registro npm oficial | instalados localmente |
| React / React DOM | 19.2.8 | 19.2.8 | registro npm oficial | READY, build frontend |
| TypeScript | 6.0.3 | 6.0.3 | registro npm oficial | READY |
| Vite | 8.2.2 | 8.2.2 | registro npm oficial | READY |
| rusqlite | 0.40.2 bundled | 0.40.2; libsqlite3-sys 0.38.2 | crates.io | READY nos testes de infraestrutura |
| windows-sys | 0.61.2 | 0.61.2 | crates.io | READY nos testes nativos |
| cargo-audit | auxiliar fixado 0.22.2 | 0.22.2 | crates.io, source build --locked | READY, DEV-ONLY |
| cargo-deny | auxiliar fixado 0.20.2 | 0.20.2 | crates.io, source build --locked | READY; política retorna FAIL |
| MSVC | reutilizar existente | cl 19.44.35228.0 | Visual Studio Build Tools Microsoft | reutilizado, sem instalação |
| Git | reutilizar existente | 2.55.0.windows.3 | git-scm.com | reutilizado |
| WebView2 | Evergreen existente | 151.0.4129.107 | Microsoft | existente; runtime NOT TESTED |
| NSIS | 3.12, análise apenas | não adquirido | NSIS / SourceForge oficial | PACKAGING_GATE BLOCKED |
| Engines locais | pins congelados | YARA-X 1.20.0; Gitleaks 8.30.0; Trivy 0.74.0; OSV-Scanner 2.5.1 | upstreams oficiais + Manifest/Receipt V2 | READY; aquisição posterior controlada |

Pins auxiliares reais constam dos manifests: serde 1.0.229, serde_json 1.0.149,
sha2 0.10.9 e zeroize 1.8.2; plugin-react 6.1.1, Vitest 4.1.11, ESLint 10.9.1,
typescript-eslint 8.69.0, @types/react 19.2.18 e @types/react-dom 19.2.5.
Não foi utilizado `latest` como especificador de instalação.

O host continua Windows 10 Pro 22H2, build 19045.6466, edição Professional.
Defender permanece OPTIONAL / DISABLED_BY_USER. SMBIOS permanece USER_MODIFIED /
UNTRUSTED. Não foram feitas alterações de sistema, upgrade ou configuração de APIs.

## Estrutura e dependências internas reais

```text
EDY-VERDICT/
  crates/{edy-core,edy-engine-manager,edy-providers,edy-storage,edy-reporting,edy-cli}
  apps/desktop/{src,src-tauri,isolation}
  tools/{manifests,.staging,receipts}
  docs/{adr,architecture,security,legacy}
  tests/  scripts/
  Cargo.toml  Cargo.lock  rust-toolchain.toml
  package.json  pnpm-workspace.yaml  pnpm-lock.yaml  deny.toml
  .local/  target/  node_modules/        # locais, não versionados
```

| CRATE/APP | DEPENDÊNCIAS INTERNAS |
|---|---|
| edy-core | nenhuma |
| edy-engine-manager | edy-core |
| edy-providers | edy-core |
| edy-storage | edy-core |
| edy-reporting | edy-core |
| edy-cli | os cinco crates acima |
| edy-desktop | os cinco crates de biblioteca; não CLI |

Gate verifica inclusive dependências transitivas proibidas de edy-core. Os dez
contratos-base pedidos estão definidos; não há algoritmo de verdict, fórmula de
score, scanner ou funcionalidades de produto. Severity e confidence são tipos
distintos. Available não equivale a análise concluída; indisponibilidade não vira clean.
IDs/timestamps ainda são strings estruturais; validação de domínio produtiva é posterior.

## Segurança e infraestrutura

- CSP local, withGlobalTauri=false, freezePrototype=true, asset protocol desativado,
  nenhuma capability remota/wildcard, devtools desativadas e nenhum plugin genérico.
- Único IPC `foundation_status`, sem argumentos, AppManifest/capability explícitos,
  validação de origem/janela/payload e Isolation hook local. Sem comandos de secrets.
- A origem dinâmica do iframe Isolation é acrescentada pelo Tauri à CSP efetiva.
  Configuração foi revisada e testada estaticamente; comportamento real NOT TESTED.
- SQLite: bundled, WAL, FULL, FK ON, trusted_schema OFF, busy timeout 5 s,
  migration 0001 checksummed, conferência do schema real, recusa de versão futura,
  backup via API e corrupção sem recriação silenciosa. Banco só de infraestrutura.
- Credential Manager: fake WRITE → READ → DELETE → CONFIRM ABSENT e limpeza no
  unwind passaram serialmente. Valor não exposto/logado; cópias Rust e blob nativo
  possuem wipe explícito. Credencial preexistente no alvo não é sobrescrita.
- Runner: executável próprio e benigno, hash SHA-256, imagem regular local <=512 MiB,
  argumentos estruturados, sem shell, ambiente vazio, stdin fechado, handles restritos,
  criação suspensa → associação ao Job → resume, limites e encerramento da árvore.
- Regressões: success, timeout, stdout excessivo, stderr, saída 23, árvore, cancelamento,
  pré-cancelamento, deadline pré-launch, hash errado, cwd inválido e argumentos Unicode.
- Manifest: schema/parser/validação, caminhos reservados/ADS/traversal/devices, limites,
  abstrações de aquisição e execução. Aquisição real é PolicyBlocked nesta fase.
- Fakes cobrem Available, NotConfigured, Offline, RateLimited, Unavailable e PolicyBlocked.

Limites: Job não é sandbox de filesystem/rede; I/O síncrono tem cancelamento
cooperativo, não prazo rígido; não há proteção absoluta contra malware do mesmo usuário,
races em diretórios controlados por adversário, dumps ou queda abrupta do sistema.
Não há serviço produtivo de concorrência SQLite, provider HTTP nem fluxo real BYOK.

## Gates executados e bloqueados

| CHECK | EVIDÊNCIA | RESULTADO | ESTADO |
|---|---|---|---|
| cargo test --workspace --exclude edy-desktop --locked | 23 testes, zero falhas | PASS | READY, infraestrutura |
| Credential Manager, testes ignored explícitos | 2 passaram, execução serial, ausência confirmada | PASS | READY no teste autorizado |
| Clippy, mesmo subconjunto, --all-targets -- -D warnings | zero warnings | PASS | READY |
| cargo fmt --all -- --check | exit 0 | PASS | READY |
| Gates arquiteturais/segurança | 4 passaram | PASS | READY |
| pnpm install --frozen-lockfile | scripts desabilitados pela configuração | PASS | READY |
| pnpm typecheck / lint / test / build | exit 0; 29 testes; build de assets locais | PASS | READY, frontend |
| pnpm audit --audit-level=high | nenhuma vulnerabilidade conhecida reportada | PASS | READY na data da consulta |
| cargo audit | exit 0; zero vulnerabilities, warnings preservados | PASS do comando | NÃO aprova sozinho a baseline |
| cargo deny check, Windows x64 | 5 erros advisories; 13 avisos de versões duplicadas | FAIL | BLOCKED |
| Licenses/sources/bans do cargo deny | zero erros; duplicações sinalizadas | PASS com avisos | não é clearance de distribuição |
| Secret scan local | zero achados; somente fontes/docs deste projeto | PASS limitado | heurístico, não Gitleaks |
| cargo test / clippy --workspace incluindo desktop | não executados após bloqueio | NOT TESTED | BLOCKED |
| Build Rust/Tauri da aplicação | não executado após bloqueio | NOT TESTED | BLOCKED |
| Tauri inicia, WebView local, IPC real e zero chamadas externas | aplicação não iniciada | NOT TESTED | BLOCKED |
| Fechamento da aplicação sem órfão | aplicação não iniciada | NOT TESTED | BLOCKED |
| Fixtures sem processos órfãos | Job vazio nos testes; checagem final sem fixtures ativas | PASS | READY no cenário testado |

O problema inicial de pnpm com ignorePnpmfile + verifyDepsBeforeRun foi corrigido
declarando `pnpmfile: []`, sem relaxar nenhuma das duas políticas. Os comandos oficiais
foram reexecutados com sucesso; não se apresenta execução direta como substituta final.

## Bloqueio de dependências

Caminho efetivo: **Tauri 2.11.5 → tauri-utils 2.9.3 → urlpattern 0.3.0 → unic-***.

| CRATE | ADVISORY | TIPO |
|---|---|---|
| unic-char-range 0.9.0 | RUSTSEC-2025-0075 | unmaintained |
| unic-common 0.9.0 | RUSTSEC-2025-0080 | unmaintained |
| unic-char-property 0.9.0 | RUSTSEC-2025-0081 | unmaintained |
| unic-ucd-version 0.9.0 | RUSTSEC-2025-0098 | unmaintained |
| unic-ucd-ident 0.9.0 | RUSTSEC-2025-0100 | unmaintained |

São avisos de ausência de manutenção, não evidência de exploração ou cinco CVEs
críticos. São relevantes à política de longevidade e estão no grafo Windows, por
isso impedem promoção sem decisão explícita. Não foi alterado o pin Tauri nem
adicionada lista ignore. GTK/glib, incluindo RUSTSEC-2024-0429, aparecem no lock
multiplataforma, mas não no grafo Windows consultado; ficam registrados para futuro Linux.

## Locks, licenças, SBOM e custos

Cargo.lock e pnpm-lock.yaml foram gerados e adicionados ao índice Git local
(confirmados por git ls-files); sem remote, publicação ou commit de promoção.
Inventário preliminar: **279 crates no grafo Windows de metadata**, com hashes de
arquivos .crate conferidos, e **137 pacotes npm instalados**. Isso não significa
que todos tenham sido compilados ou que sejam todos dependências finais de runtime.

Foram gerados license-inventory.json, dependency-graph.json, lock-hashes.json,
SBOM CycloneDX preliminar e THIRD_PARTY_NOTICES.md. Há **28 pacotes sem arquivo de
licença na raiz**: metadados não substituem clearance; exige revisão antes de distribuição.
SBOM não inclui todos os grafos transitivos dos toolchains/auditores independentes;
estes têm inventário de ferramentas, origem, versão e hash em tools/receipts.

Principais licenças: MIT/Apache-2.0, BSD, ISC, Unicode-3.0, Zlib e MPL-2.0; npm
inclui BlueOak-1.0.0. SQLite é bundled via rusqlite; fontes/notices estão inventariados.
Windows SDK/MSVC/WebView2 mantêm termos Microsoft separados. Nenhuma licença do
próprio produto foi inventada e nenhum pacote foi publicado.
**Custo mensal obrigatório criado: R$ 0.** Nenhum serviço pago ou chave foi configurado.

NSIS 3.12: origem oficial confirmada, mas SHA-256 não publicado na metadata consultada
(valor null), sem assinatura/provenance estabelecida nesta revisão. SHA-1/MD5 não
foram aceitos como substitutos. **PACKAGING_GATE = BLOCKED**; nenhum download/instalador.
Detalhes de módulos/licenças: security/packaging-gate.md.

## Preservação e incidente corrigido

Os 19 documentos antigos foram preservados byte a byte em docs/legacy/codex-pack-v0.1;
o ADR 0001 registra formalmente a substituição da stack, alternativas e fallback Slint.
Windows 10 fixo, horizonte WebView2, riscos e reavaliação estão documentados.

Uma checagem sem o ambiente local acionou instalação duplicada de Rust 1.98.0 em C:.
O incidente foi informado e corrigido removendo somente a duplicata criada pela rodada.
Verificação final: Rust global 1.97.1 e Node global 24.17.0 preservados; ferramentas
aprovadas permanecem no projeto em D:. Registro: security/provisioning-incident.md.

## Próximas decisões — nenhuma executada automaticamente

1. Autorizar investigação/remediação dos cinco advisories transitivos: avaliar uma
   combinação upstream mantida e compatível; qualquer alteração dos pins congelados
   ou exceção temporária deve ser apresentada para decisão. Não ignorar automaticamente.
2. Após resolver esse gate, concluir testes/clippy de todo o workspace e build
   Tauri sem bundle, seguido de smoke real, CSP/IPC/rede e fechamento sem órfãos.
3. Resolver aquisição verificável do NSIS e pendências de notices/SBOM antes de
   qualquer empacotamento, que continua exigindo autorização separada.
4. Reavaliar Level -1C. Mesmo um futuro PASS não autoriza avanço automático ao Nível 0.

**LEVEL -1C: FAIL — aguardando decisão do usuário.**

## Level -1D.1 — Engine Manifest Contract V2

O contrato compartilhado do `edy-engine-manager` foi normalizado e versionado sob
integração serial do JR. Engine Manifest V1 ficou `SUPERSEDED`; V2 ficou `ACTIVE`.
O schema histórico é usado apenas pelo teste de rejeição explícita e não permanece
como formato ativo.

V2 separa identidade, origem, conjunto fechado do artefato, evidências estruturadas,
licença/redistribuição, extração, processo, version probe e revisão. Receipt V2 fica
fora da pasta da engine e ancora hashes do manifesto, entrypoint e artifact set.
Canonicalização `DETERMINISTIC_TYPED_JSON_V1`, parsing sem chaves duplicadas e SHA-256
lowercase estão documentados no ADR 0002.

Os testes incluem quatro fixtures sintéticas, corpus negativo, policy, receipt,
round-trip e gate JSON Schema↔Rust. Evidência `failed` é parseável, mas bloqueia policy;
Sigstore `present_unverified` não satisfaz `SIGSTORE_REQUIRED`. Aquisição continua
deliberadamente bloqueada. Nenhum engine foi baixado, executado ou promovido.

Gate focado final: 34 testes Contract V2 e 9 testes do runner passaram. Formatter,
testes e Clippy de todo o workspace sem `edy-desktop` passaram sem warnings. Os
comandos obrigatórios do workspace completo foram executados, mas test/clippy pararam
no build script Tauri por mismatch preexistente da feature `isolation`; nenhuma feature
foi alterada. `cargo deny check` permaneceu FAIL exclusivamente pelos cinco advisories
`unic-*` já atribuídos ao grafo Tauri. Os dois bloqueios ficam fora do Contract Gate.

Este gate é independente do bloqueio upstream Tauri. Mesmo com Contract V2 aprovado:

```text
LEVEL -1C = FAIL / WAITING UPSTREAM
TAURI = WAITING_FOR_OFFICIAL_RELEASE
```

## Local Engines Gate — aquisição e promoção controladas

Em 2026-09-02, após aprovação explícita do Contract V2, foram adquiridos e
promovidos exclusivamente YARA-X 1.20.0, Gitleaks 8.30.0, Trivy 0.74.0 e
OSV-Scanner 2.5.1. Gitleaks 8.30.1 permaneceu em `HOLD / REJECTED`.

Os quatro assets oficiais passaram por conferência de release/advisories/licença,
hash publicado, validação segura do arquivo, hashes do conjunto fechado, inspeção
PE estática, policy V2, probe de versão sem shell/rede observada, receipt externo,
testes de adulteração e promoção atômica para diretórios versionados. Todos os
estados finais são `READY`.

O OSV-Scanner teve sua attestation in-toto/SLSA v0.2 verificada criptograficamente
com identidade exata do workflow e timestamp Rekor. O bundle Sigstore do Trivy é
uma assinatura de blob `hashedrekord` incompatível com o verificador de attestations
disponível; ficou honestamente `present_unverified`. A policy continua PASS por
checksum e source commit independentemente verificados, sem relaxamento.

Durante a checagem final, uma invocação de inventário do Rustup feita sob o override
do projeto provisionou acidentalmente o toolchain global 1.98.0. A rodada parou. Após
autorização explícita, somente esse toolchain foi removido pelo Rustup oficial a partir
de diretório neutro. O `stable` permaneceu único/ativo/default e hashes de settings e
PATH permaneceram idênticos. Resultado da remediação: PASS.

Gate focado final: 34 testes Contract V2 e 9 testes de contenção/processo passaram;
Clippy do `edy-engine-manager` passou com `-D warnings`. Todos os nove hashes
congelados permaneceram iguais. Notices, inventário de licenças e SBOM foram
atualizados. Evidência detalhada: `docs/security/evidence/local-engines-20260902/LOCAL_ENGINES_GATE.md`.

```text
RUSTUP INCIDENT REMEDIATION = PASS
LOCAL ENGINES GATE          = PASS WITH ACTIONS
LEVEL -1C                   = FAIL / WAITING TAURI
```

A ação não bloqueante é verificar no futuro o bundle Sigstore de blob do Trivy com
um verificador compatível previamente aprovado. Nenhum scan, adapter, DB, chave,
Tauri ou Nível 0 foi iniciado.

## Level -1E.1 — Tauri Isolation Gate

Em 2026-09-02, o mismatch entre `tauri.conf.json` e `tauri-build` foi corrigido
sem alterar o pin Tauri 2.11.5: `tauri-build/isolation` foi habilitado, a aresta
inevitável `tauri-codegen` foi registrada no lock e a chamada inválida
`enable_clipboard_access(false)` foi removida. O clipboard permanece desabilitado
por padrão; Isolation, CSP, capabilities e validação IPC não foram relaxados.

O build order obrigatório para checkout preparado fica formalizado como:

```text
pnpm build
  -> cargo test --workspace --locked
  -> cargo clippy --workspace --all-targets --locked -- -D warnings
  -> cargo fmt --all -- --check
```

O build frontend, 55 testes Rust, Clippy, rustfmt e 29 testes frontend passaram.
`cargo deny check` continuou falhando exclusivamente nos cinco advisories `unic-*`
conhecidos; nenhuma exceção foi adicionada. A aplicação não foi iniciada e o Nível 0
permanece não autorizado.

```text
TAURI_ISOLATION_GATE = PASS
TAURI_UPSTREAM_GATE  = WAITING_FOR_OFFICIAL_RELEASE
LEVEL -1C            = FAIL / WAITING UPSTREAM
```
