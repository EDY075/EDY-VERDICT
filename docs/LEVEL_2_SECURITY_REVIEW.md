# Level 2 — revisão formal de segurança

Data: 2026-09-02. Método: revisão manual do código pelo JR, análise de fluxos e testes locais. Não é auditoria independente, certificação ou conclusão do antigo scan externo. Escopo: delta File/Binary desde a tag Level 1 e correções desta rodada.

**PASS no escopo de código e regressões executadas.** Pendentes: Critical 0, High 0, Medium 0, Low 1, Informational 3. O aceite global continua PARTIAL por falta do E2E nativo completo.

## Achados e resolução

| ID | Classe | Achado | Resolução / evidência |
|---|---|---|---|
| L2-M01 | Medium, corrigido | Raiz não confiável confundida com cadeia indisponível; faltava prova criptográfica independente da confiança | TrustChainUntrusted; CMS e digest SIP devem verificar antes de afirmar validade; original válido, cadeia untrusted, tamper inválido |
| L2-M02 | Medium, corrigido | Cancelamento e conclusão podiam sobrescrever snapshots entre leitura e escrita | Decisão e escrita sob o mesmo mutex; terminal imutável; teste determinístico das duas ordens com resultado real |
| L2-M03 | Medium, corrigido | Parser aceitava extensão declarada de seção fora do arquivo | Soma em u64 e comparação com tamanho real; SectionDataOutsideFile; 4.096 mutações/truncamentos sem panic |
| L2-M04 | Medium, corrigido | Signing time não implementado; countersigner sem distinção explícita de timestamp confiável | Parser DER estrito de atributo autenticado, campos separados; ausência real registrada |
| L2-H01 | High, corrigido durante desenvolvimento, antes de commit | Protótipo de rechecagem SIP com cópia superficial de SIP_SUBJECTINFO causou 0xC0000005 | Protótipo removido; estrutura nova zerada, GUID/path/handle controlados, sem copiar pClientData; positivos/negativos repetidos PASS |
| L2-F01 | Correção funcional | Host recusava SQLite v2 válido por comparar com literal v1 anterior ao Level 0 | Storage::open valida schema real; envelope IPC continua v1 conforme contrato congelado; três smokes reais PASS |
| L2-L01 | Low, aberto | WinVerifyTrust/SIP são síncronos; cancelamento cooperativo não interrompe chamada em andamento | Arquivo explícito, limite 256 MiB, offline, cancelamento conferido após retorno. Antes de produção, avaliar worker isolado/timeout; não criar execução genérica nesta rodada |
| L2-I01 | Informational | Cinco advisories unic-* herdados | Release bloqueado; sem exceção ou mudança de pin |
| L2-I02 | Informational / validation debt | E2E File/Binary no WebView e matriz visual incompletos por falhas de automação | Evidência concreta no ledger; smokes de infraestrutura/render tests não equivalem a E2E |
| L2-I03 | Informational / limite | Signatário primário da assinatura PE embutida; confiança offline sem revogação atual não garante segurança | Não reivindica catálogos, todas as assinaturas aninhadas ou resistência a administrador/kernel comprometido |

As contagens de aceite são de achados abertos. O High intermediário foi corrigido antes de integrar código. Uma tentativa do teste de corrida também encontrou UNIQUE do SQLite; foram corrigidos os IDs da fixture, sem enfraquecer a restrição.

## Matriz de revisão

| Fronteira | Verificação | Resultado |
|---|---|---|
| Autorização | Preview opaco, até 64 sessões, confirmação, identidade vinculada, consumo único | PASS |
| Caminhos | Absoluto/local fixo, sem UNC/device/ADS/parent/control; reparse e caminho final por handle | PASS, regressões Windows sintéticas |
| Identidade/TOCTOU | Volume/file ID/tamanho/mtime/atributos; nova abertura e comparações; share somente leitura | PASS no modelo user-space testado, não garantia universal |
| Hash | 64 KiB streaming, SHA-256/512, sem bytes em logs, cancelamento entre chunks, RAII | PASS |
| PE | Até 1 MiB de header, offset limitado, checked arithmetic, até 96 seções, diretórios e extensões limitados | PASS; testes dirigidos e 4.096 mutações determinísticas, não fuzzing exaustivo |
| Assinatura | Cache-only/sem revogação remota, sem store mutável, matemática distinta de confiança | PASS real positivo/tamper |
| Metadata | Nomes até 512 caracteres/buffer 2.048 UTF-16; DER público até 64 KiB; até 32 atributos e signingTime até 32 bytes | PASS |
| Publisher/time | Só cópias públicas escapam; signingTime é declaração do signatário, não TSA | PASS |
| SQLite | Só resultados/metadados, sem file bytes/chaves/credenciais/DER completo; transações, revisões, hash, até 256 snapshots | PASS do fluxo; SHA detecta corrupção, não autentica contra usuário que reescreve o banco |
| Terminais | Cancelamento/commit serializados, terminal não reabre; cancelado/TARGET_CHANGED sem análise/veredito; reinício invalida pendentes | PASS backend |
| Relatório | JSON e escaping de caracteres HTML; script/img/onerror nunca viram HTML ativo | PASS |
| IPC | 18 comandos específicos, UUID/limites, preview/confirmação; sem read/fs/shell/process genérico | PASS revisão/testes; fluxo File/Binary nativo ainda pendente |
| Isolation/capabilities | Hook de validação fechado; main/local; guard de label/URL | PASS, configs preservadas |
| Navegação/CSP | URL local exata; sem janela nova/download/CDN/remotos; assets locais | PASS |
| Devtools/clipboard | Devtools false, clipboard não habilitado; shell/fs negados no frontend | PASS |
| Engines/providers | Plano argv/parser apenas; reputação aceita hash, não bytes; nenhuma rede/upload | PASS da política |
| Segredos | Padrões locais sobre conjunto versionado/candidato, sem imprimir valores | Zero candidatos; limite heurístico explicitado |

## Todos os oito blocos unsafe do Level 2

Cada local tem comentário SAFETY no código. Não há novo unsafe no IPC, React, provider ou relatório.

| Local/API | Necessidade e pré-condições | Vida útil, limpeza, NULL/erro |
|---|---|---|
| file_identity / GetFileInformationByHandle | FFI, File vivo e output inicializado | Sem transferência; zero vira Io; File fecha handle |
| final_path / GetFinalPathNameByHandleW | Buffer com capacidade explícita | File/buffer vivos; zero/oversize rejeitados antes de slice; sem fallback |
| is_local_fixed / GetVolumePathNameW | UTF-16 terminado e output limitado | Falha recusa; sucesso permite próxima chamada |
| is_local_fixed / GetDriveTypeW | Root terminado produzido pela API anterior | Buffer local vivo; não fixo/erro recusado; sem ownership |
| inspect_authenticode / VERIFY | Union/tag FILE concordam; structs/GUID/path/handle do chamador | Tudo vive até CLOSE; RAII inclusive VERIFY com erro; resultado LONG não é GetLastError |
| TrustState::drop / CLOSE | Mesmo WINTRUST_DATA/FILE/GUID, estado pode ser NULL | Um CLOSE por VERIFY; ponteiros filhos não escapam; File não é fechado pelo wrapper |
| verify_crypto_from_state / CMS + SIP | TrustState vivo, tipo SIP, mensagem/cert/SIP não NULL; CMS com certificado primário | Subject SIP novo, sem client data transitório, mesmo handle bloqueado/path original/GUID local; missing/zero retorna false; sem chain/network/store API extra |
| publisher_from_state / helpers + CryptoAPI | Estado vivo, ponteiros OS checados, contagens/tamanhos limitados antes de slices | Só Strings/bools/hash públicos escapam; nulo/inválido vira None; WinTrust libera contexts |

UNDOCUMENTED UNSAFE = 0. APIs Windows permanecem na base confiável; estes testes não provam ausência universal de falhas do sistema.

## APIs, política offline e fontes

WinVerifyTrust usa WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_CHOICE_FILE, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY e WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4. Fecha com WTD_STATEACTION_CLOSE. Não se reivindica revogação CRL/OCSP atual. Cache-only é necessário: REVOKE_NONE isoladamente não impede toda busca de rede. [Microsoft: WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

Em falha de cadeia, exige CryptMsgControl(CMSG_CTRL_VERIFY_SIGNATURE_EX, CMSG_VERIFY_SIGNER_CERT) e CryptSIPVerifyIndirectData no mesmo arquivo bloqueado antes de afirmar validade matemática. A cadeia continua untrusted/unavailable. Erro genérico continua Error/Indeterminate; não se infere validade ou invalidade indiscriminadamente. [CryptMsgControl](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol), [CryptSIPVerifyIndirectData](https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipverifyindirectdata), [SIP_SUBJECTINFO](https://learn.microsoft.com/en-us/windows/win32/api/mssip/ns-mssip-sip_subjectinfo).

SigningTime vem apenas de AuthAttrs PKCS#9, DER UTC/GeneralizedTime estrito, data válida, segundos e Z. Nunca de sftVerifyAsOf. Countersigner só produz timestamp confiável quando resultado e cadeia correspondente não têm erro; caso contrário permanece desconhecido. O fixture real não tem signingTime nem countersigner. [CRYPT_PROVIDER_SGNR](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr).

## Aceite

A revisão manual de código está encerrada no escopo documentado. Isso não fecha E2E nativo, não habilita engines/providers, não promove Tauri e não libera produção. Próximo trabalho: concluir a validação nativa do Level 2 em mecanismo de automação funcional ou sessão manual observada. Não iniciar Level 3.
