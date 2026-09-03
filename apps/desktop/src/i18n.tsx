import { Children, cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";
import type { Locale } from "./product";

const exactPt: Readonly<Record<string,string>> = {
  "No data available": "Nenhum dado disponível",
  "File / Binary Security": "Segurança de arquivo / binário",
  "One explicit local file only. Preview never starts analysis.": "Somente um arquivo local explícito. A prévia nunca inicia a análise.",
  "Repository Security": "Segurança de repositório",
  "Repository inventory available. Some security checks are unavailable until execution policy requirements are satisfied.": "Inventário de repositório disponível. Algumas verificações permanecem indisponíveis até que a política de execução seja satisfeita.",
  "Passive URL analysis cancelled": "Análise passiva de URL cancelada",
  "No final security verdict was generated.": "Nenhum veredito final de segurança foi gerado.",
  "Late worker results cannot replace this terminal state.": "Resultados tardios não podem substituir este estado terminal.",
  "Analyze another URL": "Analisar outra URL",
  "Passive URL analysis stopped safely": "A análise passiva de URL parou com segurança",
  "No request is retried and no final security verdict is generated.": "Nenhuma requisição é repetida e nenhum veredito final é gerado.",
  "Passive checks only: public DNS, validated TLS, bounded redirects, selected headers, cookie attributes and optional exact-match reputation. No body, JavaScript, crawler, form or exploit probe.": "Somente verificações passivas: DNS público, TLS validado, redirecionamentos limitados, cabeçalhos selecionados, atributos de cookies e reputação exata opcional. Sem corpo, JavaScript, crawler, formulário ou teste de exploração.",
  "Strip values before network request": "Remover valores antes da requisição de rede",
  "Send values once, never retain them": "Enviar valores uma vez e nunca retê-los",
  "Validate target": "Validar alvo",
  "Sanitized preview": "Prévia sanitizada",
  "Authorize this exact sanitized target": "Autorizar este alvo sanitizado exato",
  "URL authorization captured": "Autorização da URL registrada",
  "One bounded passive request chain will be attempted. Proxies are bypassed and every hop is DNS-validated and IP-pinned.": "Uma cadeia passiva limitada será tentada. Proxies são ignorados; cada salto tem DNS validado e IP fixado.",
  "Confirm passive URL analysis": "Confirmar análise passiva de URL",
  "Installed Application Security": "Segurança de aplicativos instalados",
  "Read-only inventory from standard uninstall registry views and current-user MSIX. Portable apps, other users and filesystem crawling are outside coverage.": "Inventário somente leitura das visões padrão de desinstalação e MSIX do usuário atual. Apps portáteis, outros usuários e varredura do sistema de arquivos ficam fora da cobertura.",
  "Include system components": "Incluir componentes do sistema",
  "Preview inventory": "Pré-visualizar inventário",
  "Refresh public data": "Atualizar dados públicos",
  "Authorize this snapshot": "Autorizar este snapshot",
  "Confirm installed-app analysis": "Confirmar análise de aplicativos instalados",
  "Provider status": "Estado dos providers",
  "Inventory coverage": "Cobertura do inventário",
  "Validated affected findings": "Achados afetados validados",
  "No validated affected finding from available datasets. This is not a clean guarantee.": "Nenhum achado afetado foi validado nos datasets disponíveis. Isso não garante ausência de risco.",
  "File preview": "Prévia do arquivo",
  "Resolved location": "Local resolvido",
  "Detected type": "Tipo detectado",
  "Proposed checks": "Verificações propostas",
  "Policy limitations": "Limitações da política",
  "Authorize this exact file": "Autorizar este arquivo exato",
  "Authorization captured": "Autorização registrada",
  "Analysis still requires explicit confirmation. YARA-X is unavailable by execution policy; reputation will be Not checked.": "A análise ainda exige confirmação explícita. YARA-X está indisponível pela política de execução; reputação não será verificada.",
  "Confirm file analysis": "Confirmar análise do arquivo",
  "Repository path": "Caminho do repositório",
  "Authorize and inspect": "Autorizar e inspecionar",
  "Authorization preview": "Prévia da autorização",
  "Confirm repository scan": "Confirmar análise do repositório",
  "Finding detail": "Detalhe do achado",
  "Secret value: [REDACTED] · reveal is unavailable": "Valor secreto: [REDACTED] · revelação indisponível",
  "Partial coverage: unavailable checks are recorded and are not treated as a security pass.": "Cobertura parcial: verificações indisponíveis são registradas e não contam como aprovação de segurança.",
  "Cancelled: no final verdict was generated.": "Cancelada: nenhum veredito final foi gerado.",
  "No final file verdict was generated.": "Nenhum veredito final de arquivo foi gerado.",
  "No safety guarantee is made. Coverage limitations remain visible.": "Nenhuma garantia de segurança é feita. As limitações de cobertura permanecem visíveis.",
  "No findings from available checks. This is not a clean guarantee.": "Nenhum achado nas verificações disponíveis. Isso não garante ausência de risco.",
  "Cross-target investigations": "Investigações entre alvos",
  "Correlation running — no candidate graph is authoritative until atomic completion.": "Correlação em execução — nenhum grafo candidato é autoritativo antes da conclusão atômica.",
  "Correlation stopped safely. No partial graph was promoted.": "A correlação parou com segurança. Nenhum grafo parcial foi promovido.",
  "Run correlation": "Executar correlação",
  "Cancel correlation": "Cancelar correlação",
  "Investigation cases": "Casos de investigação",
  "No cases match the bounded filters.": "Nenhum caso corresponde aos filtros limitados.",
  "Automatic target changes and rollback are policy blocked": "Alterações automáticas do alvo e rollback são bloqueados pela política",
};

const exactEn: Readonly<Record<string,string>> = {
  "A área não inventa dados. Inicie uma correlação determinística somente sobre observações aprovadas e persistidas.": "This area invents no data. Start deterministic correlation only over approved, persisted observations.",
};

const ptTokens: Readonly<Record<string,string>> = {
  "File":"Arquivo", "Binary":"Binário", "Security":"Segurança", "Identity":"Identidade", "Hashes":"Hashes",
  "Digital":"Digital", "Signature":"Assinatura", "Presence":"Presença", "Present":"Presente", "Unsigned":"Não assinado",
  "Unavailable":"Indisponível", "available":"disponível", "Coverage":"Cobertura", "Findings":"Achados", "Finding":"Achado",
  "History":"Histórico", "Reports":"Relatórios", "Report":"Relatório", "Settings":"Configurações", "Status":"Estado",
  "Risk":"Risco", "Confidence":"Confiança", "Category":"Categoria", "Severity":"Severidade", "Evidence":"Evidência",
  "Sources":"Fontes", "Source":"Fonte", "Limitations":"Limitações", "Application":"Aplicativo", "Applications":"Aplicativos",
  "Version":"Versão", "Publisher":"Publicador", "Installed":"Instalado", "Unknown":"Desconhecido", "Search":"Pesquisar",
  "Priority":"Prioridade", "All":"Todos", "Cancel":"Cancelar", "Generate":"Gerar", "Executive":"Executivo",
  "Technical":"Técnico", "Developer":"Desenvolvedor", "Elapsed":"Decorrido", "Tasks":"Tarefas", "Planned":"Planejadas",
  "Failed":"Falharam", "Skipped":"Ignoradas", "Progress":"Progresso", "Target":"Alvo", "Redirects":"Redirecionamentos",
  "headers":"cabeçalhos", "Cookie":"Cookie", "attributes":"atributos", "Reputation":"Reputação",
  "Timeline":"Linha do tempo", "Relationship":"Relacionamento", "graph":"grafo", "Affected":"Afetados", "assets":"ativos",
  "Case":"Caso", "Cases":"Casos", "Open":"Abertos", "Immediate":"Imediata", "High":"Alta", "Low":"Baixa",
  "Observed":"Observados", "Reason":"Motivo", "Rule":"Regra", "Strength":"Força", "Refresh":"Atualizar",
};

export function translateUiText(value: string, locale: Locale): string {
  const exact = locale === "pt-BR" ? exactPt[value] : exactEn[value];
  if (exact !== undefined) return exact;
  if (locale === "en") return value;
  let translated=value;
  for(const [source,target] of Object.entries(ptTokens)){
    translated=translated.replace(new RegExp(`\\b${source}\\b`,"g"),target);
  }
  return translated;
}

interface LocalizableProps {
  children?: ReactNode;
  title?: string;
  placeholder?: string;
  "aria-label"?: string;
}

export function localizeTree(node: ReactNode, locale: Locale): ReactNode {
  if(typeof window === "undefined") return node;
  if(typeof node === "string") return translateUiText(node,locale);
  if(Array.isArray(node)) return node.map(child=>localizeTree(child,locale));
  if(!isValidElement(node)) return node;
  const element=node as ReactElement<LocalizableProps>;
  if(element.type === "code" || element.type === "pre") return element;
  const updates: Partial<LocalizableProps>={};
  for(const key of ["title","placeholder","aria-label"] as const){
    const value=element.props[key]; if(typeof value === "string") updates[key]=translateUiText(value,locale);
  }
  if(element.props.children !== undefined) updates.children=Children.map(element.props.children,child=>localizeTree(child,locale));
  return cloneElement(element,updates);
}
