# Post — EDY VERDICT

Nos últimos meses, trabalhei em uma pergunta simples: como reunir verificações de segurança no Windows sem esconder lacunas de cobertura e sem mandar os dados do usuário para fora da máquina?

O resultado é o **EDY VERDICT**, um workbench local-first para análise de repositórios, arquivos e binários, aplicativos instalados e URLs em modo passivo.

O projeto combina Rust, Tauri, React e SQLite. A interface conversa com o núcleo por IPC tipado e restrito; cada análise exige um alvo explícito; e os resultados mantêm cobertura, risco, confiança e evidência como conceitos separados. Quando um verificador não está disponível, isso aparece como ausência de cobertura — nunca como aprovação.

Alguns dos pontos em que mais aprendi:

- construir limites claros entre UI, IPC e acesso ao sistema;
- tratar autorização e escopo como parte do produto, não como texto decorativo;
- preservar evidência e proveniência para relatórios reproduzíveis;
- projetar proteção contra SSRF, redirects e DNS rebinding na análise passiva de URLs;
- manter toolchains, caches e dados de execução isolados no próprio projeto.

O candidato atual é o **v1.0.0-rc.1**, distribuído como source build. A validação inclui testes de arquitetura, frontend e Rust, análise estática, build de produção, persistência SQLite, secret scanning e cenários nativos em múltiplas resoluções. As limitações conhecidas continuam documentadas de forma explícita.

Código e documentação: https://github.com/EDY075/EDY-VERDICT

Feedback técnico é muito bem-vindo — especialmente sobre o modelo de evidência, os limites de confiança e a experiência de análise local.

#cybersecurity #blueteam #rust #tauri #react #windows #opensource
