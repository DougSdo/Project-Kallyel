# Modelo de ameaça do Kallyel

Kallyel: análise de logs para detecção de ataques web

Este documento descreve como o **próprio Kallyel** pode ser atacado e o que foi feito a
respeito. Um analisador de logs lê dados escolhidos por quem ataca, então ele precisa ser
tratado como um alvo, não só como uma ferramenta.

Cada mitigação indica, quando existe, o teste que a verifica. Os **riscos residuais** estão
listados no fim, sem maquiagem.

## Ativos e limites de confiança

| O que | Confiança | Observação |
|---|---|---|
| Conteúdo dos logs | **Nenhuma** | Controlado, no todo ou em parte, por quem ataca: URL, User-Agent, referrer, nome de usuário no SSH, mensagens de erro da aplicação. |
| Pasta de regras (`--rules`) | Limitada | Regras de terceiros são dados YAML, mas contêm regex e podem enganar a análise. |
| Arquivo de configuração e variáveis `KALLYEL_*` | Alta | Do próprio usuário. Mesmo assim, o arquivo não é lido do diretório atual. |
| Argumentos da linha de comando | Alta | Do usuário que executa. |
| O analista (quem lê a saída) | Alvo | O terminal, o navegador ou o visualizador de Markdown dele são o que o atacante quer atingir. |

**Adversário considerado:** alguém que consegue colocar bytes arbitrários em um log (basta uma
requisição HTTP ou uma tentativa de login SSH) e que **não** tem acesso ao computador do
analista. O objetivo dele pode ser executar algo no terminal ou no navegador do analista,
travar ou deixar lenta a análise, esconder seu próprio ataque ou incriminar outro IP.

**Fora de escopo:** quem já tem acesso de escrita aos arquivos do analista, aos logs
originais em disco ou ao código do Kallyel; ataques ao sistema operacional.

## Ameaças e mitigações

### 1. Logs hostis

| Ameaça | Mitigação | Verificada por |
|---|---|---|
| **Injeção de terminal:** sequências ANSI/OSC e caracteres de controle em um User-Agent ou URL reescrevem a tela, mudam o título da janela ou escondem linhas. | Todo texto de log passa por `neutralize` (controles, ESC e caracteres de direção bidi viram escapes visíveis) antes de ser impresso, e o `rich` usa objetos `Text` (nunca interpreta marcação). | `test_cli_timeline_neutralises_ansi_and_markup_from_logs`, `test_table_output_neutralised_and_shows_unparsed_count`, `test_report_has_no_control_characters_anywhere` |
| **Injeção de HTML/JavaScript** no relatório HTML. | Jinja2 com `autoescape=True`, nenhum `\|safe`, sem JavaScript, sem recursos externos e política CSP `default-src 'none'` dentro do arquivo (se algo passasse, o navegador ainda bloquearia scripts). | `test_html_escapes_hostile_user_agent_and_ip`, `test_html_is_well_formed_and_has_no_script_or_external_resources`, `test_html_template_never_disables_escaping` |
| **Injeção de Markdown/HTML** no dossiê. | Texto vindo de log só entra em `code span` (com crases suficientes) ou em bloco de código com cerca maior que qualquer sequência de crases do conteúdo; texto corrido tem caracteres especiais escapados. | `test_md_block_fence_cannot_be_closed_by_content`, `test_markdown_dossier_content_and_hostile_data` |
| **Falsificação de campos:** um nome de usuário SSH como `x from 10.9.9.9 port 1 ssh2: y` tenta incriminar outro IP; aspas escapadas no User-Agent tentam quebrar a análise do nginx. | O IP é ancorado pela **direita** na linha do sshd e só se aceita o sufixo que o próprio sshd escreve; o parser do nginx entende `\"` dentro dos campos entre aspas. | `test_username_cannot_spoof_the_client_ip`, `test_username_spoofing_in_auth_log_blames_the_real_ip_only`, `test_escaped_quote_in_user_agent_stays_inside_field` |
| **ReDoS** nos parsers e nas regras: uma linha patológica trava a análise. | Regex dos parsers e das regras embutidas usam classes de caracteres disjuntas e quantificadores sem aninhamento; linhas limitadas a 8 KB; testes medem o tempo (limite de 0,25 s) com dezenas de entradas patológicas. Regras novas passam por checagem estática (veja o item 3). | `test_redos.py`, `test_pathological_lines_are_parsed_fast`, `test_pathological_headers_are_fast`, `test_redaction_is_fast_on_pathological_input` |
| **Linha gigante** esgota memória. | Leitura em pedaços (`readline` com limite): o excedente é descartado sem acumular, e a linha truncada é contada e avisada. | `test_giant_line_is_truncated_and_following_lines_survive` |
| **Registro multilinha gigante** (Laravel). | Máximo de 1000 linhas e 64 KB por registro; o excedente conta em `line_count` mas não fica na memória. | `test_huge_record_is_capped_in_memory_but_counted`, `test_record_char_cap` |
| **Muitos IPs distintos** (milhões de endereços de origem) fazem o estado das regras crescer. | Estado por regra limitado a 20 mil IPs (os mais antigos saem) e a 100 mil achados por regra, sempre com **aviso** no resultado. A memória medida em 1 milhão de linhas é constante. | `test_state_eviction_is_bounded_and_warns`, `test_findings_cap_per_rule_warns`, `test_one_million_lines_bounded_memory_and_exact_detections` (`pytest -m perf`) |
| **Travessia de pastas:** links simbólicos e arquivos especiais (FIFO, dispositivos) dentro de uma pasta. | Ao percorrer pastas, links simbólicos não são seguidos por padrão e só arquivos regulares são lidos. Um arquivo passado explicitamente pelo usuário é aceito se for regular. | `test_symlinks_inside_directories_are_not_followed` (veja o risco R4) |
| **Evasão por truncamento:** o atacante coloca o payload depois dos 8 KB. | A linha truncada é contada e o resumo avisa que "um payload após o corte não foi examinado". O Kallyel não consegue examinar o que cortou. | `test_truncated_lines_are_counted` |

### 2. Relatórios e dados pessoais

| Ameaça | Mitigação | Verificada por |
|---|---|---|
| **Vazamento de dados pessoais** (LGPD) em relatórios compartilhados. | Mascaramento ligado por padrão em toda saída: e-mail, CPF/CNPJ, `Authorization`, `Cookie`, tokens, chaves e valores de parâmetros sensíveis. Relatórios nunca incluem corpo de requisição. | `test_redaction_on_by_default_in_every_format`, `test_redact.py` |
| **Mascaramento desligado sem querer.** | Só `--no-redact` desliga; arquivo de configuração e variáveis de ambiente não conseguem. Quando desligado, Markdown, HTML e tabela mostram um aviso no relatório. | `test_no_redact_shows_data_and_warns`, `test_invalid_config_is_rejected` (`redact = false` é rejeitado) |
| **Segredo no fundo de um stack trace** (Laravel) aparece na evidência. | A evidência mostra só o trecho ao redor do casamento e passa pelo mascaramento. | `test_laravel_evidence_shows_the_context_of_the_match_deep_in_the_trace` |

### 3. Regras de terceiros (`--rules`)

| Ameaça | Mitigação | Verificada por |
|---|---|---|
| **Execução de código** via YAML. | Somente `yaml.safe_load_all`; regras são dados, sem código. Um teste confirma que uma tag `!!python/object/apply` é recusada. | `test_yaml_object_tags_are_not_executed` |
| **Arquivo ou regra enorme.** | Arquivo de até 256 KB, regex de até 500 caracteres, no máximo 50 padrões por regra, chaves desconhecidas rejeitadas. | `test_huge_rule_file_rejected`, `test_invalid_rules_fail_with_clear_message` |
| **ReDoS em uma regra nova.** | Rejeição estática de quantificador ilimitado dentro de outro, como `(a+)+`. É uma **heurística** (veja R1). | `test_redos_prone_regex_is_rejected` |
| **Regra que sobrescreve uma embutida** para silenciar uma detecção. | Ids duplicados são rejeitados. | `test_duplicate_ids_rejected` |
| **Regra enganosa** (muito ruído ou que não detecta nada). | Não há como impedir por código: **trate a pasta de regras como código** e revise antes de usar. | (não aplicável) |

### 4. Configuração, execução e rede

- **Nenhuma chamada de rede e nenhuma telemetria** em nenhum caminho de código. Um teste examina
  a fonte (módulos de rede) e outro roda a análise com o `socket` impedido de conectar:
  `test_source_has_no_network_modules`, `test_analysis_works_with_the_network_blocked`.
  (A **instalação** usa rede, porque o `pip` baixa as dependências; a execução não.)
- **Nenhuma execução externa:** sem `subprocess`, `os.system`, `eval`, `exec`, `pickle` nem
  `shell=True`; só `yaml.safe_load`. `test_source_has_no_dangerous_calls` examina a fonte.
- **O `kallyel.toml` não é lido do diretório atual.** Um arquivo de configuração plantado junto
  de logs ou de um projeto não confiável não consegue mudar o comportamento. Só valem
  `--config`, `KALLYEL_CONFIG` e a pasta de dados do usuário. `test_cwd_config_is_not_loaded`.
- **Menor privilégio:** o Kallyel só lê os arquivos indicados e só escreve no `--out`. Não rode
  como root; para ler `/var/log/auth.log`, use um usuário do grupo `adm`. `--out` se recusa a
  sobrescrever um arquivo de entrada (`test_out_refuses_to_overwrite_an_input_file`).

### 5. Cadeia de suprimentos

Dependências de execução: `typer`, `rich`, `PyYAML`, `jinja2` (e as que elas trazem). Elas
**não estão fixadas** com versão exata nem hash, e o `.deb` baixa as versões mais recentes no
momento do build. Para um build reprodutível, gere um arquivo de requisitos com hashes e rode
`pip-audit` (ou equivalente) antes de distribuir.

## Riscos residuais

- **R1. ReDoS em regras novas.** A checagem estática não pega alternâncias sobrepostas como
  `(a|a)*`. Python não tem tempo-limite para regex. Uma regra de terceiros mal escrita pode
  travar a análise (negação de serviço), mas não executar código.
- **R2. Bomba de compressão.** A descompressão de `.gz` é em fluxo, então a **memória** fica
  constante, mas não há limite de **tempo** nem de volume descomprimido: um `.gz` pequeno que
  expande para terabytes ocupa a CPU por muito tempo.
- **R3. Evasão por adulteração.** Quem controla o servidor pode apagar ou alterar logs; o
  Kallyel não detecta isso. Tampouco vê o que foi cortado por passar de 8 KB (só o avisa).
- **R4. Links simbólicos no Windows.** O teste de links simbólicos foi **pulado** no ambiente
  de desenvolvimento (Windows sem privilégio para criá-los), então esse comportamento só foi
  exercitado por leitura de código, não por teste em execução. Além disso, o Python 3.11 não
  trata *junctions* do Windows como links simbólicos; ao percorrer uma pasta, o Kallyel pode
  entrar em uma junction que aponta para fora dela. **Não foi verificado.** Em pastas que você
  não controla, passe arquivos explícitos.
- **R5. Ambiguidade no `sudo`.** O comando é lido após a primeira ocorrência de `COMMAND=`.
  Quem controla o diretório de trabalho pode fabricar um `PWD` que imite esse campo e mudar como
  a linha é classificada. O efeito é só na classificação de uma linha de `sudo` desse mesmo
  usuário.
- **R6. Mascaramento incompleto.** Cobre padrões conhecidos. Nomes, endereços, telefones e
  formatos de segredo fora da lista não são mascarados. Endereços IP não são mascarados.
- **R7. Relatórios são sensíveis.** Mesmo mascarados, trazem IPs, caminhos e trechos de logs.
  Os arquivos são gravados com as permissões padrão do sistema; proteja-os. Não verifiquei como
  cada visualizador de Markdown trata o dossiê: só as propriedades de escape são testadas.
- **R8. Parsers e regras não são auditoria.** O Kallyel é triagem. Um atacante que conhece as
  regras (elas são públicas) consegue evadi-las, e há lacunas verificadas em
  [avaliacao.md](avaliacao.md).
- **R9. IP de proxy.** Atrás de proxy reverso sem IP real no log, um atacante se esconde atrás
  do endereço do proxy; o Kallyel não lê `X-Forwarded-For`.

## Como relatar um problema de segurança

O projeto ainda não tem canal público definido. Até lá, relate diretamente ao mantenedor e
**não** envie logs reais de terceiros: reproduza com dados sintéticos
(`tests/data/generate.py`).
