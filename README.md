# Kallyel

**Kallyel: análise de logs para detecção de ataques web**

Kallyel é uma ferramenta de linha de comando, local e leve, que lê logs de servidor, normaliza
os eventos, aplica regras de detecção mapeadas para **MITRE ATT&CK, CWE e OWASP**, correlaciona
por IP e devolve ao analista o que importa: achados, linha do tempo do ataque e uma pontuação
de risco **sempre explicada**.

Tudo roda offline: nenhum dado sai do seu computador e não há telemetria.

> **Triagem, não veredito.** O Kallyel aponta onde olhar. Cada achado deve ser confirmado nos
> logs originais antes de qualquer ação. As regras geram falsos positivos e **não cobrem todo
> ataque**: leia [O que o Kallyel não detecta](#o-que-o-kallyel-não-detecta).

Posicionamento: triagem para quem não tem SIEM. Ele **não substitui** Splunk, Elastic ou Wazuh.

*(O nome é Kallyel, com dois "l". O subtítulo acima existe para diferenciar o projeto de
perfis pessoais com o mesmo nome em buscas.)*

## O que ele lê

| Formato | Arquivos típicos | Observações |
|---|---|---|
| nginx e Apache, *combined* | `access.log` | Detectado pelo conteúdo. O fuso vem na própria linha. |
| `auth.log` / `secure` (syslog) | `/var/log/auth.log`, `/var/log/secure` | sshd, sudo e useradd. Formato tradicional e ISO 8601. |
| Laravel | `storage/logs/laravel.log` | Registros de várias linhas (stack traces) viram um evento só. |

Entradas: arquivo, **pasta** (recursivo), **stdin** (`-`), arquivos `.gz` e rotacionados
(`access.log.1`, `access.log.2.gz`; o gzip é reconhecido pelo conteúdo). A leitura é em fluxo,
linha a linha, com memória limitada. Linhas acima de 8 KB são truncadas e contadas.

Linhas que o Kallyel não reconhece **nunca são descartadas em silêncio**: o total aparece no
resumo, e `--show-unparsed` mostra amostras.

## Instalação

Requer Python 3.10 ou superior.

```bash
pipx install .          # na raiz do projeto; instala o comando `kallyel`
kallyel version
```

- **Debian/Ubuntu (`.deb`):** `packaging/build_deb.sh`. Veja [packaging/README.md](packaging/README.md)
  para o estado de verificação e as limitações.
- **Windows:** funciona a partir do código ou do `pipx` (testado no Windows 11 com Python 3.11).
  Não há instalador na v0.1: [packaging/windows/README.md](packaging/windows/README.md).
- **Desenvolvimento:** `python -m venv .venv`, ative e rode `pip install -e ".[dev]"`.

## Uso

```text
kallyel analyze PATH... [--format table|json|jsonl|html|md] [--out ARQ]
                        [--fail-on low|medium|high|critical] [--since T] [--until T]
                        [--rules DIR] [--no-redact] [--show-unparsed] [--include-private]
                        [--log-utc-offset -03:00] [--config ARQ]
kallyel timeline --ip IP PATH...
kallyel rules list | show ID | validate DIR
kallyel parsers list
kallyel version
```

Códigos de saída: **0** sem achados na gravidade de `--fail-on` ou acima; **1** com achados;
**2** erro de uso ou de entrada. O padrão de `--fail-on` é `low` (qualquer achado sai com 1).

### Exemplo: analisar uma pasta de logs

Os exemplos abaixo usam logs **sintéticos** (nginx, `auth.log` e Laravel) gerados por
`tests/data/generate.py`.

```text
$ kallyel analyze .
Kallyel: análise de logs para detecção de ataques web
Gerado em 2026-11-11 18:42:36 UTC · versão 0.1.0

Arquivos: 3  Linhas lidas: 107  Reconhecidas: 107  NÃO reconhecidas: 0 (0.0%)  Truncadas: 0
Eventos analisados: 73  Ignorados (IP privado/configurado): 0  Fora do período: 0
Achados: 7  IPs com achados: 1

IPs por risco
┌───┬──────────────┬───────────────────┬──────────────────────────────────────┬────────┬───────────────────────────────────────────┐
│ # │ IP           │ Risco             │ Fases                                │ Regras │ Período (UTC)                             │
├───┼──────────────┼───────────────────┼──────────────────────────────────────┼────────┼───────────────────────────────────────────┤
│ 1 │ 203.0.113.50 │ 100/100 (crítico) │ reconhecimento → tentativa → sucesso │ 5      │ 2024-01-01 12:00:00 a 2024-01-01 12:03:30 │
└───┴──────────────┴───────────────────┴──────────────────────────────────────┴────────┴───────────────────────────────────────────┘
...
  [crítica] KALLYEL-AUTH-002: Força bruta seguida de login com sucesso
    1 ocorrência(s), de 2024-01-01 12:03:20 a 2024-01-01 12:03:30; fase: sucesso
    Critério: falhas de autenticação → login com sucesso em até 900s
    Mapeamento: T1110, T1078, CWE-307, A07:2021
    Motivo: O mesmo IP errou a autenticação 5 ou mais vezes e, em seguida, conseguiu entrar, ...
    Falsos positivos prováveis: Usuário legítimo que errou a senha várias vezes e depois acertou.
    Mitigação: Tratar a conta como comprometida até prova em contrário: trocar credenciais, ...
...
7 achado(s) com gravidade low ou acima (código de saída 1)
```

(O `...` marca trechos cortados aqui; a saída real mostra todos os achados, com evidências.)

### Exemplo: a linha do tempo de um IP

```text
$ kallyel timeline --ip 203.0.113.50 .
Linha do tempo de 203.0.113.50
Período dos achados: 2024-01-01 12:00:00 → 2024-01-01 12:03:30 UTC (duração 3m30s)
Fases: reconhecimento → tentativa → sucesso
Eventos deste IP analisados: 67

┌─────────────────────┬────────────────┬────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────┐
│ Hora (UTC)          │ Fase           │ Regra(s)                           │ Evento (arquivo:linha)                                                                    │
├─────────────────────┼────────────────┼────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ 2024-01-01 12:00:00 │ reconhecimento │ KALLYEL-WEB-005, KALLYEL-WEB-007   │ GET /x0 → 404  (×40, até 2024-01-01 12:00:39)                                             │
│                     │                │                                    │ access.log:1                                                                              │
│ 2024-01-01 12:01:40 │ tentativa      │ KALLYEL-WEB-008                    │ POST /login → 401  (×20, até 2024-01-01 12:01:59)                                         │
│                     │                │                                    │ access.log:41                                                                             │
│ 2024-01-01 12:03:20 │ tentativa      │ KALLYEL-AUTH-001, KALLYEL-AUTH-002 │ Failed password for root from 203.0.113.50 port 40000 ssh2  (×6, até 2024-01-01 12:03:25) │
│                     │                │                                    │ auth.log:1                                                                                │
│ 2024-01-01 12:03:30 │ sucesso        │ KALLYEL-AUTH-002                   │ Accepted password for root from 203.0.113.50 port 40010 ssh2                              │
│                     │                │                                    │ auth.log:7                                                                                │
└─────────────────────┴────────────────┴────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────┘

Pontuação de risco: 100/100 (crítico)
  +45  Gravidade crítica: 1 regra(s) × 45 pontos (KALLYEL-AUTH-002)
  +20  Gravidade alta: 1 regra(s) × 20 pontos (KALLYEL-AUTH-001)
  +24  Gravidade média: 3 regra(s) × 8 pontos (KALLYEL-WEB-005, KALLYEL-WEB-007, KALLYEL-WEB-008)
  +8   Diversidade de técnicas: 3 técnicas ATT&CK distintas (T1078, T1110, T1595): +4 por técnica além da primeira (máx. 20)
  +20  Progressão entre fases: reconhecimento → tentativa → sucesso: +10 por fase além da primeira (máx. 30)
  Soma 117, limitada a 100.
```

### Outros formatos de saída

```bash
kallyel analyze /var/log/nginx -f html -o relatorio.html   # arquivo único, sem scripts nem recursos externos
kallyel analyze /var/log/nginx -f md   -o dossie.md        # dossiê em Markdown
kallyel analyze /var/log/nginx -f json -o saida.json       # estruturado
kallyel analyze /var/log/nginx -f jsonl                    # uma linha JSON por registro (ingestão)
zcat access.log.2.gz | kallyel analyze - --fail-on high    # stdin; use em CI/pipelines
kallyel analyze /var/log --since 2024-01-01 --until 2024-01-02T06:00
```

**Ordem dos arquivos:** as regras de taxa e de sequência assumem eventos em ordem cronológica
dentro de cada arquivo. Com logs rotacionados, passe do **mais antigo para o mais novo**. O
Kallyel avisa quando vê eventos fora de ordem.

### Fuso e ano dos logs sem fuso

O `auth.log` tradicional (`Jan  5 12:00:01`) e o Laravel (`[2024-01-05 12:00:01]`) não trazem
fuso. Por padrão são tratados como **UTC**; se o servidor usa outro fuso, informe-o
(`--log-utc-offset -03:00` ou `log_utc_offset` em `kallyel.toml`), senão a linha do tempo
mistura horários e a história sai na ordem errada. O **ano** do syslog é deduzido da data de
modificação do arquivo.

### Se o servidor está atrás de um proxy ou CDN

O Kallyel agrupa por **o IP que está no log**. Atrás de um proxy reverso, o `access.log` registra
o IP do proxy, e todo o tráfego parece vir de um só endereço. Configure o servidor para
registrar o IP real do cliente (por exemplo `real_ip` no nginx) antes de analisar. O Kallyel
**não** lê o cabeçalho `X-Forwarded-For`.

## Regras

13 regras embutidas, em YAML, cada uma com técnica ATT&CK, CWE/OWASP quando aplicável, motivo,
falsos positivos prováveis e mitigação. Tabela completa, exemplos de log e o formato para
escrever as suas: [docs/rules.md](docs/rules.md).

| Regra | Detecta |
|---|---|
| WEB-001 a 003 | SQL injection, XSS refletido, path traversal/LFI |
| WEB-004, 005 | Acesso a arquivos sensíveis (`.env`, `.git`, `wp-config`, `phpinfo`); User-Agent de scanner |
| WEB-006 | Injeção de comando / execução remota |
| WEB-007 a 009 | Pico de 404 (enumeração); muitos 401/403; pico de erros 500 |
| AUTH-001, 002 | Força bruta de SSH; força bruta **seguida de login com sucesso** |
| AUTH-003 | Novo usuário local ou `sudo` incomum |
| APP-001 | Stack trace do Laravel com dado sensível (senha, token, chave) |

`kallyel rules list`, `kallyel rules show KALLYEL-WEB-001` e `kallyel rules validate DIR`
inspecionam e validam regras.

## Como a pontuação de risco funciona

A pontuação (0 a 100) ordena IPs para triagem; **não é uma probabilidade**. Cada ponto vem com
uma justificativa impressa junto:

- **Gravidade:** cada regra que disparou para o IP conta uma vez (baixa 3, média 8, alta 20,
  crítica 45).
- **Diversidade de técnicas:** +4 por técnica ATT&CK distinta além da primeira (máx. 20).
- **Progressão entre fases:** +10 por fase além da primeira (reconhecimento, tentativa,
  sucesso, ação; máx. 30).

Faixas: baixo (até 19), médio (20 a 44), alto (45 a 74), crítico (75 ou mais). Os pesos são
heurísticas simples e foram escolhidos sem dados reais; veja [docs/avaliacao.md](docs/avaliacao.md).

Por padrão, IPs de redes privadas (10/8, 172.16/12, 192.168/16, loopback, link-local, CGNAT,
ULA) são **ignorados**. Use `--include-private` ou `ignore_private = false` para analisá-los, e
`ignore_networks` para ignorar também redes suas (monitoramento próprio, por exemplo).

## Configuração

`kallyel.toml` na pasta de dados do usuário (`~/.local/share/kallyel` no Linux,
`%LOCALAPPDATA%\Kallyel` no Windows), ou o caminho de `--config` / `KALLYEL_CONFIG`.

```toml
ignore_private = true
ignore_networks = ["203.0.113.0/24"]
rules_dir = "/etc/kallyel/rules"
log_utc_offset = "-03:00"
```

Variáveis de ambiente: `KALLYEL_CONFIG`, `KALLYEL_IGNORE_PRIVATE`, `KALLYEL_IGNORE_NETWORKS`,
`KALLYEL_RULES_DIR`, `KALLYEL_LOG_UTC_OFFSET`. Precedência: linha de comando, ambiente, arquivo.

Por segurança, o `kallyel.toml` **não é lido do diretório atual** (poderia vir junto de logs ou
projetos não confiáveis), e o mascaramento **não pode** ser desligado por arquivo nem por
ambiente, só com `--no-redact`.

## Privacidade e segurança

Logs são **entrada controlada por quem ataca**. O Kallyel foi escrito assumindo isso:

- **Mascaramento (LGPD) ligado por padrão** em toda saída: e-mails, CPF/CNPJ (os sem pontuação só quando
  o dígito verificador confere), `Authorization`, `Cookie`, tokens, chaves e valores de parâmetros como
  `password`, `token` e `senha`. `--no-redact` precisa ser pedido explicitamente e o relatório
  avisa quando foi usado. Endereços IP **não** são mascarados. Nomes, endereços e telefones
  **também não** são: o mascaramento cobre padrões conhecidos, não tudo.
- **Saída segura:** HTML com autoescape do Jinja2 (sem `|safe`), sem JavaScript e com uma
  política CSP no próprio arquivo; Markdown com texto escapado e evidências em blocos
  protegidos; terminal com sequências ANSI e de controle neutralizadas.
- **Entradas hostis:** linhas limitadas a 8 KB, regras com checagem contra ReDoS, `yaml.safe_load`
  apenas, nunca `eval`, `pickle` nem `shell=True`, pastas percorridas sem seguir links
  simbólicos, nenhuma chamada de rede. Veja [docs/threat-model.md](docs/threat-model.md).
- Relatórios nunca incluem corpo de requisição (os formatos suportados não o registram).
- Os arquivos de relatório podem conter dados sensíveis mesmo mascarados: proteja-os.

## O que o Kallyel NÃO detecta

Prefira esta lista a qualquer promessa de cobertura. Várias destas lacunas estão **verificadas
com logs de teste** em [docs/avaliacao.md](docs/avaliacao.md).

- **O que não aparece no log:** corpo de requisições (POST), a maioria dos cabeçalhos, tráfego
  cifrado interno, DNS. Um SQLi enviado no corpo de um POST não deixa rastro no `access.log`.
- **Ataque lento ou distribuído:** varreduras abaixo dos limiares (30 respostas 404 por minuto,
  15 respostas 401/403 por minuto, 5 falhas de SSH em 2 minutos) ou espalhadas por muitos IPs
  passam. O Kallyel correlaciona por **um IP de cada vez**.
- **Ofuscação:** mais de duas camadas de codificação `%xx`, SQL com comentários
  (`UN/**/ION`), injeção numérica sem aspas (`or 1=1`), `..;/`, quebra de linha como
  separador, manipuladores de evento fora da lista, arquivos sensíveis fora da lista.
- **Classes inteiras de falha:** XSS armazenado e DOM, SSRF, desserialização, falhas de lógica de
  negócio, autorização quebrada (IDOR/BOLA) e CSRF quase nunca são visíveis em log de acesso.
- **Se o ataque funcionou:** o Kallyel vê a tentativa, não o resultado. O status HTTP é um
  indício, não uma prova.
- **Servidor de SSH só com chave pública:** o log traz `Invalid user`, que não conta como falha
  de senha, então a força bruta não dispara AUTH-001.
- **`message repeated N times`** do syslog conta como uma ocorrência.
- **Logs adulterados ou apagados** por quem invadiu; **linhas maiores que 8 KB** (o que vier
  depois do corte não é examinado: o resumo conta as linhas truncadas).
- **Proxy reverso sem IP real no log** (veja acima) e IPs privados (ignorados por padrão).
- **Outros formatos e fontes:** IIS, Caddy, logs JSON, syslog remoto, EVTX do Windows, logs de
  nuvem. Também fora de escopo na v0.1: GeoIP, reputação online, IA/ML, alertas por webhook,
  `--follow`, interface gráfica ou web, compatibilidade com Sigma.
- **Correlação por sessão:** não implementada (nenhum dos formatos suportados traz cookie ou ID
  de sessão no log).

## Desempenho

Medido em um notebook com Windows 11 e Python 3.11, com logs sintéticos (1.063.518 linhas,
168 MB, nginx + `auth.log` + Laravel):

- **Memória:** pico de 25,7 MB contra 21,4 MB antes de ler o log, ou seja, cerca de **+4 MB**
  para 168 MB de entrada. A memória não cresce com o tamanho do arquivo.
- **Velocidade:** de 15 a 19 mil linhas por segundo de forma sustentada (cerca de 1 minuto por
  milhão de linhas) e até ~35 mil em rajadas curtas. A queda ocorre porque o processador
  reduz o clock sob carga contínua; um benchmark de Python puro mostra a mesma queda.
- Em 1 milhão de linhas de tráfego limpo: **zero achados**.

Reproduzir: `pytest -m perf -s` (1 milhão de linhas; leva cerca de 1 minuto e meio).

## Desenvolvimento

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy                       # modo strict
pytest                     # inclui testes de segurança e de ReDoS
pytest -m perf -s          # desempenho com 1 milhão de linhas

python tests/data/generate.py --out saida --scenarios all      # logs sintéticos com gabarito
python tests/data/evaluate.py --update-docs                    # reescreve docs/avaliacao.md
python tests/data/render_rules_doc.py --update-docs            # reescreve docs/rules.md
```

`docs/avaliacao.md` e `docs/rules.md` são gerados, e há testes que falham se ficarem
desatualizados. Os dados de teste são **100% sintéticos** (IPs de documentação, nomes e senhas
inventados); nunca adicione logs reais de empresas ao repositório.

## Documentação

- [docs/rules.md](docs/rules.md): regras, técnica ATT&CK, exemplo de log, mitigação e formato YAML.
- [docs/avaliacao.md](docs/avaliacao.md): detecções, falsos positivos e lacunas medidos.
- [docs/threat-model.md](docs/threat-model.md): modelo de ameaça da própria ferramenta.
- [docs/lab.md](docs/lab.md): roteiro para validar em laboratório isolado e próprio.
- [packaging/README.md](packaging/README.md): `pipx`, `.deb` e Windows.

## Escopo ético

O projeto é exclusivamente **defensivo**: não implementa exploração, evasão nem ferramentas
ofensivas, e o repositório não contém scripts de ataque. As regras descrevem padrões de ataque
apenas o suficiente para reconhecê-los.

## Licença

**Ainda não definida.** O projeto não tem arquivo `LICENSE`; defina uma antes de distribuir.
