# Avaliação das regras

Kallyel: análise de logs para detecção de ataques web

Este documento registra, regra a regra, o que foi medido: detecções, falsos positivos e
lacunas conhecidas. **Por enquanto, só com dados sintéticos.** A seção final fica reservada
para os números do laboratório isolado e próprio, que ainda não foram coletados.

## O que estes números provam, e o que não provam

- **Não provam que o Kallyel detecta ataques reais.** Os cenários de ataque foram escritos
  por quem escreveu as regras, sabendo o que elas procuram. Detectar 100% deles é esperado e
  não diz nada sobre ataques que a regra nunca previu. Esse é um teste de **regressão**: se um
  ajuste quebrar uma regra, a tabela muda.
- **Os falsos positivos medidos valem para o tráfego que o gerador produz** (loja virtual
  fictícia, padrão de acesso simples, buscas inofensivas que parecem ataque, como
  `union+station` e `sleep+tips`). Tráfego real tem mais variedade e vai gerar falsos
  positivos que aqui não aparecem.
- **O mais útil aqui são as lacunas verificadas**: variações de ataque que, comprovadamente,
  o Kallyel não detecta hoje. Prefira confiar nelas a confiar no 100%.

## Método

1. `tests/data/generate.py` gera, de forma determinística (por semente), tráfego normal de
   nginx, `auth.log` e Laravel, e oito cenários de ataque: varredura de scanner, SQLi,
   força bruta de SSH seguida de sucesso, repetição de login web, XSS, path traversal,
   injeção de comando e vazamento de segredo em stack trace. Cada cenário vem com um
   **gabarito**: quais regras devem disparar e para qual IP.
2. O gerador **não importa o Kallyel**, para o gabarito não herdar erros da ferramenta.
3. `tests/data/evaluate.py` roda a análise e compara o resultado com o gabarito. Conta
   achados esperados que dispararam e achados inesperados (falsos positivos).
4. Também executa pequenos logs com **variações de evasão** (ofuscação, ataque lento ou
   distribuído) e **controles** parecidos que devem ser detectados, para mostrar onde a
   fronteira está.
5. Os dados usam só IPs de documentação (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 e
   2001:db8::/32), domínios e senhas inventados. Nenhum dado de terceiros.

Para reproduzir: `python tests/data/evaluate.py` (imprime o bloco abaixo) ou
`python tests/data/evaluate.py --update-docs` (reescreve o bloco neste arquivo). Um teste
automático falha se o bloco estiver desatualizado.

## Resultados com dados sintéticos

<!-- BEGIN GENERATED -->

### Parâmetros desta medição

- Semente(s) de cenário: 1, 2, 3, 4, 5 (5 execuções, 58792 linhas no total, com os 8 cenários de ataque em cada uma).
- Tráfego limpo (sem ataque): 60000 linhas nginx, 6000 de auth.log e 2000 de Laravel (68552 linhas lidas), semente 1.
- Gerado por `python tests/data/evaluate.py --update-docs`; um teste confere que este bloco está atualizado.

### Resultado por regra

| Regra | Gravidade | Detectado / esperado | Achados inesperados | Lacunas conhecidas |
|---|---|---|---|---|
| `KALLYEL-APP-001` Stack trace do Laravel com dado sensível no log | high | 5/5 | 0 | Só padrões conhecidos de segredo (nomes de variável, Bearer, base64:, AKIA, chave privada); nomes personalizados passam. |
| `KALLYEL-AUTH-001` Força bruta de SSH | high | 5/5 | 0 | Só conta 'Failed ...'; servidor só com chave pública vê apenas 'Invalid user'; 'message repeated N times' conta uma vez; ataque lento ou distribuído passa. |
| `KALLYEL-AUTH-002` Força bruta seguida de login com sucesso | critical | 5/5 | 0 | Agrupa por IP: falhas de um IP e sucesso de outro não se ligam. |
| `KALLYEL-AUTH-003` Novo usuário local ou uso incomum de sudo | medium | 5/5 | 0 | Lista de comandos, não comparação com o comportamento habitual; `sudo bash` de rotina é falso positivo; outros binários que abrem shell passam. |
| `KALLYEL-WEB-001` Possível SQL Injection na requisição | high | 5/5 | 0 | Não vê corpo de POST (o log não o traz); só decodifica 2 camadas de %xx; não trata ofuscação por comentário SQL nem injeção numérica sem aspas. |
| `KALLYEL-WEB-002` Possível XSS refletido na requisição | medium | 5/5 | 0 | Só olha a URL; XSS armazenado, DOM XSS e payload em corpo ficam de fora; lista curta de manipuladores de evento. |
| `KALLYEL-WEB-003` Possível path traversal ou inclusão de arquivo local (LFI) | high | 5/5 | 0 | 2 camadas de decodificação; não trata variantes como `..;/`; wrappers de stream fora da lista. |
| `KALLYEL-WEB-004` Acesso a arquivo sensível ou de configuração | medium | 5/5 | 0 | Lista fixa de nomes; 404 e 200 geram o mesmo achado (o status está nas evidências, não na gravidade). |
| `KALLYEL-WEB-005` User-Agent de ferramenta de varredura | medium | 5/5 | 0 | Só pega scanner que se identifica; trocar o User-Agent desliga a regra. |
| `KALLYEL-WEB-006` Possível injeção de comando ou execução remota de código | critical | 5/5 | 0 | Lista curta de comandos e de metacaracteres; não trata quebra de linha (`%0a`) como separador. |
| `KALLYEL-WEB-007` Enumeração de recursos por pico de respostas 404 | medium | 5/5 | 0 | Um IP por vez: varredura lenta (abaixo de 30/min) ou distribuída entre muitos IPs passa. |
| `KALLYEL-WEB-008` Muitas respostas 401/403 do mesmo IP | medium | 5/5 | 0 | Idem: abaixo de 15 respostas 401/403 por minuto, ou espalhado por IPs, não dispara. |
| `KALLYEL-WEB-009` Pico de erros 500 provocados pelo mesmo IP | medium | 5/5 | 0 | Não distingue falha real da aplicação de fuzzing; não cobre 502/503. |
| **Total** | | **65/65** | **0** | |

"Achados inesperados" são achados (regra, IP) que não estão no gabarito do gerador: 0 vieram do tráfego limpo e 0 do fundo normal das execuções com cenários. Todos seriam falsos positivos nesta base sintética.

### Variações verificadas (lacunas e controles)

Cada linha é um pequeno log executado de verdade. "Não detectado" é uma lacuna conhecida; "controle" mostra que uma variação parecida é detectada.

| Regra | Variação | Tipo | Resultado |
|---|---|---|---|
| `KALLYEL-WEB-001` | SQLi com dupla codificação (%2520) | controle | detectado |
| `KALLYEL-WEB-003` | Traversal com dupla codificação (%252e%252e%252f) | controle | detectado |
| `KALLYEL-WEB-001` | SQLi ofuscada com comentário SQL (UN/**/ION SEL/**/ECT) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-001` | SQLi numérica sem aspas (`or 1=1`) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-001` | SQLi com 4 camadas de codificação | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-002` | XSS com manipulador fora da lista (`ontoggle`) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-003` | Traversal com 3 camadas (%25252e) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-003` | Traversal com `..;/` | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-004` | Arquivo sensível fora da lista (`/config/secrets.yml`) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-004` | Backup do .env com til (`/.env.local~`) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-006` | Injeção por quebra de linha (`%0a`) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-005` | Varredura com User-Agent de navegador (WEB-007 pega pelo volume; WEB-005 não) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-007` | Varredura lenta (1 resposta 404 a cada 5 s, 60 no total) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-007` | Varredura distribuída (40 IPs x 3 respostas 404) | lacuna suspeita | **não detectado** |
| `KALLYEL-WEB-008` | Tentativas lentas de login (1 resposta 401 a cada 10 s) | lacuna suspeita | **não detectado** |
| `KALLYEL-AUTH-001` | Força bruta lenta de SSH (1 falha por minuto) | lacuna suspeita | **não detectado** |
| `KALLYEL-AUTH-001` | Spray distribuído de SSH (20 IPs x 2 falhas) | lacuna suspeita | **não detectado** |
| `KALLYEL-AUTH-001` | Servidor só com chave: apenas 'Invalid user' no log | lacuna suspeita | **não detectado** |
| `KALLYEL-AUTH-002` | Falhas de um IP e sucesso de outro (mesma conta) | lacuna suspeita | **não detectado** |
| `KALLYEL-AUTH-003` | sudo python que abre shell (binário fora da lista) | lacuna suspeita | **não detectado** |
| `KALLYEL-APP-001` | Segredo com nome personalizado (`STRIPE_KEY=sk_live_...`) | lacuna suspeita | **não detectado** |

<!-- END GENERATED -->

## Dados do laboratório (a preencher)

Roteiro em `docs/lab.md`. Preencha depois de rodar contra uma aplicação vulnerável de teste,
montada por você, em ambiente isolado e próprio. Não use logs reais de empresas.

| Regra | Data e ambiente | Detecções confirmadas | Falsos positivos | Lacunas observadas |
|---|---|---|---|---|
| `KALLYEL-WEB-001` | | | | |
| `KALLYEL-WEB-002` | | | | |
| `KALLYEL-WEB-003` | | | | |
| `KALLYEL-WEB-004` | | | | |
| `KALLYEL-WEB-005` | | | | |
| `KALLYEL-WEB-006` | | | | |
| `KALLYEL-WEB-007` | | | | |
| `KALLYEL-WEB-008` | | | | |
| `KALLYEL-WEB-009` | | | | |
| `KALLYEL-AUTH-001` | | | | |
| `KALLYEL-AUTH-002` | | | | |
| `KALLYEL-AUTH-003` | | | | |
| `KALLYEL-APP-001` | | | | |

Triagem, não veredito: os achados do Kallyel devem ser confirmados nos logs originais.
