# Roteiro de laboratório: validar o Kallyel em ambiente isolado e próprio

Kallyel: análise de logs para detecção de ataques web

Os números de [avaliacao.md](avaliacao.md) são **sintéticos**: provam que as regras não
regrediram, não que elas funcionam contra ataques reais. Este roteiro explica como obter dados
reais **de forma segura e legal**, para preencher a tabela "Dados do laboratório" daquele
documento.

> **Este repositório não contém scripts de ataque e este roteiro também não.** Ele descreve o
> ambiente, a coleta e a comparação. Para gerar tráfego de teste, use as ferramentas pelo nome e
> leia a documentação oficial de cada uma.

## 1. Regras de ouro (leia antes de começar)

1. **Só ataque o que é seu.** Todas as máquinas do laboratório devem ser suas (ou você deve ter
   autorização por escrito de quem for o dono). Testar sistemas de terceiros, mesmo "só uma
   varredura", pode ser crime.
2. **Isole.** Rede virtual sem rota para a internet nem para a sua rede doméstica ou de
   trabalho (por exemplo, rede "somente host" ou "interna" do hipervisor). Aplicações propositalmente
   vulneráveis **nunca** devem ficar expostas.
3. **Use máquinas descartáveis.** Tire um *snapshot* limpo de cada VM antes de começar e volte a
   ele no fim.
4. **Não misture dados.** Não copie logs reais de empresas, clientes ou do seu trabalho para o
   laboratório, nem logs do laboratório para repositórios públicos sem revisar.
5. **Ferramentas ofensivas ficam só na VM atacante**, nunca no repositório do Kallyel.

## 2. Montagem sugerida

| Máquina | Função | Sugestões |
|---|---|---|
| **alvo** | Aplicação vulnerável de teste atrás de nginx ou Apache; servidor SSH; opcional: uma aplicação Laravel de teste | Aplicações feitas para treino, como DVWA, OWASP Juice Shop, bWAPP ou WebGoat (escolha uma ou mais e siga a documentação delas). |
| **atacante** | Gera o tráfego de teste | Uma VM de segurança de sua preferência, com as ferramentas que você quiser exercitar. |
| **analista** | Roda o Kallyel | Pode ser o seu próprio computador, **recebendo apenas cópias dos logs**. |

Ligue o *log* certo no alvo:

- **nginx/Apache:** formato *combined* (é o padrão). Confirme que o log traz o **IP real do
  cliente**; se houver proxy entre o cliente e o servidor, configure o IP real, porque o
  Kallyel não lê `X-Forwarded-For`.
- **SSH:** `sshd` com `LogLevel INFO` (padrão) e `rsyslog` gravando em `/var/log/auth.log`
  (Debian/Ubuntu) ou `/var/log/secure` (RHEL).
- **Laravel:** canal `single` ou `daily` em `storage/logs`.
- **Horário:** anote o **fuso do servidor**. O `auth.log` tradicional e o Laravel não trazem
  fuso; sem informar `--log-utc-offset`, a linha do tempo mistura horários.

## 3. Duas fases: primeiro o normal, depois o ataque

Os falsos positivos só aparecem com tráfego **legítimo**, então comece por ele.

**Fase A: linha de base limpa (pelo menos algumas horas, de preferência 24 h).**
Use a aplicação normalmente, como um usuário faria: navegue, busque, faça login (inclusive
errando a senha de vez em quando), use `sudo` para administrar o alvo. Não rode nenhuma
ferramenta ofensiva. Guarde os logs desse período separados.

**Fase B: ações de teste, com registro.** Execute, a partir da VM atacante, as atividades que
quer validar (varredura de diretórios, tentativas de injeção em campos da aplicação de teste,
tentativas de login repetidas, tentativas de SSH). A regra é **uma ação por vez e anotada** (veja
o gabarito abaixo). Use cada ferramenta conforme a documentação oficial dela.

### O gabarito (o que torna a medição confiável)

Mantenha uma planilha, preenchida **na hora**, com uma linha por ação:

| Início (com fuso) | Fim | IP de origem | Alvo | O que foi feito | Regra(s) que deveria(m) disparar |
|---|---|---|---|---|---|
| 2024-03-01 14:02:10 -03:00 | 14:02:40 | 192.168.56.20 | /login | 30 tentativas de login com senha errada | KALLYEL-WEB-008 |

Sem esse gabarito, você não consegue separar verdadeiro positivo de falso positivo depois.

## 4. Coleta dos logs

1. No alvo, **copie** os logs (não analise no servidor). Inclua os rotacionados, que podem ser
   `.gz`.
2. Preserve **a ordem cronológica**: passe os arquivos rotacionados do **mais antigo para o mais
   novo** ao Kallyel (`access.log.2.gz`, depois `access.log.1`, depois `access.log`).
3. Anote o fuso do servidor e o intervalo de cada fase.
4. Como os IPs do laboratório são privados (por exemplo `192.168.x.x`), o Kallyel os ignora por
   padrão. Rode com `--include-private`, ou defina `ignore_private = false` no `kallyel.toml`.

## 5. Rodar e comparar

```bash
# Fase A (tráfego limpo): o esperado é NENHUM achado ou só achados explicáveis
kallyel analyze logs/faseA/ --include-private --log-utc-offset -03:00 --format md -o faseA.md

# Fase B (com as ações do gabarito)
kallyel analyze logs/faseB/ --include-private --log-utc-offset -03:00 --format md -o faseB.md

# História de um IP específico
kallyel timeline --ip 192.168.56.20 logs/faseB/ --include-private --log-utc-offset -03:00
```

Para cada linha do gabarito, marque o resultado:

| Situação | Como chamar |
|---|---|
| A ação aconteceu e o Kallyel acusou a regra esperada | **Verdadeiro positivo** |
| A ação aconteceu e o Kallyel **não** acusou | **Falso negativo** (uma lacuna: registre em "Lacunas observadas") |
| O Kallyel acusou algo que não está no gabarito, na fase A ou B | **Falso positivo** (olhe a evidência: foi tráfego legítimo?) |

Confira também:

- O resumo mostra **linhas não reconhecidas**? Se sim, use `--show-unparsed`: pode ser um
  formato de log que o Kallyel ainda não entende.
- A linha do tempo aparece na ordem certa? Se o SSH aparece horas antes do nginx, o fuso está
  errado.
- Há aviso de **eventos fora de ordem**? Reordene os arquivos rotacionados.

## 6. Registrar o resultado

Preencha a tabela "Dados do laboratório" em [avaliacao.md](avaliacao.md) (data e ambiente,
detecções confirmadas, falsos positivos e lacunas observadas). Cuide para **não colar dados
pessoais**: use trechos mascarados (o padrão do Kallyel) e revise antes de commitar.

Se encontrar um falso positivo recorrente, há dois caminhos:

1. **Ajustar o ambiente:** por exemplo, `ignore_networks` para ignorar um IP de monitoramento
   próprio.
2. **Escrever uma regra sua** em uma pasta separada (`--rules DIR`, formato em
   [rules.md](rules.md#formato-das-regras-yaml)) e validar com `kallyel rules validate DIR`.
   Trate a pasta de regras como código: veja o [modelo de ameaça](threat-model.md).

## 7. Encerramento

1. Volte as VMs ao *snapshot* limpo ou apague-as.
2. Apague os logs coletados, ou guarde-os **fora** do repositório.
3. Se algum achado revelar um comportamento do Kallyel que você considera errado, reproduza com
   dados sintéticos (`tests/data/generate.py`) antes de abrir uma discussão, para não expor
   dados do seu ambiente.
