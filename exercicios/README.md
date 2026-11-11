# Exercícios: provas cegas para testar o Kallyel

Kallyel: análise de logs para detecção de ataques web

Aqui ficam **logs sintéticos** para você exercitar a ferramenta como um analista de verdade:
analisar, investigar e decidir, **sem ver as respostas antes**.

- 100% sintético: IPs de documentação (`203.0.113.0/24`, `2001:db8::/32`), nomes e senhas
  inventados. Nenhum dado real.
- Cada prova tem **ataques sorteados** (quais, de onde, a que horas) a partir de uma semente.
  Nem o autor do repositório precisa saber o que há dentro.
- **O gabarito não está no repositório.** Ele é regenerado com a mesma semente, só quando você
  quiser corrigir.

## Prova 01

`exercicios/prova-01/`: `access.log` (nginx), `auth.log` e `laravel.log`, gerados com a
semente **2024**.

### 1. Analise (sem olhar o gabarito)

```bash
kallyel analyze exercicios/prova-01
```

Dicas de investigação:

```bash
kallyel timeline --ip IP_QUE_CHAMOU_ATENCAO exercicios/prova-01
```

```bash
kallyel analyze exercicios/prova-01 --show-unparsed -f md -o logs/meu-dossie.md
```

Perguntas para guiar o raciocínio (anote as respostas antes de corrigir):

1. Quais IPs merecem atenção, e por quê? Em que ordem você os investigaria?
2. Qual IP **chegou a ter sucesso** depois de tentar? O que ele fez depois?
3. Algum achado parece **falso positivo**? O que você olharia para decidir?
4. Você acha que **algum ataque passou sem ser detectado**? Que sinal procuraria no log?
5. Algum achado **não tem IP**? Por que isso acontece, e o que ele diz?

### 2. Corrija

Salve a sua análise em JSON:

```bash
kallyel analyze exercicios/prova-01 -f json -o logs/resultado.json
```

Gere o gabarito (a mesma semente recria exatamente a mesma prova; ele vai para `logs/`, que o git
ignora):

```bash
python tests/data/realistic_day.py --out logs/prova-01-copia --blind --seed 2024 --nginx-lines 6000 --auth-lines 500 --laravel-lines 200
```

Compare:

```bash
python tests/data/realistic_day.py --check logs/resultado.json --gabarito logs/prova-01-copia-gabarito/gabarito.json
```

Ele diz quantos achados esperados você encontrou e, **só então**, o que faltou e o que veio a
mais. "A mais" pode ser um falso positivo do Kallyel ou uma limitação do gabarito: investigue
antes de concluir.

## Prova nova (outra semente)

Cada execução sem `--seed` sorteia uma prova diferente, maior ou menor:

```bash
python tests/data/realistic_day.py --out logs/prova-nova --blind
```

O comando mostra a semente usada. As pastas dentro de `logs/` ficam fora do git.

## Regras do jogo

- **Não abra** a pasta `*-gabarito` antes de terminar. Ela só existe depois do passo 2.
- Se o Kallyel perdeu algo ou acusou algo indevido, é um achado valioso: veja
  [docs/avaliacao.md](../docs/avaliacao.md) para as lacunas já conhecidas e
  [docs/rules.md](../docs/rules.md) para o formato de uma regra nova.
- **Logs reais** (do seu servidor, por exemplo) nunca devem entrar neste repositório. Guarde-os
  em `logs/` ou fora do projeto: veja [docs/lab.md](../docs/lab.md).
