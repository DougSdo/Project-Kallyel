# Empacotamento

Kallyel: análise de logs para detecção de ataques web

| Alvo | Como | Estado |
|---|---|---|
| `pipx` (Linux, Windows, macOS) | `pipx install .` na raiz do projeto | **Testado** (Windows 11, Python 3.11): instala o comando e carrega regras e template HTML do pacote. |
| `.deb` (Debian/Ubuntu) | `packaging/build_deb.sh` | Veja "Estado do .deb" abaixo. |
| Windows (instalador) | [windows/README.md](windows/README.md) | **Não gerado na v0.1**; só o plano e a estrutura. |

## pipx

```bash
pipx install .          # na raiz do projeto
kallyel version
```

## .deb

```bash
# Em Debian/Ubuntu, com python3, python3-venv e acesso à internet (para o pip):
packaging/build_deb.sh              # gera dist/kallyel_<versão>_<arquitetura>.deb
sudo apt install ./dist/kallyel_0.1.0_amd64.deb
kallyel version
sudo apt remove kallyel
```

Como é montado:

- Um virtualenv em `/opt/kallyel/venv` com o Kallyel e as dependências, e um link
  `/usr/bin/kallyel`. Nada fora de `/opt/kallyel` e do link é escrito.
- A fonte é copiada para uma pasta temporária antes do build: o repositório não é alterado.
- Como as dependências têm código compilado, o pacote fica atrelado à versão **menor** do
  Python do build (por exemplo, `python3 (>= 3.11), python3 (<< 3.12)`). Para outra
  distribuição ou outra versão do Python, construa nela.
- O `Maintainer` padrão é um endereço inválido de propósito; defina o seu com
  `KALLYEL_DEB_MAINTAINER="Nome <email>"`.
- **Licença:** o projeto ainda não tem licença; o arquivo `copyright` do pacote diz isso.
  Defina uma antes de distribuir o `.deb`.
- As dependências são baixadas do PyPI em tempo de build sem fixar versões nem hashes, então
  dois builds em datas diferentes podem trazer versões diferentes. Para um build reprodutível,
  fixe-as com um arquivo de requisitos com hashes.

## Estado do .deb

**Verificado de verdade** em um contêiner `debian:bookworm-slim` limpo (Debian 12, Python 3.11.2,
`amd64`): `build_deb.sh` gerou o pacote (cerca de 8 MB), e `smoke_test_deb.sh` o instalou com
`apt`, rodou `kallyel version`, conferiu as 13 regras embutidas, analisou um log sintético,
gerou JSON e HTML (sem `<script>`), mostrou a linha do tempo, removeu o pacote e confirmou que
não sobrou nada em `/usr/bin` nem em `/opt/kallyel`.

**Não verificado:** Ubuntu, outras versões do Debian ou do Python, a arquitetura `arm64`, o
`lintian` (o pacote não tem licença definida, então não passaria na política do Debian) e a
atualização de uma versão para outra.

Para repetir o teste sem tocar na sua máquina (precisa de Docker; na raiz do projeto):

```bash
mkdir -p dist
docker run --rm -v "$PWD:/src:ro" -v "$PWD/dist:/out" debian:bookworm-slim bash -c '
  apt-get update -qq && apt-get install -y -qq python3 python3-venv > /dev/null &&
  bash /src/packaging/build_deb.sh --out /out &&
  bash /src/packaging/smoke_test_deb.sh /out/kallyel_*.deb'
```

`smoke_test_deb.sh` instala e remove um pacote: rode-o só como root em um contêiner ou máquina
descartável.

## Estrutura

```
packaging/
├── README.md             este arquivo
├── build_deb.sh          gera o .deb
├── smoke_test_deb.sh     instala, usa e remove o .deb (em contêiner descartável)
└── windows/
    └── README.md         plano para o instalador do Windows (não implementado)
```
