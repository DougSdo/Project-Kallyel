# Empacotamento para Windows (estrutura, sem instalador na v0.1)

Kallyel: análise de logs para detecção de ataques web

**Na v0.1 não há instalador para Windows.** O que existe é o caminho já verificado e o plano
para quando ele for necessário.

## O que funciona hoje no Windows

- **A partir do código ou do `pip`/`pipx`**, que é o suportado e testado:

  ```powershell
  python -m pip install pipx
  python -m pipx install .
  kallyel version
  ```

  `pipx install .` foi executado de verdade no Windows 11 com Python 3.11 e instala o comando
  `kallyel.exe` com as regras e o template HTML dentro do pacote.
- Os testes (`pytest`) rodam em Windows. Um deles (links simbólicos) é pulado quando o usuário
  não tem o privilégio de criar links simbólicos.
- Pasta de dados do usuário: `%LOCALAPPDATA%\Kallyel`. O `kallyel.toml` é procurado ali
  (ou no caminho de `--config`/`KALLYEL_CONFIG`).

## Plano para um instalador (não implementado, não testado)

1. **Executável:** [PyInstaller](https://pyinstaller.org) em modo `--onedir`, com um script de
   entrada que chama `kallyel.cli.main()`. É preciso incluir os dados do pacote
   (`kallyel/rules/builtin/*.yaml` e `kallyel/report/templates/*.j2`), por exemplo com
   `--collect-data kallyel`.
2. **Instalador:** [Inno Setup](https://jrsoftware.org/isinfo.php) ou WiX para gerar um `.exe`
   ou `.msi` que copie a pasta, adicione ao `PATH` do usuário e crie a pasta de dados.
3. **Assinatura de código** do executável e do instalador: sem ela, o SmartScreen do Windows
   avisa o usuário. Exige um certificado, que o projeto ainda não tem.
4. **Verificação:** instalar em uma VM limpa, rodar `kallyel version`, analisar um log
   sintético (`tests/data/generate.py`) e conferir que o HTML abre sem recursos externos.

Pontos de atenção conhecidos:

- Um executável do PyInstaller descompacta em uma pasta temporária; antivírus costumam
  desconfiar de executáveis não assinados.
- Em Windows, o Python 3.11 não trata *junctions* como links simbólicos. Ao percorrer uma
  pasta, o Kallyel pode entrar em uma junction apontando para fora da pasta analisada. Não foi
  verificado; use caminhos de arquivo explícitos em pastas que você não controla.
