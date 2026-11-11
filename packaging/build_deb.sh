#!/usr/bin/env bash
# Gera o pacote .deb do Kallyel.
#
# O pacote leva um virtualenv autocontido em /opt/kallyel/venv (o Kallyel e suas dependências)
# e um link /usr/bin/kallyel. O ambiente de execução só precisa do python3 do sistema.
#
# Uso:
#   packaging/build_deb.sh [--out DIR] [--help]
#
# Variáveis de ambiente:
#   KALLYEL_DEB_MAINTAINER   campo Maintainer (padrão: "Kallyel <kallyel@example.invalid>")
#
# Requisitos NO COMPUTADOR DE BUILD (Debian/Ubuntu): python3 (>= 3.10), python3-venv,
# dpkg-deb (pacote dpkg) e acesso à internet para o pip baixar as dependências. O Kallyel
# em si não usa rede ao executar; a rede é só para montar o pacote.
#
# Compatibilidade: o venv fica atrelado à versão MENOR do Python do build (por exemplo 3.11),
# porque as dependências têm código compilado. O pacote declara
# "python3 (>= 3.11), python3 (<< 3.12)". Para outra versão do Python/distro, construa nela.

set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
MAINTAINER="${KALLYEL_DEB_MAINTAINER:-Kallyel <kallyel@example.invalid>}"
APP=/opt/kallyel

usage() {
    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

die() {
    echo "erro: $*" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)
            [ $# -ge 2 ] || die "--out exige um diretório"
            OUT="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "argumento desconhecido: $1 (use --help)" ;;
    esac
done

need() { command -v "$1" > /dev/null 2>&1 || die "comando necessário não encontrado: $1"; }
need python3
need dpkg-deb
need dpkg
need du
need sed
need grep

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "python3 >= 3.10 é obrigatório (encontrado: $(python3 --version 2>&1))"
python3 -c 'import venv, ensurepip' 2> /dev/null \
    || die "módulos venv/ensurepip ausentes: instale o pacote python3-venv"

VERSION="$(grep -m1 '^version *= *"' "$ROOT/pyproject.toml" | cut -d'"' -f2)"
[ -n "$VERSION" ] || die "não consegui ler a versão em pyproject.toml"
echo "$VERSION" | grep -Eq '^[0-9]+(\.[0-9]+)*$' \
    || die "versão '$VERSION' não suportada por este script (use X.Y.Z; sem sufixos dev/rc)"

ARCH="$(dpkg --print-architecture)"
PY_MIN="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_NEXT="$(python3 -c 'import sys; print("%d.%d" % (sys.version_info[0], sys.version_info[1] + 1))')"

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

VENV="$STAGE$APP/venv"
SRC="$STAGE/source"

echo "==> Copiando a fonte (o repositório não é alterado)"
mkdir -p "$SRC"
cp "$ROOT/pyproject.toml" "$ROOT/README.md" "$SRC/"
cp -r "$ROOT/src" "$SRC/src"
find "$SRC" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$SRC" -name '*.egg-info' -type d -prune -exec rm -rf {} +

echo "==> Criando o virtualenv em $APP/venv (Python $PY_MIN)"
mkdir -p "$STAGE$APP"
python3 -m venv "$VENV"

echo "==> Instalando o Kallyel e as dependências"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-cache-dir \
    --no-compile "$SRC"

echo "==> Ajustando caminhos para o destino final"
# Os scripts do venv foram gerados com o caminho da área de montagem; aponte para $APP.
grep -rIl -- "$STAGE" "$VENV" 2> /dev/null | while IFS= read -r file; do
    sed -i "s#$STAGE##g" "$file"
done
if grep -rIl -- "$STAGE" "$VENV" 2> /dev/null | grep -q .; then
    die "sobrou caminho temporário dentro do venv; abortando"
fi
[ -x "$VENV/bin/kallyel" ] || die "o venv não tem o comando kallyel"

echo "==> Montando o pacote"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/doc/kallyel" "$STAGE/DEBIAN"
ln -s "$APP/venv/bin/kallyel" "$STAGE/usr/bin/kallyel"
cp "$ROOT/README.md" "$STAGE/usr/share/doc/kallyel/README.md"
cp -r "$ROOT/docs/." "$STAGE/usr/share/doc/kallyel/"
cat > "$STAGE/usr/share/doc/kallyel/copyright" << 'EOF'
Kallyel: análise de logs para detecção de ataques web

Licença: ainda não definida pelo autor do projeto. Não redistribua este pacote
sem confirmar os termos de uso com o autor.
EOF

SIZE_KB="$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" << EOF
Package: kallyel
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3 (>= $PY_MIN), python3 (<< $PY_NEXT)
Installed-Size: $SIZE_KB
Maintainer: $MAINTAINER
Description: Kallyel: análise de logs para detecção de ataques web
 Ferramenta de linha de comando que lê logs de nginx, Apache, auth.log e
 Laravel, aplica regras mapeadas para MITRE ATT&CK, CWE e OWASP e correlaciona
 os eventos por IP, com linha do tempo e pontuação de risco explicada.
 .
 Roda offline, sem enviar dados para fora. É triagem, não veredito.
EOF

cat > "$STAGE/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    # Compila o bytecode já no destino (o pacote é montado sem .pyc de propósito).
    /opt/kallyel/venv/bin/python -m compileall -q /opt/kallyel/venv/lib > /dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$STAGE/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
case "$1" in
    remove | purge)
        # Remove também o bytecode gerado no postinst, que o dpkg não conhece.
        rm -rf /opt/kallyel
        ;;
esac
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/postrm"
find "$STAGE" -type d -exec chmod 0755 {} +
chmod -R go-w "$STAGE"

mkdir -p "$OUT"
DEB="$OUT/kallyel_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" > /dev/null

echo "==> Pronto: $DEB"
dpkg-deb --info "$DEB" | sed -n '1,/Description:/p'
echo
echo "Instalar:  sudo apt install $DEB"
echo "Testar:    kallyel version"
echo "Remover:   sudo apt remove kallyel"
