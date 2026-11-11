#!/usr/bin/env bash
# Teste de fumaça do pacote .deb: instala, usa, remove e confere que nada sobrou.
#
# Uso (como root, em Debian/Ubuntu ou, de preferência, em um contêiner descartável):
#   packaging/smoke_test_deb.sh dist/kallyel_0.1.0_amd64.deb
#
# NÃO rode em uma máquina que você não queira alterar: ele instala e remove um pacote.

set -euo pipefail

DEB="${1:?uso: $0 PACOTE.deb}"
[ -f "$DEB" ] || { echo "erro: arquivo não encontrado: $DEB" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "erro: execute como root (o teste instala e remove o pacote)" >&2; exit 2; }

ok() { echo "ok: $*"; }
fail() { echo "FALHOU: $*" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Instalando"
apt-get install -y -qq "$DEB" > /dev/null
[ -x /usr/bin/kallyel ] || fail "/usr/bin/kallyel não existe ou não é executável"
ok "comando instalado em /usr/bin/kallyel"

VERSION_OUT="$(kallyel version)"
grep -q '^kallyel [0-9]' <<< "$VERSION_OUT" || fail "kallyel version"
ok "$VERSION_OUT"

RULES_OUT="$(kallyel rules list)"
RULES="$(grep -c '^KALLYEL-' <<< "$RULES_OUT")"
[ "$RULES" -eq 13 ] || fail "esperava 13 regras embutidas, vieram $RULES (dados do pacote ausentes?)"
ok "13 regras embutidas carregadas do pacote"

echo "==> Analisando um log sintético"
for i in $(seq 0 39); do
    printf '203.0.113.50 - - [01/Jan/2024:12:00:%02d +0000] "GET /x%d HTTP/1.1" 404 162 "-" "Nikto/2.1.6"\n' "$i" "$i"
done > "$TMP/access.log"

# código 1 = achados (esperado aqui); qualquer outro código é falha
status=0
kallyel analyze "$TMP/access.log" --format json --out "$TMP/r.json" 2> /dev/null || status=$?
[ "$status" -eq 1 ] || fail "analyze devia sair com 1 (há achados), saiu com $status"
grep -q 'KALLYEL-WEB-005' "$TMP/r.json" || fail "achado esperado ausente no JSON"
ok "achados detectados (código de saída 1)"

kallyel analyze "$TMP/access.log" --format html --out "$TMP/r.html" 2> /dev/null || [ $? -eq 1 ]
grep -q '<!doctype html>' "$TMP/r.html" || fail "HTML não foi gerado (template ausente no pacote?)"
if grep -qi '<script' "$TMP/r.html"; then fail "o HTML contém <script>"; fi
ok "relatório HTML gerado, sem <script>"

# Captura a saída antes do grep: com "set -o pipefail", um "grep -q" que fecha o pipe cedo
# faria o kallyel receber SIGPIPE e a checagem falharia à toa.
TIMELINE="$(kallyel timeline --ip 203.0.113.50 "$TMP/access.log")"
grep -q 'reconhecimento' <<< "$TIMELINE" || fail "timeline sem a fase de reconhecimento"
ok "linha do tempo"

echo "==> Removendo"
apt-get remove -y -qq kallyel > /dev/null
[ ! -e /usr/bin/kallyel ] || fail "/usr/bin/kallyel sobrou após a remoção"
[ ! -e /opt/kallyel ] || fail "/opt/kallyel sobrou após a remoção"
ok "remoção limpa (nada sobrou em /usr/bin nem /opt/kallyel)"

echo "TUDO OK"
