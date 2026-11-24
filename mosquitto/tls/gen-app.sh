#!/bin/sh
# Identité « app » : l'observateur du labo (sub.py, cmd-led.py).
# Cette clé reste sur la machine. Elle n'entre pas dans le sketch Wokwi.
set -e
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
[ -f "$BASE/certs/ca.crt" ] || { echo "Lancer d'abord : ./gen-ca.sh"; exit 1; }

if [ -f "$BASE/private/app.crt" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "app.crt existe déjà. FORCE=1 $0 pour le régénérer."
  exit 0
fi

openssl req -newkey rsa:2048 -nodes \
  -keyout "$BASE/private/app.key" -out "$BASE/private/app.csr" \
  -subj "/CN=app/O=m2dfs-lab"

printf '%s\n' \
  "basicConstraints=CA:FALSE" \
  "keyUsage=digitalSignature,keyEncipherment" \
  "extendedKeyUsage=clientAuth" \
  "authorityKeyIdentifier=keyid,issuer" \
  "subjectKeyIdentifier=hash" > "$BASE/private/app.ext"

openssl x509 -req -in "$BASE/private/app.csr" \
  -CA "$BASE/certs/ca.crt" -CAkey "$BASE/private/ca.key" -CAcreateserial \
  -out "$BASE/private/app.crt" -days 365 \
  -extfile "$BASE/private/app.ext"

rm -f "$BASE/private/app.csr" "$BASE/private/app.ext" "$BASE/certs/ca.srl"
chmod 600 "$BASE/private/app.key"
echo "✓ Identité app : $BASE/private/app.crt"
