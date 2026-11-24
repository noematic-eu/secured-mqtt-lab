#!/bin/sh
# Certificat du service d'enrôlement HTTPS. Même CA, clé distincte du broker.
set -e
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
[ -f "$BASE/certs/ca.crt" ] || { echo "Lancer d'abord : ./gen-ca.sh"; exit 1; }

if [ -f "$BASE/private/enroll.crt" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "enroll.crt existe déjà. FORCE=1 $0 pour le régénérer."
  exit 0
fi

PUBLIC_HOST="${PUBLIC_HOST:-play.why.noematic.eu}"

openssl req -newkey rsa:2048 -nodes \
  -keyout "$BASE/private/enroll.key" -out "$BASE/private/enroll.csr" \
  -subj "/CN=${PUBLIC_HOST}/O=m2dfs-enroll"

printf '%s\n' \
  "basicConstraints=CA:FALSE" \
  "keyUsage=digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:${PUBLIC_HOST},DNS:why.noematic.eu,DNS:play.why.noematic.eu,DNS:localhost,IP:127.0.0.1" \
  "authorityKeyIdentifier=keyid,issuer" \
  "subjectKeyIdentifier=hash" > "$BASE/private/enroll.ext"

openssl x509 -req -in "$BASE/private/enroll.csr" \
  -CA "$BASE/certs/ca.crt" -CAkey "$BASE/private/ca.key" -CAcreateserial \
  -out "$BASE/private/enroll.crt" -days 365 \
  -extfile "$BASE/private/enroll.ext"

rm -f "$BASE/private/enroll.csr" "$BASE/private/enroll.ext" "$BASE/certs/ca.srl"
chmod 600 "$BASE/private/enroll.key"
echo "✓ Certificat d'enrôlement : $BASE/private/enroll.crt"
