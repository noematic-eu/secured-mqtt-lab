#!/bin/sh
# Certificat présenté par Mosquitto aux devices.
set -e
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
[ -f "$BASE/certs/ca.crt" ] || { echo "Lancer d'abord : ./gen-ca.sh"; exit 1; }

if [ -f "$BASE/certs/server.crt" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "server.crt existe déjà. FORCE=1 $0 pour le régénérer."
  exit 0
fi

PUBLIC_HOST="${PUBLIC_HOST:-play.why.noematic.eu}"

openssl req -newkey rsa:2048 -nodes \
  -keyout "$BASE/certs/server.key" -out "$BASE/certs/server.csr" \
  -subj "/CN=${PUBLIC_HOST}/O=m2dfs-lab"

printf '%s\n' \
  "basicConstraints=CA:FALSE" \
  "keyUsage=digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:${PUBLIC_HOST},DNS:why.noematic.eu,DNS:play.why.noematic.eu,DNS:localhost,IP:127.0.0.1" \
  "authorityKeyIdentifier=keyid,issuer" \
  "subjectKeyIdentifier=hash" > "$BASE/certs/server.ext"

openssl x509 -req -in "$BASE/certs/server.csr" \
  -CA "$BASE/certs/ca.crt" -CAkey "$BASE/private/ca.key" -CAcreateserial \
  -out "$BASE/certs/server.crt" -days 365 \
  -extfile "$BASE/certs/server.ext"

rm -f "$BASE/certs/server.csr" "$BASE/certs/server.ext" "$BASE/certs/ca.srl"
# 644 et non 600 : le broker tourne sous l'utilisateur `mosquitto` du conteneur,
# qui ne peut pas lire une clé 600 appartenant à l'utilisateur hôte via le
# bind mount en lecture seule. Les autres clés (tls/private/) restent en 600.
chmod 644 "$BASE/certs/server.key"
echo "✓ Certificat broker : $BASE/certs/server.crt"

# Le broker charge les certificats au démarrage. Un SIGHUP ne suffit pas.
"$BASE/../restart-broker.sh"
