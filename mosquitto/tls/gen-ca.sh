#!/bin/sh
# CA du labo. La clé privée reste dans tls/private/ et n'est pas montée dans Mosquitto.
set -e
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -p "$BASE/certs" "$BASE/private"

if [ -f "$BASE/certs/ca.crt" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "ca.crt existe déjà. FORCE=1 $0 pour la régénérer."
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout "$BASE/private/ca.key" -out "$BASE/certs/ca.crt" \
  -subj "/CN=m2dfs-secured-v3-lab-ca" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -addext subjectKeyIdentifier=hash

chmod 600 "$BASE/private/ca.key"
echo "✓ CA : $BASE/certs/ca.crt"
echo "  Clé privée : $BASE/private/ca.key"

# ca.crt est relu au prochain démarrage du processus, avec server.crt.
# C'est gen-server.sh qui appelle restart-broker.sh : redémarrer ici,
# avant le certificat serveur signé par cette CA, ferait sortir Mosquitto.
