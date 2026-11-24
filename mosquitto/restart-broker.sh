#!/bin/sh
# Redémarre le broker Mosquitto et vérifie que le certificat présenté
# correspond à mosquitto/tls/certs/server.crt.
# Au premier lancement le conteneur n'existe pas encore : on sort 0
# pour que gen-server.sh puisse précéder `docker compose up -d`.
set -e

CONTAINER="${M2DFS_CONTAINER:-m2dfs-secured-v3}"
HOST="${M2DFS_BROKER_HOST:-127.0.0.1}"
PORT="${M2DFS_BROKER_PORT:-8884}"
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
CERT_FILE="${M2DFS_SERVER_CERT:-$BASE/tls/certs/server.crt}"

if [ ! -f "$CERT_FILE" ]; then
  echo "→ $CERT_FILE absent, restart reporté"
  exit 0
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "→ conteneur $CONTAINER absent, restart reporté (docker compose up -d)"
  exit 0
fi

echo "→ docker restart $CONTAINER"
docker restart "$CONTAINER"

# Attend que le broker réponde en TLS.
deadline=$((SECONDS + 20))
while [ "$SECONDS" -lt "$deadline" ]; do
  if echo | openssl s_client -connect "${HOST}:${PORT}" -servername localhost 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

# Compare l'empreinte du certificat servi à celle du fichier sur disque.
SERVED=$(echo | openssl s_client -connect "${HOST}:${PORT}" -servername localhost 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
DISK=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_FILE" 2>/dev/null) || true

if [ -z "$SERVED" ]; then
  echo "✗ Le broker ne répond pas sur ${HOST}:${PORT}" >&2
  exit 1
fi

if [ "$SERVED" != "$DISK" ]; then
  echo "✗ Certificat servi ≠ certificat sur disque" >&2
  echo "  servi : $SERVED" >&2
  echo "  disque: $DISK" >&2
  exit 1
fi

echo "✓ Broker redémarré, certificat vérifié : $SERVED"
