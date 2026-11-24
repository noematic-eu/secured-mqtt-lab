# Provisioning v3

Le broker est l'autorité sur les publications. Le service d'enrôlement est l'autorité sur la délivrance du certificat. Le firmware applique la configuration reçue. Il ne s'octroie pas de droits.

## Flux

```
ESP32 (Wokwi)                         Service d'enrôlement              Mosquitto :8884
      │                                        │                              │
      │  génère P-256, affiche l'empreinte     │                              │
      │── POST /v1/enroll  {nom, CSR} ────────>│  mémorise, état pending      │
      │<──────── 202 {empreinte} ──────────────│                              │
      │                                        │                              │
      │            administrateur compare l'empreinte du moniteur             │
      │                                        │── signe le CSR, CN = nom     │
      │                                        │── écrit l'ACL, SIGHUP ──────>│
      │── GET /v1/enroll/<empreinte> ─────────>│                              │
      │<── cert, CA, hôte, port, topics ───────│                              │
      │                                        │                              │
      │  charge les PEM en RAM                 │                              │
      │──────────── MQTTS mTLS, CN = nom ────────────────────────────────────>│
      │                                        │                     ACL devices/<nom>/*
```

Le canal d'enrôlement est HTTPS, certificat de serveur signé par la CA du labo, CA épinglée dans `wokwi/ca_pin.h`. Ce n'est pas le broker public.

L'hôte public est `play.why.noematic.eu`. L'enrôlement écoute sur le port 8443, la page admin sur 8444, le broker sur 8884. Les scripts client et le sketch joignent ce nom. `self_check.py` reste sur `127.0.0.1`.

## Règles de délivrance

- Le nom matche `^[a-z][a-z0-9-]{0,31}$`. `app` et `admin` sont réservés.
- La signature du CSR est vérifiée. La clé publique est RSA ou ECDSA.
- Le sujet du CSR est ignoré. Le CN du certificat émis est le nom approuvé.
- Une demande en attente expire au bout de 30 minutes. Un nom déjà approuvé reste pris jusqu'à `revoke`.
- La même empreinte peut redemander son paquet : la réponse contient le certificat, pas la clé privée.
- Durée du certificat : 1 à 48 heures. Le broker refuse un certificat expiré.

## ACL

Deny-by-default. Un device approuvé écrit `devices/<id>/telemetry` et `devices/<id>/status`, et lit `devices/<id>/cmd`. L'identité `app` lit `devices/#` et écrit `devices/+/cmd`. Il n'y a pas de topic d'enrôlement sur ce broker.

L'ACL est réécrite en place (même inode — le bind mount Docker suit l'inode, pas le chemin). Il ne faut pas renommer ce fichier : le conteneur garderait l'ancien inode. Après l'écriture complète, `enroll.py` envoie SIGHUP au processus 1 **dans** le conteneur (`docker exec m2dfs-secured-v3 kill -HUP 1`). Ce n'est pas `docker kill` : un `docker kill` compte comme un arrêt manuel et `restart: unless-stopped` ne relève plus le conteneur. Mosquitto relit l'ACL sans couper les sessions déjà établies. Si le port 8884 ne répond plus ensuite, `docker restart` part dans tous les cas, que le conteneur soit encore « running » ou non.

## Certificats du broker

`ca.crt`, `server.crt` et `server.key` sont chargés au démarrage du processus. Un SIGHUP ne les recharge pas. `gen-server.sh` appelle `mosquitto/restart-broker.sh` après une génération réelle (pas quand `server.crt` existe déjà et que `FORCE` n'est pas `1`). Si le conteneur `m2dfs-secured-v3` n'existe pas, le script sort 0. Sinon il fait `docker restart`, puis compare l'empreinte SHA-256 du certificat présenté sur `127.0.0.1:8884` à `mosquitto/tls/certs/server.crt`. `gen-ca.sh` n'envoie pas ce restart : relancer le broker avant d'avoir régénéré `server.crt` le ferait démarrer avec un certificat signé par l'ancienne CA.

`gen-enroll.sh` ne touche pas au broker. Le certificat d'enrôlement est lu par `enroll.py serve` au lancement : après `FORCE=1 ./gen-enroll.sh`, relancer `serve`. Après `FORCE=1 ./gen-ca.sh`, relancer aussi `python3 enroll.py pin-ca`, puis `gen-server.sh` et `gen-enroll.sh`, sinon le broker, le service HTTPS et `ca_pin.h` ne portent plus la même CA.

L'image est épinglée sur `eclipse-mosquitto:2.0.20`. `server.key` est en mode 644 : le processus tourne avec l'utilisateur `mosquitto` de l'image et le volume est en lecture seule, une clé 600 appartenant à l'utilisateur hôte lui est illisible. `ca.key`, `enroll.key` et `app.key` restent en 600 dans `tls/private/`, qui n'est pas monté.

## Ce qui reste ouvert

- Le nom seul ne prouve rien. La décision porte sur l'empreinte lue en séance.
- Le service d'enrôlement accepte un CSR de quiconque l'atteint. Sans approbation, il ne délivre pas de certificat.
- Après délivrance, la clé est dans le simulateur. Le moniteur ne l'affiche pas. Un sketch modifié peut l'afficher.
- `revoke` retire l'ACL. Le certificat reste valide jusqu'à son expiration. Sans ACL, la publication est refusée.
- L'horloge de l'ESP32 doit être à l'heure pour accepter le certificat du serveur d'enrôlement et celui du broker.
