# lab-secured-v3 — enrôlement par CSR

Le sketch Wokwi est public. Il contient un nom et l'adresse du service d'enrôlement. La clé privée naît dans le simulateur, le serveur signe le CSR après avoir vu l'empreinte, puis il remet le certificat et la configuration MQTT. Le broker impose l'ACL.

Le lab v2 reste à côté, sur le port 8883. Celui-ci écoute en MQTTS sur **8884**.

## Ce que le device prouve

| Étape | Qui | Quoi |
|---|---|---|
| Étiquette | Sketch | `DEVICE_NAME`, par exemple `sensor-lea` |
| Clé | Device | P-256, générée en RAM, jamais écrite dans le sketch |
| Demande | Device → HTTPS | Nom + CSR. Le CN du CSR est ignoré |
| Décision | Administrateur | Compare l'empreinte affichée au moniteur série |
| Identité | Serveur | Certificat court, CN = nom approuvé |
| Accès | Broker | mTLS, ACL `devices/<nom>/*` |

L'empreinte est le SHA-256 du SubjectPublicKeyInfo, en hexadécimal minuscule. Deux demandes avec le même nom ne coexistent pas. Un reset du simulateur produit une nouvelle clé : l'empreinte précédente ne vaut plus.

## Lancer

Depuis `lab-secured-v3`, avec un interpréteur qui a `cryptography` et `paho-mqtt` (`scripts/requirements.txt`) :

```bash
cd mosquitto/tls
./gen-ca.sh && ./gen-server.sh && ./gen-enroll.sh && ./gen-app.sh
cd ../../enrollment_service
python3 enroll.py pin-ca
cd ../mosquitto
docker compose up -d
cd ../enrollment_service
python3 enroll.py serve
```

`gen-server.sh` appelle `restart-broker.sh` quand il régénère le certificat. Si le conteneur n'existe pas encore, le script sort 0 et `docker compose up -d` charge les PEM au premier démarrage. S'il tourne déjà, il est redémarré et l'empreinte SHA-256 servie sur `127.0.0.1:8884` est comparée à `mosquitto/tls/certs/server.crt`. `gen-ca.sh` n'appelle pas ce restart : la nouvelle CA et le certificat serveur doivent être écrits avant de relancer le processus.

`serve` affiche le jeton admin. Collez-le et cliquez sur Connexion : la page réutilise celui-là. Il ne va pas dans le sketch. Un redémarrage de `serve` reprend le même fichier `admin.token`.

- Enrôlement device : `https://play.why.noematic.eu:8443/v1/enroll` (écoute sur toutes les interfaces)
- Page admin : [http://play.why.noematic.eu:8444/admin](http://play.why.noematic.eu:8444/admin) (HTTP, le jeton est le verrou)

Le sketch joint `play.why.noematic.eu`. Après l'accord, le broker annoncé est `play.why.noematic.eu:8884`. Ouvrir ces deux ports. Dans le sketch, réglez `DEVICE_NAME`, lancez la simulation, lisez l'empreinte, approuvez-la. La page admin affiche la température publiée par le device et envoie la commande LED vers lui. Le certificat utilisé pour ce sens-là est `app`.

Avant Wokwi, depuis cette machine, vers `play.why.noematic.eu` :

```bash
python3 scripts/flux.py --name sensor-flux
```

Le script affiche l'empreinte. Après l'accord sur la page admin, il vérifie la température (device → système) puis la LED allumée et éteinte (système → device), sur l'hôte et le port reçus.

`scripts/device_sim.py` s'arrête après une publication. `scripts/sub.py` et `scripts/cmd-led.py` parlent au même broker. `scripts/self_check.py` reste local : il efface l'état d'enrôlement, régénère le matériel seulement s'il manque, puis fait `docker compose up -d`.

## Wokwi

Le fichier de code s'appelle `sketch.ino`. Wokwi le compile en C++. Un onglet `main.c` est compilé en C : les en-têtes Arduino (`class Print`) sont alors refusés. Sur wokwi.com, partir de [projects/new/esp32](https://wokwi.com/projects/new/esp32), puis remplacer `sketch.ino`, `diagram.json`, et ajouter `libraries.txt` et `ca_pin.h`. Si l'onglet s'appelle déjà `main.c`, le renommer en `sketch.ino`.

1. Le nom TLS du service et du broker est `play.why.noematic.eu`. Après un changement de nom : `FORCE=1 ./gen-server.sh` (redémarre le broker) et `FORCE=1 ./gen-enroll.sh`, puis relancer `enroll.py serve`. `ca_pin.h` ne change pas tant que la CA reste la même. Si la CA est régénérée (`FORCE=1 ./gen-ca.sh`), enchaîner `pin-ca`, `FORCE=1 ./gen-server.sh` et `FORCE=1 ./gen-enroll.sh`.
2. `ca_pin.h` est produit par `pin-ca`. C'est le certificat public de la CA, celui qui authentifie le service d'enrôlement.
3. Le sketch synchronise l'heure (NTP) avant le TLS. Sans heure, l'ESP32 rejette le certificat du serveur.
4. Après l'accord, `WiFiClientSecure` charge en RAM le certificat, la CA et la clé déjà générée, puis se connecte à l'hôte et au port reçus.
5. Le WiFi : le sketch retente l'association avec `Wokwi-GUEST` de lui-même (8 fois) et surveille le lien pendant l'exécution. S'il est encore coupé, il rétablit le lien avant toute opération HTTP ou MQTT. Le labo ne fait que des connexions sortantes : le gateway par défaut de Wokwi suffit, aucun gateway local à lancer. Si le simulateur reste bloqué, le resetter.

La clé reste dans la mémoire du simulateur. Ce labo ne la met pas dans un élément sécurisé. Le certificat dure au plus 48 h (8 h par défaut). `revoke` retire l'ACL et envoie un SIGHUP à Mosquitto. Le conteneur n'est redémarré que si le port 8884 ne répond plus. Le certificat device peut encore être valide : sans ACL, le broker refuse la publication.

## Fichiers

```
lab-secured-v3/
├── enrollment_service/    enroll.py, server.py, live.py, admin.html
├── mosquitto/             compose, conf, restart-broker.sh, scripts de CA
├── scripts/               flux.py, device_sim.py, self_check.py, sub.py, cmd-led.py
└── wokwi/                 sketch public, ca_pin.h généré
```

Deux rechargements distincts :

- **ACL** (`approve`, `revoke`) : écriture en place de `mosquitto/acl`, puis `docker exec m2dfs-secured-v3 kill -HUP 1`. Si le broker ne répond plus en TLS, `docker restart`.
- **Certificats broker** (`gen-server.sh`, seulement quand il régénère) : `mosquitto/restart-broker.sh` fait `docker restart` si le conteneur existe, puis compare l'empreinte SHA-256 du certificat servi à `mosquitto/tls/certs/server.crt`. Sans conteneur, le restart est reporté.

`mosquitto/tls/private/` n'est pas monté. Le conteneur reçoit `mosquitto.conf`, `acl`, `ca.crt`, `server.crt` et `server.key`. `mosquitto/acl` est versionné avec la seule identité `app`. `enroll.py` le réécrit en place. Il n'y a pas de `.gitignore` : ne pas versionner `tls/private/`, `tls/certs/`, `state_store.json`, `admin.token` ni `wokwi/ca_pin.h`.

`server.key` est en 644 (et non 600) : le broker tourne sous l'utilisateur `mosquitto` du conteneur, qui ne pourrait pas lire une clé 600 appartenant à l'utilisateur hôte à travers le bind mount en lecture seule. Les autres clés, dans `tls/private/`, restent en 600.
