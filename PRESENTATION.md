# lab-secured-v3 — enrôlement par CSR

## D'où l'on vient

| | v1 (`lab-secured/`) | v2 (`lab-secured-v2/`) | **v3 (celui-ci)** |
|---|---|---|---|
| Qui crée la clé du device ? | Le serveur d'enrôlement | Le serveur d'enrôlement | **Le device lui-même** |
| Canal d'enrôlement | Topic MQTT partagé | Topic MQTT par device | **HTTPS, POST + GET par empreinte** |
| Config reçue | JSON en clair | JSON signé ECDSA + nonce + expiration | **Certificat signé (CSR) + config MQTT** |
| Ce que le device vérifie | `device_id` | Signature, `device_id`, nonce, expiration | **`device_id` = nom demandé, topics portent l'identité** |
| La clé privée transite-t-elle ? | Oui (le serveur la crée et la remet) | Oui (idem) | **Non — elle naît et reste dans le device** |

La progression est celle-ci : **on déplace la confiance de l'infrastructure vers le device**.

- v1 : le broker fait tout (mTLS + ACL). Le firmware est un participant.
- v2 : on ajoute une signature pour que la config d'enrôlement soit vérifiable. Le device ne s'active que si tout passe.
- v3 : **la clé est générée sur le device**. Le serveur ne signe qu'un CSR. La clé privée ne quitte jamais la RAM du simulateur.

---

## Ce que v3 prouve, en une phrase

Le device **dépose** une clé publique (via un CSR) et **reçoit** un certificat. Il ne **reçoit pas** de clé privée. L'empreinte lue au moniteur est la preuve que c'est bien *cette* clé, et non une autre, que le serveur a approuvée.

---

## Le flux, étape par étape

### Étape 1 — Le device génère sa clé et son CSR

**v1 / v2** : vous exécutez `enroll.py enroll sensor-001`. Le serveur crée la paire de clés, signe le certificat, écrit l'ACL. Le device reçoit un certificat préfabriqué.

**v3** : le sketch (ou `device_sim.py`) génère une clé P-256 **en RAM**, construit un CSR, et affiche :

```
═══════════════════════════════════════
  DEMANDE D'ENRÔLEMENT
  nom       : sensor-lea
  empreinte : a3f2c8e1d94b7f60…
  clé P-256 en RAM, non affichée
  Lisez l'empreinte à l'administrateur.
═══════════════════════════════════════
```

L'empreinte est le SHA-256 du SubjectPublicKeyInfo. Elle identifie la clé publique sans l'exposer. Un reset du simulateur fabrique une nouvelle clé : l'empreinte précédente ne vaut plus.

> Le CN écrit dans le CSR (`CN=pending`) est **ignoré** par le serveur. Le serveur impose le nom approuvé comme CN du certificat. Le device ne peut pas s'auto-attribuer un nom.

### Étape 2 — La demande part en HTTPS

**v1** : le device publie sur `m2dfs-secured/enroll/request` (topic partagé, JSON en clair, broker public).

**v2** : le device publie sur `enroll/<id>/request` (topic par device, JSON en clair sur broker local, nonce + timestamp).

**v3** : le device envoie un `POST /v1/enroll` en HTTPS (certificat de serveur signé par la CA du labo, CA épinglée dans `ca_pin.h`). Le corps est :

```json
{ "name": "sensor-lea", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n…" }
```

Le serveur répond `202 { "status": "pending", "fingerprint": "a3f2c8e1…" }`. Il n'envoie rien d'autre. Le device passe en état `AWAITING` et sonde toutes les 3 s.

> Le canal d'enrôlement n'est **pas** le broker MQTT. C'est un service HTTPS séparé (port 8443). Le broker (port 8884) ne porte aucun topic d'enrôlement.

### Étape 3 — La décision humaine

**v1** : l'admin approuve sur la page admin, la config est publiée sur MQTT.

**v2** : l'admin approuve, le service signe la config (ECDSA P-256, nonce, expiration 5 min), publication sur `enroll/<id>/response`.

**v3** : l'admin **compare l'empreinte du moniteur série** avec celle affichée sur la page admin. C'est le seul geste. Il clique Approuver. Le serveur :

1. signe le CSR → certificat court (CN = nom approuvé, 8 h par défaut, 48 h max)
2. enregistre la demande `approved` et écrit l'ACL (`devices/<nom>/*`)
3. recharge l'ACL : SIGHUP au processus Mosquitto dans le conteneur ; `docker restart` seulement si le port 8884 ne répond plus

> Deux demandes avec le même nom ne coexistent pas. Une demande en attente expire au bout de 30 min. `app` et `admin` sont réservés.

### Étape 4 — Le device reçoit son paquet

**v1** : le device reçoit une config JSON en clair sur MQTT. Il vérifie `device_id`.

**v2** : le device reçoit une config signée. Il vérifie : signature → `device_id` → nonce → expiration → `approved`. S'il manque un contrôle, état `REJECTED`, pas d'activation.

**v3** : le device sonde `GET /v1/enroll/<empreinte>`. Quand l'état est `approved`, le serveur renvoie :

```json
{
  "status": "approved",
  "device_id": "sensor-lea",
  "expires_at": "2026-11-13T18:00:00Z",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
  "ca_pem": "-----BEGIN CERTIFICATE-----\n…",
  "mqtt": {
    "host": "play.why.noematic.eu",
    "port": 8884,
    "topics": {
      "telemetry": "devices/sensor-lea/telemetry",
      "status":    "devices/sensor-lea/status",
      "cmd":       "devices/sensor-lea/cmd"
    }
  }
}
```

Le device vérifie :
- `device_id` est égal au nom qu'il a demandé (`DEVICE_NAME`). Sinon : `REJECTED`.
- Chaque topic contient l'identité. Sinon : `REJECTED`.
- Le port est valide.

Puis il charge les PEM en RAM et se connecte.

> **La clé privée n'est jamais dans cette réponse.** Le script `flux.py` vérifie explicitement que le mot `PRIVATE` n'apparaît pas dans le JSON reçu.

### Étape 5 — Le broker impose l'ACL

C'est identique dans les trois versions, et c'est le principe cardinal :

- mTLS : le broker exige un certificat client. Le CN est l'identité.
- ACL deny-by-default : le device écrit `devices/<nom>/telemetry` et `/status`, lit `devices/<nom>/cmd`.
- L'identité `app` lit `devices/#` et écrit `devices/+/cmd`.
- `revoke` retire l'ACL et la fait relire (SIGHUP, redémarrage seulement si le broker ne répond plus). Le certificat peut encore être valide, la publication est refusée. Un nouveau certificat de broker (`gen-server.sh`) suit un autre chemin : `restart-broker.sh` redémarre le processus s'il tourne déjà, et vérifie l'empreinte du certificat servi.

> La sécurité ne repose pas sur le firmware. Le firmware est un participant. Le broker est l'autorité finale.

---

## Ce que vous voyez en séance

### Moniteur série (device)

| Moment | Ce qui s'affiche |
|---|---|
| Boot | `lab-secured-v3 — enrôlement par CSR` |
| NTP | Date et heure synchronisées |
| Clé | Empreinte + « Lisez l'empreinte à l'administrateur. » |
| En attente | `[enrôlement] en attente de l'empreinte` (toutes les 3 s) |
| Approuvé | `[enrôlement] approuvé, certificat jusqu'à …` |
| Connecté | `CONNECTÉ play.why.noematic.eu:8884`, identité, topics |
| Télémétrie | `[TELEM] 21.5 °C` (toutes les 5 s) |
| LED | `[LED] ON` / `[LED] OFF` |
| Refus | `[enrôlement] REFUSÉ — <raison>` |

### Page admin (`http://play.why.noematic.eu:8444/admin`)

- **Jeton admin** : collé depuis `enroll.py serve` (affiché au lancement, persistant dans `admin.token`).
- **Tableau des demandes** : nom, empreinte, état, expiration.
- **Température** : en direct du device (device → système).
- **LED** : bouton ON/OFF (système → device).

### Terminal (vérification hors Wokwi)

```bash
# Enrôlement + flux complet, sans Wokwi :
python3 scripts/flux.py --name sensor-flux
# → affiche l'empreinte, attend l'accord, vérifie température + LED

# Une seule publication :
python3 scripts/device_sim.py --name sensor-lea

# Écouter :
python3 scripts/sub.py
python3 scripts/cmd-led.py sensor-lea on

# Vérifier le service, le CN, l'ACL, la révocation :
python3 scripts/self_check.py
```

---

## Ce que v3 ne fait pas (et pourquoi c'est acceptable en labo)

| Limite | Conséquence | Pourquoi c'est OK ici |
|---|---|---|
| La clé est en RAM, pas dans un élément sécurisé (eFuse, HSM) | Un sketch modifié peut l'afficher ou l'envoyer | Le labo prouve le **flux**, pas la résistance physique |
| Le nom seul ne prouve rien | Quiconque atteint le service peut déposer un CSR | La décision porte sur l'empreinte lue en séance, pas sur le nom |
| Le certificat dure au plus 48 h | Après expiration, le broker refuse | C'est voulu : pas de certificat pérenne en labo |
| `revoke` retire l'ACL, pas le certificat | Le certificat reste valide sur le device | La publication est refusée par le broker, pas par le device |
| L'horloge NTP doit être fiable | Sans heure, le TLS échoue (vérification de date) | Le sketch synchronise l'heure avant tout échange TLS |

---

## Ce qu'il faut retenir

1. **La clé naît sur le device.** Le serveur signe un CSR, il ne crée pas une identité.
2. **L'empreinte est la preuve.** C'est elle que l'admin compare, pas le nom.
3. **Le broker reste l'autorité.** mTLS + ACL. Le firmware applique, il ne décide pas.
4. **La clé privée ne transite pas.** Ni dans la demande, ni dans la réponse. Le script le vérifie.
5. **Un reset change tout.** Nouvelle clé, nouvelle empreinte, l'ancienne ne vaut plus.
