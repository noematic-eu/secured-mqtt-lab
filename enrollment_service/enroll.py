#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Enrôlement v3 — le device possède la clé, le serveur décide.

Le device envoie un CSR et un nom. L'administrateur approuve l'empreinte
de la clé publique. Le serveur signe alors un certificat dont le CN est
le nom, écrit l'ACL, et remet le certificat avec l'adresse du broker.
La clé privée ne transite pas.

Usage :
  python3 enroll.py pin-ca
  python3 enroll.py serve
  python3 enroll.py list
  python3 enroll.py approve <empreinte>
  python3 enroll.py reject <empreinte>
  python3 enroll.py revoke <device_id>
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LAB_ROOT = Path(__file__).resolve().parent.parent
CERTS = LAB_ROOT / "mosquitto" / "tls" / "certs"
PRIVATE = LAB_ROOT / "mosquitto" / "tls" / "private"
CA_CERT = CERTS / "ca.crt"
CA_KEY = PRIVATE / "ca.key"
ENROLL_CERT = PRIVATE / "enroll.crt"
ENROLL_KEY = PRIVATE / "enroll.key"
APP_CERT = PRIVATE / "app.crt"
APP_KEY = PRIVATE / "app.key"
ACL_FILE = LAB_ROOT / "mosquitto" / "acl"
STATE_FILE = Path(__file__).resolve().parent / "state_store.json"
LOCK_FILE = Path(__file__).resolve().parent / "state_store.lock"
TOKEN_FILE = Path(__file__).resolve().parent / "admin.token"
CA_PIN = LAB_ROOT / "wokwi" / "ca_pin.h"

# 8884 sur l'hôte : le conteneur v2 écoute déjà sur 8883.
# Le sketch ne connaît pas ce port. Il le reçoit après approbation.
# Le nom public est celui que Wokwi et les scripts client joignent.
# self_check et le pont admin parlent à 127.0.0.1, à côté du broker.
MQTT_HOST_DEVICE = os.environ.get("M2DFS_MQTT_HOST", "play.why.noematic.eu")
MQTT_PORT = 8884
ENROLL_PORT = 8443
ADMIN_PORT = 8444
CONTAINER = "m2dfs-secured-v3"

CERT_HOURS_DEFAULT = 8
CERT_HOURS_MAX = 48
PENDING_MINUTES = 30
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
RESERVED_NAMES = {"app", "admin"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def public_fingerprint(public_key) -> str:
    """SHA-256 du SubjectPublicKeyInfo DER, hexadécimal minuscule."""
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"requests": {}}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n")


@contextmanager
def locked():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "a+") as handle:
        import fcntl

        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def validate_name(name: str) -> str | None:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        return "nom invalide : une lettre minuscule, puis lettres, chiffres ou tirets (32 caractères au plus)"
    if name in RESERVED_NAMES:
        return "nom réservé"
    return None


def pending_fresh(record: dict, moment: datetime) -> bool:
    if record.get("status") != "pending":
        return False
    requested = datetime.fromisoformat(record["requested_at"])
    return moment - requested < timedelta(minutes=PENDING_MINUTES)


def find_name(state: dict, name: str, moment: datetime) -> dict | None:
    for record in state["requests"].values():
        if record.get("name") != name:
            continue
        if record.get("status") == "approved":
            return record
        if pending_fresh(record, moment):
            return record
    return None


def resolve_fingerprint(state: dict, prefix: str) -> str:
    prefix = prefix.strip().lower()
    if len(prefix) < 8:
        raise ValueError("empreinte trop courte (8 caractères hexadécimaux au minimum)")
    hits = [fp for fp in state["requests"] if fp.startswith(prefix)]
    if not hits:
        raise ValueError("aucune demande avec cette empreinte")
    if len(hits) > 1:
        raise ValueError("plusieurs demandes correspondent — donnez une empreinte plus longue")
    return hits[0]


def load_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    if not isinstance(csr_pem, str) or len(csr_pem) > 12000:
        raise ValueError("CSR absent ou trop volumineux")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("CSR illisible") from exc
    if not csr.is_signature_valid:
        raise ValueError("signature de CSR invalide")
    public_key = csr.public_key()
    if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise ValueError("clé publique ni RSA ni ECDSA")
    return csr


def public_view(record: dict) -> dict:
    """Vue admin : pas de CSR, pas de certificat."""
    return {
        "name": record.get("name"),
        "fingerprint": record.get("fingerprint"),
        "status": record.get("status"),
        "device_id": record.get("device_id"),
        "requested_at": record.get("requested_at"),
        "expires_at": record.get("expires_at"),
    }


def mqtt_bundle(record: dict) -> dict:
    device_id = record["device_id"]
    return {
        "status": "approved",
        "device_id": device_id,
        "expires_at": record["expires_at"],
        "cert_pem": record["cert_pem"],
        "ca_pem": CA_CERT.read_text(),
        "mqtt": {
            "host": MQTT_HOST_DEVICE,
            "port": MQTT_PORT,
            "topics": {
                "telemetry": f"devices/{device_id}/telemetry",
                "status": f"devices/{device_id}/status",
                "cmd": f"devices/{device_id}/cmd",
            },
        },
    }


def submit_request(name: str, csr_pem: str) -> tuple[int, dict]:
    error = validate_name(name)
    if error:
        return 400, {"error": error}
    try:
        csr = load_csr(csr_pem)
    except ValueError as exc:
        return 400, {"error": str(exc)}

    fingerprint = public_fingerprint(csr.public_key())
    moment = now()
    with locked():
        state = load_state()
        requests = state["requests"]
        if len(requests) > 200 and fingerprint not in requests:
            return 429, {"error": "trop de demandes en mémoire"}

        existing_name = find_name(state, name, moment)
        current = requests.get(fingerprint)
        if current and current.get("name") != name:
            return 409, {"error": "cette clé a déjà été présentée sous un autre nom"}
        if existing_name and existing_name.get("fingerprint") != fingerprint:
            return 409, {"error": "ce nom est déjà en attente ou déjà enrôlé"}

        if current and current.get("status") == "approved":
            return 200, mqtt_bundle(current)
        if current and current.get("status") == "rejected":
            return 200, {"status": "rejected", "fingerprint": fingerprint, "name": name}

        requests[fingerprint] = {
            "name": name,
            "fingerprint": fingerprint,
            "csr_pem": csr_pem if csr_pem.endswith("\n") else csr_pem + "\n",
            "status": "pending",
            "requested_at": iso(moment),
            "device_id": None,
            "cert_pem": None,
            "expires_at": None,
        }
        save_state(state)

    return 202, {"status": "pending", "fingerprint": fingerprint, "name": name}


def get_status(fingerprint: str) -> tuple[int, dict]:
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint or ""):
        return 400, {"error": "empreinte invalide"}
    with locked():
        record = load_state()["requests"].get(fingerprint)
        if record is None:
            return 404, {"error": "demande inconnue"}
        snapshot = dict(record)
    if snapshot["status"] == "approved":
        return 200, mqtt_bundle(snapshot)
    return 200, {
        "status": snapshot["status"],
        "fingerprint": fingerprint,
        "name": snapshot["name"],
    }


def key_usage_for(public_key) -> x509.KeyUsage:
    encipher = isinstance(public_key, rsa.RSAPublicKey)
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=encipher,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def sign_csr(csr: x509.CertificateSigningRequest, device_id: str, hours: int) -> tuple[str, str]:
    ca_cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    ca_key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
    moment = now()
    public_key = csr.public_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - timedelta(minutes=5))
        .not_valid_after(moment + timedelta(hours=hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage_for(public_key), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_key.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii"), iso(cert.not_valid_after_utc)


def render_acl(state: dict) -> str:
    lines = [
        "# lab-secured-v3 — ACL Mosquitto.",
        "# Deny-by-default. Réécrit par enroll.py. Ne pas renommer ce fichier (montage Docker).",
        "",
        "# ── App : observation et commandes ────────────────────────────────",
        "user app",
        "topic read  devices/#",
        "topic write devices/+/cmd",
        "",
    ]
    for record in state["requests"].values():
        if record.get("status") != "approved":
            continue
        device_id = record["device_id"]
        lines.extend([
            f"# ── Device : {device_id}",
            f"user {device_id}",
            f"topic write devices/{device_id}/telemetry",
            f"topic write devices/{device_id}/status",
            f"topic read  devices/{device_id}/cmd",
            "",
        ])
    return "\n".join(lines)


def write_acl(state: dict) -> None:
    """Écriture en place (même inode) : le bind mount Docker suit l'inode, pas le chemin.

    On écrit directement dans le fichier pour que le conteneur voie le changement.
    Le SIGHUP est envoyé après coup, une fois le fichier complet.
    """
    ACL_FILE.write_text(render_acl(state))
    # Flush explicite pour forcer la propagation via le partage de fichiers.
    with open(ACL_FILE, "rb") as f:
        os.fsync(f.fileno())


def wait_mqtt_tls(timeout: float = 20.0) -> bool:
    """Attend que le broker présente un certificat vérifiable par la CA."""
    context = ssl.create_default_context(cafile=str(CA_CERT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", MQTT_PORT), 1) as sock:
                with context.wrap_socket(sock, server_hostname="localhost"):
                    return True
        except OSError:
            time.sleep(0.25)
    return False


def restart_broker_verified() -> tuple[bool, str]:
    """Redémarre le conteneur et vérifie que le broker répond en TLS.

    À utiliser après un changement de certificats (gen-ca.sh, gen-server.sh)
    ou comme fallback quand le SIGHUP ne suffit pas.
    """
    result = subprocess.run(
        ["docker", "restart", CONTAINER],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return False, detail or "docker restart a échoué"
    if not wait_mqtt_tls():
        return False, f"le broker ne répond pas sur 127.0.0.1:{MQTT_PORT} après restart"
    return True, ""


def reload_broker() -> tuple[bool, str]:
    """Recharge l'ACL via SIGHUP envoyé à mosquitto (PID 1) dans le conteneur.

    docker exec ne marque pas le conteneur comme arrêté manuellement :
    la politique restart: unless-stopped reste active.

    Si le port 8884 ne répond plus après le SIGHUP, on enchaîne
    systématiquement sur docker restart — que State.Running soit vrai ou faux.
    """
    # Délai pour laisser le partage de fichiers propager l'écriture de l'ACL.
    time.sleep(0.3)
    result = subprocess.run(
        ["docker", "exec", CONTAINER, "kill", "-HUP", "1"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # docker exec a échoué (conteneur arrêté, mosquitto absent, …) → restart direct.
        return restart_broker_verified()

    # Le SIGHUP a été délivré. Vérifie que le broker répond encore en TLS.
    if wait_mqtt_tls(timeout=5.0):
        return True, ""

    # Le broker ne répond plus (processus sorti, listener tombé, …).
    # Restart systématique, sans condition sur State.Running.
    return restart_broker_verified()


def approve(prefix: str, hours: int = CERT_HOURS_DEFAULT) -> tuple[int, dict]:
    if hours < 1 or hours > CERT_HOURS_MAX:
        return 400, {"error": f"durée entre 1 et {CERT_HOURS_MAX} heures"}
    if not CA_CERT.exists() or not CA_KEY.exists():
        return 500, {"error": "CA absente — lancer mosquitto/tls/gen-ca.sh"}
    with locked():
        state = load_state()
        try:
            fingerprint = resolve_fingerprint(state, prefix)
        except ValueError as exc:
            return 404, {"error": str(exc)}
        record = state["requests"][fingerprint]
        if record["status"] == "rejected":
            return 409, {"error": "demande déjà refusée"}
        if record["status"] != "approved":
            csr = load_csr(record["csr_pem"])
            # Le CN du CSR est ignoré. Le nom approuvé devient l'identité MQTT.
            cert_pem, expires_at = sign_csr(csr, record["name"], hours)
            record["status"] = "approved"
            record["device_id"] = record["name"]
            record["cert_pem"] = cert_pem
            record["expires_at"] = expires_at
            record["approved_at"] = iso(now())
            save_state(state)
            write_acl(state)
        device_id = record["device_id"]
        fingerprint_out = fingerprint
    ok, detail = reload_broker()
    body = {"status": "approved", "device_id": device_id, "fingerprint": fingerprint_out}
    if not ok:
        body["broker"] = f"ACL écrite, broker non rechargé : {detail}"
    return 200, body


def reject(prefix: str) -> tuple[int, dict]:
    with locked():
        state = load_state()
        try:
            fingerprint = resolve_fingerprint(state, prefix)
        except ValueError as exc:
            return 404, {"error": str(exc)}
        record = state["requests"][fingerprint]
        if record["status"] == "approved":
            return 409, {"error": "déjà approuvé — utiliser revoke"}
        record["status"] = "rejected"
        save_state(state)
    return 200, {"status": "rejected", "fingerprint": fingerprint}


def revoke(device_id: str) -> tuple[int, dict]:
    with locked():
        state = load_state()
        found = None
        for record in state["requests"].values():
            if record.get("device_id") == device_id and record.get("status") == "approved":
                found = record
                break
        if found is None:
            return 404, {"error": "aucun device approuvé avec cet identifiant"}
        found["status"] = "revoked"
        save_state(state)
        write_acl(state)
    ok, detail = reload_broker()
    body = {"status": "revoked", "device_id": device_id}
    if not ok:
        body["broker"] = f"ACL écrite, broker non rechargé : {detail}"
    return 200, body


def list_requests() -> list[dict]:
    with locked():
        state = load_state()
    return [public_view(record) for record in state["requests"].values()]


_CACHED_TOKEN: str | None = None


def ensure_token() -> str:
    """Jeton du processus. Un fichier vide ou réécrit ne le remplace pas en cours de route."""
    global _CACHED_TOKEN
    if _CACHED_TOKEN:
        return _CACHED_TOKEN
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if token:
            _CACHED_TOKEN = token
            return _CACHED_TOKEN
    import secrets

    token = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(token + "\n")
    os.chmod(TOKEN_FILE, 0o600)
    _CACHED_TOKEN = token
    return _CACHED_TOKEN


def token_matches(given: str) -> bool:
    expected = ensure_token()
    if not isinstance(given, str) or len(given) != len(expected):
        return False
    return hmac.compare_digest(given, expected)


def pin_ca() -> Path:
    if not CA_CERT.exists():
        raise SystemExit("CA absente. Lancer : mosquitto/tls/gen-ca.sh")
    pem = CA_CERT.read_text().strip() + "\n"
    if ")pem" in pem:
        raise SystemExit("le certificat contient la séquence )pem — pin-ca ne peut pas l'embarquer")
    CA_PIN.write_text(
        "#pragma once\n"
        "// Certificat public de la CA du labo. Généré par enroll.py pin-ca.\n"
        "// Il authentifie le serveur d'enrôlement. Ce n'est pas la clé d'un device.\n"
        "static const char ENROLL_CA_PEM[] =\n"
        'R"pem(' + pem + ')pem";\n'
    )
    return CA_PIN


def require_ok(status: int, body: dict) -> dict:
    if status >= 400:
        print(body.get("error", body), file=sys.stderr)
        raise SystemExit(1)
    return body


def cmd_list(_args: argparse.Namespace) -> None:
    rows = list_requests()
    if not rows:
        print("Aucune demande.")
        return
    for row in rows:
        print(
            f"{row['status']:10} {row['name']:16} {row['fingerprint']}  "
            f"expire={row.get('expires_at') or '-'}"
        )


def cmd_approve(args: argparse.Namespace) -> None:
    status, body = approve(args.fingerprint, args.hours)
    body = require_ok(status, body)
    print(f"✓ {body['device_id']} approuvé ({body['fingerprint'][:16]}…)")
    if "broker" in body:
        print(f"  ⚠ {body['broker']}")
    else:
        print(f"  Broker rechargé. MQTTS 127.0.0.1:{MQTT_PORT}")


def cmd_reject(args: argparse.Namespace) -> None:
    status, body = reject(args.fingerprint)
    body = require_ok(status, body)
    print(f"✓ demande refusée ({body['fingerprint'][:16]}…)")


def cmd_revoke(args: argparse.Namespace) -> None:
    status, body = revoke(args.device_id)
    body = require_ok(status, body)
    print(f"✓ {body['device_id']} révoqué (ACL retirée).")
    if "broker" in body:
        print(f"  ⚠ {body['broker']}")


def cmd_pin(_args: argparse.Namespace) -> None:
    path = pin_ca()
    print(f"✓ CA publique écrite dans {path}")


def cmd_serve(_args: argparse.Namespace) -> None:
    import server

    server.serve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enrôlement v3 — CSR, accord sur l'empreinte, certificat court.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="HTTPS d'enrôlement + page admin locale").set_defaults(func=cmd_serve)
    sub.add_parser("list", help="Demandes et devices").set_defaults(func=cmd_list)
    sub.add_parser("pin-ca", help="Écrit wokwi/ca_pin.h (certificat public)").set_defaults(func=cmd_pin)
    approve_cmd = sub.add_parser("approve", help="Signe le CSR et ouvre l'ACL")
    approve_cmd.add_argument("fingerprint")
    approve_cmd.add_argument("--hours", type=int, default=CERT_HOURS_DEFAULT)
    approve_cmd.set_defaults(func=cmd_approve)
    reject_cmd = sub.add_parser("reject", help="Refuse une demande en attente")
    reject_cmd.add_argument("fingerprint")
    reject_cmd.set_defaults(func=cmd_reject)
    revoke_cmd = sub.add_parser("revoke", help="Retire l'ACL d'un device approuvé")
    revoke_cmd.add_argument("device_id")
    revoke_cmd.set_defaults(func=cmd_revoke)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
