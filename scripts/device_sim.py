#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Device de référence : clé P-256 locale, CSR, attente, puis MQTT.

Le CN écrit dans le CSR n'est pas l'identité. Le serveur impose le nom
approuvé comme CN. La clé privée reste dans ce processus.

Usage :
  python3 device_sim.py --name sensor-lea
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "enrollment_service"))
import enroll  # noqa: E402

from mqttutil import connect, new_client, publish  # noqa: E402


def _devices_dir(name: str) -> Path:
    """Dossier local du device : clé privée persistée entre les lancements."""
    return Path(enroll.LAB_ROOT) / "devices" / name


def make_identity(name: str | None = None) -> tuple[object, str, str]:
    """Génère (ou recharge) la clé du device et son CSR.

    Si une clé existe déjà pour ce nom, on la réutilise : même empreinte,
    le serveur reconnaît le device approuvé et renvoie le certificat sans
    nouvelle approbation.
    """
    key_path = _devices_dir(name) / "key.pem" if name else None

    if key_path and key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        if key_path:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            key_path.chmod(0o600)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-username")]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key, csr_pem, enroll.public_fingerprint(key.public_key())


def tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(enroll.CA_CERT))
    return context


def request_json(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=tls_context(), timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = {"error": payload}
        return exc.code, parsed


def enroll_url(path: str) -> str:
    return f"https://{enroll.MQTT_HOST_DEVICE}:{enroll.ENROLL_PORT}{path}"


def key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def wait_decision(fingerprint: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = request_json("GET", enroll_url(f"/v1/enroll/{fingerprint}"))
        if status == 200 and body.get("status") in ("approved", "rejected", "revoked"):
            return body
        time.sleep(1)
    raise SystemExit("pas de décision dans le délai")


def run_mqtt(body: dict, private_key, host: str | None, port: int | None) -> None:
    if "PRIVATE" in json.dumps(body):
        raise SystemExit("la réponse d'enrôlement contient une clé privée")
    device_id = body["device_id"]
    announced = body["mqtt"]
    topics = announced["topics"]
    client = new_client(f"sim-{device_id}", body["cert_pem"], key_pem(private_key))
    connect(client, announced["host"] if host is None else host, announced["port"] if port is None else port)
    try:
        telemetry = topics["telemetry"]
        code = publish(client, telemetry, json.dumps({"device_id": device_id, "temp_c": 21.5}))
        print(f"télémétrie {telemetry} → code {code}")
        forbidden = publish(client, "devices/not-mine/telemetry", "{}")
        print(f"topic interdit → code {forbidden}")
    finally:
        client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simule un device qui demande son enrôlement.")
    parser.add_argument("--name", default="sensor-lea")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--mqtt-host", default=None, help="défaut : l'hôte reçu dans la réponse")
    parser.add_argument("--mqtt-port", type=int, default=None, help="défaut : le port reçu dans la réponse")
    args = parser.parse_args()

    _key, csr_pem, fingerprint = make_identity(args.name)
    status, body = request_json("POST", enroll_url("/v1/enroll"), {"name": args.name, "csr_pem": csr_pem})
    print(f"demande {status} empreinte {fingerprint}")
    if status >= 400:
        print(body.get("error", body), file=sys.stderr)
        raise SystemExit(1)
    if body.get("fingerprint") not in (None, fingerprint) and body.get("status") == "pending":
        raise SystemExit("empreinte serveur différente de la clé locale")
    if body.get("status") == "pending":
        print("En attente. Approuvez cette empreinte, pas seulement le nom.")
        body = wait_decision(fingerprint, args.timeout)
    if body.get("status") != "approved":
        print(f"décision : {body.get('status')}")
        raise SystemExit(1)
    print(f"broker indiqué : {body['mqtt']['host']}:{body['mqtt']['port']}")
    run_mqtt(body, _key, args.mqtt_host, args.mqtt_port)


if __name__ == "__main__":
    main()
