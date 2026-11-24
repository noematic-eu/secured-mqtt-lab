#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Vérifie le service d'enrôlement, le CN imposé, l'ACL et la révocation."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "enrollment_service"))
sys.path.insert(0, str(ROOT / "scripts"))

import enroll  # noqa: E402
import server  # noqa: E402
from device_sim import make_identity, request_json  # noqa: E402
from mqttutil import connect, new_client, publish  # noqa: E402


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("ÉCHEC : " + message)
    print("✓ " + message)


def cert_cn(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def tamper_csr(csr_pem: str) -> str:
    lines = [line for line in csr_pem.splitlines() if line and not line.startswith("-----")]
    body = list("".join(lines))
    body[8] = "A" if body[8] != "A" else "B"
    raw = "".join(body)
    wrapped = "\n".join(raw[i:i + 64] for i in range(0, len(raw), 64))
    return "-----BEGIN CERTIFICATE REQUEST-----\n" + wrapped + "\n-----END CERTIFICATE REQUEST-----\n"


def sketch_has_no_secret() -> None:
    sketch = (ROOT / "wokwi" / "sketch.ino").read_text()
    for forbidden in ("BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY", "8883", "8884", "broker.emqx.io"):
        expect(forbidden not in sketch, f"sketch sans {forbidden}")
    expect(enroll.MQTT_HOST_DEVICE in sketch, "sketch connaît l'hôte d'enrôlement")
    expect('#include "ca_pin.h"' in sketch, "sketch épingle la CA publique")
    expect("devices/" not in sketch, "les topics MQTT viennent de la réponse")


def gen_material() -> None:
    tls = ROOT / "mosquitto" / "tls"
    for script in ("gen-ca.sh", "gen-server.sh", "gen-enroll.sh", "gen-app.sh"):
        subprocess.run(["sh", str(tls / script)], check=True)
    enroll.pin_ca()


def start_broker() -> None:
    subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT / "mosquitto", check=True)
    expect(enroll.wait_mqtt_tls(40), "broker TLS prêt sur 8884")


def mqtt_code(cert_pem: str, key, topic: str) -> int:
    from device_sim import key_pem

    client = new_client("self-check", cert_pem, key_pem(key))
    connect(client, "127.0.0.1")
    try:
        return publish(client, topic, json.dumps({"temp_c": 21.5}))
    finally:
        client.disconnect()


def main() -> None:
    sketch_has_no_secret()
    gen_material()
    # État propre pour les noms de test.
    if enroll.STATE_FILE.exists():
        enroll.STATE_FILE.unlink()
    start_broker()
    server.start_background()
    time.sleep(0.3)
    try:
        with urllib.request.urlopen(f"https://127.0.0.1:{enroll.ENROLL_PORT}/health", context=__import__("ssl").create_default_context(cafile=str(enroll.CA_CERT)), timeout=5) as response:
            expect(response.status == 200, "HTTPS d'enrôlement répond")

        _key, csr_pem, fingerprint = make_identity()
        status, body = request_json("POST", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll", {"name": "app", "csr_pem": csr_pem})
        expect(status == 400, "le nom app est refusé")

        status, body = request_json("POST", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll", {"name": "sensor-check", "csr_pem": tamper_csr(csr_pem)})
        expect(status == 400, "CSR altéré refusé")

        status, body = request_json("POST", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll", {"name": "sensor-check", "csr_pem": csr_pem})
        expect(status == 202 and body["fingerprint"] == fingerprint, "demande acceptée, empreinte = SPKI")

        _other_key, other_csr, _other_fp = make_identity()
        status, body = request_json("POST", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll", {"name": "sensor-check", "csr_pem": other_csr})
        expect(status == 409, "un second demandeur ne prend pas le nom")

        reject_key, reject_csr, reject_fp = make_identity()
        status, _body = request_json("POST", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll", {"name": "sensor-rejet", "csr_pem": reject_csr})
        expect(status == 202, "demande sensor-rejet déposée")
        status, body = enroll.reject(reject_fp)
        expect(status == 200, "refus enregistré")
        status, body = request_json("GET", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll/{reject_fp}")
        expect(body.get("status") == "rejected", "le device voit le refus")

        status, body = enroll.approve(fingerprint, hours=1)
        expect(status == 200 and "broker" not in body, "approbation et broker rechargé")
        status, granted = request_json("GET", f"https://127.0.0.1:{enroll.ENROLL_PORT}/v1/enroll/{fingerprint}")
        expect(status == 200 and granted["status"] == "approved", "le device reçoit le paquet")
        blob = json.dumps(granted)
        expect("PRIVATE" not in blob and "csr_pem" not in blob, "pas de clé privée dans la réponse")
        expect(cert_cn(granted["cert_pem"]) == "sensor-check", "le CN est le nom approuvé, pas celui du CSR")
        expect(granted["mqtt"]["host"] == enroll.MQTT_HOST_DEVICE, "l'hôte MQTT vient du serveur")
        expect(granted["mqtt"]["port"] == 8884, "le port MQTT vient du serveur")
        expect(enroll.public_fingerprint(
            x509.load_pem_x509_certificate(granted["cert_pem"].encode()).public_key()
        ) == fingerprint, "le certificat porte la clé du device")
        issued = x509.load_pem_x509_certificate(granted["cert_pem"].encode())
        lifetime = issued.not_valid_after_utc - issued.not_valid_before_utc
        expect(lifetime.total_seconds() < 2 * 3600, "certificat court (1 h demandée)")

        code = mqtt_code(granted["cert_pem"], _key, "devices/sensor-check/telemetry")
        expect(code in (0, 16), f"publication autorisée (code {code})")
        code = mqtt_code(granted["cert_pem"], _key, "devices/not-mine/telemetry")
        expect(code == 135, f"publication hors ACL refusée (code {code})")

        status, body = enroll.revoke("sensor-check")
        expect(status == 200 and "broker" not in body, "révocation et broker rechargé")
        code = mqtt_code(granted["cert_pem"], _key, "devices/sensor-check/telemetry")
        expect(code == 135, f"publication après révocation refusée (code {code})")
        expect("user sensor-check" not in enroll.ACL_FILE.read_text(), "l'ACL ne contient plus le device")
        print("self_check OK")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
