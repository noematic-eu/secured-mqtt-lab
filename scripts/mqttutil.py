# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Connexion mTLS du lab v3. L'identité est le CN du certificat client."""
from __future__ import annotations

import ssl
import sys
import tempfile
import time
from pathlib import Path

import paho.mqtt.client as mqtt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "enrollment_service"))
import enroll  # noqa: E402

ALLOWED = {0, 16}


def reason_code(rc: object) -> int:
    if isinstance(rc, int):
        return rc
    return int(getattr(rc, "value"))


def new_client(client_id: str, cert_pem: str, key_pem: str) -> mqtt.Client:
    kwargs = {"client_id": client_id, "protocol": mqtt.MQTTv5}
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, **kwargs)
    except AttributeError:
        client = mqtt.Client(**kwargs)
    context = ssl.create_default_context(cafile=str(enroll.CA_CERT))
    # paho lit les chemins tout de suite. Les fichiers temporaires sont effacés ensuite.
    cert_file = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    key_file = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    try:
        cert_file.write(cert_pem)
        key_file.write(key_pem)
        cert_file.close()
        key_file.close()
        context.load_cert_chain(cert_file.name, key_file.name)
    finally:
        Path(cert_file.name).unlink(missing_ok=True)
        Path(key_file.name).unlink(missing_ok=True)
    client.tls_set_context(context)
    return client


def app_client(client_id: str) -> mqtt.Client:
    missing = [path.name for path in (enroll.CA_CERT, enroll.APP_CERT, enroll.APP_KEY) if not path.exists()]
    if missing:
        sys.exit("Certificat app manquant. Lancer : mosquitto/tls/gen-app.sh")
    return new_client(client_id, enroll.APP_CERT.read_text(), enroll.APP_KEY.read_text())


def connect(client: mqtt.Client, host: str | None = None, port: int | None = None) -> mqtt.Client:
    client.connect(
        enroll.MQTT_HOST_DEVICE if host is None else host,
        enroll.MQTT_PORT if port is None else port,
        60,
    )
    for _ in range(50):
        client.loop(timeout=0.1)
        if client.is_connected():
            return client
    raise SystemExit("MQTT : pas de CONNACK")


def publish(client: mqtt.Client, topic: str, payload: str, *, qos: int = 1, retain: bool = False) -> int:
    reasons: dict[int, int] = {}

    def on_publish(_c, _u, mid, rc=0, _p=None):
        reasons[mid] = reason_code(rc)

    client.on_publish = on_publish
    info = client.publish(topic, payload, qos=qos, retain=retain)
    if info.rc not in (mqtt.MQTT_ERR_SUCCESS, 0):
        return int(getattr(info.rc, "value", info.rc))
    for _ in range(50):
        if info.mid in reasons:
            return reasons[info.mid]
        client.loop(timeout=0.1)
    return -1
