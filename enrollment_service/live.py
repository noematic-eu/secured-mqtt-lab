# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Côté système : reçoit la température, envoie la commande LED.

Identité MQTT : certificat `app` (CN = app).
  devices/<id>/telemetry   device → système
  devices/<id>/cmd         système → device
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import enroll  # noqa: E402
from mqttutil import app_client, reason_code  # noqa: E402

_BUS: "SystemBus | None" = None


class SystemBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._temps: dict[str, dict] = {}
        self._client = None
        self._error = "broker non joint"
        self._started = False
        self._stop = False
        self._pubacks: dict[int, int] = {}

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        if not enroll.APP_CERT.exists() or not enroll.APP_KEY.exists():
            with self._lock:
                self._error = "certificat app manquant — mosquitto/tls/gen-app.sh"
            return
        threading.Thread(target=self._run, name="sys-mqtt", daemon=True).start()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "devices": {key: dict(value) for key, value in self._temps.items()},
                "broker": self._error,
            }

    def set_led(self, device_id: str, on: bool) -> None:
        invalid = enroll.validate_name(device_id)
        if invalid:
            raise ValueError(invalid)
        with self._lock:
            client = self._client
            error = self._error
        if client is None or not client.is_connected():
            raise RuntimeError(error or "broker non joint")
        info = client.publish(f"devices/{device_id}/cmd", json.dumps({"led": on}), qos=1)
        info.wait_for_publish(timeout=3)
        with self._lock:
            code = self._pubacks.pop(info.mid, None)
        if code not in (0, 16):
            raise RuntimeError(f"commande refusée par le broker (code {code})")

    def _run(self) -> None:
        while not self._stop:
            client = None
            try:
                client = app_client("sys-admin")
                client.on_connect = self._on_connect
                client.on_message = self._on_message
                client.on_publish = self._on_publish
                client.on_disconnect = self._on_disconnect
                client.connect("127.0.0.1", enroll.MQTT_PORT, 30)
                client.loop_start()
                for _ in range(50):
                    if client.is_connected():
                        break
                    time.sleep(0.1)
                with self._lock:
                    self._client = client
                while client.is_connected() and not self._stop:
                    time.sleep(0.4)
            except Exception as exc:
                with self._lock:
                    self._error = str(exc)
                    self._client = None
            finally:
                if client is not None:
                    client.loop_stop()
                    try:
                        client.disconnect()
                    except Exception:
                        pass
            if not self._stop:
                time.sleep(2)

    def _on_connect(self, client, _userdata, _flags, reason_code, _properties=None) -> None:
        code = reason_code if isinstance(reason_code, int) else int(getattr(reason_code, "value", 1))
        if code != 0:
            with self._lock:
                self._error = f"connexion système refusée ({code})"
            return
        client.subscribe("devices/+/telemetry", qos=1)
        with self._lock:
            self._error = ""

    def _on_disconnect(self, _client, _userdata, _flags=None, reason_code=None, _properties=None) -> None:
        with self._lock:
            self._client = None
            if not self._error:
                self._error = "lien MQTT coupé"

    def _on_publish(self, _client, _userdata, mid, rc=0, _properties=None) -> None:
        with self._lock:
            self._pubacks[mid] = reason_code(rc)

    def _on_message(self, _client, _userdata, message) -> None:
        parts = message.topic.split("/")
        if len(parts) != 3 or parts[0] != "devices" or parts[2] != "telemetry":
            return
        device_id = parts[1]
        try:
            payload = json.loads(message.payload.decode("utf-8"))
            temp = float(payload["temp_c"])
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            return
        with self._lock:
            self._temps[device_id] = {"temp_c": temp, "ts": int(time.time())}
            self._error = ""


def bus() -> SystemBus:
    global _BUS
    if _BUS is None:
        _BUS = SystemBus()
    return _BUS
