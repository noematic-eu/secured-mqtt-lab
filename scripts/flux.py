#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Vérifie les deux sens MQTT sans Wokwi.

  device → système   température sur devices/<nom>/telemetry
  système → device   commande LED sur devices/<nom>/cmd

Le service visé est play.why.noematic.eu (enrôlement 8443, MQTTS 8884).
Le script demande l'enrôlement, affiche l'empreinte, attend l'accord,
puis envoie une température et deux commandes LED sur l'hôte reçu.

Usage :
  python3 scripts/flux.py --name sensor-flux
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_sim import enroll_url, key_pem, make_identity, request_json, wait_decision  # noqa: E402
from mqttutil import ALLOWED, app_client, connect, new_client, reason_code  # noqa: E402


def fail(message: str) -> None:
    print(f"✗ {message}", file=sys.stderr)
    raise SystemExit(1)


def enroll(name: str, timeout: float) -> tuple[object, dict]:
    key, csr_pem, fingerprint = make_identity(name)
    status, body = request_json("POST", enroll_url("/v1/enroll"), {"name": name, "csr_pem": csr_pem})
    print(f"demande {status}")
    print(f"nom       {name}")
    print(f"empreinte {fingerprint}")
    if status >= 400:
        fail(str(body.get("error", body)))
    if body.get("status") == "pending":
        print("En attente de l'accord sur cette empreinte.")
        body = wait_decision(fingerprint, timeout)
    if body.get("status") != "approved":
        fail(f"décision : {body.get('status')}")
    if "PRIVATE" in json.dumps(body):
        fail("la réponse d'enrôlement contient une clé privée")
    print(f"accordé   {body['mqtt']['host']}:{body['mqtt']['port']}")
    return key, body


def open_clients(cert_pem: str, private_key, device_id: str, host: str, port: int):
    """Le broker redémarre juste après l'accord. On réessaie jusqu'à ce qu'il réponde."""
    last = "pas de CONNACK"
    for _ in range(25):
        device = new_client(f"flux-{device_id}", cert_pem, key_pem(private_key))
        system = app_client("sys-flux")
        try:
            connect(device, host, port)
            connect(system, host, port)
            return device, system
        except (SystemExit, OSError) as exc:
            last = str(exc)
            for client in (device, system):
                try:
                    client.disconnect()
                except Exception:
                    pass
            time.sleep(0.4)
    fail(f"MQTT injoignable après l'accord ({last})")


def watch_puback(client) -> dict[int, int]:
    found: dict[int, int] = {}

    def on_publish(_c, _u, mid, rc=0, _p=None):
        found[mid] = reason_code(rc)

    client.on_publish = on_publish
    return found


def wait_count(items: list, count: int, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if len(items) >= count:
            return True
        time.sleep(0.05)
    return False


def round_trip(key, body) -> None:
    device_id = body["device_id"]
    topics = body["mqtt"]["topics"]
    telemetry = topics["telemetry"]
    command = topics["cmd"]
    temps: list[dict] = []
    leds: list[dict] = []
    lock = threading.Lock()

    announced = body["mqtt"]
    device, system = open_clients(body["cert_pem"], key, device_id, announced["host"], announced["port"])

    def on_temp(_c, _u, message):
        if message.topic != telemetry:
            return
        with lock:
            temps.append(json.loads(message.payload.decode("utf-8")))

    def on_led(_c, _u, message):
        if message.topic != command:
            return
        with lock:
            leds.append(json.loads(message.payload.decode("utf-8")))

    system.on_message = on_temp
    device.on_message = on_led
    system.subscribe(telemetry, qos=1)
    device.subscribe(command, qos=1)
    system.loop_start()
    device.loop_start()
    time.sleep(0.5)
    try:
        payload = json.dumps({"device_id": device_id, "temp_c": 21.5})
        device_acks = watch_puback(device)
        info = device.publish(telemetry, payload, qos=1)
        info.wait_for_publish(timeout=3)
        code = device_acks.get(info.mid, -1)
        if code not in ALLOWED:
            fail(f"publication température refusée (code {code})")
        if not wait_count(temps, 1, 5):
            fail("le système n'a pas reçu la température")
        print(f"montant    device → système   {telemetry}  {temps[0].get('temp_c')} °C")

        system_acks = watch_puback(system)
        for on in (True, False):
            before = len(leds)
            info = system.publish(command, json.dumps({"led": on}), qos=1)
            info.wait_for_publish(timeout=3)
            code = system_acks.get(info.mid, -1)
            if code not in ALLOWED:
                fail(f"commande LED refusée (code {code})")
            if not wait_count(leds, before + 1, 5):
                fail(f"le device n'a pas reçu led={on}")
            state = "allumée" if leds[before].get("led") is True else "éteinte"
            print(f"descendant système → device   {command}  LED {state}")
    finally:
        device.loop_stop()
        system.loop_stop()
        device.disconnect()
        system.disconnect()
    print("flux OK")


def main() -> None:
    parser = argparse.ArgumentParser(description="Teste température et commande LED sans Wokwi.")
    parser.add_argument("--name", default="sensor-flux")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    key, body = enroll(args.name, args.timeout)
    round_trip(key, body)


if __name__ == "__main__":
    main()
