#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Envoie une commande LED sur play.why.noematic.eu avec le certificat app."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mqttutil import ALLOWED, app_client, connect, publish  # noqa: E402


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in ("on", "off"):
        print("Usage : cmd-led.py <device_id> on|off")
        raise SystemExit(1)
    device_id, state = sys.argv[1], sys.argv[2]
    client = app_client("app-cmd")
    connect(client)
    try:
        topic = f"devices/{device_id}/cmd"
        code = publish(client, topic, json.dumps({"led": state == "on"}))
    finally:
        client.disconnect()
    if code in ALLOWED:
        print(f"✓ {topic} led={state}")
    else:
        print(f"✗ refusé (code {code})")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
