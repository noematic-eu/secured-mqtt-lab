#!/usr/bin/env python3
# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""Écoute la télémétrie sur play.why.noematic.eu avec le certificat app."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mqttutil import app_client, connect  # noqa: E402


def main() -> None:
    client = app_client("app-sub")

    def on_message(_c, _u, message):
        print(f"{message.topic} {message.payload.decode('utf-8', 'replace')}")

    client.on_message = on_message
    connect(client)
    client.subscribe("devices/+/telemetry", qos=1)
    client.subscribe("devices/+/status", qos=1)
    print("En écoute sur devices/+/telemetry et devices/+/status")
    client.loop_forever()


if __name__ == "__main__":
    main()
