# Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
"""HTTPS d'enrôlement (0.0.0.0:8443) et page admin (0.0.0.0:8444).

Le device n'a pas de jeton : il dépose un CSR et interroge son empreinte.
L'approbation exige le jeton admin, imprimé au lancement de `enroll.py serve`.
"""
from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import enroll
import live

ADMIN_HTML = Path(__file__).resolve().parent / "admin.html"
SERVERS: list[ThreadingHTTPServer] = []


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        # command/path n'existent pas si la requête est mal formée (parse_request échoue)
        command = getattr(self, "command", None) or "-"
        path = getattr(self, "path", None) or "-"
        extra = args[1] if len(args) > 1 else ""
        print(f"[{self.address_string()}] {command} {path} {extra}")

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 16384:
            raise ValueError("corps trop volumineux")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            raise ValueError("corps JSON manquant")
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("JSON invalide") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON objet attendu")
        return data

    def send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def bearer_ok(self) -> bool:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        given = header[len(prefix):].strip()
        return enroll.token_matches(given)


class EnrollHandler(QuietHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(200, {"ok": True})
            return
        prefix = "/v1/enroll/"
        if path.startswith(prefix):
            status, body = enroll.get_status(path[len(prefix):])
            self.send_json(status, body)
            return
        self.send_json(404, {"error": "chemin inconnu"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/v1/enroll":
            self.send_json(404, {"error": "chemin inconnu"})
            return
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        status, body = enroll.submit_request(data.get("name", ""), data.get("csr_pem", ""))
        self.send_json(status, body)


class AdminHandler(QuietHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/admin"):
            payload = ADMIN_HTML.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True
            return
        if path == "/v1/requests":
            if not self.bearer_ok():
                self.send_json(401, {"error": "jeton admin requis"})
                return
            self.send_json(200, {"requests": enroll.list_requests()})
            return
        if path == "/v1/live":
            if not self.bearer_ok():
                self.send_json(401, {"error": "jeton admin requis"})
                return
            self.send_json(200, live.bus().snapshot())
            return
        self.send_json(404, {"error": "chemin inconnu"})

    def do_POST(self) -> None:
        if not self.bearer_ok():
            self.send_json(401, {"error": "jeton admin requis"})
            return
        path = urlparse(self.path).path
        try:
            data = self.read_json()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return
        try:
            if path == "/v1/approve":
                hours = int(data.get("hours", enroll.CERT_HOURS_DEFAULT))
                status, body = enroll.approve(str(data.get("fingerprint", "")), hours)
            elif path == "/v1/reject":
                status, body = enroll.reject(str(data.get("fingerprint", "")))
            elif path == "/v1/revoke":
                status, body = enroll.revoke(str(data.get("device_id", "")))
            elif path == "/v1/cmd":
                if not isinstance(data.get("led"), bool):
                    status, body = 400, {"error": "led booléen attendu"}
                else:
                    try:
                        live.bus().set_led(str(data.get("device_id", "")), data["led"])
                        status, body = 200, {"ok": True}
                    except ValueError as exc:
                        status, body = 400, {"error": str(exc)}
                    except RuntimeError as exc:
                        status, body = 503, {"error": str(exc)}
            else:
                status, body = 404, {"error": "chemin inconnu"}
        except (TypeError, ValueError):
            status, body = 400, {"error": "paramètres invalides"}
        self.send_json(status, body)


class ReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _listen(handler, host: str, port: int, context: ssl.SSLContext | None = None) -> ThreadingHTTPServer:
    httpd = ReuseServer((host, port), handler)
    if context is not None:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    SERVERS.append(httpd)
    return httpd


def serve() -> None:
    missing = [path.name for path in (enroll.CA_CERT, enroll.ENROLL_CERT, enroll.ENROLL_KEY) if not path.exists()]
    if missing:
        raise SystemExit(
            "Certificats manquants : "
            + ", ".join(missing)
            + "\n  cd mosquitto/tls && ./gen-ca.sh && ./gen-server.sh && ./gen-enroll.sh"
        )
    token = enroll.ensure_token()
    live.bus().start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(enroll.ENROLL_CERT, enroll.ENROLL_KEY)
    enroll_httpd = _listen(EnrollHandler, "0.0.0.0", enroll.ENROLL_PORT, context)
    admin_httpd = _listen(AdminHandler, "0.0.0.0", enroll.ADMIN_PORT, None)

    import threading

    threading.Thread(target=enroll_httpd.serve_forever, daemon=True).start()
    print("Enrôlement  https://%s:%d/v1/enroll" % (enroll.MQTT_HOST_DEVICE, enroll.ENROLL_PORT))
    print("Admin       http://%s:%d/admin" % (enroll.MQTT_HOST_DEVICE, enroll.ADMIN_PORT))
    print("Jeton admin %s" % token)
    print("Le jeton autorise l'approbation. Il ne va pas dans le sketch.")
    try:
        admin_httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        stop()


def start_background() -> None:
    """Démarre les deux ports dans des threads. Utilisé par self_check."""
    missing = [path.name for path in (enroll.ENROLL_CERT, enroll.ENROLL_KEY) if not path.exists()]
    if missing:
        raise SystemExit("certificat d'enrôlement manquant")
    live.bus().start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(enroll.ENROLL_CERT, enroll.ENROLL_KEY)
    enroll_httpd = _listen(EnrollHandler, "0.0.0.0", enroll.ENROLL_PORT, context)
    admin_httpd = _listen(AdminHandler, "0.0.0.0", enroll.ADMIN_PORT, None)
    import threading

    threading.Thread(target=enroll_httpd.serve_forever, daemon=True).start()
    threading.Thread(target=admin_httpd.serve_forever, daemon=True).start()
    enroll.ensure_token()


def stop() -> None:
    for httpd in SERVERS:
        httpd.shutdown()
        httpd.server_close()
    SERVERS.clear()


if __name__ == "__main__":
    serve()
