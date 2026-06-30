"""HTTP transport for a Relay server (stdlib-only, no heavy deps).

Wraps :class:`RelayExecutor` behind a single ``POST /run`` endpoint. Auth is
performed cryptographically inside the executor, so the transport itself stays
minimal and binds to localhost by default — pair with the Cloudflare Tunnel
helper for zero-open-port remote access.
"""
from __future__ import annotations

import http.server
import threading

from specter.relay.executor import RelayExecutor
from specter.relay.protocol import RelayRequest


def make_handler(executor: RelayExecutor):
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a):
            return

        def do_POST(self):
            if self.path.rstrip("/") != "/run":
                self.send_error(404, "not found")
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode()
            try:
                req = RelayRequest.from_json(raw)
            except Exception:
                self.send_error(400, "bad envelope")
                return
            resp = executor.handle(req)
            payload = resp.to_json().encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return _Handler


class RelayServer:
    def __init__(self, executor: RelayExecutor, host: str = "127.0.0.1",
                 port: int = 8443) -> None:
        self.executor = executor
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None

    def start(self) -> "RelayServer":
        self._httpd = http.server.ThreadingHTTPServer(
            (self.host, self.port), make_handler(self.executor))
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._httpd = http.server.ThreadingHTTPServer(
            (self.host, self.port), make_handler(self.executor))
        self._httpd.serve_forever()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
