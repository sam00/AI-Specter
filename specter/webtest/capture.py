"""Traffic capture + live session-context discovery (improved "HackBrowser").

Rather than ship a bundled Chromium, Specter captures traffic through open,
inspectable paths that work in CI and air-gapped labs:

- **HAR import** — record traffic in *any* browser's devtools (or Burp/ZAP) and
  export a ``.har``; Specter reconstructs the full session, including which
  identity made each request. This is the "autonomous capture" replacement and
  is fully offline-testable.
- **Recording proxy** — a lightweight forwarding HTTP proxy that records every
  request/response into a :class:`SessionContext` while you browse.

Both paths perform **role & credential discovery**: distinct ``Authorization`` /
``Cookie`` values are clustered into :class:`Identity` objects, and privilege is
inferred from the routes each identity successfully reaches (e.g. an identity
that hits ``/admin`` is ranked higher). The sub-testers consume this directly.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from specter.webtest.model import (
    HttpRequest,
    HttpResponse,
    Identity,
    SessionContext,
    Transaction,
)

_PRIV_ROUTE = re.compile(r"/(admin|internal|manage|console|root|superuser)", re.I)


def _auth_fingerprint(headers: dict[str, str]) -> str:
    """Stable short id for the auth material in a request (token/cookie)."""
    material = ""
    for k, v in headers.items():
        if k.lower() in ("authorization", "cookie", "x-api-key"):
            material += f"{k.lower()}={v};"
    if not material:
        return "anonymous"
    return "id-" + hashlib.sha256(material.encode()).hexdigest()[:8]


def _identity_for(headers: dict[str, str]) -> Identity:
    fp = _auth_fingerprint(headers)
    if fp == "anonymous":
        return Identity("anonymous", role="anonymous", privilege=0)
    auth_headers = {k: v for k, v in headers.items()
                    if k.lower() in ("authorization", "cookie", "x-api-key")}
    return Identity(fp, role="user", headers=auth_headers, privilege=1)


def har_to_context(har_path: str | Path, base_targets: list[str] | None = None) -> SessionContext:
    """Reconstruct a :class:`SessionContext` from a browser/proxy HAR export."""
    data = json.loads(Path(har_path).read_text())
    ctx = SessionContext(base_targets=list(base_targets or []))
    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        headers = {h["name"]: h["value"] for h in req.get("headers", [])
                   if not h["name"].startswith(":")}
        body = ""
        post = req.get("postData")
        if post:
            body = post.get("text", "")
        request = HttpRequest(method=req.get("method", "GET"),
                              url=req.get("url", ""), headers=headers, body=body)
        resp = entry.get("response", {})
        content = resp.get("content", {})
        response = HttpResponse(
            status=resp.get("status", 0),
            headers={h["name"]: h["value"] for h in resp.get("headers", [])},
            body=content.get("text", ""),
            elapsed_ms=float(entry.get("time", 0.0)),
        )
        ident = _identity_for(headers)
        ctx.add_identity(ident)
        ctx.add_transaction(Transaction(request=request, response=response, identity=ident.name))
    _infer_privileges(ctx)
    return ctx


def _infer_privileges(ctx: SessionContext) -> None:
    """Rank identities: any that successfully reached a privileged route is elevated."""
    for txn in ctx.transactions:
        ident = ctx.identities.get(txn.identity)
        if not ident or ident.privilege == 0:
            continue
        if _PRIV_ROUTE.search(txn.request.path) and txn.response and txn.response.ok:
            ident.privilege = max(ident.privilege, 2)
            ident.role = "admin"
    # Give human-friendly names to the two most relevant identities.
    for ident in ctx.identities.values():
        if ident.privilege >= 2:
            ident.role = "admin"


class RecordingProxy:
    """A forwarding HTTP proxy that records traffic into a SessionContext.

    HTTP requests are inspected and recorded; HTTPS ``CONNECT`` tunnels are
    passed through untouched (use the HAR path for TLS inspection). Designed to
    run in a background thread; call :meth:`stop` to shut it down.
    """

    def __init__(self, ctx: SessionContext, host: str = "127.0.0.1", port: int = 8081) -> None:
        self.ctx = ctx
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None

    def start(self) -> "RecordingProxy":
        import http.server
        import threading
        import httpx

        ctx = self.ctx

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):  # silence default logging
                return

            def _record_and_forward(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("latin-1") if length else ""
                url = self.path
                headers = {k: v for k, v in self.headers.items()}
                request = HttpRequest(method=method, url=url, headers=headers, body=body)
                if not ctx.in_scope(request.host):
                    self.send_error(403, "out of scope")
                    return
                try:
                    with httpx.Client(timeout=20, follow_redirects=False) as client:
                        upstream = client.request(method, url, headers=headers,
                                                  content=body or None)
                    response = HttpResponse(status=upstream.status_code,
                                            headers=dict(upstream.headers),
                                            body=upstream.text)
                except Exception as e:
                    self.send_error(502, str(e))
                    return
                ident = _identity_for(headers)
                ctx.add_identity(ident)
                ctx.add_transaction(Transaction(request=request, response=response,
                                                identity=ident.name))
                _infer_privileges(ctx)
                payload = upstream.content
                self.send_response(upstream.status_code)
                for k, v in upstream.headers.items():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self._record_and_forward("GET")

            def do_POST(self):
                self._record_and_forward("POST")

            def do_PUT(self):
                self._record_and_forward("PUT")

            def do_PATCH(self):
                self._record_and_forward("PATCH")

            def do_DELETE(self):
                self._record_and_forward("DELETE")

        self._httpd = http.server.ThreadingHTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
