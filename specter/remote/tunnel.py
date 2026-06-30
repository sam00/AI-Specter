"""Zero-open-port remote access via Cloudflare Tunnel.

Specter binds its server/dashboard/Relay to ``localhost`` and uses an
*outbound-only* ``cloudflared`` connection to expose it — so there are no
inbound firewall rules or port-forwards, and the data plane stays TLS the whole
way. This wrapper just manages the ``cloudflared`` subprocess; auth on the
exposed service is still enforced by Specter (server password / Relay keys).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


def cloudflared_available() -> bool:
    return shutil.which("cloudflared") is not None


@dataclass
class CloudflareTunnel:
    local_url: str = "http://127.0.0.1:8787"
    name: str = ""           # named tunnel; if empty, uses a quick (trycloudflare) tunnel
    _proc: subprocess.Popen | None = None

    def command(self) -> list[str]:
        if self.name:
            return ["cloudflared", "tunnel", "--url", self.local_url, "run", self.name]
        # Quick tunnel — ephemeral *.trycloudflare.com hostname, no account needed.
        return ["cloudflared", "tunnel", "--url", self.local_url]

    def start(self) -> "CloudflareTunnel":
        if not cloudflared_available():
            raise RuntimeError(
                "cloudflared not found — install it (brew install cloudflared) "
                "or see https://developers.cloudflare.com/cloudflare-one/")
        self._proc = subprocess.Popen(self.command())
        return self

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._proc.kill()
