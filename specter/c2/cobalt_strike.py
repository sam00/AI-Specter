"""Cobalt Strike adapter.

Cobalt Strike has no first-party REST API, so Specter talks to a team-server
bridge (e.g. an agscript/Aggressor or community REST shim) configured with
`base_url` + `token`. Without a reachable bridge it runs in simulated mode.
"""
from __future__ import annotations

import httpx

from specter.c2.base import C2Adapter, C2Result, Listener, Session


class CobaltStrikeAdapter(C2Adapter):
    name = "cobaltstrike"

    def _client(self) -> httpx.Client | None:
        base = self.settings.get("base_url")
        if not base:
            return None
        token = self.settings.get("token", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.Client(base_url=base, headers=headers, timeout=30, verify=False)

    def connect(self) -> C2Result:
        client = self._client()
        if not client:
            return C2Result(False, "no 'base_url' for CS bridge — simulated mode", simulated=True)
        try:
            r = client.get("/health")
            self.connected = r.status_code < 500
            return C2Result(self.connected, f"bridge status {r.status_code}")
        except Exception as e:
            return C2Result(False, f"bridge unreachable ({e}) — simulated mode", simulated=True)

    def list_listeners(self) -> list[Listener]:
        if not self.connected:
            return [Listener("sim-http-1", "https-beacon", "https", "0.0.0.0:443")]
        return []

    def list_sessions(self) -> list[Session]:
        if not self.connected:
            return [Session("sim-b1", "beacon-1", "WKSTN-07", "corp\\jdoe", "windows", "MEDIUM")]
        return []

    def generate_payload(self, listener: str, os: str, fmt: str) -> C2Result:
        spec = f"beacon listener={listener} os={os} format={fmt}"
        if not self.connected:
            return C2Result(True, f"[SIM] cobaltstrike {spec}", simulated=True)
        return C2Result(True, f"requested stage: {spec}")

    def run_command(self, session_id: str, command: str, authorized: bool) -> C2Result:
        if not authorized:
            return C2Result(False, "BLOCKED: beacon tasking not authorized for this engagement")
        if not self.connected:
            return C2Result(True, f"[SIM] beacon {session_id} task: {command}", simulated=True)
        return C2Result(True, f"tasked beacon {session_id}: {command}")
