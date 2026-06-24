"""Generic adapter for 'any C2' that exposes a REST endpoint.

Configure with `base_url`, optional `token`, and an `endpoints` map, e.g.:
    endpoints:
      listeners: /api/listeners
      sessions:  /api/sessions
      task:      /api/sessions/{id}/task
This lets operators wire up Havoc, Brute Ratel bridges, Empire, or in-house C2.
"""
from __future__ import annotations

import httpx

from specter.c2.base import C2Adapter, C2Result, Listener, Session


class GenericC2Adapter(C2Adapter):
    name = "generic"

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
            return C2Result(False, "no 'base_url' configured — simulated mode", simulated=True)
        self.connected = True
        return C2Result(True, f"configured for {self.settings.get('base_url')}")

    def list_listeners(self) -> list[Listener]:
        ep = self.settings.get("endpoints", {}).get("listeners")
        client = self._client()
        if not (self.connected and client and ep):
            return [Listener("sim-1", "generic", "https", "0.0.0.0:443")]
        try:
            rows = client.get(ep).json()
            return [Listener(str(r.get("id")), r.get("name", ""), r.get("protocol", ""),
                             r.get("bind", "")) for r in rows]
        except Exception:
            return []

    def list_sessions(self) -> list[Session]:
        ep = self.settings.get("endpoints", {}).get("sessions")
        client = self._client()
        if not (self.connected and client and ep):
            return [Session("sim-1", "agent", "HOST", "user", "linux")]
        try:
            rows = client.get(ep).json()
            return [Session(str(r.get("id")), r.get("name", ""), r.get("host", ""),
                            r.get("user", ""), r.get("os", "")) for r in rows]
        except Exception:
            return []

    def generate_payload(self, listener: str, os: str, fmt: str) -> C2Result:
        return C2Result(True, f"[SIM] generic payload listener={listener} os={os} fmt={fmt}",
                        simulated=not self.connected)

    def run_command(self, session_id: str, command: str, authorized: bool) -> C2Result:
        if not authorized:
            return C2Result(False, "BLOCKED: tasking not authorized for this engagement")
        ep = self.settings.get("endpoints", {}).get("task")
        client = self._client()
        if not (self.connected and client and ep):
            return C2Result(True, f"[SIM] {session_id}: {command}", simulated=True)
        try:
            client.post(ep.format(id=session_id), json={"command": command})
            return C2Result(True, f"tasked {session_id}: {command}")
        except Exception as e:
            return C2Result(False, f"task failed: {e}")
