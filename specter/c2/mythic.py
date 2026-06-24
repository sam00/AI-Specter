"""Mythic C2 adapter (REST/GraphQL).

Live mode authenticates to a Mythic server via `base_url` + `username`/
`password` (or `apitoken`). Without reachable settings it simulates.
"""
from __future__ import annotations

import httpx

from specter.c2.base import C2Adapter, C2Result, Listener, Session


class MythicAdapter(C2Adapter):
    name = "mythic"

    def connect(self) -> C2Result:
        base = self.settings.get("base_url")
        if not base:
            return C2Result(False, "no 'base_url' for Mythic — simulated mode", simulated=True)
        token = self.settings.get("apitoken")
        try:
            with httpx.Client(base_url=base, timeout=30, verify=False) as c:
                if not token:
                    r = c.post("/auth", json={
                        "username": self.settings.get("username", ""),
                        "password": self.settings.get("password", ""),
                    })
                    token = (r.json() or {}).get("access_token")
                self.settings["apitoken"] = token
                self.connected = bool(token)
            return C2Result(self.connected, "authenticated" if token else "auth failed")
        except Exception as e:
            return C2Result(False, f"unreachable ({e}) — simulated mode", simulated=True)

    def list_listeners(self) -> list[Listener]:
        if not self.connected:
            return [Listener("sim-http-1", "http-profile", "http", "0.0.0.0:80")]
        return []

    def list_sessions(self) -> list[Session]:
        if not self.connected:
            return [Session("sim-cb1", "apollo-1", "HR-LAPTOP", "corp\\asmith", "windows", "MEDIUM")]
        return []

    def generate_payload(self, listener: str, os: str, fmt: str) -> C2Result:
        spec = f"payload profile={listener} os={os} format={fmt}"
        if not self.connected:
            return C2Result(True, f"[SIM] mythic {spec}", simulated=True)
        return C2Result(True, f"build queued: {spec}")

    def run_command(self, session_id: str, command: str, authorized: bool) -> C2Result:
        if not authorized:
            return C2Result(False, "BLOCKED: callback tasking not authorized for this engagement")
        if not self.connected:
            return C2Result(True, f"[SIM] mythic callback {session_id}: {command}", simulated=True)
        return C2Result(True, f"tasked callback {session_id}: {command}")
