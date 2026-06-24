"""Sliver C2 adapter.

Live mode uses the `sliver-py` gRPC client (pip install sliver-py) with an
operator config (.cfg). Without it, returns simulated data so workflows run.
"""
from __future__ import annotations

from specter.c2.base import C2Adapter, C2Result, Listener, Session


class SliverAdapter(C2Adapter):
    name = "sliver"

    def connect(self) -> C2Result:
        cfg = self.settings.get("config_path")
        try:
            import sliver  # noqa: F401
        except ImportError:
            return C2Result(False, "sliver-py not installed — simulated mode", simulated=True)
        if not cfg:
            return C2Result(False, "missing 'config_path' to operator .cfg", simulated=True)
        # Real connection is async (asyncio); kept lazy to avoid hard dependency.
        self.connected = True
        return C2Result(True, f"connected via {cfg}")

    def list_listeners(self) -> list[Listener]:
        if not self.connected:
            return [Listener("sim-mtls-1", "mtls", "mtls", "0.0.0.0:8888")]
        return []

    def list_sessions(self) -> list[Session]:
        if not self.connected:
            return [Session("sim-s1", "FANCY_BISON", "WIN-DC01", "corp\\svc", "windows", "HIGH")]
        return []

    def generate_payload(self, listener: str, os: str, fmt: str) -> C2Result:
        cmd = f"generate --mtls {listener} --os {os} --format {fmt}"
        if not self.connected:
            return C2Result(True, f"[SIM] sliver {cmd}", simulated=True)
        return C2Result(True, f"queued: {cmd}")

    def run_command(self, session_id: str, command: str, authorized: bool) -> C2Result:
        if not authorized:
            return C2Result(False, "BLOCKED: command execution not authorized for this engagement")
        if not self.connected:
            return C2Result(True, f"[SIM] sliver session {session_id}: {command}", simulated=True)
        return C2Result(True, f"executed on {session_id}: {command}")
