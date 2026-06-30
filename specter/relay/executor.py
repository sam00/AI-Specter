"""Server-side Relay execution: verify -> authorize -> scope-guard -> run.

The executor is transport-independent so it can be unit-tested in-process and
reused by the HTTP server. It enforces, in order:

1. signature validity (envelope really came from the claimed client key)
2. client allowlist (that key is authorized on this Relay)
3. anti-replay (fresh timestamp + unused nonce)
4. scope allowlist (target is authorized) — reusing Specter's tool guard
"""
from __future__ import annotations

from dataclasses import dataclass

from specter.relay.keys import KeyPair
from specter.relay.protocol import RelayRequest, RelayResponse, ReplayGuard
from specter.tools.registry import ToolRegistry


@dataclass
class RelayExecutor:
    server_key: KeyPair
    allowed_clients: set[str]            # base64 client public keys
    scope: set[str]                      # authorized target hosts/roots
    registry: ToolRegistry
    replay: ReplayGuard = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.replay is None:
            self.replay = ReplayGuard()

    def _in_scope(self, target: str) -> bool:
        if not self.scope:
            return False
        return any(target == s or target.endswith("." + s) for s in self.scope)

    def handle(self, req: RelayRequest, now: float | None = None) -> RelayResponse:
        def deny(msg: str) -> RelayResponse:
            return RelayResponse(tool=req.tool, target=req.target, error=msg,
                                 returncode=2).sign(self.server_key)

        if not req.verify():
            return deny("signature verification failed")
        if req.client_pub not in self.allowed_clients:
            return deny("client key not authorized on this relay")
        fresh, why = self.replay.check(req, now=now)
        if not fresh:
            return deny(f"rejected: {why}")
        if not self._in_scope(req.target):
            return deny("BLOCKED: target out of authorized scope")

        result = self.registry.run(req.tool, req.target, in_scope=True, extra=req.args)
        return RelayResponse(
            tool=result.tool, target=result.target, stdout=result.stdout,
            error=result.error, returncode=result.returncode,
            simulated=result.simulated).sign(self.server_key)
