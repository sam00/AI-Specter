"""Signed request/response envelopes for Relay, with anti-replay.

A :class:`RelayRequest` is canonicalized to JSON, signed by the client key,
and carries a nonce + timestamp. The server verifies the signature against its
allowlist, rejects stale or replayed envelopes, then executes the tool behind
the same scope guard Specter uses locally. Results are signed back by the
server so the client can trust them too.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field

from specter.relay.keys import KeyPair, verify


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class RelayRequest:
    tool: str
    target: str
    args: list[str] = field(default_factory=list)
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)
    client_pub: str = ""
    signature: str = ""

    def signing_payload(self) -> dict:
        return {"tool": self.tool, "target": self.target, "args": self.args,
                "nonce": self.nonce, "ts": self.ts, "client_pub": self.client_pub}

    def sign(self, keypair: KeyPair) -> "RelayRequest":
        self.client_pub = keypair.public_b64()
        self.signature = keypair.sign(_canonical(self.signing_payload()))
        return self

    def verify(self) -> bool:
        return verify(self.client_pub, _canonical(self.signing_payload()), self.signature)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, text: str) -> "RelayRequest":
        return cls(**json.loads(text))


@dataclass
class RelayResponse:
    tool: str
    target: str
    stdout: str = ""
    error: str = ""
    returncode: int = 0
    simulated: bool = False
    server_pub: str = ""
    signature: str = ""

    def signing_payload(self) -> dict:
        return {"tool": self.tool, "target": self.target, "stdout": self.stdout,
                "error": self.error, "returncode": self.returncode,
                "simulated": self.simulated, "server_pub": self.server_pub}

    def sign(self, keypair: KeyPair) -> "RelayResponse":
        self.server_pub = keypair.public_b64()
        self.signature = keypair.sign(_canonical(self.signing_payload()))
        return self

    def verify(self, expected_server_pub: str | None = None) -> bool:
        if expected_server_pub and self.server_pub != expected_server_pub:
            return False
        return verify(self.server_pub, _canonical(self.signing_payload()), self.signature)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, text: str) -> "RelayResponse":
        return cls(**json.loads(text))


class ReplayGuard:
    """Rejects stale envelopes and reused nonces within a freshness window."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = window_seconds
        self._seen: dict[str, float] = {}

    def check(self, req: RelayRequest, now: float | None = None) -> tuple[bool, str]:
        now = now if now is not None else time.time()
        if abs(now - req.ts) > self.window:
            return False, "stale timestamp outside freshness window"
        # prune old nonces
        self._seen = {n: t for n, t in self._seen.items() if now - t <= self.window}
        if req.nonce in self._seen:
            return False, "nonce replay detected"
        self._seen[req.nonce] = req.ts
        return True, "ok"
