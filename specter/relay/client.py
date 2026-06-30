"""Relay client: sign, dispatch, and fan out across many Relay servers.

One Specter instance can orchestrate dozens of Relay servers, each with its own
toolkit and network position. The client signs every request with its key,
pins each server's public key, and verifies signed responses.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from specter.relay.keys import KeyPair
from specter.relay.protocol import RelayRequest, RelayResponse


@dataclass
class RelayEndpoint:
    name: str
    url: str                  # e.g. https://relay-1.example.com:8443
    server_pub: str = ""      # pinned server public key (base64)
    tools: list[str] = field(default_factory=list)


class RelayClient:
    def __init__(self, keypair: KeyPair, timeout: float = 60.0) -> None:
        self.keypair = keypair
        self.timeout = timeout
        self.endpoints: dict[str, RelayEndpoint] = {}

    def add_endpoint(self, ep: RelayEndpoint) -> None:
        self.endpoints[ep.name] = ep

    def run(self, endpoint: str, tool: str, target: str,
            args: list[str] | None = None) -> RelayResponse:
        import httpx
        ep = self.endpoints[endpoint]
        req = RelayRequest(tool=tool, target=target, args=args or []).sign(self.keypair)
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(ep.url.rstrip("/") + "/run", content=req.to_json(),
                            headers={"Content-Type": "application/json"})
            r.raise_for_status()
            resp = RelayResponse.from_json(r.text)
        if not resp.verify(expected_server_pub=ep.server_pub or None):
            return RelayResponse(tool=tool, target=target,
                                 error="response signature/pin verification failed", returncode=2)
        return resp

    def pick_endpoint(self, tool: str) -> str | None:
        """Choose the first endpoint advertising the requested tool (simple LB hook)."""
        for name, ep in self.endpoints.items():
            if not ep.tools or tool in ep.tools:
                return name
        return next(iter(self.endpoints), None)
