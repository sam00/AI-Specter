"""Unified C2 adapter interface.

Every C2 (Sliver, Cobalt Strike, Mythic, ...) is exposed through the same
small surface so the engine and CLI never special-case a framework. Adapters
degrade gracefully: with no live connection they return simulated data so the
operator can rehearse the workflow safely.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Listener:
    id: str
    name: str
    protocol: str
    bind: str
    status: str = "running"


@dataclass
class Session:
    id: str
    name: str
    host: str
    user: str
    os: str
    integrity: str = ""
    last_checkin: str = ""


@dataclass
class C2Result:
    ok: bool
    summary: str
    data: Any = field(default=None)
    simulated: bool = False


class C2Adapter(abc.ABC):
    name: str = "base"

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.settings = settings or {}
        self.connected = False

    @abc.abstractmethod
    def connect(self) -> C2Result: ...

    @abc.abstractmethod
    def list_listeners(self) -> list[Listener]: ...

    @abc.abstractmethod
    def list_sessions(self) -> list[Session]: ...

    @abc.abstractmethod
    def generate_payload(self, listener: str, os: str, fmt: str) -> C2Result: ...

    @abc.abstractmethod
    def run_command(self, session_id: str, command: str, authorized: bool) -> C2Result: ...

    def health(self) -> dict[str, Any]:
        return {"c2": self.name, "connected": self.connected, "settings": bool(self.settings)}
