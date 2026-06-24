"""C2 framework integrations with a single factory entrypoint."""
from __future__ import annotations

from typing import Any

from specter.c2.base import C2Adapter, C2Result, Listener, Session
from specter.c2.cobalt_strike import CobaltStrikeAdapter
from specter.c2.generic import GenericC2Adapter
from specter.c2.mythic import MythicAdapter
from specter.c2.sliver import SliverAdapter

ADAPTERS: dict[str, type[C2Adapter]] = {
    "sliver": SliverAdapter,
    "cobaltstrike": CobaltStrikeAdapter,
    "mythic": MythicAdapter,
    "generic": GenericC2Adapter,
}


def get_c2(name: str, settings: dict[str, Any] | None = None) -> C2Adapter:
    cls = ADAPTERS.get(name.lower(), GenericC2Adapter)
    return cls(settings or {})


__all__ = [
    "C2Adapter", "C2Result", "Listener", "Session",
    "ADAPTERS", "get_c2",
    "SliverAdapter", "CobaltStrikeAdapter", "MythicAdapter", "GenericC2Adapter",
]
