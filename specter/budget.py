"""Token/cost accounting and per-engagement budget enforcement.

Prices are sourced from the advisor's model catalog so there's a single source
of truth. A limit of 0 means unlimited. Local/echo models cost nothing.
"""
from __future__ import annotations

import threading

from specter.advisor.model_advisor import MODEL_CATALOG


class BudgetExceeded(Exception):
    """Raised when an engagement would exceed its configured cost/token cap."""


def _price_table() -> dict[tuple[str, str], tuple[float, float]]:
    return {(s.provider, s.name): (s.cost_in, s.cost_out) for s in MODEL_CATALOG}


class Budget:
    def __init__(self, max_usd: float = 0.0, max_tokens: int = 0) -> None:
        self.max_usd = max_usd
        self.max_tokens = max_tokens
        self.usd = 0.0
        self.tokens = 0
        self.calls = 0
        self._prices = _price_table()
        self._lock = threading.Lock()

    def add(self, provider: str, model: str, in_tok: int, out_tok: int) -> None:
        ci, co = self._prices.get((provider, model), (0.0, 0.0))
        with self._lock:
            self.usd += (in_tok / 1_000_000) * ci + (out_tok / 1_000_000) * co
            self.tokens += in_tok + out_tok
            self.calls += 1

    def check(self) -> None:
        if self.max_usd and self.usd >= self.max_usd:
            raise BudgetExceeded(f"cost ${self.usd:.4f} ≥ cap ${self.max_usd:.2f}")
        if self.max_tokens and self.tokens >= self.max_tokens:
            raise BudgetExceeded(f"tokens {self.tokens} ≥ cap {self.max_tokens}")

    def remaining_usd(self) -> float:
        return max(0.0, self.max_usd - self.usd) if self.max_usd else float("inf")

    def stats(self) -> dict:
        return {
            "usd": round(self.usd, 4),
            "tokens": self.tokens,
            "calls": self.calls,
            "max_usd": self.max_usd,
            "max_tokens": self.max_tokens,
        }
