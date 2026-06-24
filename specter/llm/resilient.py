"""Wraps any LLMClient with caching, retries+backoff, and budget accounting."""
from __future__ import annotations

import time

from specter.budget import Budget, BudgetExceeded
from specter.cache import LLMCache
from specter.llm.base import LLMClient, LLMResponse, Message


class ResilientClient(LLMClient):
    def __init__(
        self,
        inner: LLMClient,
        retries: int = 3,
        backoff: float = 0.5,
        cache: LLMCache | None = None,
        budget: Budget | None = None,
    ) -> None:
        super().__init__(inner.model, inner.api_key, inner.base_url)
        self.inner = inner
        self.provider = inner.provider
        self.retries = max(1, retries)
        self.backoff = backoff
        self.cache = cache
        self.budget = budget

    def chat(self, messages: list[Message], max_tokens: int = 2048,
             temperature: float = 0.2) -> LLMResponse:
        system = "\n".join(m.content for m in messages if m.role == "system")
        user = "\n".join(m.content for m in messages if m.role != "system")

        ck = None
        if self.cache and self.cache.enabled:
            ck = LLMCache.key(self.provider, self.model, system, user, max_tokens)
            hit = self.cache.get(ck)
            if hit is not None:
                return LLMResponse(text=hit, provider=self.provider, model=self.model, cached=True)

        last_err: Exception | None = None
        for attempt in range(self.retries):
            try:
                resp = self.inner.chat(messages, max_tokens=max_tokens, temperature=temperature)
                if ck:
                    self.cache.set(ck, resp.text)
                if self.budget:
                    self.budget.add(self.provider, self.model, resp.input_tokens, resp.output_tokens)
                    self.budget.check()  # may raise BudgetExceeded (not retried)
                return resp
            except BudgetExceeded:
                raise
            except Exception as e:  # pragma: no cover - network variability
                last_err = e
                if attempt < self.retries - 1:
                    time.sleep(self.backoff * (2 ** attempt))
        raise last_err if last_err else RuntimeError("LLM call failed")
