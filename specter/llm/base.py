"""Provider-agnostic chat interface."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cached: bool = False
    raw: dict = field(default_factory=dict)


class LLMClient(abc.ABC):
    """All providers implement this so the engine never special-cases vendors."""

    provider: str = "base"

    def __init__(self, model: str, api_key: str | None = None, base_url: str = "") -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url

    @abc.abstractmethod
    def chat(
        self,
        messages: list[Message],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        ...

    def complete(self, system: str, user: str, **kw) -> LLMResponse:
        return self.chat([Message("system", system), Message("user", user)], **kw)
