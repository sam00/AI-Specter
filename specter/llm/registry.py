"""Builds LLM clients from Specter config and reports what's usable."""
from __future__ import annotations

import importlib.util

from specter.config import Config
from specter.llm.base import LLMClient
from specter.llm.providers import PROVIDER_CLASSES


def _sdk_present(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def available_providers(config: Config) -> set[str]:
    """Providers that have both credentials/endpoint and (if needed) an SDK."""
    out: set[str] = {"echo"}  # always available as a fallback
    for name, prov in config.providers.items():
        if not prov.enabled:
            continue
        if name == "anthropic" and config.provider_key(name) and _sdk_present("anthropic"):
            out.add(name)
        elif name == "openai" and config.provider_key(name) and _sdk_present("openai"):
            out.add(name)
        elif name in ("ollama", "openai-compatible") and prov.base_url:
            out.add(name)
    return out


def build_client(config: Config, provider: str, model: str) -> LLMClient:
    cls = PROVIDER_CLASSES.get(provider, PROVIDER_CLASSES["echo"])
    prov_cfg = config.providers.get(provider)
    api_key = config.provider_key(provider) if prov_cfg else None
    base_url = prov_cfg.base_url if prov_cfg else ""
    return cls(model=model, api_key=api_key, base_url=base_url)
