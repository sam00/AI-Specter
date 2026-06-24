"""Configuration loading and the engagement authorization gate."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

CONFIG_DIR = Path(os.environ.get("SPECTER_HOME", Path.home() / ".specter"))
CONFIG_FILE = CONFIG_DIR / "config.yaml"
RUNS_DIR = CONFIG_DIR / "runs"


class ProviderConfig(BaseModel):
    """Credentials and defaults for a single LLM provider."""

    enabled: bool = False
    api_key_env: str = ""
    base_url: str = ""
    default_model: str = ""


class Scope(BaseModel):
    """Authorized engagement scope. Specter refuses to act outside this."""

    targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    authorized_by: str = ""
    authorization_ref: str = ""
    rules_of_engagement: str = ""


class Config(BaseModel):
    """Top-level Specter configuration."""

    profile: str = "balanced"
    offline: bool = False
    allow_exploitation: bool = False
    log_level: str = "info"      # debug | info | warn | error
    log_compress: bool = True    # gzip the audit log on close to save space
    max_workers: int = 6         # parallel tool/triage workers
    llm_retries: int = 3         # retries per LLM call (with backoff)
    cache_enabled: bool = True   # cache LLM responses (skipped when offline)
    verify_findings: bool = True # run a second-opinion verification pass
    max_usd: float = 0.0         # per-engagement cost cap (0 = unlimited)
    max_tokens: int = 0          # per-engagement token cap (0 = unlimited)
    actor: str = ""              # operator identity recorded on runs/events
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    scope: Scope = Field(default_factory=Scope)
    c2: dict[str, dict[str, Any]] = Field(default_factory=dict)
    models: list[dict] = Field(default_factory=list)  # optional catalog overrides
    api_keys: dict[str, str] = Field(default_factory=dict)  # server: api_key -> role

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        load_dotenv()
        path = path or CONFIG_FILE
        if path.exists():
            data = yaml.safe_load(path.read_text()) or {}
            return cls.model_validate(data)
        return cls()

    def save(self, path: Path | None = None) -> Path:
        path = path or CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(self.model_dump(), sort_keys=False))
        return path

    def provider_key(self, name: str) -> str | None:
        prov = self.providers.get(name)
        if not prov or not prov.api_key_env:
            return None
        return os.environ.get(prov.api_key_env)

    def in_scope(self, target: str) -> bool:
        """Allowlist check used before any active action.

        Authorized roots and their subdomains are in scope; exclusions always win.
        This lets adaptive discovery fold in subdomains of authorized targets
        without ever stepping outside the approved roots.
        """
        if target in self.scope.exclusions:
            return False
        for t in self.scope.targets:
            if target == t or target.endswith("." + t):
                return True
        return False
