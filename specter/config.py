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

# Provider -> environment variable Specter auto-detects for zero-config setup.
KNOWN_PROVIDER_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "azure-openai": "AZURE_OPENAI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


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
    model_override: str = ""     # force one 'provider:model' for every task (any LLM)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    scope: Scope = Field(default_factory=Scope)
    c2: dict[str, dict[str, Any]] = Field(default_factory=dict)
    models: list[dict] = Field(default_factory=list)  # optional catalog overrides
    api_keys: dict[str, str] = Field(default_factory=dict)  # server: api_key -> role

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        # Credentials may live in the shell, a project .env, or next to the config.
        load_dotenv()
        load_dotenv(CONFIG_DIR / ".env", override=False)
        path = path or CONFIG_FILE
        if path.exists():
            data = yaml.safe_load(path.read_text()) or {}
            cfg = cls.model_validate(data)
        else:
            cfg = cls()
        cfg.autodetect_providers()
        return cfg

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

    def autodetect_providers(self) -> None:
        """Enable providers whose credentials are present in the environment.

        Purely additive — never overrides a provider already declared in the
        config file. This makes Specter zero-config: exporting ANTHROPIC_API_KEY,
        OPENAI_API_KEY, or OLLAMA_HOST is enough to start using it. It does not
        change engine behaviour, only which providers are available to route to.
        """
        for name, env in KNOWN_PROVIDER_ENV.items():
            if name not in self.providers and os.environ.get(env):
                base = ""
                # Azure needs the resource endpoint alongside its key.
                if name == "azure-openai":
                    base = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
                    if not base:
                        continue  # key without endpoint isn't usable yet
                self.providers[name] = ProviderConfig(
                    enabled=True, api_key_env=env, base_url=base)
        # Amazon Bedrock: IAM-based, so detect on AWS region presence (no key).
        if "bedrock" not in self.providers and (
                os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
                or os.environ.get("AWS_PROFILE")):
            self.providers["bedrock"] = ProviderConfig(
                enabled=True,
                base_url=os.environ.get("AWS_REGION")
                or os.environ.get("AWS_DEFAULT_REGION", ""),
                default_model="anthropic.claude-3-5-sonnet-20241022-v2:0")
        # Self-hosted / local OpenAI-compatible servers, detected by URL env.
        for name, env, default_model in (
            ("vllm", "VLLM_BASE_URL", ""),
            ("lmstudio", "LMSTUDIO_BASE_URL", ""),
        ):
            url = os.environ.get(env)
            if url and name not in self.providers:
                self.providers[name] = ProviderConfig(
                    enabled=True, base_url=url, default_model=default_model)
        host = os.environ.get("OLLAMA_HOST")
        if host and "ollama" not in self.providers:
            base = host if host.startswith("http") else f"http://{host}"
            self.providers["ollama"] = ProviderConfig(
                enabled=True, base_url=base, default_model="llama3.1:70b")
        # Any OpenAI-compatible endpoint (Groq, Together, OpenRouter, vLLM,
        # LM Studio, LiteLLM, …) — the "use any model" path. Pair with
        # `--model openai-compatible:<model>` or a config `models:` entry.
        if "openai-compatible" not in self.providers:
            base_url = (os.environ.get("SPECTER_LLM_BASE_URL")
                        or os.environ.get("OPENAI_BASE_URL")
                        or os.environ.get("OPENAI_API_BASE"))
            if base_url:
                key_env = ("SPECTER_LLM_API_KEY" if os.environ.get("SPECTER_LLM_API_KEY")
                           else "OPENAI_API_KEY")
                self.providers["openai-compatible"] = ProviderConfig(
                    enabled=True, api_key_env=key_env, base_url=base_url,
                    default_model=(os.environ.get("SPECTER_LLM_MODEL")
                                   or os.environ.get("OPENAI_MODEL", "")))

    @staticmethod
    def detected_env_keys() -> dict[str, str | None]:
        """Known provider -> the env var value currently set (or None)."""
        return {name: os.environ.get(env) for name, env in KNOWN_PROVIDER_ENV.items()}

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
