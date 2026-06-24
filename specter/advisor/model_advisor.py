"""Selects the best available LLM for each pentest sub-task.

The advisor scores every registered model against the needs of a task
(reasoning depth, speed, cost, context size) and returns the highest-scoring
model that the user actually has credentials for. This is what lets Specter
mix a cheap fast model for parsing with a deep reasoner for exploit chains.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class TaskKind(str, enum.Enum):
    PLANNING = "planning"            # build the attack plan / phase strategy
    RECON_TRIAGE = "recon_triage"    # summarize scan output, pick leads
    EXPLOIT_REASONING = "exploit"    # chain vulns, craft exploitation logic
    PAYLOAD = "payload"              # generate payloads / commands
    PARSING = "parsing"              # structure raw tool output to JSON
    REPORT_RISK = "report_risk"      # business/risk narrative
    REPORT_TECHNICAL = "report_tech" # technical write-up
    REPORT_REMEDIATION = "report_fix"  # remediation recommendations
    CHAT = "chat"                    # interactive Q&A


@dataclass(frozen=True)
class ModelSpec:
    """Static capability profile for a model (1-10 scales, cost in $/Mtok)."""

    provider: str
    name: str
    reasoning: int
    speed: int
    cost_in: float
    cost_out: float
    context_k: int
    notes: str = ""


@dataclass
class Recommendation:
    task: TaskKind
    provider: str
    model: str
    score: float
    rationale: str
    fallbacks: list[tuple[str, str]] = field(default_factory=list)


# Capability matrix. Tweak freely or override via config; unknown models still
# work — they just get neutral default scores.
MODEL_CATALOG: list[ModelSpec] = [
    ModelSpec("anthropic", "claude-opus-4", 10, 5, 15.0, 75.0, 200, "deepest reasoning"),
    ModelSpec("anthropic", "claude-sonnet-4", 9, 8, 3.0, 15.0, 200, "balanced workhorse"),
    ModelSpec("anthropic", "claude-haiku-3.5", 6, 10, 0.8, 4.0, 200, "fast/cheap"),
    ModelSpec("openai", "gpt-4o", 9, 8, 2.5, 10.0, 128, "strong generalist"),
    ModelSpec("openai", "gpt-4o-mini", 6, 10, 0.15, 0.6, 128, "very cheap parser"),
    ModelSpec("openai", "o3", 10, 4, 10.0, 40.0, 200, "heavy reasoning"),
    ModelSpec("ollama", "llama3.1:70b", 7, 6, 0.0, 0.0, 128, "local, private"),
    ModelSpec("ollama", "qwen2.5:14b", 6, 9, 0.0, 0.0, 64, "local, fast"),
]


def catalog_from_config(models: list[dict] | None) -> list[ModelSpec]:
    """Build a catalog from user config, falling back to the built-in one."""
    if not models:
        return list(MODEL_CATALOG)
    specs: list[ModelSpec] = []
    for m in models:
        try:
            specs.append(ModelSpec(
                provider=str(m["provider"]), name=str(m["name"]),
                reasoning=int(m.get("reasoning", 6)), speed=int(m.get("speed", 6)),
                cost_in=float(m.get("cost_in", 0.0)), cost_out=float(m.get("cost_out", 0.0)),
                context_k=int(m.get("context_k", 128)), notes=str(m.get("notes", ""))))
        except (KeyError, ValueError, TypeError):
            continue
    return specs or list(MODEL_CATALOG)


def discover_models(config, timeout: float = 5.0) -> list[ModelSpec]:
    """Best-effort probe of provider endpoints to validate/augment the catalog.

    Returns discovered models (never raises); used to avoid routing to models
    that don't actually exist for the user's providers.
    """
    import httpx

    found: list[ModelSpec] = []
    provs = getattr(config, "providers", {}) or {}
    for name in ("openai", "openai-compatible"):
        prov = provs.get(name)
        if not prov or not getattr(prov, "enabled", False):
            continue
        key = config.provider_key(name) if hasattr(config, "provider_key") else None
        base = getattr(prov, "base_url", "") or "https://api.openai.com/v1"
        try:
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            r = httpx.get(base.rstrip("/") + "/models", headers=headers, timeout=timeout)
            for m in (r.json() or {}).get("data", [])[:50]:
                found.append(ModelSpec(name, m.get("id", ""), 7, 7, 0.0, 0.0, 128, "discovered"))
        except Exception:
            pass
    prov = provs.get("ollama")
    if prov and getattr(prov, "enabled", False) and getattr(prov, "base_url", ""):
        try:
            r = httpx.get(prov.base_url.rstrip("/") + "/api/tags", timeout=timeout)
            for m in (r.json() or {}).get("models", []):
                found.append(ModelSpec("ollama", m.get("name", ""), 6, 8, 0.0, 0.0, 64, "discovered"))
        except Exception:
            pass
    return found

# Per-task weighting of (reasoning, speed, cost, context).
TASK_WEIGHTS: dict[TaskKind, tuple[float, float, float, float]] = {
    TaskKind.PLANNING: (0.55, 0.10, 0.20, 0.15),
    TaskKind.RECON_TRIAGE: (0.30, 0.35, 0.25, 0.10),
    TaskKind.EXPLOIT_REASONING: (0.65, 0.05, 0.15, 0.15),
    TaskKind.PAYLOAD: (0.45, 0.25, 0.20, 0.10),
    TaskKind.PARSING: (0.10, 0.45, 0.45, 0.00),
    TaskKind.REPORT_RISK: (0.45, 0.15, 0.20, 0.20),
    TaskKind.REPORT_TECHNICAL: (0.40, 0.20, 0.20, 0.20),
    TaskKind.REPORT_REMEDIATION: (0.50, 0.15, 0.20, 0.15),
    TaskKind.CHAT: (0.30, 0.40, 0.25, 0.05),
}

# Profile multipliers nudge the whole engagement toward a posture.
PROFILES = {
    "fast": {"speed": 1.5, "cost": 1.3, "reasoning": 0.8},
    "balanced": {"speed": 1.0, "cost": 1.0, "reasoning": 1.0},
    "deep": {"speed": 0.7, "cost": 0.8, "reasoning": 1.5},
    "frugal": {"speed": 1.1, "cost": 2.0, "reasoning": 0.7},
    "offline": {"speed": 1.0, "cost": 1.0, "reasoning": 1.0},
}


class ModelAdvisor:
    """Ranks models per task given the providers the user can actually use."""

    def __init__(
        self,
        available_providers: set[str],
        profile: str = "balanced",
        catalog: list[ModelSpec] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> None:
        self.available = available_providers
        self.profile = profile if profile in PROFILES else "balanced"
        self.catalog = catalog or MODEL_CATALOG
        self.overrides = overrides or {}

    def _cost_score(self, spec: ModelSpec) -> float:
        # Cheaper = higher score; local models (cost 0) get full marks.
        blended = spec.cost_in + spec.cost_out
        if blended <= 0:
            return 10.0
        return max(1.0, 10.0 - blended / 9.0)

    def _context_score(self, spec: ModelSpec) -> float:
        return min(10.0, spec.context_k / 20.0)

    def _score(self, spec: ModelSpec, task: TaskKind) -> float:
        wr, ws, wc, wk = TASK_WEIGHTS[task]
        mult = PROFILES[self.profile]
        reasoning = spec.reasoning * mult["reasoning"]
        speed = spec.speed * mult["speed"]
        cost = self._cost_score(spec) * mult["cost"]
        context = self._context_score(spec)
        return wr * reasoning + ws * speed + wc * cost + wk * context

    def recommend(self, task: TaskKind) -> Recommendation | None:
        """Return the best in-budget model for a task, or None if none usable."""
        if task.value in self.overrides:
            prov, _, model = self.overrides[task.value].partition(":")
            if prov in self.available:
                return Recommendation(task, prov, model, 99.0, "user override")

        candidates = [s for s in self.catalog if s.provider in self.available]
        if self.profile == "offline":
            candidates = [s for s in candidates if s.provider == "ollama"]
        if not candidates:
            # No scored model is usable; fall back to the offline echo stub so
            # the engine still runs end-to-end without credentials.
            if "echo" in self.available:
                return Recommendation(
                    task, "echo", "echo", 0.0,
                    "no scored models available; using offline echo stub",
                )
            return None

        ranked = sorted(candidates, key=lambda s: self._score(s, task), reverse=True)
        best = ranked[0]
        return Recommendation(
            task=task,
            provider=best.provider,
            model=best.name,
            score=round(self._score(best, task), 2),
            rationale=f"{best.notes or best.name} fits '{task.value}' under '{self.profile}' profile",
            fallbacks=[(s.provider, s.name) for s in ranked[1:3]],
        )

    def plan(self) -> dict[str, Recommendation]:
        """Full task->model routing table for the current engagement."""
        out: dict[str, Recommendation] = {}
        for task in TaskKind:
            rec = self.recommend(task)
            if rec:
                out[task.value] = rec
        return out
