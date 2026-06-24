"""Cross-phase engagement memory and a lightweight knowledge base.

Earlier today each triage call was isolated. EngagementMemory gives later
phases a condensed view of what's already been observed, so reasoning compounds
instead of restarting. KnowledgeBase is a tiny keyword retriever for injecting
relevant reference notes (CVE summaries, technique tips) into prompts.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EngagementMemory:
    observations: list[str] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    finding_keys: set[str] = field(default_factory=set)

    def note(self, text: str) -> None:
        if text:
            self.observations.append(text.strip())

    def add_host(self, host: str) -> None:
        if host:
            self.hosts.add(host)

    def add_finding(self, title: str, target: str, severity: str) -> bool:
        key = f"{severity}:{title.lower().strip()}@{target}"
        new = key not in self.finding_keys
        self.finding_keys.add(key)
        if new:
            self.note(f"[{severity}] {title} on {target}")
        return new

    def context(self, max_chars: int = 1500) -> str:
        if not self.observations and not self.hosts:
            return "No prior observations."
        lines = []
        if self.hosts:
            lines.append("Known hosts: " + ", ".join(sorted(self.hosts)[:25]))
        lines += [f"- {o}" for o in self.observations[-30:]]
        text = "\n".join(lines)
        return text[:max_chars]


class KnowledgeBase:
    """Minimal keyword retriever over reference entries (no heavy deps)."""

    def __init__(self, entries: list[dict] | None = None) -> None:
        self.entries = entries or []

    def search(self, query: str, k: int = 3) -> list[str]:
        if not query or not self.entries:
            return []
        terms = {t.lower() for t in query.split() if len(t) > 2}
        scored: list[tuple[int, str]] = []
        for e in self.entries:
            text = f"{e.get('title', '')} {e.get('text', '')}"
            score = sum(1 for t in terms if t in text.lower())
            if score:
                scored.append((score, f"{e.get('title', '')}: {e.get('text', '')}"))
        scored.sort(reverse=True)
        return [s for _, s in scored[:k]]
