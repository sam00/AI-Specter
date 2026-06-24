"""Core data models shared across phases and reporting."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return uuid.uuid4().hex[:12]


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @property
    def cvss_band(self) -> str:
        return {
            "info": "0.0", "low": "0.1-3.9", "medium": "4.0-6.9",
            "high": "7.0-8.9", "critical": "9.0-10.0",
        }[self.value]


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""


class Host(BaseModel):
    address: str
    hostname: str = ""
    os: str = ""
    services: list[Service] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=_id)
    title: str
    severity: Severity = Severity.INFO
    target: str = ""
    cvss: float = 0.0
    cve: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    phase: str = ""
    confirmed: bool = False
    verified: bool = False
    confidence: float = 0.0
    status: str = "open"          # open | triage | confirmed | dismissed
    assignee: str = ""
    comments: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    source: str = ""              # parser | llm | manual
    created_at: str = Field(default_factory=_now)


class Step(BaseModel):
    phase: str
    action: str
    tool: str = ""
    target: str = ""
    model: str = ""
    summary: str = ""
    started_at: str = Field(default_factory=_now)
    ok: bool = True


class Engagement(BaseModel):
    id: str = Field(default_factory=_id)
    name: str = "specter-engagement"
    profile: str = "balanced"
    targets: list[str] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    steps: list[Step] = Field(default_factory=list)
    routing: dict[str, str] = Field(default_factory=dict)
    clusters: list[dict] = Field(default_factory=list)
    actor: str = ""
    log_file: str = ""
    created_at: str = Field(default_factory=_now)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def add_step(self, s: Step) -> None:
        self.steps.append(s)

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def top_findings(self, n: int = 10) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.cvss), reverse=True)[:n]
