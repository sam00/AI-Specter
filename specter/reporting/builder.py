"""Renders risk, technical, and remediation reports from an Engagement."""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from jinja2 import Environment

from specter.advisor import TaskKind
from specter.engine.models import Engagement, Severity
from specter.reporting import templates as T

Narrator = Callable[[TaskKind, str], str]


class ReportType(str, enum.Enum):
    RISK = "risk"
    TECHNICAL = "technical"
    REMEDIATION = "remediation"
    ALL = "all"


class ReportBuilder:
    def __init__(self, engagement: Engagement, narrate: Narrator | None = None) -> None:
        self.eng = engagement
        self.narrate = narrate or (lambda task, prompt: "")
        self.env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)

    def _fallback(self, task: TaskKind, prompt: str) -> str:
        counts = self.eng.by_severity()
        crit, high = counts["critical"], counts["high"]
        if task == TaskKind.REPORT_RISK:
            return (f"The assessment identified {crit} critical and {high} high-severity "
                    f"issues across {len(self.eng.targets)} target(s). Immediate attention is "
                    "advised for critical items, which present the highest likelihood of "
                    "material business impact.")
        return ("Address findings in severity order. Remediate critical and high items first, "
                "then validate fixes with a focused re-test.")

    def _overall(self) -> str:
        c = self.eng.by_severity()
        if c["critical"]:
            return "CRITICAL"
        if c["high"]:
            return "HIGH"
        if c["medium"]:
            return "MEDIUM"
        if c["low"]:
            return "LOW"
        return "INFORMATIONAL"

    def _ctx(self) -> dict:
        return {
            "eng": self.eng,
            "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "counts": self.eng.by_severity(),
            "bands": {s.value: s.cvss_band for s in Severity},
            "top": self.eng.top_findings(10),
            "findings": sorted(self.eng.findings,
                               key=lambda f: (f.severity.rank, f.cvss), reverse=True),
            "overall": self._overall(),
        }

    def risk(self) -> str:
        ctx = self._ctx()
        prompt = (f"Write a 1-2 paragraph executive risk summary. Findings: {ctx['counts']}, "
                  f"overall {ctx['overall']}, targets {self.eng.targets}.")
        ctx["narrative"] = self.narrate(TaskKind.REPORT_RISK, prompt) or self._fallback(
            TaskKind.REPORT_RISK, prompt)
        return self.env.from_string(T.RISK_TEMPLATE).render(**ctx)

    def technical(self) -> str:
        return self.env.from_string(T.TECH_TEMPLATE).render(**self._ctx())

    def remediation(self) -> str:
        ctx = self._ctx()
        prompt = ("Write a prioritized remediation strategy paragraph for these findings: "
                  f"{[f.title for f in ctx['top']]}.")
        ctx["narrative"] = self.narrate(TaskKind.REPORT_REMEDIATION, prompt) or self._fallback(
            TaskKind.REPORT_REMEDIATION, prompt)
        return self.env.from_string(T.FIX_TEMPLATE).render(**ctx)

    def build(self, kind: ReportType, out_dir: Path) -> list[Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        jobs = {
            ReportType.RISK: ("risk.md", self.risk),
            ReportType.TECHNICAL: ("technical.md", self.technical),
            ReportType.REMEDIATION: ("remediation.md", self.remediation),
        }
        selected = jobs.values() if kind == ReportType.ALL else [jobs[kind]]
        written: list[Path] = []
        for fname, fn in selected:
            path = out_dir / fname
            path.write_text(fn())
            written.append(path)
        return written
