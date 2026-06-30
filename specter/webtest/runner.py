"""Drives the sub-testers over a session's transactions and emits findings.

Improvements over a naive scanner:
- **Evidence-gated**: only confirmed results (baseline+attack+control+reproduce)
  become findings.
- **Cross-session dedup**: the same (endpoint, tester) is reported once.
- **Audit-friendly**: every finding carries its gate trail in ``evidence``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from specter.engine.models import Finding, Severity
from specter.webtest.model import SessionContext
from specter.webtest.protocol import ConfirmProtocol, Sender
from specter.webtest.testers import ALL_TESTERS, TestResult, Tester


@dataclass
class WebTestReport:
    results: list[TestResult] = field(default_factory=list)
    attempted: int = 0
    confirmed: int = 0

    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            gate_trail = "; ".join(f"{g.name}:{'ok' if g.passed else 'x'} {g.detail}"
                                   for g in r.evidence.gates)
            out.append(Finding(
                title=r.title,
                severity=Severity(r.severity),
                target=r.target,
                description=f"{r.endpoint} — {r.evidence.rationale}",
                evidence=f"payload: {r.payload}\ngates: {gate_trail}",
                phase="webtest",
                confirmed=True,
                verified=True,
                confidence=r.evidence.confidence,
                source="webtest",
                mitre_attack=[r.owasp] if r.owasp else [],
            ))
        return out


class WebTestRunner:
    def __init__(self, sender: Sender, reproduce: int = 2,
                 enabled: list[str] | None = None) -> None:
        self.protocol = ConfirmProtocol(sender, reproduce=reproduce)
        testers = [t() for t in ALL_TESTERS]
        if enabled:
            testers = [t for t in testers if t.name in enabled]
        self.testers: list[Tester] = testers

    def run(self, ctx: SessionContext) -> WebTestReport:
        report = WebTestReport()
        seen: set[tuple[str, str]] = set()
        for txn in ctx.transactions:
            if not ctx.in_scope(txn.request.host):
                continue
            for tester in self.testers:
                try:
                    if not tester.applicable(txn, ctx):
                        continue
                except Exception:
                    continue
                report.attempted += 1
                for result in tester.run(txn, ctx, self.protocol):
                    key = (result.endpoint, result.tester)
                    if key in seen:
                        continue
                    seen.add(key)
                    report.confirmed += 1
                    report.results.append(result)
        return report
