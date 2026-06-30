"""Evidence-gated confirmation protocol for active web testing.

Specter improves on a simple "baseline vs attack" comparison with a
**multi-gate, reproducibility-checked** protocol. A finding is only emitted
when every gate agrees *and* the attack signal reproduces across repeated
trials — which kills the speculative, one-shot false positives that plague
naive scanners.

Gates
-----
- **baseline**   the unmodified request (expected legitimate behaviour)
- **attack**     the mutated request carrying the test payload
- **control**    a negative control that should NOT trigger the signal
- **reproduce**  the attack repeated N times; the signal must hold every time

The protocol is transport-agnostic: it talks to any object implementing
``Sender.send(request, identity) -> HttpResponse``. Tests inject a scripted
sender; production uses :class:`HttpxSender`, which enforces the scope guard.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from specter.webtest.model import HttpRequest, HttpResponse, Identity, SessionContext


class Sender(Protocol):
    def send(self, request: HttpRequest, identity: Identity | None = None) -> HttpResponse:
        ...


@dataclass
class Gate:
    name: str
    passed: bool
    detail: str = ""
    status: int = 0


@dataclass
class Evidence:
    """The audit trail behind a single confirmation attempt."""

    confirmed: bool = False
    confidence: float = 0.0
    rationale: str = ""
    gates: list[Gate] = field(default_factory=list)

    def add(self, gate: Gate) -> None:
        self.gates.append(gate)


# A Signal inspects (baseline_response, candidate_response) and returns
# (triggered, human_detail). Each tester supplies its own.
Signal = Callable[[HttpResponse, HttpResponse], "tuple[bool, str]"]


class ConfirmProtocol:
    """Runs the baseline → attack → control → reproduce gate sequence."""

    def __init__(self, sender: Sender, reproduce: int = 2) -> None:
        self.sender = sender
        self.reproduce = max(1, reproduce)

    def confirm(
        self,
        *,
        baseline_req: HttpRequest,
        attack_req: HttpRequest,
        control_req: HttpRequest | None,
        signal: Signal,
        baseline_identity: Identity | None = None,
        attack_identity: Identity | None = None,
    ) -> Evidence:
        ev = Evidence()

        baseline = self.sender.send(baseline_req, baseline_identity)
        ev.add(Gate("baseline", passed=baseline.error == "",
                    detail=f"{baseline.status} ({baseline.length}b)", status=baseline.status))
        if baseline.error:
            ev.rationale = f"baseline request failed: {baseline.error}"
            return ev

        attack = self.sender.send(attack_req, attack_identity)
        triggered, detail = signal(baseline, attack)
        ev.add(Gate("attack", passed=triggered, detail=detail, status=attack.status))
        if not triggered:
            ev.rationale = "attack did not produce the vulnerability signal"
            return ev

        # Negative control: the signal must NOT fire here, or we're just seeing
        # generic behaviour rather than a real, attack-specific effect.
        if control_req is not None:
            control = self.sender.send(control_req, attack_identity)
            ctrl_triggered, ctrl_detail = signal(baseline, control)
            ev.add(Gate("control", passed=not ctrl_triggered,
                        detail=("control also triggered — likely false positive"
                                if ctrl_triggered else f"control clean: {ctrl_detail}"),
                        status=control.status))
            if ctrl_triggered:
                ev.rationale = "negative control also triggered the signal (false positive)"
                return ev

        # Reproducibility: the attack signal must hold on every repeat.
        holds = 0
        for _ in range(self.reproduce):
            time.sleep(0)  # placeholder hook for rate-limiting/backoff
            rep = self.sender.send(attack_req, attack_identity)
            again, _ = signal(baseline, rep)
            holds += 1 if again else 0
        reproducible = holds == self.reproduce
        ev.add(Gate("reproduce", passed=reproducible,
                    detail=f"signal held {holds}/{self.reproduce} repeats"))
        if not reproducible:
            ev.rationale = "attack signal was not reproducible"
            return ev

        ev.confirmed = True
        # Confidence scales with how many corroborating gates passed.
        passed = sum(1 for g in ev.gates if g.passed)
        ev.confidence = round(min(1.0, 0.6 + 0.1 * passed), 2)
        ev.rationale = detail
        return ev


class HttpxSender:
    """Live sender backed by httpx, with an enforced scope allowlist."""

    def __init__(self, ctx: SessionContext, timeout: float = 15.0,
                 verify_tls: bool = True) -> None:
        self.ctx = ctx
        self.timeout = timeout
        self.verify_tls = verify_tls

    def send(self, request: HttpRequest, identity: Identity | None = None) -> HttpResponse:
        import httpx
        if not self.ctx.in_scope(request.host):
            return HttpResponse(error="BLOCKED: target out of authorized scope")
        headers = dict(request.headers)
        if identity:
            headers.update(identity.headers)
        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify_tls,
                              follow_redirects=False) as client:
                resp = client.request(request.method, request.url,
                                       headers=headers, content=request.body or None)
            return HttpResponse(
                status=resp.status_code,
                headers={k: v for k, v in resp.headers.items()},
                body=resp.text,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception as e:  # network errors are data, not crashes
            return HttpResponse(error=str(e), elapsed_ms=(time.perf_counter() - t0) * 1000)
