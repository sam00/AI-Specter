"""Offline tests for the active web-testing engine.

A scripted sender models a vulnerable app so the evidence-gated protocol and
each tester can be exercised with zero network access.
"""
from __future__ import annotations

import json

from specter.webtest import (
    ConfirmProtocol,
    HttpRequest,
    HttpResponse,
    Identity,
    SessionContext,
    Transaction,
    WebTestRunner,
)
from specter.webtest.testers import IDORTester, InjectionTester, MassAssignmentTester


class ScriptedSender:
    """Sender driven by a callable so tests fully control responses."""

    def __init__(self, fn):
        self.fn = fn
        self.calls = 0

    def send(self, request: HttpRequest, identity: Identity | None = None) -> HttpResponse:
        self.calls += 1
        return self.fn(request, identity)


def _ctx_two_identities() -> SessionContext:
    ctx = SessionContext(base_targets=["app.example.com"])
    ctx.add_identity(Identity("owner", role="admin", headers={"Cookie": "s=owner"}, privilege=2))
    ctx.add_identity(Identity("attacker", role="user", headers={"Cookie": "s=atk"}, privilege=1))
    return ctx


def test_scope_guard_blocks_out_of_scope():
    from specter.webtest import HttpxSender
    ctx = SessionContext(base_targets=["app.example.com"])
    sender = HttpxSender(ctx)
    resp = sender.send(HttpRequest("GET", "http://evil.test/"))
    assert "BLOCKED" in resp.error


def test_idor_confirmed_when_attacker_reads_owner_object():
    ctx = _ctx_two_identities()
    req = HttpRequest("GET", "http://app.example.com/api/orders/1001")
    ctx.add_transaction(Transaction(request=req, identity="owner"))

    owner_body = json.dumps({"order": 1001, "total": 42, "owner": "owner"})

    def app(request: HttpRequest, identity: Identity | None):
        # The non-existent control id is denied; the real object is readable by anyone.
        if "999999999" in request.url:
            return HttpResponse(status=404, body="not found")
        return HttpResponse(status=200, body=owner_body)

    sender = ScriptedSender(app)
    results = IDORTester().run(ctx.transactions[0], ctx, ConfirmProtocol(sender, reproduce=2))
    assert len(results) == 1
    ev = results[0].evidence
    assert ev.confirmed and ev.confidence > 0.6
    assert [g.name for g in ev.gates] == ["baseline", "attack", "control", "reproduce"]


def test_idor_not_reported_when_control_also_triggers():
    ctx = _ctx_two_identities()
    req = HttpRequest("GET", "http://app.example.com/api/orders/1001")
    ctx.add_transaction(Transaction(request=req, identity="owner"))

    # Everything returns the same 200 body — including the control — so the
    # negative control should veto the finding (no real access-control flaw).
    def app(request: HttpRequest, identity: Identity | None):
        return HttpResponse(status=200, body="same body for everything")

    sender = ScriptedSender(app)
    results = IDORTester().run(ctx.transactions[0], ctx, ConfirmProtocol(sender, reproduce=2))
    assert results == []


def test_injection_detected_via_sql_error_signature():
    ctx = SessionContext(base_targets=["app.example.com"])
    req = HttpRequest("GET", "http://app.example.com/search?q=phone")
    ctx.add_transaction(Transaction(request=req, identity="anonymous"))

    def app(request: HttpRequest, identity: Identity | None):
        q = request.query_params().get("q", "")
        if "'" in q or "`" in q:
            return HttpResponse(status=500, body="You have an error in your SQL syntax near '''")
        return HttpResponse(status=200, body="results for phone")

    sender = ScriptedSender(app)
    results = InjectionTester().run(ctx.transactions[0], ctx, ConfirmProtocol(sender, reproduce=1))
    assert any("SQL" in r.evidence.rationale for r in results)


def test_mass_assignment_confirmed_on_reflected_role():
    ctx = SessionContext(base_targets=["app.example.com"])
    req = HttpRequest("POST", "http://app.example.com/api/profile",
                      headers={"Content-Type": "application/json"},
                      body=json.dumps({"name": "joe"}))
    ctx.add_transaction(Transaction(request=req, identity="user"))

    def app(request: HttpRequest, identity: Identity | None):
        data = request.json_body() or {}
        if data.get("role") == "admin":
            return HttpResponse(status=200, body=json.dumps({"name": "joe", "role": "admin"}))
        return HttpResponse(status=200, body=json.dumps({"name": "joe"}))

    sender = ScriptedSender(app)
    results = MassAssignmentTester().run(ctx.transactions[0], ctx,
                                         ConfirmProtocol(sender, reproduce=1))
    assert len(results) == 1 and results[0].evidence.confirmed


def test_runner_dedups_and_builds_findings():
    ctx = _ctx_two_identities()
    req = HttpRequest("GET", "http://app.example.com/api/orders/1001")
    # two identical transactions should yield a single deduped finding
    ctx.add_transaction(Transaction(request=req, identity="owner"))
    ctx.add_transaction(Transaction(request=req.copy(), identity="owner"))

    owner_body = json.dumps({"order": 1001})

    def app(request: HttpRequest, identity: Identity | None):
        if "999999999" in request.url:
            return HttpResponse(status=404, body="nope")
        return HttpResponse(status=200, body=owner_body)

    runner = WebTestRunner(ScriptedSender(app), reproduce=1, enabled=["idor"])
    report = runner.run(ctx)
    findings = report.findings()
    assert report.confirmed == 1
    assert len(findings) == 1
    assert findings[0].source == "webtest" and findings[0].verified


def test_har_import_builds_session_context(tmp_path):
    from specter.webtest import har_to_context
    har = {
        "log": {"entries": [
            {"request": {"method": "GET", "url": "http://app.example.com/admin",
                         "headers": [{"name": "Cookie", "value": "s=admintoken"}]},
             "response": {"status": 200, "headers": [], "content": {"text": "admin panel"}},
             "time": 12.0},
            {"request": {"method": "GET", "url": "http://app.example.com/home",
                         "headers": [{"name": "Cookie", "value": "s=usertoken"}]},
             "response": {"status": 200, "headers": [], "content": {"text": "home"}},
             "time": 8.0},
        ]}
    }
    path = tmp_path / "session.har"
    path.write_text(json.dumps(har))
    ctx = har_to_context(path, base_targets=["app.example.com"])
    assert len(ctx.transactions) == 2
    # the identity that reached /admin successfully is ranked as elevated
    high = ctx.highest_privilege()
    assert high is not None and high.privilege >= 2
