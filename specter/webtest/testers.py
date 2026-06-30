"""The eight active web-application sub-testers.

Each tester is intentionally *safe by construction*: it sends benign,
non-destructive probes and relies on the differential, multi-gate
:class:`~specter.webtest.protocol.ConfirmProtocol` for proof. No payload here
attempts data exfiltration, deletion, or denial of service.

A tester implements:
- ``applicable(txn, ctx)`` — cheap check for whether this txn is worth testing
- ``run(txn, ctx, protocol)`` — yields :class:`TestResult` only for *confirmed*
  findings, each carrying the full :class:`Evidence` gate trail.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from specter.webtest.model import HttpRequest, HttpResponse, SessionContext, Transaction
from specter.webtest.protocol import ConfirmProtocol, Evidence


@dataclass
class TestResult:
    title: str
    severity: str             # info|low|medium|high|critical
    target: str
    endpoint: str
    tester: str
    owasp: str
    payload: str
    evidence: Evidence = field(default_factory=Evidence)


def _similar(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


# Signatures used by individual testers --------------------------------------
SQL_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|psql:|SQLSTATE|sqlite3\.|"
    r"unclosed quotation mark|pg_query|near \".*\": syntax error)", re.I)
PASSWD_LINE = re.compile(r"root:.*:0:0:")
WIN_INI = re.compile(r"\[(extensions|fonts|files)\]", re.I)


class Tester:
    name = "base"
    title = "Generic issue"
    severity = "medium"
    owasp = ""

    def applicable(self, txn: Transaction, ctx: SessionContext) -> bool:
        return False

    def run(self, txn: Transaction, ctx: SessionContext,
            protocol: ConfirmProtocol) -> list[TestResult]:
        return []

    # convenience for subclasses
    def _result(self, txn: Transaction, payload: str, ev: Evidence) -> TestResult:
        return TestResult(
            title=self.title, severity=self.severity, target=txn.request.host,
            endpoint=f"{txn.request.method} {txn.request.path}", tester=self.name,
            owasp=self.owasp, payload=payload, evidence=ev)


class IDORTester(Tester):
    """Object-level access control: can a low-priv identity read another's object?"""

    name = "idor"
    title = "Insecure Direct Object Reference (BOLA)"
    severity = "high"
    owasp = "API1:2023 / WSTG-ATHZ-04"

    def applicable(self, txn, ctx) -> bool:
        return bool(SessionContext.object_ids(txn.request)) and len(ctx.identities) >= 2

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        owner = ctx.highest_privilege() or ctx.identities.get(txn.identity)
        attacker = ctx.lowest_authenticated()
        if not owner or not attacker or owner.name == attacker.name:
            return []
        baseline = txn.request  # owner reads their own object
        attack = txn.request.copy()  # attacker requests the same object id
        # Negative control: attacker requests an id that nobody owns.
        control = self._swap_id(txn.request, "999999999")

        def signal(base: HttpResponse, cand: HttpResponse):
            if not cand.ok:
                return False, f"denied ({cand.status})"
            sim = _similar(base.body, cand.body)
            return sim > 0.9, f"attacker read owner object (status {cand.status}, sim {sim:.2f})"

        ev = protocol.confirm(baseline_req=baseline, attack_req=attack, control_req=control,
                              signal=signal, baseline_identity=owner, attack_identity=attacker)
        return [self._result(txn, f"id={SessionContext.object_ids(txn.request)}", ev)] \
            if ev.confirmed else []

    @staticmethod
    def _swap_id(req: HttpRequest, new: str) -> HttpRequest:
        r = req.copy()
        r.url = re.sub(r"/(\d{1,12})(?=/|$|\?)", f"/{new}", r.url, count=1)
        return r


class AuthzBypassTester(Tester):
    """Vertical privilege escalation: low-priv hitting a high-priv endpoint."""

    name = "authz-bypass"
    title = "Broken Function-Level Authorization (privilege escalation)"
    severity = "high"
    owasp = "API5:2023 / WSTG-ATHZ-02"

    _PRIV = re.compile(r"/(admin|internal|manage|console|settings|users?/\d+/(role|perm))", re.I)

    def applicable(self, txn, ctx) -> bool:
        return bool(self._PRIV.search(txn.request.path)) and len(ctx.identities) >= 2

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        high = ctx.highest_privilege()
        low = ctx.lowest_authenticated()
        if not high or not low or high.name == low.name:
            return []

        def signal(base: HttpResponse, cand: HttpResponse):
            ok = cand.ok and _similar(base.body, cand.body) > 0.8
            return ok, f"low-priv reached privileged endpoint (status {cand.status})"

        ev = protocol.confirm(
            baseline_req=txn.request, attack_req=txn.request.copy(),
            control_req=txn.request.copy(), signal=signal,
            baseline_identity=high, attack_identity=low)
        # control here uses anonymous: it should be denied
        if ev.confirmed:
            return [self._result(txn, "low-privilege access to privileged route", ev)]
        return []


class MassAssignmentTester(Tester):
    """Unexpected writable fields injected into a JSON body (role/price/balance...)."""

    name = "mass-assignment"
    title = "Mass Assignment / Excessive Data Exposure"
    severity = "high"
    owasp = "API3:2023 / WSTG-INPV"
    SENSITIVE = {"role": "admin", "is_admin": True, "admin": True, "isAdmin": True,
                 "balance": 999999, "price": 0, "verified": True, "userId": 1}

    def applicable(self, txn, ctx) -> bool:
        return txn.request.method in ("POST", "PUT", "PATCH") and txn.request.json_body() is not None

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        body = txn.request.json_body() or {}
        injected = {**body, **self.SENSITIVE}
        attack = txn.request.with_json(injected)
        control = txn.request.with_json({**body, "spctr_nonsense_field": "x"})

        def signal(base: HttpResponse, cand: HttpResponse):
            if not cand.ok:
                return False, f"rejected ({cand.status})"
            # Differential proof: a privileged field is reflected in the response
            # here but not in the baseline. Generic 200s are NOT enough — that's
            # what produces false positives in naive scanners.
            reflected = any(
                str(v) in cand.body and str(v) not in base.body
                for k, v in self.SENSITIVE.items() if k in ("role", "balance", "verified"))
            return reflected, ("server reflected privileged field it should have stripped"
                               if reflected else "no privileged field reflected")

        ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                              control_req=control, signal=signal)
        return [self._result(txn, "injected fields: role,is_admin,balance,price", ev)] \
            if ev.confirmed else []


class InjectionTester(Tester):
    """SQL / template injection via reflected error or differential boolean test."""

    name = "injection"
    title = "Injection (SQL/Template)"
    severity = "critical"
    owasp = "API8 / WSTG-INPV-05"
    PAYLOAD = "'\"`{{7*7}}"  # error-provoking + SSTI canary, non-destructive

    def applicable(self, txn, ctx) -> bool:
        return bool(txn.request.query_params())

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        results: list[TestResult] = []
        params = txn.request.query_params()
        for key in params:
            attack = txn.request.with_query({**params, key: params[key] + self.PAYLOAD})
            control = txn.request.with_query({**params, key: params[key] + "SPCTRsafe"})

            def signal(base: HttpResponse, cand: HttpResponse, _k=key):
                if SQL_ERRORS.search(cand.body) and not SQL_ERRORS.search(base.body):
                    return True, f"SQL error signature surfaced via '{_k}'"
                if "49" in cand.body and "{{7*7}}" not in cand.body and "49" not in base.body:
                    return True, f"template expression 7*7 evaluated via '{_k}' (SSTI)"
                return False, "no injection signal"

            ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                                  control_req=control, signal=signal)
            if ev.confirmed:
                results.append(self._result(txn, f"param '{key}' = {self.PAYLOAD}", ev))
        return results


class AuthTester(Tester):
    """Authentication weaknesses: token still accepted after tampering/removal."""

    name = "auth"
    title = "Broken Authentication (token validation)"
    severity = "high"
    owasp = "API2:2023 / WSTG-ATHN"

    def applicable(self, txn, ctx) -> bool:
        h = txn.request.headers
        return any(k.lower() in ("authorization", "cookie") for k in h)

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        # Attack: strip the signature segment of a JWT (alg/none-style tamper).
        attack = txn.request.copy()
        for k in list(attack.headers):
            if k.lower() == "authorization" and attack.headers[k].count(".") == 2:
                head, payload, _ = attack.headers[k].split(".")
                attack.headers[k] = f"{head}.{payload}."  # drop signature
        # Control: a clearly bogus token must be rejected.
        control = txn.request.copy()
        for k in list(control.headers):
            if k.lower() == "authorization":
                control.headers[k] = "Bearer spctr.invalid.token"

        def signal(base: HttpResponse, cand: HttpResponse):
            ok = cand.ok and _similar(base.body, cand.body) > 0.8
            return ok, f"request authorized with unsigned token (status {cand.status})"

        if attack.headers == txn.request.headers:
            return []  # nothing tamperable
        ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                              control_req=control, signal=signal)
        return [self._result(txn, "JWT signature stripped (alg:none-style)", ev)] \
            if ev.confirmed else []


class BusinessLogicTester(Tester):
    """Price/quantity manipulation: negative or zero values accepted."""

    name = "business-logic"
    title = "Business Logic Flaw (value manipulation)"
    severity = "high"
    owasp = "API6:2023 / WSTG-BUSL"
    NUMERIC = ("price", "amount", "quantity", "qty", "total", "discount", "balance")

    def applicable(self, txn, ctx) -> bool:
        body = txn.request.json_body()
        return bool(body) and any(k in body for k in self.NUMERIC)

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        body = txn.request.json_body() or {}
        tampered = {k: (-1 if k in self.NUMERIC and isinstance(v, (int, float)) else v)
                    for k, v in body.items()}
        attack = txn.request.with_json(tampered)
        control = txn.request.with_json(body)  # original values, must be clean

        def signal(base: HttpResponse, cand: HttpResponse):
            return cand.status in (200, 201), (
                f"negative value accepted (status {cand.status})")

        ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                              control_req=control, signal=signal)
        return [self._result(txn, "negative numeric values (price/quantity)", ev)] \
            if ev.confirmed else []


class SSRFTester(Tester):
    """Server-side request forgery via user-controlled URL/redirect params."""

    name = "ssrf"
    title = "Server-Side Request Forgery (SSRF)"
    severity = "high"
    owasp = "API7:2023 / WSTG-INPV-19"
    URL_PARAMS = ("url", "uri", "next", "redirect", "dest", "callback", "image",
                  "img", "src", "target", "return", "feed", "webhook")
    # Link-local metadata endpoint — a canonical SSRF canary (read-only probe).
    CANARY = "http://169.254.169.254/latest/meta-data/"

    def applicable(self, txn, ctx) -> bool:
        return any(k.lower() in self.URL_PARAMS for k in txn.request.query_params())

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        results: list[TestResult] = []
        params = txn.request.query_params()
        for key in params:
            if key.lower() not in self.URL_PARAMS:
                continue
            attack = txn.request.with_query({**params, key: self.CANARY})
            control = txn.request.with_query({**params, key: "http://spctr.invalid/"})

            def signal(base: HttpResponse, cand: HttpResponse):
                hit = ("ami-id" in cand.body or "instance-id" in cand.body
                       or "iam/security-credentials" in cand.body)
                return hit, "fetched cloud metadata content (SSRF)"

            ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                                  control_req=control, signal=signal)
            if ev.confirmed:
                results.append(self._result(txn, f"param '{key}' -> metadata canary", ev))
        return results


class FileAttackTester(Tester):
    """Path traversal in file/path parameters (read-only /etc/passwd canary)."""

    name = "file-attacks"
    title = "Path Traversal / Local File Disclosure"
    severity = "high"
    owasp = "WSTG-ATHZ-01 / WSTG-INPV-11"
    FILE_PARAMS = ("file", "path", "template", "include", "page", "doc",
                   "download", "filename", "view")
    TRAVERSAL = "../../../../../../etc/passwd"

    def applicable(self, txn, ctx) -> bool:
        return any(k.lower() in self.FILE_PARAMS for k in txn.request.query_params())

    def run(self, txn, ctx, protocol) -> list[TestResult]:
        results: list[TestResult] = []
        params = txn.request.query_params()
        for key in params:
            if key.lower() not in self.FILE_PARAMS:
                continue
            attack = txn.request.with_query({**params, key: self.TRAVERSAL})
            control = txn.request.with_query({**params, key: params[key]})

            def signal(base: HttpResponse, cand: HttpResponse):
                if PASSWD_LINE.search(cand.body) and not PASSWD_LINE.search(base.body):
                    return True, "read /etc/passwd via traversal"
                if WIN_INI.search(cand.body) and not WIN_INI.search(base.body):
                    return True, "read Windows system file via traversal"
                return False, "no file disclosure"

            ev = protocol.confirm(baseline_req=txn.request, attack_req=attack,
                                  control_req=control, signal=signal)
            if ev.confirmed:
                results.append(self._result(txn, f"param '{key}' = {self.TRAVERSAL}", ev))
        return results


ALL_TESTERS: list[type[Tester]] = [
    IDORTester, AuthzBypassTester, MassAssignmentTester, InjectionTester,
    AuthTester, BusinessLogicTester, SSRFTester, FileAttackTester,
]
