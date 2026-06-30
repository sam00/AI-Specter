"""HTTP transaction + live session-context models for active web testing.

These are deliberately transport-light dataclasses so the test engine never
depends on a live browser. Transactions can come from the intercepting proxy,
a crawler, an imported HAR file, or be hand-built in unit tests.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class HttpRequest:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def copy(self) -> "HttpRequest":
        return HttpRequest(self.method, self.url, dict(self.headers), self.body)

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    def query_params(self) -> dict[str, str]:
        return dict(parse_qsl(urlsplit(self.url).query, keep_blank_values=True))

    def with_query(self, params: dict[str, str]) -> "HttpRequest":
        parts = urlsplit(self.url)
        new = parts._replace(query=urlencode(params))
        r = self.copy()
        r.url = urlunsplit(new)
        return r

    def json_body(self) -> dict | None:
        ctype = self.headers.get("Content-Type", self.headers.get("content-type", ""))
        if "json" not in ctype.lower() and not self.body.strip().startswith("{"):
            return None
        try:
            data = json.loads(self.body)
            return data if isinstance(data, dict) else None
        except (ValueError, TypeError):
            return None

    def with_json(self, data: dict) -> "HttpRequest":
        r = self.copy()
        r.body = json.dumps(data)
        r.headers = {**r.headers, "Content-Type": "application/json"}
        return r


@dataclass
class HttpResponse:
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def length(self) -> int:
        return len(self.body or "")


@dataclass
class Transaction:
    """A captured request/response pair plus the identity that produced it."""

    request: HttpRequest
    response: HttpResponse | None = None
    identity: str = ""  # which credential/role made this request (see SessionContext)


@dataclass
class Identity:
    """A discovered principal: a role name + the auth material to act as it."""

    name: str
    role: str = "user"          # e.g. user | admin | anonymous
    headers: dict[str, str] = field(default_factory=dict)  # e.g. Authorization, Cookie
    privilege: int = 1          # 0 = anonymous, 1 = user, 2+ = elevated


_ID_IN_PATH = re.compile(r"/(\d{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})(?=/|$)")


@dataclass
class SessionContext:
    """Live map of what we learned while browsing/crawling the target.

    The sub-testers read from this directly: they know which identity is a
    high-privilege baseline and which is a low-privilege attacker, which
    endpoints exist, and which object identifiers each identity legitimately
    owns. This is the "improved HackBrowser" session context — populated by the
    proxy, a crawler, a HAR import, or tests.
    """

    base_targets: list[str] = field(default_factory=list)
    identities: dict[str, Identity] = field(default_factory=dict)
    transactions: list[Transaction] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)

    def add_identity(self, ident: Identity) -> None:
        self.identities[ident.name] = ident

    def add_transaction(self, txn: Transaction) -> None:
        self.transactions.append(txn)
        self.endpoints.add(f"{txn.request.method} {txn.request.path}")

    def in_scope(self, host: str) -> bool:
        if not self.base_targets:
            return True
        return any(host == t or host.endswith("." + t) for t in self.base_targets)

    def highest_privilege(self) -> Identity | None:
        if not self.identities:
            return None
        return max(self.identities.values(), key=lambda i: i.privilege)

    def lowest_authenticated(self) -> Identity | None:
        auth = [i for i in self.identities.values() if i.privilege >= 1]
        return min(auth, key=lambda i: i.privilege) if auth else None

    def anonymous(self) -> Identity:
        return self.identities.get("anonymous", Identity("anonymous", "anonymous", privilege=0))

    @staticmethod
    def object_ids(req: HttpRequest) -> list[str]:
        """Identifiers that look like object references in path or query."""
        ids = [m.group(1) for m in _ID_IN_PATH.finditer(req.path)]
        for k, v in req.query_params().items():
            if k.lower() in ("id", "uid", "user", "user_id", "account", "order", "doc") and v:
                ids.append(v)
        return ids
