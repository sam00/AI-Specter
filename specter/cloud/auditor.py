"""Cloud posture auditing against a normalized, provider-agnostic state model.

The auditor evaluates *checks* (CIS-aligned) against a :class:`CloudState` that
is collected once and shared across providers. State can come from:

- a live collector (AWS via boto3 — optional dependency), or
- an injected/simulated state (offline demo + unit tests).

This separation keeps the checks pure and fully testable without cloud creds,
and lets the same check logic run across AWS, Azure, and GCP by normalizing
their resources into a common shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from specter.engine.models import Finding, Severity


@dataclass
class CloudState:
    """Normalized snapshot of cloud resources across one or more providers."""

    provider: str = "aws"            # aws | azure | gcp
    account: str = ""
    iam_principals: list[dict] = field(default_factory=list)
    storage_buckets: list[dict] = field(default_factory=list)
    network_rules: list[dict] = field(default_factory=list)
    logging: dict = field(default_factory=dict)
    encryption: dict = field(default_factory=dict)
    compute: list[dict] = field(default_factory=list)


@dataclass
class CloudCheck:
    id: str
    title: str
    severity: str
    providers: tuple[str, ...]
    cis_ref: str
    remediation: str
    fn: Callable[[CloudState], list[str]]  # returns list of human-readable issues

    def applies_to(self, provider: str) -> bool:
        return "*" in self.providers or provider in self.providers


# --- Check implementations (pure functions over CloudState) -----------------
def _chk_wildcard_iam(state: CloudState) -> list[str]:
    issues = []
    for p in state.iam_principals:
        for stmt in p.get("policies", []):
            if stmt.get("Effect") == "Allow" and (
                    "*" in _aslist(stmt.get("Action")) and "*" in _aslist(stmt.get("Resource"))):
                issues.append(f"principal '{p.get('name')}' has Action:* on Resource:*")
    return issues


def _chk_stale_keys(state: CloudState) -> list[str]:
    issues = []
    for p in state.iam_principals:
        for key in p.get("access_keys", []):
            if key.get("age_days", 0) > 90 and key.get("active", True):
                issues.append(f"'{p.get('name')}' active key age {key['age_days']}d (>90)")
    return issues


def _chk_mfa(state: CloudState) -> list[str]:
    return [f"console user '{p['name']}' has no MFA"
            for p in state.iam_principals
            if p.get("console_access") and not p.get("mfa_enabled")]


def _chk_public_buckets(state: CloudState) -> list[str]:
    return [f"bucket '{b.get('name')}' is publicly accessible"
            for b in state.storage_buckets if b.get("public")]


def _chk_unencrypted_buckets(state: CloudState) -> list[str]:
    return [f"bucket '{b.get('name')}' is not encrypted at rest"
            for b in state.storage_buckets if not b.get("encrypted", False)]


def _chk_open_ingress(state: CloudState) -> list[str]:
    issues = []
    risky = {22, 3389, 3306, 5432, 6379, 27017, 9200, 1433}
    for r in state.network_rules:
        if r.get("direction", "ingress") != "ingress":
            continue
        if r.get("source") in ("0.0.0.0/0", "::/0") and r.get("port") in risky:
            issues.append(f"rule '{r.get('name')}' exposes port {r['port']} to the internet")
    return issues


def _chk_logging(state: CloudState) -> list[str]:
    issues = []
    if not state.logging.get("audit_trail_enabled"):
        issues.append("no account-wide audit trail (CloudTrail/Activity Log) enabled")
    if state.logging.get("audit_trail_enabled") and not state.logging.get("log_integrity"):
        issues.append("audit log file integrity validation is disabled")
    return issues


def _chk_public_compute(state: CloudState) -> list[str]:
    return [f"instance '{c.get('name')}' has a public IP and open management port"
            for c in state.compute if c.get("public_ip") and c.get("mgmt_open")]


def _aslist(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


CHECKS: list[CloudCheck] = [
    CloudCheck("IAM-001", "Over-permissive IAM policy (Action:* on Resource:*)", "high",
               ("aws", "azure", "gcp"), "CIS 1.16",
               "Scope policies to least privilege; remove wildcard actions/resources.",
               _chk_wildcard_iam),
    CloudCheck("IAM-002", "Stale active access keys (>90 days)", "medium",
               ("aws",), "CIS 1.14", "Rotate or disable access keys older than 90 days.",
               _chk_stale_keys),
    CloudCheck("IAM-003", "Console user without MFA", "high",
               ("aws", "azure", "gcp"), "CIS 1.2",
               "Enforce MFA for all principals with console access.", _chk_mfa),
    CloudCheck("STOR-001", "Publicly accessible storage bucket", "critical",
               ("aws", "azure", "gcp"), "CIS 3.x",
               "Block public access; use signed URLs or private access only.",
               _chk_public_buckets),
    CloudCheck("STOR-002", "Storage bucket not encrypted at rest", "medium",
               ("aws", "azure", "gcp"), "CIS 3.x",
               "Enable default server-side / CMK encryption on all buckets.",
               _chk_unencrypted_buckets),
    CloudCheck("NET-001", "Security group exposes sensitive port to 0.0.0.0/0", "high",
               ("aws", "azure", "gcp"), "CIS 5.2",
               "Restrict ingress to known CIDRs; front with a bastion/VPN.",
               _chk_open_ingress),
    CloudCheck("LOG-001", "Account audit logging gaps", "medium",
               ("aws", "azure", "gcp"), "CIS 3.1",
               "Enable a multi-region audit trail with log file integrity validation.",
               _chk_logging),
    CloudCheck("CMP-001", "Public instance with exposed management port", "high",
               ("aws", "azure", "gcp"), "CIS 5.x",
               "Remove public IPs from management interfaces; use SSM/Bastion.",
               _chk_public_compute),
]


class CloudAuditor:
    def __init__(self, checks: list[CloudCheck] | None = None) -> None:
        self.checks = checks or CHECKS

    def audit(self, state: CloudState) -> list[Finding]:
        findings: list[Finding] = []
        for check in self.checks:
            if not check.applies_to(state.provider):
                continue
            for issue in check.fn(state):
                findings.append(Finding(
                    title=f"[{check.id}] {check.title}",
                    severity=Severity(check.severity),
                    target=f"{state.provider}:{state.account or 'account'}",
                    description=issue,
                    evidence=f"check {check.id} ({check.cis_ref})",
                    remediation=check.remediation,
                    phase="cloud-audit",
                    confirmed=True,
                    verified=True,
                    confidence=0.9,
                    source="cloud",
                    mitre_attack=[check.cis_ref],
                ))
        return findings


def demo_state(provider: str = "aws") -> CloudState:
    """A deliberately-misconfigured state for offline demos and tests."""
    return CloudState(
        provider=provider,
        account="123456789012",
        iam_principals=[
            {"name": "ci-deployer", "console_access": False,
             "policies": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
             "access_keys": [{"age_days": 220, "active": True}]},
            {"name": "alice", "console_access": True, "mfa_enabled": False,
             "policies": [], "access_keys": []},
        ],
        storage_buckets=[
            {"name": "public-assets", "public": True, "encrypted": False},
            {"name": "app-data", "public": False, "encrypted": True},
        ],
        network_rules=[
            {"name": "sg-web", "direction": "ingress", "source": "0.0.0.0/0", "port": 22},
            {"name": "sg-db", "direction": "ingress", "source": "10.0.0.0/8", "port": 5432},
        ],
        logging={"audit_trail_enabled": True, "log_integrity": False},
        compute=[{"name": "jump-1", "public_ip": True, "mgmt_open": True}],
    )
