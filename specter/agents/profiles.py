"""Domain-specialized agent profiles.

Specter's engine is provider-agnostic; an *agent profile* layers domain
methodology on top of it. Each profile carries the recognised testing
framework (OWASP WSTG, OWASP API Top 10, MASTG/MASVS, CIS Benchmarks,
MITRE ATT&CK), the tools the agent should prefer, a default objective, and a
methodology checklist the agent is steered to work through.

This is deliberately *data*, not a re-implementation of an LLM wrapper: the
profile customises the existing ``AgentRunner`` system prompt and tool subset,
so all of Specter's scope guard, budget, caching, and audit behaviour is reused
unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentProfile:
    """A domain specialist configuration for the autonomous agent loop."""

    name: str
    title: str
    domain: str
    methodology: str
    description: str
    tools: list[str] = field(default_factory=list)
    default_objective: str = ""
    checklist: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def system_addendum(self) -> str:
        """Methodology context injected into the agent system prompt."""
        items = "\n".join(f"  - {c}" for c in self.checklist)
        return (
            f"\n\nYou are operating as the **{self.title}** specialist "
            f"({self.domain}). Follow the {self.methodology} methodology. "
            f"Work systematically through this checklist, choosing the highest-"
            f"signal item next and skipping anything out of scope:\n{items}\n"
            "Only report a finding when you have concrete, reproducible evidence."
        )


AGENT_PROFILES: dict[str, AgentProfile] = {}


def register(profile: AgentProfile) -> None:
    AGENT_PROFILES[profile.name] = profile


def get_profile(name: str) -> AgentProfile | None:
    return AGENT_PROFILES.get(name)


def profile_names() -> list[str]:
    return list(AGENT_PROFILES)


register(AgentProfile(
    name="general",
    title="General Operator",
    domain="full-scope",
    methodology="PTES (Penetration Testing Execution Standard)",
    description="Primary all-rounder: recon, enumeration, vuln discovery, exploitation, reporting.",
    tools=["nmap", "httpx", "whatweb", "naabu", "nmap-full", "ffuf", "katana",
           "nuclei", "nikto", "testssl", "wpscan"],
    default_objective="find and prioritize exploitable risk across the authorized scope",
    checklist=[
        "Passive + active recon to map the attack surface",
        "Service/version enumeration and tech fingerprinting",
        "Template-based vulnerability scanning of exposed services",
        "Triage and correlate findings into attack chains",
        "Validate the highest-impact issues with concrete evidence",
    ],
    references=["https://www.pentest-standard.org/"],
))

register(AgentProfile(
    name="web-application",
    title="Web Application Tester",
    domain="web",
    methodology="OWASP WSTG v4.2 + OWASP Top 10",
    description="Web app assessment following the OWASP Web Security Testing Guide.",
    tools=["httpx", "whatweb", "katana", "ffuf", "nuclei", "nikto", "testssl", "wpscan"],
    default_objective="identify OWASP Top 10 class vulnerabilities in the web application",
    checklist=[
        "Information gathering: fingerprint server, frameworks, entry points (WSTG-INFO)",
        "Configuration & deployment management testing (WSTG-CONF)",
        "Identity & authentication testing: weak creds, session fixation (WSTG-IDNT/ATHN)",
        "Authorization testing: privilege escalation, IDOR (WSTG-ATHZ)",
        "Session management: cookie flags, CSRF, token entropy (WSTG-SESS)",
        "Input validation: SQLi, XSS, SSTI, command/LDAP injection (WSTG-INPV)",
        "Business logic flaws and workflow bypass (WSTG-BUSL)",
        "Client-side: DOM XSS, postMessage, CORS misconfig (WSTG-CLNT)",
    ],
    references=["https://owasp.org/www-project-web-security-testing-guide/"],
))

register(AgentProfile(
    name="api",
    title="API Security Tester",
    domain="api",
    methodology="OWASP API Security Top 10 (2023)",
    description="REST/GraphQL API assessment focused on object- and function-level access control.",
    tools=["httpx", "katana", "ffuf", "nuclei"],
    default_objective="find broken object/function-level authorization and injection in the API",
    checklist=[
        "API1 Broken Object Level Authorization (BOLA/IDOR)",
        "API2 Broken Authentication",
        "API3 Broken Object Property Level Authorization (mass assignment / excessive data)",
        "API4 Unrestricted Resource Consumption (rate limits)",
        "API5 Broken Function Level Authorization",
        "API6 Unrestricted Access to Sensitive Business Flows",
        "API7 Server Side Request Forgery (SSRF)",
        "API8 Security Misconfiguration",
    ],
    references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"],
))

register(AgentProfile(
    name="mobile-application",
    title="Mobile Application Tester",
    domain="mobile",
    methodology="OWASP MASTG / MASVS",
    description="Android/iOS assessment with Frida/Objection following MASTG.",
    tools=["frida", "objection", "apktool", "mobsf", "nuclei"],
    default_objective="assess the mobile app against MASVS controls",
    checklist=[
        "MASVS-STORAGE: insecure data storage, logs, backups",
        "MASVS-CRYPTO: weak/hardcoded keys and algorithms",
        "MASVS-AUTH: local/remote authentication and session handling",
        "MASVS-NETWORK: TLS, certificate pinning bypass (Frida)",
        "MASVS-PLATFORM: IPC, deep links, WebView misuse",
        "MASVS-CODE: outdated libs, debuggable builds",
        "MASVS-RESILIENCE: anti-tampering, root/jailbreak detection bypass",
    ],
    references=["https://mas.owasp.org/MASTG/", "https://mas.owasp.org/MASVS/"],
))

register(AgentProfile(
    name="cloud-security",
    title="Cloud Security Auditor",
    domain="cloud",
    methodology="CIS Benchmarks (AWS/Azure/GCP) + cloud attack paths",
    description="Cloud posture review: IAM misconfig, exposed resources, CIS controls.",
    tools=["cloud-audit", "nuclei", "trivy"],
    default_objective="find IAM misconfigurations and exposed resources against CIS benchmarks",
    checklist=[
        "Identity & access: over-permissive roles, wildcard policies, unused keys",
        "Public exposure: open storage buckets, public snapshots/AMIs, security groups",
        "Logging & monitoring: CloudTrail/Activity Log coverage, log integrity",
        "Encryption: at-rest and in-transit for storage, databases, secrets",
        "Network: overly broad ingress, missing segmentation",
        "Privilege escalation & lateral movement paths",
    ],
    references=["https://www.cisecurity.org/cis-benchmarks"],
))

register(AgentProfile(
    name="internal-network",
    title="Internal Network / AD Tester",
    domain="network",
    methodology="MITRE ATT&CK + Active Directory attack paths",
    description="Internal network and Active Directory assessment: lateral movement, Kerberos.",
    tools=["nmap", "nmap-full", "naabu", "nuclei"],
    default_objective="map the internal network and identify AD privilege escalation paths",
    checklist=[
        "Host & service discovery across the internal range",
        "SMB/LDAP/Kerberos enumeration and null/guest sessions",
        "Credential exposure: shares, SYSVOL, GPP, LSASS opportunities",
        "Kerberos attacks: AS-REP roasting, Kerberoasting",
        "Lateral movement & pivoting opportunities",
        "Path to Domain Admin / tier-0 assets",
    ],
    references=["https://attack.mitre.org/"],
))
