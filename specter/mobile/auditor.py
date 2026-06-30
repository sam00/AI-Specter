"""Mobile app auditing against MASVS controls from normalized app facts.

Specter extracts a small set of *facts* about a build (debuggable flag,
cleartext-traffic policy, exported components, hardcoded secrets, cert
pinning, …) and maps issues to MASVS categories. Fact extraction is best-effort
and offline for APKs (manifest + strings via the standard library); the
auditor itself is pure and unit-testable.

Dynamic instrumentation (Frida/Objection) is wired through the tool registry
(`specter doctor` shows availability) and steered by the
``mobile-application`` agent profile.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from specter.engine.models import Finding, Severity


@dataclass
class MobileFacts:
    """Normalized facts about a mobile build (Android-leaning, iOS-compatible)."""

    platform: str = "android"            # android | ios
    package: str = ""
    min_sdk: int = 0
    debuggable: bool = False
    allow_backup: bool = False
    cleartext_traffic: bool = False
    cert_pinning: bool = True
    root_detection: bool = True
    exported_components: list[str] = field(default_factory=list)
    hardcoded_secrets: list[str] = field(default_factory=list)
    weak_crypto: list[str] = field(default_factory=list)


@dataclass
class MASVSControl:
    id: str
    category: str
    title: str
    severity: str
    remediation: str


MASVS_CHECKLIST: list[MASVSControl] = [
    MASVSControl("MASVS-STORAGE-2", "STORAGE", "Backups expose app data (allowBackup)",
                 "medium", "Set android:allowBackup=false for sensitive apps."),
    MASVSControl("MASVS-CRYPTO-1", "CRYPTO", "Hardcoded secret / key in the binary",
                 "high", "Move secrets server-side; use the platform keystore."),
    MASVSControl("MASVS-CRYPTO-2", "CRYPTO", "Weak/deprecated cryptographic primitive",
                 "high", "Use AES-GCM / SHA-256+; drop MD5/SHA1/DES/ECB."),
    MASVSControl("MASVS-NETWORK-1", "NETWORK", "Cleartext (HTTP) traffic permitted",
                 "high", "Enforce TLS; disable cleartextTrafficPermitted."),
    MASVSControl("MASVS-NETWORK-2", "NETWORK", "No certificate pinning",
                 "medium", "Pin server certificates/public keys for sensitive APIs."),
    MASVSControl("MASVS-PLATFORM-1", "PLATFORM", "Exported component without permission",
                 "medium", "Set android:exported=false or guard with a permission."),
    MASVSControl("MASVS-RESILIENCE-1", "RESILIENCE", "Debuggable production build",
                 "high", "Ship release builds with android:debuggable=false."),
    MASVSControl("MASVS-RESILIENCE-2", "RESILIENCE", "No root/jailbreak detection",
                 "low", "Add root/jailbreak detection for high-risk flows."),
]
_BY_ID = {c.id: c for c in MASVS_CHECKLIST}


class MobileAuditor:
    def audit(self, facts: MobileFacts) -> list[Finding]:
        out: list[Finding] = []

        def add(control_id: str, detail: str) -> None:
            c = _BY_ID[control_id]
            out.append(Finding(
                title=f"[{c.id}] {c.title}", severity=Severity(c.severity),
                target=facts.package or facts.platform, description=detail,
                evidence=f"{c.category} control {c.id}", remediation=c.remediation,
                phase="mobile-audit", confirmed=True, verified=True, confidence=0.85,
                source="mobile", mitre_attack=[c.id]))

        if facts.debuggable:
            add("MASVS-RESILIENCE-1", "build is marked debuggable")
        if not facts.root_detection:
            add("MASVS-RESILIENCE-2", "no root/jailbreak detection present")
        if facts.allow_backup:
            add("MASVS-STORAGE-2", "android:allowBackup is enabled")
        if facts.cleartext_traffic:
            add("MASVS-NETWORK-1", "cleartext traffic is permitted")
        if not facts.cert_pinning:
            add("MASVS-NETWORK-2", "no certificate pinning detected")
        for secret in facts.hardcoded_secrets:
            add("MASVS-CRYPTO-1", f"hardcoded secret: {secret}")
        for algo in facts.weak_crypto:
            add("MASVS-CRYPTO-2", f"weak crypto primitive in use: {algo}")
        for comp in facts.exported_components:
            add("MASVS-PLATFORM-1", f"exported component without guard: {comp}")
        return out


_SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9A-Za-z]{16,}|"
    r"-----BEGIN (?:RSA|EC|PRIVATE) KEY-----)")
_WEAK_RE = re.compile(r"\b(MD5|SHA1|DES|RC4|ECB)\b")


def extract_facts_from_apk(path: str | Path) -> MobileFacts:
    """Best-effort static fact extraction from an APK using only the stdlib."""
    import zipfile

    facts = MobileFacts(platform="android", package=Path(path).stem)
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            blob = b""
            for n in names:
                if n.endswith((".xml", ".json", ".properties", ".txt")) or n == "resources.arsc":
                    try:
                        blob += z.read(n)
                    except Exception:
                        continue
            text = blob.decode("latin-1", errors="ignore")
            facts.debuggable = "debuggable=\"true\"" in text or "debuggable=true" in text
            facts.allow_backup = "allowBackup=\"true\"" in text
            facts.cleartext_traffic = ("cleartextTrafficPermitted=\"true\"" in text
                                       or "usesCleartextTraffic=\"true\"" in text)
            facts.cert_pinning = "pin-set" in text or "certificatePinner" in text.lower()
            facts.hardcoded_secrets = sorted(set(_SECRET_RE.findall(text)))[:10]
            facts.weak_crypto = sorted(set(_WEAK_RE.findall(text)))
    except Exception:
        pass
    return facts


def demo_facts() -> MobileFacts:
    """A deliberately-insecure build for offline demos and tests."""
    return MobileFacts(
        platform="android", package="com.example.shop", min_sdk=21,
        debuggable=True, allow_backup=True, cleartext_traffic=True,
        cert_pinning=False, root_detection=False,
        exported_components=["com.example.shop.DebugActivity"],
        hardcoded_secrets=["AKIAIOSFODNN7EXAMPLE"],
        weak_crypto=["MD5"],
    )
