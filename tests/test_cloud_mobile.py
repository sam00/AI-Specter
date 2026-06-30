"""Offline tests for the cloud and mobile auditors."""
from __future__ import annotations

from specter.cloud import CloudAuditor, CloudState, demo_state
from specter.mobile import MobileAuditor, MobileFacts, demo_facts


def test_cloud_audit_flags_known_misconfigurations():
    findings = CloudAuditor().audit(demo_state("aws"))
    titles = " ".join(f.title for f in findings)
    assert "IAM-001" in titles      # wildcard policy
    assert "STOR-001" in titles     # public bucket
    assert "NET-001" in titles      # open ssh ingress
    # the public bucket is the critical one
    assert any(f.severity.value == "critical" for f in findings)


def test_cloud_audit_clean_state_has_no_findings():
    clean = CloudState(provider="aws", account="x",
                       logging={"audit_trail_enabled": True, "log_integrity": True})
    assert CloudAuditor().audit(clean) == []


def test_cloud_provider_scoping():
    # IAM-002 (stale keys) is AWS-only; a GCP audit should not raise it.
    gcp = demo_state("gcp")
    findings = CloudAuditor().audit(gcp)
    assert all("IAM-002" not in f.title for f in findings)


def test_mobile_audit_maps_to_masvs():
    findings = MobileAuditor().audit(demo_facts())
    ids = " ".join(f.mitre_attack[0] for f in findings)
    assert "MASVS-RESILIENCE-1" in ids   # debuggable
    assert "MASVS-NETWORK-1" in ids       # cleartext
    assert "MASVS-CRYPTO-1" in ids        # hardcoded secret


def test_mobile_secure_build_is_clean():
    secure = MobileFacts(platform="android", package="com.secure",
                         debuggable=False, allow_backup=False, cleartext_traffic=False,
                         cert_pinning=True, root_detection=True)
    assert MobileAuditor().audit(secure) == []
