"""Offline tests for i18n, the MCP catalog, and Slack message assembly."""
from __future__ import annotations

from specter.engine.models import Finding, Severity
from specter.i18n import CATALOGS, available_locales, current_lang, t
from specter.integrations import findings_blocks
from specter.mcp_catalog import MCP_CATALOG, to_client_config, total_tools


def test_i18n_translates_and_falls_back():
    assert t("ready", lang="es") == "Listo."
    # unknown key returns the key itself
    assert t("nonexistent_key", lang="es") == "nonexistent_key"
    # unknown locale falls back to English source string
    assert t("ready", lang="zz") == CATALOGS["en"]["ready"]


def test_i18n_locale_detection(monkeypatch):
    monkeypatch.setenv("SPECTER_LANG", "pt_BR.UTF-8")
    assert current_lang() == "pt"
    monkeypatch.setenv("SPECTER_LANG", "xx")
    assert current_lang() == "en"
    assert "en" in available_locales() and "ja" in available_locales()


def test_mcp_catalog_total_and_config():
    assert total_tools() == sum(s.tools for s in MCP_CATALOG.values())
    cfg = to_client_config(["cve"])
    assert "specter-cve" in cfg["mcpServers"]
    assert cfg["mcpServers"]["specter-cve"]["command"] == "npx"


def test_slack_blocks_have_header_and_counts():
    findings = [
        Finding(title="SQLi", severity=Severity.CRITICAL, target="app"),
        Finding(title="Open port", severity=Severity.LOW, target="host"),
    ]
    msg = findings_blocks("eng", "abc123", findings)
    assert msg["blocks"][0]["type"] == "header"
    text = " ".join(str(b) for b in msg["blocks"])
    assert "critical: 1" in text and "low: 1" in text
    assert "SQLi" in text
