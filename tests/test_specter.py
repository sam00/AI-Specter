"""Smoke + behavior tests that run fully offline (no API keys, no tools)."""
from pathlib import Path

import pytest

from specter.advisor import ModelAdvisor, TaskKind
from specter.audit import AuditLogger
from specter.c2 import get_c2
from specter.config import Config, ProviderConfig, Scope
from specter.engine import Orchestrator
from specter.engine.models import Engagement, Finding, Severity
from specter.reporting import ReportBuilder, ReportType
from specter.tools import ToolRegistry


def _offline_config(targets=("scanme.nmap.org",)) -> Config:
    return Config(
        profile="offline",
        offline=True,
        allow_exploitation=False,
        providers={"ollama": ProviderConfig(enabled=True, base_url="http://localhost:11434")},
        scope=Scope(targets=list(targets), authorized_by="tester", authorization_ref="T-1"),
    )


def test_advisor_routes_every_task():
    adv = ModelAdvisor({"anthropic", "openai"}, profile="balanced")
    plan = adv.plan()
    assert set(plan.keys()) == {t.value for t in TaskKind}
    # parsing should prefer a cheap/fast model over a deep reasoner
    assert "mini" in plan[TaskKind.PARSING.value].model or plan[TaskKind.PARSING.value].score > 0


def test_advisor_offline_only_local():
    adv = ModelAdvisor({"anthropic", "ollama"}, profile="offline")
    rec = adv.recommend(TaskKind.PLANNING)
    assert rec is not None and rec.provider == "ollama"


def test_advisor_falls_back_to_echo_when_empty():
    adv = ModelAdvisor({"echo"}, profile="balanced")
    rec = adv.recommend(TaskKind.PLANNING)
    assert rec is not None and rec.provider == "echo"


def test_tool_registry_scope_guard():
    reg = ToolRegistry(offline=False, dry_run=False)
    res = reg.run("nmap", "10.0.0.5", in_scope=False)
    assert res.simulated and "out of authorized scope" in res.error


def test_tool_registry_offline_simulates():
    reg = ToolRegistry(offline=True)
    res = reg.run("nmap", "scanme.nmap.org", in_scope=True)
    assert res.simulated and "SIMULATED" in res.stdout


def test_orchestrator_runs_offline():
    eng = Orchestrator(_offline_config()).run(name="unit-test")
    assert isinstance(eng, Engagement)
    assert eng.targets == ["scanme.nmap.org"]
    assert eng.routing  # a routing table was produced
    assert len(eng.steps) > 0


def test_orchestrator_aborts_without_scope():
    cfg = _offline_config(targets=())
    eng = Orchestrator(cfg).run(name="no-scope")
    assert eng.findings == [] and eng.steps == []


def test_in_scope_respects_exclusions():
    cfg = _offline_config()
    cfg.scope.exclusions = ["scanme.nmap.org"]
    assert cfg.in_scope("scanme.nmap.org") is False


def test_reporting_builds_all(tmp_path: Path):
    eng = Engagement(name="rep-test", targets=["host"])
    eng.add_finding(Finding(title="Open admin panel", severity=Severity.CRITICAL,
                            target="host", cvss=9.1))
    eng.add_finding(Finding(title="Verbose banner", severity=Severity.LOW, target="host"))
    written = ReportBuilder(eng).build(ReportType.ALL, tmp_path)
    names = {p.name for p in written}
    assert names == {"risk.md", "technical.md", "remediation.md"}
    risk = (tmp_path / "risk.md").read_text()
    assert "CRITICAL" in risk and "rep-test" in risk


def test_c2_adapters_simulate_without_connection():
    for name in ("sliver", "cobaltstrike", "mythic", "generic"):
        adapter = get_c2(name, {})
        res = adapter.connect()
        assert res.simulated or res.ok is False
        assert adapter.list_sessions()  # simulated session present


def test_c2_blocks_unauthorized_exec():
    adapter = get_c2("sliver", {})
    res = adapter.run_command("sim-s1", "whoami", authorized=False)
    assert res.ok is False and "not authorized" in res.summary


# --- audit logger ----------------------------------------------------------
def test_audit_noop_without_path():
    a = AuditLogger(None)
    a.task("plan")
    a.command("nmap -sV host")
    assert a.close() is None
    assert a.stats()["events"] == 2 and a.stats()["bytes"] == 0


def test_audit_writes_and_reads(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, compress_on_close=False)
    a.task("plan", model="echo:echo")
    a.command("nmap -sV scanme", tool="nmap", ok=True, ms=12)
    a.close()
    events = AuditLogger.read(p)
    assert [e["ev"] for e in events] == ["task", "cmd"]
    assert events[1]["tool"] == "nmap" and events[1]["ms"] == 12


def test_audit_gzip_on_close(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, compress_on_close=True)
    a.task("x")
    closed = a.close()
    assert closed.suffix == ".gz" and closed.exists() and not p.exists()
    assert AuditLogger.read(p)[0]["ev"] == "task"  # read resolves the .gz


def test_audit_timed_records_ms_and_ok(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, compress_on_close=False)
    with a.timed("task", "planning") as ex:
        ex["model"] = "echo:echo"
    a.close()
    ev = AuditLogger.read(p)[0]
    assert ev["ok"] is True and "ms" in ev and ev["model"] == "echo:echo"


def test_audit_timed_marks_failure(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, compress_on_close=False)
    with pytest.raises(ValueError):
        with a.timed("task", "boom"):
            raise ValueError("x")
    a.close()
    assert AuditLogger.read(p)[0]["ok"] is False


def test_audit_level_filter(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, level="info", compress_on_close=False)
    a.event("route", "debug-only", level="debug")
    a.event("run", "start")
    a.close()
    assert [e["ev"] for e in AuditLogger.read(p)] == ["run"]  # debug dropped


def test_audit_omits_empty_keeps_meaningful_falsy(tmp_path):
    p = tmp_path / "log.jsonl"
    a = AuditLogger(p, compress_on_close=False)
    a.command("cmd", tool="", target=None, ok=False, ms=0)
    a.close()
    ev = AuditLogger.read(p)[0]
    assert "tool" not in ev and "target" not in ev  # empty/None omitted
    assert ev["ok"] is False and ev["ms"] == 0       # falsy-but-meaningful kept


def test_orchestrator_writes_audit_log(tmp_path):
    eng = Orchestrator(_offline_config(), audit_dir=tmp_path).run(name="audit-test")
    assert eng.log_file and Path(eng.log_file).exists()
    events = AuditLogger.read(eng.log_file)
    kinds = {e["ev"] for e in events}
    assert {"run", "cmd", "step"} <= kinds
    cmds = [e for e in events if e["ev"] == "cmd"]
    assert cmds and all("ms" in e for e in cmds)  # every command is timed
