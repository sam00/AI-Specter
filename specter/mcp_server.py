"""Optional: expose Specter as an MCP server for Claude/Cursor/etc.

Install with ``pip install 'specter-ai[mcp]'`` then run ``specter mcp``. The
``mcp`` SDK is imported lazily so the core package has no hard dependency.
"""
from __future__ import annotations

from specter.config import RUNS_DIR, Config
from specter.engine import Orchestrator
from specter.reporting import ReportBuilder
from specter.runstore import latest_run_id, load_run, save_run
from specter.store import Store


def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'specter-ai[mcp]' to use MCP mode") from e

    mcp = FastMCP("specter")

    @mcp.tool()
    def run_engagement(name: str = "specter-engagement", objective: str = "",
                       offline: bool = False) -> dict:
        """Run an engagement against the configured authorized scope."""
        cfg = Config.load()
        cfg.offline = offline
        eng = Orchestrator(cfg, audit_dir=RUNS_DIR).run(name=name, objectives=objective)
        save_run(eng)
        Store().save_engagement(eng)
        return {"id": eng.id, "findings": len(eng.findings), "clusters": len(eng.clusters)}

    @mcp.tool()
    def list_findings(engagement_id: str = "", status: str = "") -> list:
        """List findings, optionally filtered by engagement or workflow status."""
        return Store().list_findings(engagement_id or None, status or None)

    @mcp.tool()
    def get_report(run_id: str = "", kind: str = "risk") -> str:
        """Render a report (risk|technical|remediation) for a run."""
        rid = run_id or latest_run_id()
        if not rid:
            return "No runs available."
        eng = load_run(rid)
        builder = ReportBuilder(eng)
        return {"risk": builder.risk, "technical": builder.technical,
                "remediation": builder.remediation}.get(kind, builder.risk)()

    return mcp


def main() -> None:  # pragma: no cover - entrypoint
    build_server().run()
