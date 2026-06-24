"""Specter terminal interface — automated AI pentesting from your shell."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from specter import __version__
from specter.advisor import ModelAdvisor, TaskKind, catalog_from_config, discover_models
from specter.audit import AuditLogger
from specter.c2 import ADAPTERS, get_c2
from specter.config import CONFIG_FILE, RUNS_DIR, Config, ProviderConfig
from specter.engine import Orchestrator
from specter.engine.agent import AgentRunner
from specter.llm import available_providers, build_client
from specter.reporting import ReportBuilder, ReportType
from specter.runstore import latest_run_id, load_run, save_run
from specter.store import Store

app = typer.Typer(add_completion=False, help="Specter — AI-driven automated pentesting.")
c2_app = typer.Typer(help="Command & control integrations.")
app.add_typer(c2_app, name="c2")
console = Console()

BANNER = r"""[bold magenta]
  ___ ___ ___ ___ _____ ___ ___
 / __| _ \ __/ __|_   _| __| _ \
 \__ \  _/ _| (__  | | | _||   /
 |___/_| |___\___| |_| |___|_|_\
[/bold magenta][dim] Security Penetration Engine · Contextual Tactical Exploitation & Reasoning[/dim]"""


def _narrator(config: Config):
    """Closure that routes report narratives through advisor-selected models."""
    providers = {"echo"} if config.offline else available_providers(config)
    advisor = ModelAdvisor(providers, profile=config.profile)

    def narrate(task: TaskKind, prompt: str) -> str:
        rec = advisor.recommend(task)
        if not rec or rec.provider == "echo":
            return ""  # let ReportBuilder use its clean deterministic summary
        client = build_client(config, rec.provider, rec.model)
        try:
            return client.complete("You are a precise security report writer.", prompt,
                                   max_tokens=600).text.strip()
        except Exception as e:  # pragma: no cover
            return f"(narrative unavailable: {e})"

    return narrate


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"Specter [bold]{__version__}[/bold]")


@app.command()
def init() -> None:
    """Interactive setup wizard: providers, scope, and C2."""
    console.print(BANNER)
    cfg = Config.load()

    cfg.profile = typer.prompt(
        "Engagement profile (fast/balanced/deep/frugal/offline)", default=cfg.profile or "balanced")

    for name, env in (("anthropic", "ANTHROPIC_API_KEY"), ("openai", "OPENAI_API_KEY")):
        if typer.confirm(f"Enable {name}?", default=name in cfg.providers):
            cfg.providers[name] = ProviderConfig(enabled=True, api_key_env=env)
            console.print(f"  [dim]→ set {env} in your environment or .env[/dim]")

    if typer.confirm("Enable a local Ollama endpoint?", default="ollama" in cfg.providers):
        url = typer.prompt("Ollama base URL", default="http://localhost:11434")
        cfg.providers["ollama"] = ProviderConfig(enabled=True, base_url=url,
                                                 default_model="llama3.1:70b")

    targets = typer.prompt("Authorized target(s), comma-separated", default="")
    if targets:
        cfg.scope.targets = [t.strip() for t in targets.split(",") if t.strip()]
    cfg.scope.authorized_by = typer.prompt("Authorized by", default=cfg.scope.authorized_by or "")
    cfg.scope.authorization_ref = typer.prompt(
        "Authorization reference (ticket/contract)", default=cfg.scope.authorization_ref or "")

    if typer.confirm("Configure a C2 integration?", default=False):
        c2name = typer.prompt(f"Which C2? ({'/'.join(ADAPTERS)})", default="sliver")
        cfg.c2[c2name] = {"base_url": typer.prompt("C2 base URL / config path", default="")}

    path = cfg.save()
    console.print(Panel.fit(f"Config saved to [bold]{path}[/bold]", style="green"))


@app.command()
def doctor(fix: bool = typer.Option(False, help="Scaffold config + report missing tools")) -> None:
    """Check providers, advisor routing, tools, and C2 readiness."""
    cfg = Config.load()
    if fix and not CONFIG_FILE.exists():
        cfg.save()
        console.print(f"[green]scaffolded config at {CONFIG_FILE}[/green]")
    provs = available_providers(cfg)

    t = Table(title="LLM Providers", show_lines=False)
    for col in ("Provider", "Status"):
        t.add_column(col)
    for name in ("anthropic", "openai", "ollama", "openai-compatible", "echo"):
        ok = name in provs
        t.add_row(name, "[green]ready[/green]" if ok else "[dim]not configured[/dim]")
    console.print(t)

    from specter.tools import ToolRegistry
    reg = ToolRegistry()
    tt = Table(title="Security Tools")
    for col in ("Tool", "Installed"):
        tt.add_column(col)
    for name, installed in reg.available().items():
        tt.add_row(name, "[green]yes[/green]" if installed else "[yellow]no[/yellow]")
    console.print(tt)
    if fix:
        missing = [n for n, ok in reg.available().items() if not ok]
        if missing:
            console.print(f"[yellow]Missing tools:[/yellow] {', '.join(missing)} "
                          "— install via your package manager or use the Docker image.")

    ct = Table(title="C2 Adapters")
    for col in ("Adapter", "Configured"):
        ct.add_column(col)
    for name in ADAPTERS:
        ct.add_row(name, "[green]yes[/green]" if name in cfg.c2 else "[dim]no[/dim]")
    console.print(ct)


@app.command()
def advisor(profile: str = typer.Option("", help="Override profile for this view")) -> None:
    """Show the per-task model routing the advisor would choose."""
    cfg = Config.load()
    provs = {"echo"} if cfg.offline else available_providers(cfg)
    adv = ModelAdvisor(provs, profile=profile or cfg.profile,
                       catalog=catalog_from_config(cfg.models))
    t = Table(title=f"Model Routing · profile={profile or cfg.profile}")
    for col in ("Task", "Model", "Score", "Why"):
        t.add_column(col)
    for task, rec in adv.plan().items():
        t.add_row(task, f"{rec.provider}:{rec.model}", str(rec.score), rec.rationale)
    console.print(t)


def _persist_and_report(cfg: Config, eng, report: bool) -> None:
    run_dir = save_run(eng)
    try:
        Store().save_engagement(eng)  # mirror into the shared/team store
    except Exception as e:  # pragma: no cover - store is best-effort
        console.print(f"[yellow]store unavailable: {e}[/yellow]")
    sev = eng.by_severity()
    console.print(Panel.fit(
        f"Findings — critical:{sev['critical']} high:{sev['high']} "
        f"medium:{sev['medium']} low:{sev['low']} info:{sev['info']}\n"
        f"Clusters: {len(eng.clusters)}  ·  Run ID: [bold]{eng.id}[/bold]  ·  {run_dir}",
        style="green"))
    if eng.log_file and Path(eng.log_file).exists():
        console.print(f"  [green]audit[/green] {eng.log_file} "
                      f"({Path(eng.log_file).stat().st_size} bytes)")
    if report:
        for p in ReportBuilder(eng, narrate=_narrator(cfg)).build(ReportType.ALL, run_dir):
            console.print(f"  [green]report[/green] {p}")


@app.command()
def run(
    name: str = typer.Option("specter-engagement", help="Engagement name"),
    objectives: str = typer.Option("", help="Free-text objectives"),
    profile: str = typer.Option("", help="Override profile"),
    offline: bool = typer.Option(False, help="No network calls to tools/providers"),
    demo: bool = typer.Option(False, help="Use bundled demo tool output (offline showcase)"),
    agent: bool = typer.Option(False, help="Use the autonomous agent loop instead of the pipeline"),
    allow_exploitation: bool = typer.Option(False, help="Permit active exploitation steps"),
    actor: str = typer.Option("", help="Operator identity recorded on the run"),
    log_level: str = typer.Option("", help="Audit log level: debug|info|warn|error"),
    report: bool = typer.Option(True, help="Auto-generate all reports after the run"),
) -> None:
    """Run an end-to-end engagement against the authorized scope."""
    cfg = Config.load()
    if profile:
        cfg.profile = profile
    if log_level:
        cfg.log_level = log_level
    cfg.offline = offline
    cfg.allow_exploitation = allow_exploitation

    if not cfg.scope.targets:
        console.print("[red]No authorized targets. Run 'specter init' first.[/red]")
        raise typer.Exit(1)

    console.print(BANNER)
    console.print(Panel.fit(
        f"[bold]{name}[/bold]  ({'agent' if agent else 'pipeline'})\n"
        f"Targets: {', '.join(cfg.scope.targets)}\n"
        f"Profile: {cfg.profile}  •  Exploit: {allow_exploitation}  •  "
        f"Offline: {offline}  •  Demo: {demo}",
        title="Engagement", style="magenta"))

    orch = Orchestrator(cfg, reporter=lambda m: console.print(f"[cyan]{m}[/cyan]"),
                        audit_dir=RUNS_DIR, demo=demo)
    if agent:
        eng = AgentRunner(orch).run(name=name, objective=objectives, actor=actor)
    else:
        eng = orch.run(name=name, objectives=objectives, actor=actor)
    _persist_and_report(cfg, eng, report)


@app.command()
def report(
    run_id: str = typer.Argument("", help="Run ID (defaults to latest)"),
    kind: ReportType = typer.Option(ReportType.ALL, help="risk|technical|remediation|all"),
) -> None:
    """Generate reports for a saved engagement."""
    cfg = Config.load()
    rid = run_id or latest_run_id()
    if not rid:
        console.print("[red]No runs found. Execute 'specter run' first.[/red]")
        raise typer.Exit(1)
    eng = load_run(rid)
    from specter.config import RUNS_DIR
    written = ReportBuilder(eng, narrate=_narrator(cfg)).build(kind, RUNS_DIR / rid)
    for p in written:
        console.print(f"[green]wrote[/green] {p}")


@app.command()
def log(
    run_id: str = typer.Argument("", help="Run ID (defaults to latest)"),
    level: str = typer.Option("", help="Filter: debug|info|warn|error"),
    limit: int = typer.Option(40, help="Max rows to show (latest)"),
) -> None:
    """Show the compact audit trail (tasks, commands, steps, timings) for a run."""
    from specter.audit import LEVELS
    rid = run_id or latest_run_id()
    if not rid:
        console.print("[red]No runs found. Execute 'specter run' first.[/red]")
        raise typer.Exit(1)
    events = AuditLogger.read(RUNS_DIR / rid / "specter.jsonl")
    if level:
        floor = LEVELS.get(level, 20)
        events = [e for e in events if LEVELS.get(e.get("lvl", "info"), 20) >= floor]
    shown = events[-limit:]
    t = Table(title=f"Audit trail · run {rid} · {len(events)} events")
    for col in ("Time", "Event", "ms", "Detail"):
        t.add_column(col, overflow="fold")
    for e in shown:
        ts = datetime.fromtimestamp(e.get("ts", 0)).strftime("%H:%M:%S")
        detail = e.get("msg", "")
        extra = [f"{k}={v}" for k, v in e.items()
                 if k not in ("ts", "ev", "msg", "ms", "lvl")]
        if extra:
            detail = f"{detail}  [dim]{' '.join(extra)}[/dim]".strip()
        t.add_row(ts, e.get("ev", ""), str(e.get("ms", "")), detail)
    console.print(t)


@app.command()
def quickstart() -> None:
    """Zero-config offline demo: full engagement using bundled sample data."""
    console.print(BANNER)
    cfg = Config.load()
    cfg.offline = True
    if not cfg.scope.targets:
        cfg.scope.targets = ["scanme.nmap.org"]
        cfg.scope.authorized_by = "demo"
        cfg.scope.authorization_ref = "QUICKSTART"
    console.print("[cyan]Running offline demo engagement (no API keys needed)…[/cyan]")
    orch = Orchestrator(cfg, reporter=lambda m: console.print(f"[cyan]{m}[/cyan]"),
                        audit_dir=RUNS_DIR, demo=True)
    eng = orch.run(name="quickstart-demo", actor="demo")
    _persist_and_report(cfg, eng, report=True)
    console.print("\n[bold green]Done.[/bold green] Next: [bold]specter findings[/bold], "
                  "[bold]specter log[/bold], or [bold]specter report --kind risk[/bold]")


@app.command()
def models(discover: bool = typer.Option(False, help="Probe provider endpoints for live models")) -> None:
    """List the model catalog the advisor can route to."""
    cfg = Config.load()
    specs = catalog_from_config(cfg.models)
    if discover and not cfg.offline:
        specs = specs + discover_models(cfg)
    t = Table(title="Model catalog")
    for c in ("Provider", "Model", "Reason", "Speed", "$in/$out", "Notes"):
        t.add_column(c)
    for s in specs:
        t.add_row(s.provider, s.name, str(s.reasoning), str(s.speed),
                  f"{s.cost_in}/{s.cost_out}", s.notes)
    console.print(t)


@app.command()
def findings(
    run_id: str = typer.Argument("", help="Engagement ID (defaults to all)"),
    status: str = typer.Option("", help="Filter: open|triage|confirmed|dismissed"),
) -> None:
    """List findings from the shared store (team view)."""
    rows = Store().list_findings(run_id or None, status or None)
    if not rows:
        console.print("[dim]No findings yet. Try 'specter quickstart'.[/dim]")
        return
    t = Table(title=f"Findings ({len(rows)})")
    for c in ("ID", "Sev", "CVSS", "Title", "Target", "Status", "Assignee"):
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(r["id"][:8], r["severity"].upper(), str(r["cvss"]), r["title"],
                  r["target"], r["status"], r["assignee"] or "-")
    console.print(t)


@app.command()
def triage(
    finding_id: str = typer.Argument(..., help="Finding ID (8-char prefix from 'findings' works)"),
    status: str = typer.Option("", help="open|triage|confirmed|dismissed"),
    assignee: str = typer.Option("", help="Assign to a teammate"),
    comment: str = typer.Option("", help="Add a comment"),
    actor: str = typer.Option("", help="Your identity"),
) -> None:
    """Update a finding's workflow (status/assignee/comment) in the shared store."""
    store = Store()
    fid = finding_id
    if len(finding_id) < 12:
        match = [r["id"] for r in store.list_findings() if r["id"].startswith(finding_id)]
        if len(match) == 1:
            fid = match[0]
        elif len(match) > 1:
            console.print("[red]Ambiguous finding ID prefix.[/red]")
            raise typer.Exit(1)
    ok = store.update_finding(fid, status or None, assignee or None, comment or None, actor=actor)
    console.print("[green]updated[/green]" if ok else "[red]finding not found[/red]")
    if not ok:
        raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8787, help="Bind port"),
) -> None:
    """Start the team collaboration API server (needs specter-ai[server])."""
    from specter.server import serve as _serve
    console.print(f"[cyan]Specter server → http://{host}:{port}[/cyan]")
    _serve(host=host, port=port)


@app.command()
def mcp() -> None:
    """Run Specter as an MCP server for Claude/Cursor (needs specter-ai[mcp])."""
    from specter.mcp_server import main as _main
    _main()


# --- C2 subcommands ---------------------------------------------------------
@c2_app.command("status")
def c2_status(name: str = typer.Argument(..., help="sliver|cobaltstrike|mythic|generic")) -> None:
    cfg = Config.load()
    adapter = get_c2(name, cfg.c2.get(name, {}))
    res = adapter.connect()
    style = "green" if res.ok else "yellow"
    console.print(Panel.fit(f"{name}: {res.summary}", style=style))


@c2_app.command("sessions")
def c2_sessions(name: str = typer.Argument(...)) -> None:
    cfg = Config.load()
    adapter = get_c2(name, cfg.c2.get(name, {}))
    adapter.connect()
    t = Table(title=f"{name} sessions")
    for col in ("ID", "Name", "Host", "User", "OS", "Integrity"):
        t.add_column(col)
    for s in adapter.list_sessions():
        t.add_row(s.id, s.name, s.host, s.user, s.os, s.integrity)
    console.print(t)


@c2_app.command("payload")
def c2_payload(
    name: str = typer.Argument(...),
    listener: str = typer.Option("mtls", help="Listener/profile name"),
    os_: str = typer.Option("windows", "--os", help="Target OS"),
    fmt: str = typer.Option("exe", help="Output format"),
) -> None:
    cfg = Config.load()
    adapter = get_c2(name, cfg.c2.get(name, {}))
    adapter.connect()
    res = adapter.generate_payload(listener, os_, fmt)
    console.print(Panel.fit(res.summary, style="green" if res.ok else "red"))


@c2_app.command("exec")
def c2_exec(
    name: str = typer.Argument(...),
    session: str = typer.Option(..., help="Session/beacon/callback ID"),
    command: str = typer.Option(..., help="Command to task"),
) -> None:
    """Task a C2 session. Requires allow_exploitation=true in config."""
    cfg = Config.load()
    if not cfg.allow_exploitation:
        console.print("[red]Tasking blocked: set allow_exploitation=true in config.[/red]")
        raise typer.Exit(1)
    adapter = get_c2(name, cfg.c2.get(name, {}))
    adapter.connect()
    res = adapter.run_command(session, command, authorized=True)
    console.print(Panel.fit(res.summary, style="green" if res.ok else "red"))


if __name__ == "__main__":
    app()
