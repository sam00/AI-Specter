"""Specter terminal interface — automated AI pentesting from your shell."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from specter import __version__
from specter.advisor import (
    ModelAdvisor,
    TaskKind,
    catalog_from_config,
    discover_models,
    overrides_from_spec,
)
from specter.audit import AuditLogger
from specter.c2 import ADAPTERS, get_c2
from specter.config import CONFIG_FILE, KNOWN_PROVIDER_ENV, RUNS_DIR, Config, ProviderConfig
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

PROFILES = ["fast", "balanced", "deep", "frugal", "offline"]


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    """Specter — AI-driven automated pentesting from your terminal."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(BANNER)
    console.print(Panel.fit(
        "[bold]Get started in seconds[/bold]\n\n"
        "  [cyan]specter quickstart[/cyan]    full engagement, offline — no keys or tools needed\n"
        "  [cyan]specter init[/cyan]          guided setup (providers + scope)\n"
        "  [cyan]specter doctor[/cyan]        see what's configured and what's missing\n"
        "  [cyan]specter run -t HOST[/cyan]   scan an authorized target\n\n"
        "[dim]Tip: export ANTHROPIC_API_KEY or OPENAI_API_KEY and Specter auto-detects it — "
        "no config needed.[/dim]",
        title="Specter", style="magenta"))


def _narrator(config: Config):
    """Closure that routes report narratives through advisor-selected models."""
    providers = {"echo"} if config.offline else available_providers(config)
    advisor = ModelAdvisor(providers, profile=config.profile,
                           catalog=catalog_from_config(config.models),
                           overrides=overrides_from_spec(config.model_override))

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


def _setup_summary(cfg: Config, path: Path) -> None:
    """Friendly post-setup recap with a clear next step."""
    ready = sorted(available_providers(cfg))
    t = Table(title="Setup summary", show_header=False)
    t.add_column("field", style="bold")
    t.add_column("value")
    t.add_row("Profile", cfg.profile)
    t.add_row("Providers ready", ", ".join(ready))
    t.add_row("Targets", ", ".join(cfg.scope.targets) or "[dim]none — use `run -t HOST`[/dim]")
    t.add_row("Config", str(path))
    console.print(t)
    if ready == ["echo"]:
        console.print("[dim]No live LLM yet — export ANTHROPIC_API_KEY/OPENAI_API_KEY or "
                      "`pip install \"ai-specter[claude]\"`. Specter still runs fully offline.[/dim]")
    nxt = "specter run" if cfg.scope.targets else "specter run -t scanme.nmap.org"
    console.print(Panel.fit(
        f"[green]Ready.[/green]  Next:  [bold]specter doctor[/bold]  ·  "
        f"[bold]{nxt}[/bold]  ·  [bold]specter quickstart[/bold]", style="green"))


@app.command()
def init() -> None:
    """Guided setup: profile, providers (auto-detected), and authorized scope."""
    console.print(BANNER)
    cfg = Config.load()
    detected = Config.detected_env_keys()

    prof = typer.prompt(f"Engagement profile ({'/'.join(PROFILES)})",
                        default=cfg.profile or "balanced")
    if prof not in PROFILES:
        console.print(f"  [yellow]unknown profile '{prof}', using 'balanced'[/yellow]")
        prof = "balanced"
    cfg.profile = prof

    console.print("\n[bold]LLM providers[/bold] [dim](keys in your environment are auto-detected)[/dim]")
    for name, env in (("anthropic", "ANTHROPIC_API_KEY"), ("openai", "OPENAI_API_KEY")):
        seen = bool(detected.get(name))
        tag = "[green](key detected ✓)[/green]" if seen else f"[dim](reads {env})[/dim]"
        if typer.confirm(f"  Enable {name}? {tag}", default=seen or name in cfg.providers):
            cfg.providers[name] = ProviderConfig(enabled=True, api_key_env=env)

    if typer.confirm("  Enable a local Ollama endpoint?", default="ollama" in cfg.providers):
        existing = cfg.providers.get("ollama")
        url = typer.prompt("    Ollama base URL",
                           default=(existing.base_url if existing else "") or "http://localhost:11434")
        cfg.providers["ollama"] = ProviderConfig(enabled=True, base_url=url,
                                                 default_model="llama3.1:70b")

    console.print("\n[bold]Authorized scope[/bold] "
                  "[dim](optional — you can also pass `run -t HOST`)[/dim]")
    targets = typer.prompt("  Authorized target(s), comma-separated",
                           default=", ".join(cfg.scope.targets))
    if targets.strip():
        cfg.scope.targets = [t.strip() for t in targets.split(",") if t.strip()]
    cfg.scope.authorized_by = typer.prompt("  Authorized by",
                                           default=cfg.scope.authorized_by or "")
    cfg.scope.authorization_ref = typer.prompt("  Authorization ref (ticket/contract)",
                                               default=cfg.scope.authorization_ref or "")

    if typer.confirm("\nConfigure a C2 integration?", default=bool(cfg.c2)):
        c2name = typer.prompt(f"  Which C2? ({'/'.join(ADAPTERS)})", default="sliver")
        cfg.c2[c2name] = {"base_url": typer.prompt("  C2 base URL / config path", default="")}

    path = cfg.save()
    _setup_summary(cfg, path)


@app.command()
def setup() -> None:
    """Alias for `init` — the guided first-run setup."""
    init()


@app.command()
def doctor(fix: bool = typer.Option(False, help="Scaffold config + report missing tools")) -> None:
    """Check providers, advisor routing, tools, and C2 readiness."""
    cfg = Config.load()
    if fix and not CONFIG_FILE.exists():
        cfg.save()
        console.print(f"[green]scaffolded config at {CONFIG_FILE}[/green]")
    provs = available_providers(cfg)

    et = Table(title="Credentials in environment (auto-detected)")
    for col in ("Provider key", "Env var", "Detected"):
        et.add_column(col)
    for name, env in KNOWN_PROVIDER_ENV.items():
        seen = bool(os.environ.get(env))
        et.add_row(name, env, "[green]yes ✓[/green]" if seen else "[dim]no[/dim]")
    console.print(et)

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

    if provs - {"echo"}:
        console.print(Panel.fit(
            "[green]✓ Ready — a live AI provider is configured.[/green]  "
            "Run:  [bold]specter run -t HOST[/bold]", style="green"))
    else:
        console.print(Panel.fit(
            "[yellow]No live LLM provider yet[/yellow] — Specter still runs fully offline.\n"
            "  • Add a key:    [bold]export ANTHROPIC_API_KEY=sk-...[/bold]  (or OPENAI_API_KEY)\n"
            "  • Add the SDK:  [bold]pip install \"ai-specter[claude]\"[/bold]  (or \"[openai]\")\n"
            "  • Try it now:   [bold]specter quickstart[/bold]", style="yellow"))


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


def _emit_export_formats(md_paths: list[Path], fmt: str) -> None:
    """Convert generated Markdown reports to PDF/Word when requested."""
    wanted = ["pdf", "docx"] if fmt == "all" else ([fmt] if fmt in ("pdf", "docx") else [])
    if not wanted:
        return
    from specter.reporting.export import ExportUnavailable, export_markdown_file
    for md in md_paths:
        for f in wanted:
            try:
                out = export_markdown_file(md, f)
                console.print(f"  [green]{f}[/green] {out}")
            except ExportUnavailable as e:
                console.print(f"  [yellow]{f} skipped[/yellow] — {e}")
            except Exception as e:  # optional export must never break a run
                console.print(f"  [yellow]{f} export failed[/yellow] — {e}")


def _persist_and_report(cfg: Config, eng, report: bool, fmt: str = "md") -> None:
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
        md_paths = ReportBuilder(eng, narrate=_narrator(cfg)).build(ReportType.ALL, run_dir)
        for p in md_paths:
            console.print(f"  [green]report[/green] {p}")
        _emit_export_formats(md_paths, fmt)


@app.command()
def run(
    name: str = typer.Option("specter-engagement", help="Engagement name"),
    objectives: str = typer.Option("", help="Free-text objectives"),
    target: Optional[List[str]] = typer.Option(
        None, "-t", "--target",
        help="Authorized target(s); repeatable. Adds to the configured scope for this run."),
    profile: str = typer.Option("", help="Override profile"),
    model: str = typer.Option(
        "", "--model",
        help="Force one 'provider:model' for every task (e.g. openai-compatible:my-model)."),
    offline: bool = typer.Option(False, help="No network calls to tools/providers"),
    demo: bool = typer.Option(False, help="Use bundled demo tool output (offline showcase)"),
    agent: bool = typer.Option(False, help="Use the autonomous agent loop instead of the pipeline"),
    allow_exploitation: bool = typer.Option(False, help="Permit active exploitation steps"),
    actor: str = typer.Option("", help="Operator identity recorded on the run"),
    log_level: str = typer.Option("", help="Audit log level: debug|info|warn|error"),
    report: bool = typer.Option(True, help="Auto-generate all reports after the run"),
    fmt: str = typer.Option("md", "--format", help="Report format: md|pdf|docx|all"),
) -> None:
    """Run an end-to-end engagement against the authorized scope."""
    cfg = Config.load()
    if profile:
        cfg.profile = profile
    if log_level:
        cfg.log_level = log_level
    cfg.offline = offline
    cfg.allow_exploitation = allow_exploitation
    if model:
        cfg.model_override = model
    for tgt in (target or []):
        if tgt and tgt not in cfg.scope.targets:
            cfg.scope.targets.append(tgt)

    if not cfg.scope.targets:
        console.print(Panel.fit(
            "[red]No authorized targets.[/red]\n"
            "  • Try it offline:   [bold]specter quickstart[/bold]\n"
            "  • One-off target:   [bold]specter run -t scanme.nmap.org[/bold]\n"
            "  • Configure scope:  [bold]specter init[/bold]",
            title="Nothing in scope", style="red"))
        raise typer.Exit(1)

    console.print(BANNER)
    console.print(Panel.fit(
        f"[bold]{name}[/bold]  ({'agent' if agent else 'pipeline'})\n"
        f"Targets: {', '.join(cfg.scope.targets)}\n"
        f"Profile: {cfg.profile}  •  Exploit: {allow_exploitation}  •  "
        f"Offline: {offline}  •  Demo: {demo}"
        + (f"\nModel: forced → [bold]{model}[/bold]" if model else ""),
        title="Engagement", style="magenta"))

    orch = Orchestrator(cfg, reporter=lambda m: console.print(f"[cyan]{m}[/cyan]"),
                        audit_dir=RUNS_DIR, demo=demo)
    if agent:
        eng = AgentRunner(orch).run(name=name, objective=objectives, actor=actor)
    else:
        eng = orch.run(name=name, objectives=objectives, actor=actor)
    _persist_and_report(cfg, eng, report, fmt=fmt)


@app.command()
def report(
    run_id: str = typer.Argument("", help="Run ID (defaults to latest)"),
    kind: ReportType = typer.Option(ReportType.ALL, help="risk|technical|remediation|all"),
    fmt: str = typer.Option("md", "--format", help="Report format: md|pdf|docx|all"),
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
    _emit_export_formats(written, fmt)


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
    """Start the team collaboration API server (needs ai-specter[server])."""
    from specter.server import serve as _serve
    console.print(f"[cyan]Specter server → http://{host}:{port}[/cyan]")
    _serve(host=host, port=port)


@app.command()
def mcp() -> None:
    """Run Specter as an MCP server for Claude/Cursor (needs ai-specter[mcp])."""
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
