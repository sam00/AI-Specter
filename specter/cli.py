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
relay_app = typer.Typer(help="Relay — Ed25519-signed remote tool execution.")
app.add_typer(relay_app, name="relay")
suite_app = typer.Typer(help="External security MCP server ecosystem.")
app.add_typer(suite_app, name="mcp-suite")
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
    from specter.i18n import t
    console.print(BANNER)
    console.print(Panel.fit(
        f"[bold]{t('get_started')}[/bold]\n\n"
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
    for name in ("anthropic", "openai", "azure-openai", "bedrock", "mistral",
                 "ollama", "vllm", "lmstudio", "openai-compatible", "echo"):
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
    domain: str = typer.Option(
        "", help="Specialist agent profile (with --agent): "
        "web-application|api|mobile-application|cloud-security|internal-network|general"),
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
        eng = AgentRunner(orch).run(name=name, objective=objectives, actor=actor, domain=domain)
    else:
        if domain:
            console.print("[yellow]--domain only applies with --agent; ignoring.[/yellow]")
        eng = orch.run(name=name, objectives=objectives, actor=actor)
    _persist_and_report(cfg, eng, report, fmt=fmt)


@app.command()
def agents() -> None:
    """List the domain-specialist agent profiles (use with `run --agent --domain`)."""
    from specter.agents import AGENT_PROFILES
    t = Table(title="Domain-specialist agents")
    for col in ("Name", "Specialist", "Methodology", "Preferred tools"):
        t.add_column(col, overflow="fold")
    for p in AGENT_PROFILES.values():
        t.add_row(p.name, p.title, p.methodology, ", ".join(p.tools[:6]))
    console.print(t)
    console.print("[dim]Run one:[/dim] [bold]specter run --agent --domain web-application "
                  "-t app.example.com[/bold]")


@app.command()
def webtest(
    har: str = typer.Option("", help="Path to a HAR capture to test (browser/Burp/ZAP export)"),
    target: Optional[List[str]] = typer.Option(
        None, "-t", "--target", help="Authorized target host(s); repeatable"),
    only: str = typer.Option("", help="Comma-separated tester subset "
                             "(idor,authz-bypass,mass-assignment,injection,auth,"
                             "business-logic,ssrf,file-attacks)"),
    reproduce: int = typer.Option(2, help="Times the attack signal must reproduce"),
    report: bool = typer.Option(False, help="Persist confirmed findings to the shared store"),
) -> None:
    """Run the evidence-gated active web sub-testers over captured traffic."""
    from specter.webtest import HttpxSender, WebTestRunner, har_to_context
    cfg = Config.load()
    targets = list(cfg.scope.targets) + [t for t in (target or [])]
    if not har:
        console.print(Panel.fit(
            "[red]No capture provided.[/red]\n"
            "  Record traffic in your browser devtools or Burp/ZAP, export a HAR, then:\n"
            "  [bold]specter webtest --har session.har -t app.example.com[/bold]\n"
            "  Or capture live: [bold]specter proxy -t app.example.com[/bold]",
            title="Web testing", style="red"))
        raise typer.Exit(1)
    ctx = har_to_context(har, base_targets=targets)
    if not ctx.in_scope and not targets:
        console.print("[yellow]No scope set — testing every host in the HAR.[/yellow]")
    enabled = [s.strip() for s in only.split(",") if s.strip()] or None
    sender = HttpxSender(ctx)
    console.print(f"[cyan]Loaded {len(ctx.transactions)} transactions, "
                  f"{len(ctx.identities)} identities. Running testers…[/cyan]")
    result = WebTestRunner(sender, reproduce=reproduce, enabled=enabled).run(ctx)
    findings = result.findings()
    t = Table(title=f"Web findings — {result.confirmed} confirmed / {result.attempted} attempted")
    for col in ("Sev", "Title", "Endpoint", "Confidence", "OWASP"):
        t.add_column(col, overflow="fold")
    for f in findings:
        t.add_row(f.severity.value.upper(), f.title, f.description.split(" — ")[0],
                  f"{f.confidence:.2f}", ", ".join(f.mitre_attack))
    console.print(t)
    if report and findings:
        from specter.engine.models import Engagement
        eng = Engagement(name="webtest", targets=targets, findings=findings, actor=cfg.actor)
        save_run(eng)
        Store().save_engagement(eng)
        console.print(f"[green]saved engagement {eng.id} with {len(findings)} findings[/green]")


@app.command()
def proxy(
    target: Optional[List[str]] = typer.Option(
        None, "-t", "--target", help="Authorized target host(s) to record; repeatable"),
    host: str = typer.Option("127.0.0.1", help="Proxy bind host"),
    port: int = typer.Option(8081, help="Proxy bind port"),
    har_out: str = typer.Option("", help="Optional path to also test the capture on exit"),
) -> None:
    """Start a recording HTTP proxy that builds a live session context."""
    import time as _time

    from specter.webtest import RecordingProxy, SessionContext
    cfg = Config.load()
    targets = list(cfg.scope.targets) + [t for t in (target or [])]
    ctx = SessionContext(base_targets=targets)
    proxy = RecordingProxy(ctx, host=host, port=port).start()
    console.print(Panel.fit(
        f"[green]Recording proxy on http://{host}:{port}[/green]\n"
        f"Scope: {', '.join(targets) or '[dim]all hosts[/dim]'}\n"
        f"Set your browser/CLI HTTP proxy to [bold]{host}:{port}[/bold]. "
        "Ctrl-C to stop.", title="Proxy", style="green"))
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        proxy.stop()
    console.print(f"\n[cyan]Captured {len(ctx.transactions)} transactions, "
                  f"{len(ctx.identities)} identities.[/cyan]")


def _persist_findings(cfg: Config, name: str, targets: list, findings: list) -> str:
    from specter.engine.models import Engagement
    eng = Engagement(name=name, targets=targets, findings=findings, actor=cfg.actor)
    save_run(eng)
    try:
        Store().save_engagement(eng)
    except Exception as e:  # pragma: no cover
        console.print(f"[yellow]store unavailable: {e}[/yellow]")
    return eng.id


def _print_findings(title: str, findings: list) -> None:
    t = Table(title=title)
    for col in ("Sev", "Title", "Detail", "Remediation"):
        t.add_column(col, overflow="fold")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        t.add_row(f.severity.value.upper(), f.title, f.description, f.remediation)
    console.print(t)


@app.command()
def cloud(
    provider: str = typer.Option("aws", help="aws|azure|gcp"),
    demo: bool = typer.Option(True, help="Use a simulated misconfigured account (offline)"),
    report: bool = typer.Option(False, help="Persist findings to the shared store"),
) -> None:
    """Audit cloud posture against CIS-aligned checks."""
    from specter.cloud import CloudAuditor, demo_state
    cfg = Config.load()
    if not demo:
        console.print("[yellow]Live collection needs ai-specter[bedrock]/boto3 + creds; "
                      "falling back to demo state for now.[/yellow]")
    state = demo_state(provider)
    findings = CloudAuditor().audit(state)
    _print_findings(f"Cloud audit — {provider} ({len(findings)} findings)", findings)
    if report and findings:
        rid = _persist_findings(cfg, f"cloud-{provider}", [f"{provider}:account"], findings)
        console.print(f"[green]saved engagement {rid}[/green]")


@app.command()
def mobile(
    apk: str = typer.Option("", help="Path to an APK to statically analyze"),
    demo: bool = typer.Option(False, help="Use a simulated insecure build (offline)"),
    report: bool = typer.Option(False, help="Persist findings to the shared store"),
) -> None:
    """Audit a mobile build against MASVS controls."""
    from specter.mobile import MobileAuditor, demo_facts, extract_facts_from_apk
    cfg = Config.load()
    if apk:
        facts = extract_facts_from_apk(apk)
    elif demo:
        facts = demo_facts()
    else:
        console.print("[red]Provide --apk PATH or --demo.[/red]")
        raise typer.Exit(1)
    findings = MobileAuditor().audit(facts)
    _print_findings(f"Mobile audit — {facts.package} ({len(findings)} findings)", findings)
    if report and findings:
        rid = _persist_findings(cfg, f"mobile-{facts.package}", [facts.package], findings)
        console.print(f"[green]saved engagement {rid}[/green]")


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


@app.command()
def tui() -> None:
    """Launch the interactive terminal UI (needs ai-specter[tui])."""
    from specter.tui import run_tui
    run_tui()


@app.command()
def lang() -> None:
    """Show available locales and the one currently active (set SPECTER_LANG)."""
    from specter.i18n import available_locales, current_lang, t
    cur = current_lang()
    tbl = Table(title="Locales")
    for col in ("Code", "Active", "Tagline"):
        tbl.add_column(col)
    for code in available_locales():
        tbl.add_row(code, "[green]✓[/green]" if code == cur else "",
                    t("tagline", lang=code))
    console.print(tbl)
    console.print("[dim]Switch with:[/dim] [bold]SPECTER_LANG=es specter[/bold]")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8787, help="Bind port"),
) -> None:
    """Start the server + browser dashboard (needs ai-specter[server])."""
    from specter.server import serve as _serve
    console.print(Panel.fit(
        f"[green]Specter dashboard → http://{host}:{port}/[/green]\n"
        "Tabs: Vulnerabilities · Web Context · Agents · MCP Suite · Relay\n"
        f"[dim]Expose remotely with zero open ports: "
        f"specter tunnel --url http://{host}:{port}[/dim]", style="green"))
    _serve(host=host, port=port)


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


# --- MCP ecosystem ----------------------------------------------------------
@suite_app.command("list")
def mcp_suite_list() -> None:
    """List external security MCP servers Specter can orchestrate."""
    from specter.mcp_catalog import MCP_CATALOG, total_tools
    t = Table(title=f"MCP security suite · {total_tools()} tools across "
              f"{len(MCP_CATALOG)} servers")
    for col in ("Name", "Domain", "Tools", "Description", "Repo"):
        t.add_column(col, overflow="fold")
    for s in MCP_CATALOG.values():
        t.add_row(s.name, s.domain, str(s.tools), s.description, s.repo)
    console.print(t)


@suite_app.command("enable")
def mcp_suite_enable(
    names: str = typer.Argument("", help="Comma-separated server names (default: all)"),
    out: str = typer.Option("", help="Write mcpServers config to this path"),
) -> None:
    """Emit an mcpServers config block for the selected servers."""
    import json as _json

    from specter.mcp_catalog import MCP_CATALOG, to_client_config, write_client_config
    selected = [n.strip() for n in names.split(",") if n.strip()] or list(MCP_CATALOG)
    unknown = [n for n in selected if n not in MCP_CATALOG]
    if unknown:
        console.print(f"[red]unknown servers: {', '.join(unknown)}[/red]")
        raise typer.Exit(1)
    if out:
        path = write_client_config(out, selected)
        console.print(f"[green]wrote {path}[/green]")
    else:
        console.print_json(_json.dumps(to_client_config(selected)))


# --- Slack ------------------------------------------------------------------
@app.command()
def slack(
    run_id: str = typer.Argument("", help="Run ID (defaults to latest)"),
    webhook: str = typer.Option("", help="Slack webhook (or set SPECTER_SLACK_WEBHOOK)"),
) -> None:
    """Post an engagement summary to Slack."""
    from specter.integrations import SlackNotifier
    rid = run_id or latest_run_id()
    if not rid:
        console.print("[red]No runs found.[/red]")
        raise typer.Exit(1)
    eng = load_run(rid)
    notifier = SlackNotifier(webhook)
    if not notifier.configured:
        console.print("[red]No webhook. Pass --webhook or set SPECTER_SLACK_WEBHOOK.[/red]")
        raise typer.Exit(1)
    ok, msg = notifier.send_findings(eng.name, eng.id, eng.findings)
    console.print(f"[green]{msg}[/green]" if ok else f"[red]{msg}[/red]")
    if not ok:
        raise typer.Exit(1)


# --- Cloudflare tunnel ------------------------------------------------------
@app.command()
def tunnel(
    url: str = typer.Option("http://127.0.0.1:8787", help="Local service URL to expose"),
    name: str = typer.Option("", help="Named cloudflared tunnel (empty = quick tunnel)"),
) -> None:
    """Expose a local Specter service with zero open ports via Cloudflare Tunnel."""
    from specter.remote import CloudflareTunnel, cloudflared_available
    if not cloudflared_available():
        console.print(Panel.fit(
            "[red]cloudflared not found.[/red]\n"
            "  macOS:  [bold]brew install cloudflared[/bold]\n"
            "  Docs:   https://developers.cloudflare.com/cloudflare-one/",
            title="Tunnel", style="red"))
        raise typer.Exit(1)
    console.print(Panel.fit(
        f"[green]Opening Cloudflare Tunnel → {url}[/green]\n"
        "Outbound-only; no inbound ports. Ctrl-C to stop.", style="green"))
    tun = CloudflareTunnel(local_url=url, name=name).start()
    try:
        tun._proc.wait()  # type: ignore[union-attr]
    except KeyboardInterrupt:
        tun.stop()


# --- Relay ------------------------------------------------------------------
@relay_app.command("keygen")
def relay_keygen(
    out: str = typer.Option("", help="Path to write the private key (default: ~/.specter/relay.key)"),
) -> None:
    """Generate an Ed25519 Relay identity (prints the public key to pin/allowlist)."""
    from specter.relay import KeyPair
    path = Path(out) if out else (CONFIG_FILE.parent / "relay.key")
    kp = KeyPair.generate()
    kp.save(path)
    console.print(Panel.fit(
        f"[green]Relay key written to {path}[/green]\n"
        f"Public key (share to allowlist/pin):\n[bold]{kp.public_b64()}[/bold]",
        title="Relay identity", style="green"))


@relay_app.command("serve")
def relay_serve(
    key: str = typer.Option("", help="Server private key path (default: ~/.specter/relay.key)"),
    allow: str = typer.Option(..., help="Comma-separated authorized client public keys"),
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8443, help="Bind port"),
) -> None:
    """Run a Relay server that executes scope-guarded tools for signed clients."""
    from specter.relay import KeyPair, RelayExecutor, RelayServer
    from specter.tools import ToolRegistry
    cfg = Config.load()
    key_path = Path(key) if key else (CONFIG_FILE.parent / "relay.key")
    if not key_path.exists():
        console.print(f"[red]No key at {key_path}. Run `specter relay keygen` first.[/red]")
        raise typer.Exit(1)
    server_key = KeyPair.load(key_path)
    clients = {c.strip() for c in allow.split(",") if c.strip()}
    executor = RelayExecutor(server_key=server_key, allowed_clients=clients,
                             scope=set(cfg.scope.targets),
                             registry=ToolRegistry(offline=cfg.offline))
    console.print(Panel.fit(
        f"[green]Relay server on {host}:{port}[/green]\n"
        f"Scope: {', '.join(cfg.scope.targets) or '[dim]none — set scope first[/dim]'}\n"
        f"Authorized clients: {len(clients)}  ·  Ctrl-C to stop.", style="green"))
    srv = RelayServer(executor, host=host, port=port).start()
    try:
        import time as _t
        while True:
            _t.sleep(1)
    except KeyboardInterrupt:
        srv.stop()


@relay_app.command("run")
def relay_run(
    endpoint: str = typer.Option(..., help="Relay server URL (e.g. https://relay-1:8443)"),
    tool: str = typer.Option(..., help="Tool to run remotely"),
    target: str = typer.Option(..., help="Authorized target"),
    key: str = typer.Option("", help="Client private key path (default: ~/.specter/relay.key)"),
    server_pub: str = typer.Option("", help="Pinned server public key (recommended)"),
) -> None:
    """Run a tool on a remote Relay server and print the signed result."""
    from specter.relay import KeyPair, RelayClient, RelayEndpoint
    key_path = Path(key) if key else (CONFIG_FILE.parent / "relay.key")
    if not key_path.exists():
        console.print(f"[red]No key at {key_path}. Run `specter relay keygen` first.[/red]")
        raise typer.Exit(1)
    client = RelayClient(KeyPair.load(key_path))
    client.add_endpoint(RelayEndpoint("remote", endpoint, server_pub=server_pub))
    resp = client.run("remote", tool, target)
    if resp.error:
        console.print(Panel.fit(f"[red]{resp.error}[/red]", style="red"))
        raise typer.Exit(1)
    console.print(Panel.fit(
        f"[green]{tool} @ {target}[/green]  (simulated={resp.simulated})\n\n"
        f"{resp.stdout[:4000]}", style="green"))


if __name__ == "__main__":
    app()
