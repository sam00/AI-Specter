"""Drives an engagement: plan -> recon -> enum -> vuln -> exploit -> report.

The orchestrator asks the ModelAdvisor which model to use for each phase, runs
the right security tools (scope-guarded), then has the chosen model triage the
output into structured findings.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from specter import security
from specter.advisor import ModelAdvisor, TaskKind, catalog_from_config, overrides_from_spec
from specter.audit import AuditLogger
from specter.budget import Budget, BudgetExceeded
from specter.cache import LLMCache
from specter.config import CONFIG_DIR, Config
from specter.engine import findings as findings_mod
from specter.engine import phases as ph
from specter.engine.memory import EngagementMemory
from specter.engine.models import Engagement, Finding, Severity, Step
from specter.llm import available_providers, build_client
from specter.llm.resilient import ResilientClient
from specter.tools import ToolRegistry
from specter.tools.parsers import parse_tool

# Which tools feed which phase's triage step.
PHASE_TOOLS: dict[str, list[str]] = {
    "recon": ["nmap", "httpx", "whatweb"],
    "enum": ["nmap-full", "ffuf"],
    "vuln": ["nuclei", "nikto"],
}

# Dynamic output sizing per task to avoid wasting tokens.
TASK_TOKENS: dict[TaskKind, int] = {
    TaskKind.PLANNING: 2048,
    TaskKind.RECON_TRIAGE: 1500,
    TaskKind.EXPLOIT_REASONING: 2048,
    TaskKind.PAYLOAD: 1500,
    TaskKind.PARSING: 1024,
    TaskKind.REPORT_RISK: 1500,
    TaskKind.REPORT_TECHNICAL: 1800,
    TaskKind.REPORT_REMEDIATION: 1500,
    TaskKind.CHAT: 1024,
}

Reporter = Callable[[str], None]


class Orchestrator:
    def __init__(
        self,
        config: Config,
        reporter: Reporter | None = None,
        audit_dir: Path | None = None,
        demo: bool = False,
    ) -> None:
        self.config = config
        self.log = reporter or (lambda m: None)
        self.demo = demo
        # In true offline mode we route everything to the local echo stub so no
        # network calls are made (even local model endpoints are skipped).
        self.providers = {"echo"} if config.offline else available_providers(config)
        self.advisor = ModelAdvisor(self.providers, profile=config.profile,
                                    catalog=catalog_from_config(config.models),
                                    overrides=overrides_from_spec(config.model_override))
        self.tools = ToolRegistry(offline=config.offline,
                                  dry_run=not config.allow_exploitation, demo=demo)
        self.audit_dir = audit_dir
        self.audit = AuditLogger(None)  # no-op until run() opens the real log
        cache_path = ((CONFIG_DIR / "cache.db")
                      if (config.cache_enabled and not config.offline) else None)
        self.cache = LLMCache(cache_path, enabled=bool(cache_path))
        self.budget = Budget()
        self.memory = EngagementMemory()

    def _client_for(self, task: TaskKind):
        rec = self.advisor.recommend(task)
        provider, model = (rec.provider, rec.model) if rec else ("echo", "echo")
        base = build_client(self.config, provider, model)
        client = ResilientClient(base, retries=self.config.llm_retries,
                                 cache=self.cache, budget=self.budget)
        return client, f"{provider}:{model}"

    def _llm_json(self, task: TaskKind, user: str) -> tuple[dict, str]:
        client, label = self._client_for(task)
        resp = client.complete(ph.SYSTEM_PROMPT, user, max_tokens=TASK_TOKENS.get(task, 2048))
        return ph.safe_json(resp.text), label

    def run(self, name: str, objectives: str = "", actor: str = "") -> Engagement:
        cfg = self.config
        actor = actor or cfg.actor
        eng = Engagement(name=name, profile=cfg.profile,
                         targets=list(cfg.scope.targets), actor=actor)
        eng.routing = {t: f"{r.provider}:{r.model}" for t, r in self.advisor.plan().items()}
        self.budget = Budget(max_usd=cfg.max_usd, max_tokens=cfg.max_tokens)
        self.memory = EngagementMemory()

        log_path = (self.audit_dir / eng.id / "specter.jsonl") if self.audit_dir else None
        self.audit = AuditLogger(log_path, level=cfg.log_level, compress_on_close=cfg.log_compress)
        self.audit.event("run", "start", name=name, profile=cfg.profile, actor=actor,
                         targets=",".join(eng.targets), offline=cfg.offline,
                         exploitation=cfg.allow_exploitation, demo=self.demo)
        for task_name, model in eng.routing.items():
            self.audit.event("route", task_name, level="debug", model=model)

        if not eng.targets:
            self.log("[!] No authorized targets in scope. Aborting.")
            self.audit.event("run", "aborted: no authorized targets", level="warn")
            self._finalize(eng)
            return eng

        try:
            self._plan(eng, name, objectives)
            working = list(eng.targets)
            for phase_key in ("recon", "enum", "vuln"):
                discovered = self._run_phase(eng, phase_key, working)
                for host in sorted(discovered):  # adaptive scope: authorized subdomains only
                    if host and host not in working and cfg.in_scope(host):
                        working.append(host)
                        self.memory.add_host(host)
                        self.audit.event("scope", "expanded", host=host)
            self._exploit(eng)
        except BudgetExceeded as e:
            self.log(f"[!] Budget reached, stopping early: {e}")
            self.audit.event("run", "budget-stop", level="warn", msg=str(e))

        # Post-processing: dedup -> correlate -> (optional) verify
        before = len(eng.findings)
        eng.findings = findings_mod.dedup(eng.findings)
        self.audit.event("dedup", "merge", before=before, after=len(eng.findings))
        eng.clusters = findings_mod.correlate(eng.findings)
        if cfg.verify_findings and not cfg.offline and eng.findings:
            client, label = self._client_for(TaskKind.EXPLOIT_REASONING)
            with self.audit.timed("verify", "second-opinion") as ex:
                ex["model"] = label
                ex["adjudicated"] = findings_mod.verify(client, eng.findings)

        self.log(f"[+] Engagement complete: {len(eng.findings)} findings, "
                 f"{len(eng.clusters)} clusters.")
        self.audit.event("run", "complete", findings=len(eng.findings), steps=len(eng.steps),
                         clusters=len(eng.clusters), cache_hits=self.cache.hits,
                         usd=round(self.budget.usd, 4), ms=self.audit.stats()["elapsed_ms"])
        self._finalize(eng)
        return eng

    def _plan(self, eng: Engagement, name: str, objectives: str) -> None:
        self.log("[*] Phase: Attack Planning")
        with self.audit.timed("task", "planning") as ex:
            plan, label = self._llm_json(
                TaskKind.PLANNING,
                ph.plan_prompt(name, eng.targets, self.config.scope.rules_of_engagement, objectives))
            ex["model"] = label
            ex["phases"] = len(plan.get("phases", []))
        self.memory.note(f"Planned engagement '{name}' over {len(eng.targets)} target(s).")
        eng.add_step(Step(phase="plan", action="generate plan", model=label,
                          summary=f"{len(plan.get('phases', []))} phases planned"))

    def _tool_and_triage(self, phase, target: str, tool: str):
        """Runs in a worker thread: tool exec -> native parse -> LLM enrichment."""
        in_scope = self.config.in_scope(target)
        t0 = time.perf_counter()
        res = self.tools.run(tool, target, in_scope=in_scope)
        cmd_ms = int((time.perf_counter() - t0) * 1000)
        parsed = parse_tool(tool, res.stdout)
        t1 = time.perf_counter()
        wrapped = security.wrap_untrusted(tool, res.stdout or res.error)
        prior = self.memory.context(800)
        user = ph.triage_prompt(target, tool, wrapped) + f"\n\nKnown context so far:\n{prior}"
        llm_data, label = self._llm_json(phase.task, user)
        tri_ms = int((time.perf_counter() - t1) * 1000)
        return res, parsed, llm_data, label, cmd_ms, tri_ms

    def _run_phase(self, eng: Engagement, phase_key: str, targets: list[str]) -> set[str]:
        cfg = self.config
        phase = next(p for p in ph.PHASES if p.key == phase_key)
        self.log(f"[*] Phase: {phase.title}")
        self.audit.phase(phase.title, key=phase_key)
        jobs = [(tgt, tool) for tgt in targets for tool in PHASE_TOOLS.get(phase_key, [])]
        submitted: list = []
        with ThreadPoolExecutor(max_workers=max(1, cfg.max_workers)) as pool:
            for tgt, tool in jobs:
                submitted.append(((tgt, tool),
                                  pool.submit(self._tool_and_triage, phase, tgt, tool)))

        discovered: set[str] = set()
        for (tgt, tool), fut in submitted:  # deterministic submission order
            res, parsed, llm_data, label, cmd_ms, tri_ms = fut.result()
            self.audit.command(res.command, tool=tool, target=tgt, ms=cmd_ms,
                               ok=not res.error, sim=res.simulated, err=res.error)
            self.log(f"    [{'SIM' if res.simulated else 'RUN'}] {tool} -> {tgt}")
            n = self._ingest_items(eng, parsed.get("findings", []), tgt, phase_key, "parser")
            n += self._ingest_items(eng, llm_data.get("findings", []), tgt, phase_key, "llm")
            for h in parsed.get("hosts", []):
                if h.get("address"):
                    discovered.add(h["address"])
            self.audit.step(phase_key, "triage", tool=tool, target=tgt, model=label,
                            ms=tri_ms, found=n)
            eng.add_step(Step(phase=phase_key, action="triage", tool=tool, target=tgt,
                              model=label, ok=not res.error))
        return discovered

    def _exploit(self, eng: Engagement) -> None:
        self.log("[*] Phase: Exploitation Analysis")
        confirmed = [f.model_dump() for f in eng.top_findings(15)]
        with self.audit.timed("phase", "exploitation analysis") as ex:
            paths, label = self._llm_json(
                TaskKind.EXPLOIT_REASONING,
                ph.exploit_prompt("scope", str(confirmed), self.config.allow_exploitation))
            ex["model"] = label
            ex["paths"] = len(paths.get("paths", []))
        eng.add_step(Step(phase="exploit", action="path analysis", model=label,
                          summary=f"{len(paths.get('paths', []))} exploitation paths"))

    def _finalize(self, eng: Engagement) -> None:
        closed = self.audit.close()
        if closed:
            eng.log_file = str(closed)

    def _ingest_items(self, eng: Engagement, items: list, target: str,
                      phase: str, source: str) -> int:
        count = 0
        for item in items or []:
            try:
                sev = Severity(str(item.get("severity", "info")).lower())
            except ValueError:
                sev = Severity.INFO
            host = item.get("host") or target
            f = Finding(
                title=item.get("title", "Unspecified finding"), severity=sev, target=host,
                cvss=float(item.get("cvss", 0) or 0), cve=list(item.get("cve", []) or []),
                mitre_attack=list(item.get("mitre_attack", []) or []),
                description=item.get("description", ""), evidence=item.get("evidence", ""),
                remediation=item.get("remediation", ""), phase=phase, source=source,
                confidence=0.5 if source == "parser" else 0.4)
            eng.add_finding(f)
            self.memory.add_finding(f.title, host, sev.value)
            count += 1
        return count
