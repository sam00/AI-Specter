"""Agentic (ReAct-style) engine mode.

Instead of a fixed pipeline, the model picks ONE next action at a time, observes
the result, and decides again. This turns Specter from an AI-narrated scanner
into an AI operator. It reuses the Orchestrator's clients, tools, memory, budget,
and audit so behavior (scope guard, caching, costing) stays consistent.
"""
from __future__ import annotations

import time

from specter.advisor import TaskKind
from specter.audit import AuditLogger
from specter.budget import Budget, BudgetExceeded
from specter.engine import findings as findings_mod
from specter.engine import phases as ph
from specter.engine.memory import EngagementMemory
from specter.engine.models import Engagement, Step
from specter.security import wrap_untrusted
from specter.tools.parsers import parse_tool

AGENT_SYSTEM = ph.SYSTEM_PROMPT + (
    " You operate as an autonomous loop: choose ONE next action, observe its "
    "result, then decide again. Prefer high-signal actions and stop when the "
    "objective is met."
)

AGENT_TOOLS = ["nmap", "httpx", "whatweb", "nmap-full", "ffuf", "nuclei",
               "nikto", "naabu", "katana", "testssl", "wpscan"]


def _decide_prompt(objective, targets, context, steps_left, tools) -> str:
    return (
        f"Objective: {objective}\nAuthorized targets: {targets}\n"
        f"Steps remaining: {steps_left}\nAvailable tools: {tools}\n"
        f"Context so far:\n{context}\n\n"
        "Choose the single best next action. Return ONLY JSON: "
        '{"action":"use_tool"|"finish","tool":str,"target":str,"reason":str}'
    )


class AgentRunner:
    def __init__(self, orchestrator) -> None:
        self.orch = orchestrator

    def run(self, name: str, objective: str = "", max_steps: int = 8, actor: str = "") -> Engagement:
        orch = self.orch
        cfg = orch.config
        actor = actor or cfg.actor
        eng = Engagement(name=name, profile=cfg.profile,
                         targets=list(cfg.scope.targets), actor=actor)
        eng.routing = {t: f"{r.provider}:{r.model}" for t, r in orch.advisor.plan().items()}
        orch.budget = Budget(max_usd=cfg.max_usd, max_tokens=cfg.max_tokens)
        orch.memory = EngagementMemory()

        log_path = (orch.audit_dir / eng.id / "specter.jsonl") if orch.audit_dir else None
        orch.audit = AuditLogger(log_path, level=cfg.log_level, compress_on_close=cfg.log_compress)
        orch.audit.event("run", "start", mode="agent", name=name, actor=actor,
                         targets=",".join(eng.targets))

        if not eng.targets:
            orch.log("[!] No authorized targets in scope. Aborting.")
            orch.audit.event("run", "aborted: no authorized targets", level="warn")
            orch._finalize(eng)
            return eng

        tools = [t for t in AGENT_TOOLS if t in orch.tools.specs]
        obj = objective or "find and prioritize exploitable risk"
        try:
            for step in range(max_steps):
                orch.budget.check()
                client, label = orch._client_for(TaskKind.PLANNING)
                prompt = _decide_prompt(obj, eng.targets, orch.memory.context(1000),
                                        max_steps - step, tools)
                decision = ph.safe_json(client.complete(AGENT_SYSTEM, prompt, max_tokens=512).text)
                action = decision.get("action", "finish")
                tool = decision.get("tool", "")
                target = decision.get("target") or eng.targets[0]
                orch.audit.event("agent", action, model=label, tool=tool, target=target,
                                 reason=str(decision.get("reason", ""))[:160])
                orch.log(f"[agent] step {step + 1}: {action} {tool} -> {target}")

                if action != "use_tool":
                    break
                if tool not in tools or not cfg.in_scope(target):
                    orch.memory.note(f"Skipped invalid/out-of-scope action: {tool} on {target}")
                    continue

                t0 = time.perf_counter()
                res = orch.tools.run(tool, target, in_scope=True)
                orch.audit.command(res.command, tool=tool, target=target,
                                   ms=int((time.perf_counter() - t0) * 1000),
                                   ok=not res.error, sim=res.simulated)
                parsed = parse_tool(tool, res.stdout)
                n = orch._ingest_items(eng, parsed.get("findings", []), target, "agent", "parser")
                tri, _ = orch._llm_json(
                    TaskKind.RECON_TRIAGE,
                    ph.triage_prompt(target, tool, wrap_untrusted(tool, res.stdout or res.error)))
                n += orch._ingest_items(eng, tri.get("findings", []), target, "agent", "llm")
                eng.add_step(Step(phase="agent", action=f"use {tool}", tool=tool,
                                  target=target, model=label))
                orch.memory.note(f"Ran {tool} on {target}: {n} finding(s).")
        except BudgetExceeded as e:
            orch.log(f"[!] Budget reached, stopping: {e}")
            orch.audit.event("run", "budget-stop", level="warn", msg=str(e))

        eng.findings = findings_mod.dedup(eng.findings)
        eng.clusters = findings_mod.correlate(eng.findings)
        orch.audit.event("run", "complete", mode="agent", findings=len(eng.findings),
                         steps=len(eng.steps), ms=orch.audit.stats()["elapsed_ms"])
        orch._finalize(eng)
        return eng
