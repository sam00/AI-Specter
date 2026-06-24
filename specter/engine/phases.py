"""Pentest phase definitions and the prompts that drive each one.

Each phase maps to a TaskKind so the orchestrator can route it to the
best-suited model via the advisor.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from specter.advisor import TaskKind

SYSTEM_PROMPT = (
    "You are Specter, an authorized penetration-testing assistant operating "
    "strictly inside an approved engagement scope. You never act on out-of-scope "
    "targets. You produce precise, evidence-backed, professional output. "
    "When asked for JSON, return ONLY valid JSON with no prose."
)


@dataclass(frozen=True)
class Phase:
    key: str
    title: str
    task: TaskKind
    description: str


PHASES: list[Phase] = [
    Phase("plan", "Attack Planning", TaskKind.PLANNING,
          "Translate scope + objectives into an ordered, ROE-compliant test plan."),
    Phase("recon", "Reconnaissance", TaskKind.RECON_TRIAGE,
          "Passive/active discovery of hosts, services, and attack surface."),
    Phase("enum", "Enumeration", TaskKind.RECON_TRIAGE,
          "Deep service enumeration and lead identification."),
    Phase("vuln", "Vulnerability Analysis", TaskKind.EXPLOIT_REASONING,
          "Correlate findings to known vulns; rank exploitability."),
    Phase("exploit", "Exploitation", TaskKind.EXPLOIT_REASONING,
          "Plan exploitation paths. Execution gated behind --allow-exploitation."),
    Phase("post", "Post-Exploitation", TaskKind.PLANNING,
          "Privilege escalation, lateral movement, C2 hand-off planning."),
    Phase("report", "Reporting", TaskKind.REPORT_TECHNICAL,
          "Synthesize findings into risk/technical/remediation reports."),
]


def plan_prompt(name: str, targets: list[str], roe: str, objectives: str) -> str:
    return (
        f"Engagement: {name}\nAuthorized targets: {targets}\n"
        f"Rules of engagement: {roe or 'standard non-destructive testing'}\n"
        f"Objectives: {objectives or 'identify and prioritize exploitable risk'}\n\n"
        "Produce a JSON object: {\"phases\":[{\"phase\":str,\"goal\":str,"
        "\"techniques\":[str],\"tools\":[str]}]}"
    )


def triage_prompt(target: str, tool: str, raw_output: str) -> str:
    return (
        f"Target: {target}\nTool: {tool}\n--- RAW OUTPUT ---\n{raw_output[:6000]}\n--- END ---\n\n"
        "Extract security-relevant findings. Return ONLY JSON: "
        "{\"findings\":[{\"title\":str,\"severity\":\"info|low|medium|high|critical\","
        "\"cvss\":number,\"cve\":[str],\"mitre_attack\":[str],\"description\":str,"
        "\"evidence\":str,\"remediation\":str}]}"
    )


def exploit_prompt(target: str, findings_json: str, allow_exec: bool) -> str:
    mode = "PLAN ONLY (do not execute)" if not allow_exec else "execution authorized"
    return (
        f"Target: {target}\nMode: {mode}\nConfirmed findings: {findings_json[:5000]}\n\n"
        "Propose exploitation paths ranked by likelihood and impact. Return ONLY JSON: "
        "{\"paths\":[{\"name\":str,\"finding_ref\":str,\"steps\":[str],"
        "\"prereqs\":[str],\"impact\":str,\"risk_of_detection\":\"low|medium|high\"}]}"
    )


def safe_json(text: str) -> dict:
    """Tolerant JSON extraction from model output (handles code fences/prose)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        text = text[start : end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}
