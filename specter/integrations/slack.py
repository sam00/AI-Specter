"""Slack notifications for engagement results.

Posts a concise, severity-aware summary of an engagement to a Slack Incoming
Webhook. Pure data assembly (``findings_blocks``) is separated from network IO
(``SlackNotifier.send``) so message formatting is unit-testable offline.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

_SEV_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:",
              "medium": ":large_yellow_circle:", "low": ":large_blue_circle:",
              "info": ":white_circle:"}


def findings_blocks(name: str, run_id: str, findings: list, top: int = 10) -> dict:
    """Build a Slack Block Kit message from an engagement's findings."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts[sev] = counts.get(sev, 0) + 1
    summary = "  ".join(
        f"{_SEV_EMOJI.get(s, '')} {s}: {counts.get(s, 0)}"
        for s in ("critical", "high", "medium", "low", "info"))

    def _row(f):
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        return f"{_SEV_EMOJI.get(sev, '')} *{f.title}* — `{f.target}`"

    ranked = sorted(findings, key=lambda f: getattr(f.severity, "rank", 0), reverse=True)[:top]
    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": f"Specter: {name}"}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": f"*Run* `{run_id}`\n{summary}"}},
    ]
    if ranked:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": "\n".join(_row(f) for f in ranked)}})
    return {"blocks": blocks}


@dataclass
class SlackNotifier:
    webhook_url: str = ""

    def __post_init__(self) -> None:
        self.webhook_url = self.webhook_url or os.environ.get("SPECTER_SLACK_WEBHOOK", "")

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    def send(self, message: dict) -> tuple[bool, str]:
        if not self.configured:
            return False, "no Slack webhook configured (set SPECTER_SLACK_WEBHOOK)"
        import httpx
        try:
            with httpx.Client(timeout=15) as client:
                r = client.post(self.webhook_url, json=message)
            return (200 <= r.status_code < 300), f"slack responded {r.status_code}"
        except Exception as e:
            return False, str(e)

    def send_findings(self, name: str, run_id: str, findings: list) -> tuple[bool, str]:
        return self.send(findings_blocks(name, run_id, findings))
