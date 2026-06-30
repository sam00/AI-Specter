"""Outbound integrations (Slack, etc.)."""
from specter.integrations.slack import SlackNotifier, findings_blocks

__all__ = ["SlackNotifier", "findings_blocks"]
