"""Interactive terminal UI (Textual).

A keyboard-driven cockpit over the same engine the CLI uses: browse findings
from the shared store, switch the active domain-specialist agent, and review the
MCP suite and Relay status. Textual is an optional dependency
(``pip install 'ai-specter[tui]'``); the launcher degrades gracefully if it's
missing.
"""
from __future__ import annotations


def run_tui() -> None:
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.widgets import (
            DataTable,
            Footer,
            Header,
            Static,
            TabbedContent,
            TabPane,
        )
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'ai-specter[tui]' for the interactive TUI") from e

    from specter.agents import AGENT_PROFILES
    from specter.mcp_catalog import MCP_CATALOG, total_tools
    from specter.store import Store

    class SpecterTUI(App):
        TITLE = "Specter"
        SUB_TITLE = "AI-driven pentesting cockpit"
        CSS = """
        Screen { background: $surface; }
        #agentbar { padding: 1 2; color: $text-muted; }
        DataTable { height: 1fr; }
        """
        BINDINGS = [
            Binding("tab", "next_agent", "Next agent"),
            Binding("r", "refresh", "Refresh"),
            Binding("q", "quit", "Quit"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._agents = list(AGENT_PROFILES.values())
            self._idx = 0

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static(self._agent_line(), id="agentbar")
            with TabbedContent(initial="vulns"):
                with TabPane("Vulnerabilities", id="vulns"):
                    yield DataTable(id="vt")
                with TabPane("Agents", id="agents"):
                    yield DataTable(id="at")
                with TabPane("MCP Suite", id="mcp"):
                    yield DataTable(id="mt")
                with TabPane("Relay", id="relay"):
                    yield Static(
                        "Relay nodes register at runtime.\n"
                        "  • specter relay keygen   — create an Ed25519 identity\n"
                        "  • specter relay serve     — run a remote tool node\n"
                        "  • specter relay run       — dispatch a signed remote tool",
                        id="relayinfo")
            yield Footer()

        def on_mount(self) -> None:
            vt = self.query_one("#vt", DataTable)
            vt.add_columns("Sev", "Title", "Target", "Status", "Conf")
            at = self.query_one("#at", DataTable)
            at.add_columns("Name", "Specialist", "Methodology")
            for p in self._agents:
                at.add_row(p.name, p.title, p.methodology)
            mt = self.query_one("#mt", DataTable)
            mt.add_columns("Name", "Domain", "Tools", "Description")
            for s in MCP_CATALOG.values():
                mt.add_row(s.name, s.domain, str(s.tools), s.description)
            self.action_refresh()

        def _agent_line(self) -> str:
            a = self._agents[self._idx]
            return (f"Active agent: [b]{a.title}[/b] · {a.methodology}   "
                    f"(Tab to switch · {total_tools()} MCP tools available)")

        def action_next_agent(self) -> None:
            self._idx = (self._idx + 1) % len(self._agents)
            self.query_one("#agentbar", Static).update(self._agent_line())

        def action_refresh(self) -> None:
            vt = self.query_one("#vt", DataTable)
            vt.clear()
            try:
                rows = Store().list_findings()
            except Exception:
                rows = []
            for r in rows[:200]:
                vt.add_row(r["severity"].upper(), r["title"], r["target"],
                           r["status"], f"{r.get('cvss', 0)}")
            if not rows:
                vt.add_row("—", "No findings yet — run an engagement", "", "", "")

    SpecterTUI().run()
