"""Curated catalog of external security MCP servers Specter can orchestrate.

Specter already *is* an MCP server (`specter mcp`). This catalog lets it also
*consume* a wider ecosystem of specialized security MCP servers, and emit a
standard ``mcpServers`` config block for any MCP client (Specter, Claude,
Cursor, …). Servers are launched on demand with ``npx`` — nothing is bundled.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class MCPServer:
    name: str
    domain: str
    tools: int
    description: str
    command: str
    args: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)  # required env var names
    repo: str = ""


MCP_CATALOG: dict[str, MCPServer] = {
    "cloud-audit": MCPServer(
        "cloud-audit", "Cloud (AWS/Azure/GCP)", 38,
        "Cloud security audits across AWS, Azure, GCP (60+ checks).",
        "npx", ["-y", "cloud-audit-mcp"],
        env=["AWS_PROFILE"], repo="github.com/badchars/cloud-audit-mcp"),
    "github-security": MCPServer(
        "github-security", "Source / supply chain", 39,
        "GitHub security posture: repo, org, actions, secrets, supply chain.",
        "npx", ["-y", "github-security-mcp"],
        env=["GITHUB_TOKEN"], repo="github.com/badchars/github-security-mcp"),
    "cve": MCPServer(
        "cve", "Vulnerability intel", 23,
        "CVE intelligence: NVD, EPSS, CISA KEV, GitHub Advisory, OSV.",
        "npx", ["-y", "cve-mcp"], repo="github.com/badchars/cve-mcp"),
    "osint": MCPServer(
        "osint", "OSINT / recon", 37,
        "OSINT recon: Shodan, VirusTotal, SecurityTrails, Censys, DNS, WHOIS.",
        "npx", ["-y", "osint-mcp"],
        env=["SHODAN_API_KEY"], repo="github.com/badchars/osint-mcp"),
}


def total_tools(names: list[str] | None = None) -> int:
    servers = [MCP_CATALOG[n] for n in (names or MCP_CATALOG)]
    return sum(s.tools for s in servers)


def to_client_config(names: list[str] | None = None) -> dict:
    """Emit a standard ``mcpServers`` block for any MCP client."""
    selected = names or list(MCP_CATALOG)
    servers = {}
    for n in selected:
        s = MCP_CATALOG[n]
        servers[f"specter-{s.name}"] = {
            "command": s.command,
            "args": s.args,
            "env": {e: f"${{{e}}}" for e in s.env},
        }
    return {"mcpServers": servers}


def write_client_config(path: str | Path, names: list[str] | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_client_config(names), indent=2))
    return p
