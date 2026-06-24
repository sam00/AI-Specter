"""Wrappers around external security tools with a strict scope guard.

Specter never runs an active tool against a target unless that target is in
the authorized scope. If a tool is not installed (or --offline is set), the
registry returns a clearly-labeled simulated result so the AI flow still runs.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass
class ToolResult:
    tool: str
    target: str
    command: str
    stdout: str = ""
    returncode: int = 0
    simulated: bool = False
    error: str = ""


@dataclass
class ToolSpec:
    name: str
    binary: str
    phase: str
    builder: Callable[[str, list[str]], list[str]]
    description: str = ""
    active: bool = True  # active = touches the target over the network


class ToolRegistry:
    def __init__(self, offline: bool = False, dry_run: bool = False, timeout: int = 600,
                 demo: bool = False) -> None:
        self.offline = offline
        self.dry_run = dry_run
        self.timeout = timeout
        self.demo = demo
        self.specs: dict[str, ToolSpec] = {}
        self._register_defaults()

    def register(self, spec: ToolSpec) -> None:
        self.specs[spec.name] = spec

    def installed(self, name: str) -> bool:
        spec = self.specs.get(name)
        return bool(spec and shutil.which(spec.binary))

    def available(self) -> dict[str, bool]:
        return {n: self.installed(n) for n in self.specs}

    def run(self, name: str, target: str, in_scope: bool, extra: list[str] | None = None) -> ToolResult:
        spec = self.specs.get(name)
        if not spec:
            return ToolResult(name, target, "", error=f"unknown tool '{name}'", returncode=2)

        cmd = spec.builder(target, extra or [])
        cmd_str = " ".join(cmd)

        if spec.active and not in_scope:
            return ToolResult(name, target, cmd_str, simulated=True,
                              error="BLOCKED: target out of authorized scope")

        if self.offline or self.dry_run or not shutil.which(spec.binary):
            reason = "offline" if self.offline else ("dry-run" if self.dry_run else "not-installed")
            if self.demo:
                from specter.tools.parsers import DEMO_OUTPUTS
                sample = DEMO_OUTPUTS.get(name)
                if sample:
                    return ToolResult(name, target, cmd_str, simulated=True, stdout=sample)
            return ToolResult(
                name, target, cmd_str, simulated=True,
                stdout=f"[SIMULATED:{reason}] would run: {cmd_str}",
            )

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )
            return ToolResult(
                name, target, cmd_str,
                stdout=(proc.stdout or "") + (proc.stderr or ""),
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(name, target, cmd_str, error="timeout", returncode=124)
        except Exception as e:  # pragma: no cover
            return ToolResult(name, target, cmd_str, error=str(e), returncode=1)

    def _register_defaults(self) -> None:
        self.register(ToolSpec(
            "nmap", "nmap", "recon",
            lambda t, x: ["nmap", "-sV", "-T4", "--top-ports", "1000", *x, t],
            "Service/version port scan"))
        self.register(ToolSpec(
            "nmap-full", "nmap", "enum",
            lambda t, x: ["nmap", "-sV", "-sC", "-p-", "-T4", *x, t],
            "Full TCP scan with default scripts"))
        self.register(ToolSpec(
            "httpx", "httpx", "recon",
            lambda t, x: ["httpx", "-silent", "-title", "-tech-detect", "-status-code", "-u", t, *x],
            "HTTP probing + tech detection"))
        self.register(ToolSpec(
            "subfinder", "subfinder", "recon",
            lambda t, x: ["subfinder", "-silent", "-d", t, *x],
            "Passive subdomain enumeration"))
        self.register(ToolSpec(
            "nuclei", "nuclei", "vuln",
            lambda t, x: ["nuclei", "-silent", "-u", t, *x],
            "Template-based vulnerability scanning"))
        self.register(ToolSpec(
            "nikto", "nikto", "vuln",
            lambda t, x: ["nikto", "-h", t, *x],
            "Web server vulnerability scan"))
        self.register(ToolSpec(
            "ffuf", "ffuf", "enum",
            lambda t, x: ["ffuf", "-u", f"{t}/FUZZ", *x],
            "Content/endpoint fuzzing"))
        self.register(ToolSpec(
            "whatweb", "whatweb", "recon",
            lambda t, x: ["whatweb", t, *x],
            "Web fingerprinting", active=True))
        self.register(ToolSpec(
            "naabu", "naabu", "recon",
            lambda t, x: ["naabu", "-silent", "-host", t, *x],
            "Fast SYN/CONNECT port scan"))
        self.register(ToolSpec(
            "katana", "katana", "enum",
            lambda t, x: ["katana", "-silent", "-u", t, *x],
            "Headless web crawler"))
        self.register(ToolSpec(
            "testssl", "testssl.sh", "vuln",
            lambda t, x: ["testssl.sh", "--quiet", t, *x],
            "TLS/SSL configuration audit"))
        self.register(ToolSpec(
            "wpscan", "wpscan", "vuln",
            lambda t, x: ["wpscan", "--url", t, "--no-banner", *x],
            "WordPress vulnerability scan"))
        self.register(ToolSpec(
            "trivy", "trivy", "vuln",
            lambda t, x: ["trivy", "--quiet", *(x or ["image"]), t],
            "Container/filesystem CVE scan"))
        self.register(ToolSpec(
            "sqlmap", "sqlmap", "exploit",
            lambda t, x: ["sqlmap", "-u", t, "--batch", *x],
            "SQL injection exploitation (gated)"))
        self.register(ToolSpec(
            "msfconsole", "msfconsole", "exploit",
            lambda t, x: ["msfconsole", "-q", "-x", x[0] if x else "version; exit"],
            "Metasploit console (gated)"))
