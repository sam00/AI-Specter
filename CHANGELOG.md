# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-23

Initial public release.

### Added

- **Per-task model advisor** — routes each engagement sub-task (planning, recon
  triage, exploit reasoning, parsing, reporting) to the most suitable model;
  mix providers in a single run. Config-driven catalog with optional live
  discovery (`specter models --discover`).
- **Multi-provider LLM support** — Claude, OpenAI/GPT, Ollama, and any
  OpenAI-compatible endpoint, plus a built-in offline **echo** model.
- **Two engines** — a deterministic **pipeline** (plan → recon → enum → vuln →
  exploit) and an autonomous **agent** (ReAct) loop (`specter run --agent`).
- **Resilient LLM client** — response caching, retries with exponential
  backoff, dynamic token sizing, and per-engagement **cost/token budgets**.
- **Native tool parsers** for nmap, nuclei, and httpx, with AI enrichment;
  findings are **deduplicated, correlated into clusters, and verified** with a
  second-opinion pass.
- **Scope-guarded tool registry** (nmap, nuclei, httpx, ffuf, subfinder, naabu,
  katana, nikto, sqlmap, testssl, wpscan, trivy, msfconsole) with offline/demo
  modes.
- **Prompt-injection defense** for untrusted tool output before LLM triage.
- **Cross-phase memory** and a lightweight knowledge base.
- **Reporting** — risk (executive), technical, and remediation reports.
- **Team mode** — shared SQLite store with finding workflow
  (`specter findings` / `specter triage`), attribution, and file locking; an
  optional **FastAPI server** with API-key auth + RBAC (`specter serve`); and an
  **MCP server** (`specter mcp`).
- **C2 adapters** — Sliver, Cobalt Strike, Mythic, and a generic REST adapter.
- **Compact audit logging** — append-only JSONL with gzip compression and level
  filtering.
- **CLI** (Typer + Rich) — `quickstart`, `init`, `doctor --fix`, `advisor`,
  `models`, `run`, `report`, `findings`, `triage`, `serve`, `mcp`, `c2`.
- **Setup** — Docker + docker-compose, zero-config `specter quickstart` offline
  demo, and a full offline test suite.

### Security

- Scope allowlist enforced before every active action; exploitation/C2 gated
  behind `allow_exploitation`; authorization metadata recorded per engagement.

[Unreleased]: https://github.com/sam00/AI-Specter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sam00/AI-Specter/releases/tag/v0.1.0
