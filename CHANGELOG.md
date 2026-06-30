# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Active web-app testing** (`specter webtest`, `specter proxy`) — eight
  evidence-gated sub-testers (IDOR/BOLA, AuthZ bypass, mass assignment,
  injection, broken auth, business logic, SSRF, path traversal) confirmed by a
  multi-gate **baseline → attack → control → reproduce** protocol that kills
  one-shot false positives. Fed by a HAR import or a recording HTTP proxy that
  builds a live session context (identity/role/credential discovery).
- **Domain-specialist agents** (`specter agents`, `run --agent --domain …`) —
  web-application (WSTG), api (OWASP API Top 10), mobile (MASTG/MASVS),
  cloud-security (CIS), and internal-network (ATT&CK/AD) profiles that steer the
  autonomous loop's methodology and tool subset.
- **Cloud posture auditing** (`specter cloud`) — CIS-aligned IAM/storage/network/
  logging checks across AWS/Azure/GCP, offline-simulatable.
- **Mobile auditing** (`specter mobile`) — MASVS-mapped static checks with
  best-effort APK fact extraction; Frida/Objection/apktool/MobSF tool wrappers.
- **Relay** (`specter relay keygen|serve|run`) — Ed25519-signed remote tool
  execution with client allowlisting, anti-replay, scope guard, and horizontal
  fan-out across many nodes (optional `ai-specter[relay]`).
- **More first-class providers** — Amazon Bedrock (IAM), Azure OpenAI, Mistral,
  vLLM, and LM Studio, all auto-detected from the environment.
- **Web dashboard** (`specter web`) + **interactive TUI** (`specter tui`),
  **MCP security suite** catalog (`specter mcp-suite`), **Slack**
  notifications (`specter slack`), **Cloudflare Tunnel** for zero-open-port
  remote access (`specter tunnel`), localization (`specter lang`,
  `SPECTER_LANG`), and multi-channel install (pipx/Homebrew/Scoop/npm/curl).
- **PDF & Word report export** — `--format md|pdf|docx|all` on `specter run` and
  `specter report` (optional `ai-specter[pdf]` / `[docx]` / `[reports]` extras;
  exports degrade gracefully if a backend is missing).
- **Any-LLM support** — `--model provider:model` forces one model across the
  whole engagement, and any OpenAI-compatible endpoint (Groq, Together,
  OpenRouter, vLLM, LM Studio, LiteLLM, …) is auto-detected from
  `SPECTER_LLM_BASE_URL` / `OPENAI_BASE_URL`.
- **Zero-config setup** — providers auto-detected from the environment
  (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_HOST`) and a project/`SPECTER_HOME`
  `.env`; a friendly landing screen, a `setup` alias, and `run -t/--target` for
  one-off scopes.

### Changed

- Friendlier `init` (auto-detected keys, validated profile, summary) and
  `doctor` (credentials-in-environment view + actionable verdict).

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
