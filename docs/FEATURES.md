---
layout: default
title: "Features & Capabilities — Specter AI"
---

# Specter AI — Features & Capabilities

> ⚠️ **Authorized use only.** Specter enforces a scope allowlist and gates every
> active/exploitation action behind explicit flags. Only test systems you are
> contractually authorized to assess.

Specter AI plugs **Claude, GPT, local Ollama, or _any_ LLM** into a real pentest
workflow and **routes each phase to the model best suited for it**. It runs
scope-guarded security tools, confirms findings with evidence, triages with AI,
and writes you three reports — all with a tamper-evident audit trail.

This document is the complete catalog of what Specter can do. Each section links
the relevant CLI command(s).

---

## Table of contents

- [1. LLM orchestration & the model advisor](#1-llm-orchestration--the-model-advisor)
- [2. Providers — use ANY model](#2-providers--use-any-model)
- [3. Engagement engines](#3-engagement-engines)
- [4. Domain-specialist agents](#4-domain-specialist-agents)
- [5. Active web-application testing](#5-active-web-application-testing)
- [6. Intercepting proxy & live session context](#6-intercepting-proxy--live-session-context)
- [7. Cloud security auditing](#7-cloud-security-auditing)
- [8. Mobile application auditing](#8-mobile-application-auditing)
- [9. Tooling & native parsers](#9-tooling--native-parsers)
- [10. Findings: dedup, correlation & verification](#10-findings-dedup-correlation--verification)
- [11. Reporting](#11-reporting)
- [12. Team mode & collaboration](#12-team-mode--collaboration)
- [13. Relay — signed remote tool execution](#13-relay--signed-remote-tool-execution)
- [14. MCP: server + ecosystem](#14-mcp-server--ecosystem)
- [15. C2 integrations](#15-c2-integrations)
- [16. Web dashboard & TUI](#16-web-dashboard--tui)
- [17. Notifications & remote access](#17-notifications--remote-access)
- [18. Safety, scope & audit](#18-safety-scope--audit)
- [19. Localization (i18n)](#19-localization-i18n)
- [20. Installation & distribution](#20-installation--distribution)
- [Command reference](#command-reference)

---

## 1. LLM orchestration & the model advisor

The **per-task model advisor** picks the optimal model for *each* sub-task of an
engagement instead of forcing one model to do everything — a deep reasoner for
exploit chains, a cheap/fast model for parsing, a local model for sensitive
data. You can mix providers within a single engagement.

- Per-task routing across `planning`, `recon`, `parsing`, `vuln-analysis`,
  `exploitation`, `reporting`, and more.
- Cost/latency/quality-aware scoring with profile presets:
  `fast`, `balanced`, `deep`, `frugal`, `offline`.
- **Commands:** `specter advisor`, `specter models` (`--discover` to probe).

## 2. Providers — use ANY model

First-class, auto-detected providers plus any OpenAI-compatible endpoint:

| Provider | Extra | Auth / detection |
|---|---|---|
| Anthropic Claude | `[claude]` | `ANTHROPIC_API_KEY` |
| OpenAI GPT | `[openai]` | `OPENAI_API_KEY` |
| Azure OpenAI | `[azure]` | `AZURE_OPENAI_API_KEY` + endpoint |
| Amazon Bedrock | `[bedrock]` | AWS IAM (boto3) |
| Mistral | `[mistral]` | `MISTRAL_API_KEY` |
| Ollama (local) | — | `OLLAMA_HOST` |
| vLLM / LM Studio | — | OpenAI-compatible base URL |
| Any OpenAI-compatible | — | `SPECTER_LLM_BASE_URL` (+ `_API_KEY`/`_MODEL`) |

- Force one model for a whole run with `--model provider:model`.
- Run **fully offline** with a built-in echo model + simulated tools — no key,
  no network.
- **Resilience:** response caching, retry with backoff, dynamic token sizing,
  and a per-engagement cost/token budget.

## 3. Engagement engines

Two complementary engines:

- **Deterministic pipeline** — `plan → recon → enum → vuln → exploit`, ideal for
  repeatable, auditable engagements.
- **Autonomous agent loop** — `specter run --agent` decides its own next action
  toward stated `--objectives`, with memory and a knowledge base.
- **Commands:** `specter run`, `specter run --agent --objectives "…"`.

## 4. Domain-specialist agents

Methodology-aware agent profiles that steer the autonomous loop's plan and tool
subset for a given domain.

| Agent | Specialist | Methodology |
|---|---|---|
| `web-application` | Web app pentester | OWASP WSTG |
| `api` | API security tester | OWASP API Security Top 10 |
| `mobile-application` | Mobile tester | OWASP MASTG / MASVS |
| `cloud-security` | Cloud auditor | CIS Benchmarks |
| `internal-network` | Internal/AD operator | MITRE ATT&CK |

- **Commands:** `specter agents`, `specter run --agent --domain web-application -t HOST`.

## 5. Active web-application testing

Eight **evidence-gated** sub-testers that confirm vulnerabilities instead of
guessing — each result carries a full gate trail.

- **Testers:** IDOR/BOLA, authorization bypass, mass assignment, injection
  (SQL/template), broken authentication, business-logic abuse, SSRF, and path
  traversal / file attacks.
- **Confirm protocol:** every candidate runs a **baseline → attack → negative
  control → reproduce** sequence; a finding is emitted only when all gates agree
  *and* the signal reproduces across repeated trials. This kills the one-shot
  false positives typical of naive scanners.
- **Cross-session dedup** so the same (endpoint, tester) is reported once.
- **Audit-friendly:** each finding records its gate trail and a confidence score.
- **Commands:** `specter webtest --har session.har -t app.example.com`
  (`--only`, `--reproduce`, `--report`).

## 6. Intercepting proxy & live session context

Capture traffic through open, inspectable paths (no bundled browser), then test
it.

- **HAR import** — record in any browser devtools / Burp / ZAP, export `.har`,
  and Specter reconstructs the full session.
- **Recording proxy** — a lightweight forwarding HTTP proxy that records every
  request/response into a live session context while you browse.
- **Role & credential discovery** — distinct `Authorization`/`Cookie` material is
  clustered into identities, and privilege is inferred from the routes each
  identity reaches (e.g. one that hits `/admin` is ranked higher). The testers
  consume this directly for cross-identity (IDOR/authz) checks.
- **Commands:** `specter proxy -t app.example.com`, then `specter webtest`.

## 7. Cloud security auditing

CIS-aligned posture checks across **AWS, Azure, and GCP**, evaluated against a
normalized, provider-agnostic state model (offline-simulatable).

- **Checks:** over-permissive IAM (wildcard action/resource), stale access keys,
  missing MFA, public storage buckets, unencrypted buckets, internet-exposed
  sensitive ports, audit-logging gaps, public compute with open management ports.
- Each finding maps to a CIS reference and ships remediation guidance.
- **Commands:** `specter cloud --provider aws --demo` (`--report`).

## 8. Mobile application auditing

MASVS-mapped checks driven by best-effort static fact extraction from an APK
(manifest + strings via the standard library).

- **Controls:** debuggable build, `allowBackup`, cleartext traffic, missing cert
  pinning, exported components, hardcoded secrets, weak crypto, root/jailbreak
  detection.
- **Tooling wrappers:** Frida, Objection, apktool, MobSF (availability shown by
  `specter doctor`).
- **Commands:** `specter mobile --apk app.apk` or `specter mobile --demo`.

## 9. Tooling & native parsers

- **Scope-guarded tool wrappers** — the target is checked against the allowlist
  before any active tool runs.
- **Native parsers** for common tools (e.g. nmap/nuclei/httpx) turn raw output
  into structured findings deterministically, *then* the LLM enriches them.
- **Offline simulation** — every tool has a `[SIMULATED]` mode for safe rehearsal.
- **Commands:** `specter doctor` (shows installed tools and readiness).

## 10. Findings: dedup, correlation & verification

- Deterministic parsing first, AI enrichment second.
- **Deduplication** and **correlation into clusters** of related findings.
- **Second-opinion verification** to reduce false positives.
- **Prompt-injection defense** — untrusted tool output is sandboxed before it
  ever reaches a model.

## 11. Reporting

Three audience-specific reports from one engagement:

- **Risk** (executive), **Technical** (engineer), **Remediation** (fixes).
- Export to **Markdown, PDF, and Word** — exports degrade gracefully if a
  backend isn't installed.
- **Commands:** `specter run --format all`, `specter report --kind risk --format pdf`.

## 12. Team mode & collaboration

- Shared **SQLite store** with a finding workflow (status / assignee / comment)
  and file locking for concurrent use.
- **API server** with API-key auth and simple RBAC (`viewer < operator < lead`).
- **Commands:** `specter findings`, `specter triage <id> --status confirmed`,
  `specter serve`.

## 13. Relay — signed remote tool execution

Run tools on remote nodes with **passwordless, key-based mutual auth** — no
shared secrets or bearer tokens.

- **Ed25519 identities**: servers pin an allowlist of client public keys;
  clients pin the server key.
- **Signed request/response envelopes** with **anti-replay** (fresh timestamp +
  unused nonce) and the same **scope guard** Specter uses locally.
- **Horizontal scaling** — one Specter can fan out across many Relay nodes, each
  with its own toolkit and network position.
- **Commands:** `specter relay keygen`, `specter relay serve --allow <pubkeys>`,
  `specter relay run --endpoint <url> --tool nmap --target HOST`.

## 14. MCP: server + ecosystem

- **Specter as an MCP server** for Claude/Cursor — `specter mcp`.
- **MCP security suite catalog** — orchestrate external security MCP servers
  (cloud-audit, github-security, cve, osint) and emit a standard `mcpServers`
  config block for any MCP client.
- **Commands:** `specter mcp`, `specter mcp-suite list`,
  `specter mcp-suite enable cve --out mcp.json`.

## 15. C2 integrations

Adapters for **Sliver**, **Cobalt Strike**, **Mythic**, and a **generic REST
adapter** for any C2. Tasking requires `allow_exploitation: true`.

- **Commands:** `specter c2 status <name>`, `specter c2 run …`.

## 16. Web dashboard & TUI

- **Web dashboard** (`specter web`) — a dependency-free single-page UI with tabs
  for Vulnerabilities, Web Context, Agents, MCP Suite, and Relay, served by the
  API server and usable behind the Cloudflare Tunnel.
- **Interactive TUI** (`specter tui`, Textual) — keyboard-driven cockpit to
  browse findings, switch the active domain agent, and review MCP/Relay status.

## 17. Notifications & remote access

- **Slack** — post a severity-aware engagement summary to an Incoming Webhook
  (`specter slack`, `SPECTER_SLACK_WEBHOOK`).
- **Cloudflare Tunnel** — expose a local Specter service (dashboard / Relay) with
  **zero open ports** via an outbound-only connection (`specter tunnel`).

## 18. Safety, scope & audit

- Scope **allowlist** checked before every active tool/C2/Relay action.
- Exploitation and C2 tasking require `allow_exploitation: true`.
- `--offline` / dry-run produces clearly-labeled `[SIMULATED]` output.
- Untrusted tool output is wrapped against prompt injection before triage.
- Authorization metadata (`authorized_by`, `authorization_ref`) is recorded, and
  every action is written to a tamper-evident JSONL audit log.
- **Commands:** `specter log` (compact audit trail for a run).

## 19. Localization (i18n)

- Dependency-free message catalogs (currently **en, es, pt, fr, de, ja**),
  selected via `SPECTER_LANG` (or the OS `LANG`), with English fallback.
- **Commands:** `specter lang`.

## 20. Installation & distribution

Multiple channels, all wrapping the Python package:

- **pipx / pip:** `pipx install ai-specter`
- **curl installer:** `curl -fsSL …/scripts/install.sh | bash`
- **Homebrew:** formula in `packaging/homebrew/`
- **Scoop (Windows):** manifest in `packaging/scoop/`
- **npm launcher:** `npx @ai-specter/cli` (delegates to the Python package)
- **Extras:** `[all]`, `[claude]`, `[openai]`, `[azure]`, `[bedrock]`,
  `[mistral]`, `[server]`, `[tui]`, `[relay]`, `[mcp]`, `[reports]` (PDF/Word).

---

## Command reference

| Command | Purpose |
|---|---|
| `specter quickstart` | Zero-config offline demo (full engagement) |
| `specter init` / `setup` | Guided setup: providers + scope (+ C2) |
| `specter doctor [--fix]` | Verify providers, advisor routing, tools, C2 |
| `specter advisor` | Show per-task model routing |
| `specter models [--discover]` | List/probe the model catalog |
| `specter run [--agent] [--domain] [-t HOST] [--format]` | Run an engagement |
| `specter agents` | List domain-specialist agent profiles |
| `specter webtest --har FILE -t HOST` | Evidence-gated active web testing |
| `specter proxy -t HOST` | Recording proxy → live session context |
| `specter cloud --provider aws --demo` | CIS cloud posture audit |
| `specter mobile --apk APP \| --demo` | MASVS mobile audit |
| `specter report --kind … --format …` | (Re)generate reports |
| `specter findings` / `triage <id>` | Team finding workflow |
| `specter serve` | Team API server (RBAC) |
| `specter web` | Server + browser dashboard |
| `specter tui` | Interactive terminal UI |
| `specter mcp` | Run Specter as an MCP server |
| `specter mcp-suite list \| enable …` | External MCP server ecosystem |
| `specter relay keygen \| serve \| run` | Signed remote tool execution |
| `specter c2 status \| run` | C2 integrations |
| `specter slack [RUN_ID]` | Slack notification |
| `specter tunnel --url …` | Cloudflare Tunnel (zero open ports) |
| `specter lang` | Locales / active language |
| `specter log [RUN_ID]` | Audit trail for a run |

For the full narrative docs see **https://sam00.github.io/AI-Specter/**.
