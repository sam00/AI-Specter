---
layout: default
title: "Specter AI — AI-driven automated pentesting"
---

# 👻 Specter AI

> AI-driven automated penetration testing, from your terminal.

[⭐ Star on GitHub](https://github.com/sam00/AI-Specter){: .btn }
[🚀 Quickstart](#how-do-i-run-it){: .btn }
[📦 Releases](https://github.com/sam00/AI-Specter/releases){: .btn }

---

## What is it?

**Specter AI** plugs your Claude, GPT, local Ollama, or *any* LLM into a real
pentest workflow and **routes each phase of an engagement to the model best
suited for it** — a deep reasoner for exploit chains, a cheap/fast model for
parsing, a local model for sensitive data. It runs scope-guarded security tools,
triages their output with AI, deduplicates and correlates findings, then writes
you risk / technical / remediation reports.

<p align="center">
  <img src="assets/specter-demo.svg" alt="Specter AI — offline demo run" width="840">
</p>

## Why care?

- **Right model, right task, right cost.** One LLM is either too expensive for
  parsing or too weak for exploit reasoning. Specter picks per task and tracks a
  budget.
- **Signal, not noise.** Native parsers + AI triage + dedup + clustering +
  second-opinion verification.
- **No lock-in, privacy-first.** Bring your own provider — or run fully offline
  with a built-in echo model and simulated tools.
- **Auditable & safe.** Scope allowlist, opt-in exploitation, and a
  tamper-evident JSONL audit log for every action.
- **Built for teams.** Shared findings store, a finding workflow, an optional
  API server, and an MCP server for Claude/Cursor.

## How do I run it?

No API key and no installed tools required for the demo:

```bash
pipx install ai-specter        # or: pip install ai-specter
specter quickstart             # full engagement on bundled demo data
```

Then point it at a real, **authorized** target:

```bash
specter init                   # providers + scope + C2 wizard
specter run --name acme-q3     # pipeline engagement
specter run --agent --objectives "find RCE"   # autonomous agent mode
specter report --kind risk     # regenerate a report from the latest run
```

## Who is it for?

Pentesters, red teamers, and security engineers who live in the terminal and
want AI leverage without vendor lock-in.

## What it is *not*

Not a point-and-click autopwn, not a replacement for operator judgment, and not
a way to attack systems you don't own. Scope is enforced; exploitation is opt-in.

---

### Learn more

- [README](https://github.com/sam00/AI-Specter#readme)
- [Example report output](example-report.md)
- [Changelog](https://github.com/sam00/AI-Specter/blob/main/CHANGELOG.md)
- [Security policy](https://github.com/sam00/AI-Specter/blob/main/SECURITY.md)

<sub>Apache-2.0 © 2026 Sam Gupta · Authorized use only.</sub>
