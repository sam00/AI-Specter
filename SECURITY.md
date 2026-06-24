# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via GitHub:

1. Go to the repository's **Security** tab → **Report a vulnerability**
   (GitHub Private Vulnerability Reporting), or
2. Open a draft **Security Advisory**.

Include a description, reproduction steps, affected version/commit, and impact.
You can expect an acknowledgment within a few days. Coordinated disclosure is
appreciated — please give a reasonable window for a fix before public
disclosure.

## Supported versions

This project is pre‑1.0; security fixes are applied to the latest `main` and the
most recent release.

| Version | Supported |
| ------- | --------- |
| latest `main` / latest release | ✅ |
| older tags | ❌ |

## Responsible & authorized use

Specter AI is an **offensive security** tool intended for **authorized** testing
only. It is designed to reduce risk of misuse:

- A **scope allowlist** is enforced before any active tool or C2 action.
- Exploitation and C2 tasking are gated behind an explicit
  `allow_exploitation` flag.
- An offline/dry‑run mode produces clearly labeled `[SIMULATED]` output.
- Authorization metadata (`authorized_by`, `authorization_ref`) and a tamper‑
  evident audit log are recorded for every engagement.

You are solely responsible for ensuring you have **written authorization** to
test any target. Misuse may violate the Computer Fraud and Abuse Act (US),
the Computer Misuse Act (UK), and equivalent laws worldwide.
