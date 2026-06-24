# Publishing checklist (maintainer)

Everything is prepared locally and committed as a single author (Sam Gupta).
Follow these steps to publish to **github.com/sam00/AI-Specter**.

## 1. GitHub "About" description (copy/paste)

```
👻 Specter AI — AI-driven automated penetration testing from your terminal. Per-task LLM model advisor, autonomous agent mode, native parsers + AI triage, finding dedup/correlation/verification, a resilient LLM client, team store + optional API/MCP servers, and risk/technical/remediation reports. Authorized use only.
```

## 2. Topics (max 20)

```
penetration-testing pentest security ai llm ai-agent red-team offensive-security cybersecurity security-tools automation c2 infosec claude openai ollama devsecops cli python
```

## 3. Create the empty repo + push

The local repo already has `origin = git@github.com:sam00/AI-Specter.git` and a
clean `main` branch.

**Option A — web (recommended):**
1. Go to <https://github.com/new>.
2. Owner: `sam00`, Repository name: `AI-Specter`, Visibility: **Public**.
3. **Do not** initialize with README / .gitignore / license (we have them).
4. Create, then push:
   ```bash
   git push -u origin main
   ```

**Option B — GitHub CLI (as sam00):**
```bash
gh auth login                      # authenticate as sam00 (NOT a work account)
git remote remove origin           # avoid a conflict with the preset remote
gh repo create sam00/AI-Specter --public --source=. --remote=origin --push \
  --description "👻 Specter AI — AI-driven automated penetration testing from your terminal."
```

## 4. Set topics (after auth as sam00)

```bash
gh repo edit sam00/AI-Specter \
  --add-topic penetration-testing --add-topic pentest --add-topic security \
  --add-topic ai --add-topic llm --add-topic ai-agent --add-topic red-team \
  --add-topic offensive-security --add-topic cybersecurity --add-topic security-tools \
  --add-topic automation --add-topic c2 --add-topic infosec --add-topic claude \
  --add-topic openai --add-topic ollama --add-topic devsecops --add-topic cli \
  --add-topic python
```
(Or add them in the repo's **About** ⚙️ in the web UI.)

## 5. Enable GitHub Pages (docs site)

Settings → **Pages** → Build and deployment → Source: **GitHub Actions**.
The included `.github/workflows/pages.yml` publishes `docs/` to
<https://sam00.github.io/AI-Specter/> on every push to `main`.

## 6. Cut the v0.1.0 release

```bash
git tag -a v0.1.0 -m "Specter AI v0.1.0"
git push origin v0.1.0
gh release create v0.1.0 --title "Specter AI v0.1.0" --notes-file CHANGELOG.md
```

## 7. (Optional) Polish

- Settings → General → Features: enable Issues & Discussions.
- Settings → Branches: protect `main` (require CI + PR review).
- Regenerate the demo screenshot any time: `python scripts/capture_screenshot.py`.

> Reminder: publish only from a personal account. Do **not** use a
> work/employer GitHub identity or commit a `@company` email — commit author is
> set to `Sam Gupta <sam00@users.noreply.github.com>` for this repo.
