# Contributing to Specter AI

Thanks for your interest in improving Specter AI! Contributions of all kinds are
welcome — bug reports, features, docs, and tests.

## Ground rules

- **Authorized use only.** Specter is an offensive-security tool. Do not submit
  code, examples, or test data that targets systems you don't own or aren't
  authorized to test. Use public, legal targets like `scanme.nmap.org` in
  examples.
- **No secrets, ever.** Never commit API keys, credentials, customer data, or
  internal/employer-identifying information. `.env` is git-ignored — keep it
  that way.
- **Be excellent to each other.** See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Dev setup

```bash
git clone git@github.com:sam00/AI-Specter.git
cd AI-Specter
python -m venv .venv && source .venv/bin/activate
pip install -e '.[all,dev]'
```

## Before you open a PR

```bash
ruff check specter            # lint must be clean
pytest -q                     # full suite must pass (offline, no keys needed)
```

- Keep changes focused and minimal; match the existing style.
- Add or update tests for any behavior change (tests run fully offline).
- Don't add comments/docs unless they add real value.
- Update [`CHANGELOG.md`](CHANGELOG.md) under "Unreleased".

## Commit & PR conventions

- Write clear, present-tense commit messages (e.g. "add nuclei JSONL parser").
- One logical change per PR where possible.
- By contributing, you agree your contributions are licensed under the
  project's [Apache-2.0 License](LICENSE).

## Reporting bugs / requesting features

Use the GitHub issue templates. For security vulnerabilities, **do not** open a
public issue — follow [`SECURITY.md`](SECURITY.md).
