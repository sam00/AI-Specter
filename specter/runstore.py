"""Persist and reload engagements to disk."""
from __future__ import annotations

from pathlib import Path

from specter.config import RUNS_DIR
from specter.engine.models import Engagement


def save_run(eng: Engagement, base: Path | None = None) -> Path:
    base = base or RUNS_DIR
    run_dir = base / eng.id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "engagement.json").write_text(eng.model_dump_json(indent=2))
    return run_dir


def load_run(run_id: str, base: Path | None = None) -> Engagement:
    base = base or RUNS_DIR
    path = base / run_id / "engagement.json"
    if not path.exists():
        raise FileNotFoundError(f"no engagement found for id '{run_id}' at {path}")
    return Engagement.model_validate_json(path.read_text())


def latest_run_id(base: Path | None = None) -> str | None:
    base = base or RUNS_DIR
    if not base.exists():
        return None
    runs = [d for d in base.iterdir() if (d / "engagement.json").exists()]
    if not runs:
        return None
    return max(runs, key=lambda d: (d / "engagement.json").stat().st_mtime).name
