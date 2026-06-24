"""SQLite-backed shared store for multi-user collaboration.

Adds queryable persistence on top of the JSON run store: engagements and
findings are indexed for the team, attribution (``actor``) is recorded, and
findings carry a workflow (status/assignee/comments). A simple file lock keeps
concurrent operators from corrupting shared state.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from specter.config import CONFIG_DIR
from specter.engine.models import Engagement

DEFAULT_DB = CONFIG_DIR / "specter.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY, name TEXT, profile TEXT, actor TEXT,
    created_at TEXT, findings_count INTEGER, high_count INTEGER, blob TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, engagement_id TEXT, title TEXT, severity TEXT,
    target TEXT, cvss REAL, status TEXT, assignee TEXT, source TEXT,
    comments TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_eng ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
"""


class FileLock:
    """Cross-process advisory lock via an exclusive lock file."""

    def __init__(self, path: Path | str, timeout: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.timeout
        while True:
            try:
                self._fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return self
            except FileExistsError:
                if time.time() > deadline:
                    raise TimeoutError(f"could not acquire lock {self.path}")
                time.sleep(0.1)

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class Store:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    @contextmanager
    def lock(self, engagement_id: str) -> Iterator[None]:
        with FileLock(self.path.with_suffix(f".{engagement_id}.lock")):
            yield

    def save_engagement(self, eng: Engagement, actor: str = "") -> None:
        actor = actor or eng.actor
        sev = eng.by_severity()
        with self.lock(eng.id):
            self.db.execute(
                "INSERT OR REPLACE INTO engagements "
                "(id, name, profile, actor, created_at, findings_count, high_count, blob) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (eng.id, eng.name, eng.profile, actor, eng.created_at, len(eng.findings),
                 sev["high"] + sev["critical"], eng.model_dump_json()),
            )
            self.db.execute("DELETE FROM findings WHERE engagement_id=?", (eng.id,))
            self.db.executemany(
                "INSERT OR REPLACE INTO findings "
                "(id, engagement_id, title, severity, target, cvss, status, assignee, "
                "source, comments, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(f.id, eng.id, f.title, f.severity.value, f.target, f.cvss, f.status,
                  f.assignee, f.source, json.dumps(f.comments), f.created_at)
                 for f in eng.findings],
            )
            self.db.commit()

    def list_engagements(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, name, profile, actor, created_at, findings_count, high_count "
            "FROM engagements ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_engagement(self, engagement_id: str) -> dict | None:
        row = self.db.execute("SELECT blob FROM engagements WHERE id=?",
                              (engagement_id,)).fetchone()
        return json.loads(row["blob"]) if row else None

    def list_findings(self, engagement_id: str | None = None,
                      status: str | None = None, limit: int = 200) -> list[dict]:
        q = ("SELECT id, engagement_id, title, severity, target, cvss, status, assignee, "
             "source FROM findings")
        clauses, params = [], []
        if engagement_id:
            clauses.append("engagement_id=?")
            params.append(engagement_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY cvss DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.execute(q, params).fetchall()]

    def update_finding(self, finding_id: str, status: str | None = None,
                       assignee: str | None = None, comment: str | None = None,
                       actor: str = "") -> bool:
        row = self.db.execute("SELECT comments FROM findings WHERE id=?",
                              (finding_id,)).fetchone()
        if not row:
            return False
        comments = json.loads(row["comments"] or "[]")
        if comment:
            prefix = f"{actor}: " if actor else ""
            comments.append(prefix + comment)
        sets, params = [], []
        if status:
            sets.append("status=?")
            params.append(status)
        if assignee is not None:
            sets.append("assignee=?")
            params.append(assignee)
        sets.append("comments=?")
        params.append(json.dumps(comments))
        params.append(finding_id)
        self.db.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id=?", params)
        self.db.commit()
        return True

    def close(self) -> None:
        self.db.close()
