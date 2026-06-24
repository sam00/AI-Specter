"""Content-hash LLM response cache (SQLite, stdlib only).

Keying on provider+model+prompt makes re-runs cheap and deterministic. A None
path disables the cache (no-op) so tests and offline runs stay clean.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path


class LLMCache:
    def __init__(self, path: Path | str | None, enabled: bool = True) -> None:
        self.enabled = enabled and path is not None
        self.path = Path(path) if path else None
        self.hits = 0
        self.misses = 0
        self._db: sqlite3.Connection | None = None
        if self.enabled and self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(k TEXT PRIMARY KEY, text TEXT, ts REAL)"
            )
            self._db.commit()

    @staticmethod
    def key(provider: str, model: str, system: str, user: str, max_tokens: int) -> str:
        blob = f"{provider}\x1f{model}\x1f{max_tokens}\x1f{system}\x1f{user}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get(self, key: str) -> str | None:
        if not self._db:
            return None
        row = self._db.execute("SELECT text FROM cache WHERE k=?", (key,)).fetchone()
        if row:
            self.hits += 1
            return row[0]
        self.misses += 1
        return None

    def set(self, key: str, text: str) -> None:
        if not self._db:
            return
        self._db.execute(
            "INSERT OR REPLACE INTO cache (k, text, ts) VALUES (?, ?, ?)",
            (key, text, time.time()),
        )
        self._db.commit()

    def stats(self) -> dict:
        return {"enabled": self.enabled, "hits": self.hits, "misses": self.misses}

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None
