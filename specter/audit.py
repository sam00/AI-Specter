"""Compact, append-only audit logger for tasks, commands, steps, and timings.

Storage is minimized by:
- one JSONL line per event with no whitespace (``separators=(",", ":")``),
- empty/None fields omitted entirely,
- long strings truncated to ``max_field`` characters,
- a level filter so ``debug`` chatter is dropped by default, and
- gzip compression of the whole log on ``close()`` (≈80-90% smaller).

The logger is a no-op when ``path`` is None, so it is free to use in tests and
as a library default without touching disk.
"""
from __future__ import annotations

import gzip
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, TextIO

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class AuditLogger:
    def __init__(
        self,
        path: Path | str | None,
        level: str = "info",
        max_field: int = 240,
        compress_on_close: bool = True,
        echo: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.threshold = LEVELS.get(level, 20)
        self.max_field = max_field
        self.compress_on_close = compress_on_close
        self.echo = echo
        self.counts: dict[str, int] = {}
        self._fh: TextIO | None = None
        self._t0 = time.perf_counter()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")

    # -- internals -----------------------------------------------------------
    def _trim(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) > self.max_field:
            return value[: self.max_field] + "…"
        return value

    def _write(self, kind: str, msg: str, level: str, fields: dict[str, Any]) -> None:
        if LEVELS.get(level, 20) < self.threshold:
            return
        self.counts[kind] = self.counts.get(kind, 0) + 1
        ev: dict[str, Any] = {"ts": round(time.time(), 3), "ev": kind}
        if level != "info":
            ev["lvl"] = level
        if msg:
            ev["msg"] = self._trim(msg)
        for key, val in fields.items():
            if val is None or val == "":  # keep 0, False, and other falsy-but-meaningful
                continue
            ev[key] = self._trim(val)
        line = json.dumps(ev, separators=(",", ":"), ensure_ascii=False)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        if self.echo:
            self.echo(line)

    # -- public event helpers ------------------------------------------------
    def event(self, kind: str, msg: str = "", level: str = "info", **fields: Any) -> None:
        self._write(kind, msg, level, fields)

    def task(self, name: str, **fields: Any) -> None:
        self._write("task", name, "info", fields)

    def command(self, cmd: str, **fields: Any) -> None:
        self._write("cmd", cmd, "info", fields)

    def step(self, phase: str, action: str, **fields: Any) -> None:
        self._write("step", action, "info", {"phase": phase, **fields})

    def phase(self, name: str, **fields: Any) -> None:
        self._write("phase", name, "info", fields)

    def finding(self, title: str, severity: str, **fields: Any) -> None:
        self._write("finding", title, "info", {"sev": severity, **fields})

    @contextmanager
    def timed(self, kind: str, msg: str, level: str = "info", **fields: Any) -> Iterator[dict]:
        """Time a block and emit one event with ``ms`` and ``ok`` on exit.

        Yields a mutable dict so callers can attach fields discovered inside
        the block (e.g. the chosen model)::

            with audit.timed("task", "plan") as ex:
                ex["model"] = label
        """
        start = time.perf_counter()
        extra: dict[str, Any] = {}
        ok = True
        try:
            yield extra
        except Exception:
            ok = False
            raise
        finally:
            ms = int((time.perf_counter() - start) * 1000)
            self._write(kind, msg, level, {**fields, **extra, "ms": ms, "ok": ok})

    # -- lifecycle / readers -------------------------------------------------
    def stats(self) -> dict[str, Any]:
        size = self.path.stat().st_size if (self.path and self.path.exists()) else 0
        return {
            "events": sum(self.counts.values()),
            "by_kind": dict(self.counts),
            "bytes": size,
            "elapsed_ms": int((time.perf_counter() - self._t0) * 1000),
            "path": str(self.path) if self.path else None,
        }

    def close(self) -> Path | None:
        if self._fh:
            self._fh.close()
            self._fh = None
        if self.path and self.compress_on_close and self.path.exists():
            gz = self.path.with_suffix(self.path.suffix + ".gz")
            with self.path.open("rb") as src, gzip.open(gz, "wb") as dst:
                dst.writelines(src)
            self.path.unlink()
            return gz
        return self.path

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @staticmethod
    def read(path: Path | str) -> list[dict]:
        """Load events from a ``.jsonl`` or ``.jsonl.gz`` audit file."""
        path = Path(path)
        if not path.exists():
            gz = path.with_suffix(path.suffix + ".gz")
            if gz.exists():
                path = gz
        if not path.exists():
            return []
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as fh:  # type: ignore[arg-type]
            return [json.loads(line) for line in fh if line.strip()]
