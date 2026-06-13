"""Temporal persistence — the memory that turns scans into a time series.

Every other OSINT tool is stateless: you scan, you get a report, the knowledge
evaporates. GHOSTNET keeps a per-target history of graph snapshots so the
evolution engine can diff "then vs now" and forecast "next".

SQLite is the right call here: zero-ops, file-backed, ships with Python, and the
access pattern (append snapshot, read last N for a target) is trivial. The graph
itself is stored as a JSON blob per snapshot -- we are versioning whole twins,
not doing relational graph queries, so a document-per-snapshot model is simplest
and keeps the schema migration-free.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.intel.graph import DigitalTwin

_DEFAULT = Path(__file__).resolve().parents[2] / "reports" / "ghostnet.db"


class SnapshotStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        # ":memory:" is honoured for tests; default is the gitignored reports dir.
        self.path = ":memory:" if db_path == ":memory:" else Path(db_path or _DEFAULT)
        if self.path != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                target    TEXT NOT NULL,
                ts        TEXT NOT NULL,
                graph     TEXT NOT NULL,
                posture   REAL,
                findings  INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_snap_target ON snapshots(target, ts);
            """
        )
        self.conn.commit()

    def save(self, target: str, twin: DigitalTwin, posture: float | None = None,
             findings: int = 0, ts: datetime | None = None) -> int:
        ts = ts or datetime.now(timezone.utc)
        cur = self.conn.execute(
            "INSERT INTO snapshots(target, ts, graph, posture, findings) VALUES (?,?,?,?,?)",
            (target, ts.isoformat(), json.dumps(twin.to_dict()), posture, findings),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def history(self, target: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, graph, posture, findings FROM snapshots "
            "WHERE target=? ORDER BY ts ASC LIMIT ?",
            (target, limit),
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["id"],
                "ts": datetime.fromisoformat(r["ts"]),
                "twin": DigitalTwin.from_dict(json.loads(r["graph"])),
                "posture": r["posture"],
                "findings": r["findings"],
            })
        return out

    def latest(self, target: str) -> dict | None:
        h = self.history(target)
        return h[-1] if h else None

    def close(self) -> None:
        self.conn.close()
