"""Result storage: a single SQLite database per engagement.

Everything a scan discovers — assets, HTTP services, findings — lands here so
runs are resumable, de-duplicated and queryable. SQLite is in the stdlib, so
there is no external database to run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    kind TEXT NOT NULL,              -- domain | subdomain | ip | url
    source TEXT,
    in_scope INTEGER DEFAULT 0,
    first_seen REAL,
    data TEXT,                       -- JSON blob of extra attributes
    UNIQUE(value, kind)
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    host TEXT,
    status INTEGER,
    title TEXT,
    server TEXT,
    tech TEXT,                       -- JSON list
    content_length INTEGER,
    first_seen REAL,
    data TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT DEFAULT 'info',    -- info|low|medium|high|critical
    evidence TEXT,
    first_seen REAL,
    data TEXT,
    UNIQUE(target, module, name)
);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
"""


@dataclass
class Store:
    path: Path
    _conn: sqlite3.Connection | None = None
    _lock: threading.Lock | None = None

    @classmethod
    def open(cls, path: str | Path) -> "Store":
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        conn.commit()
        return cls(path=p, _conn=conn, _lock=threading.Lock())

    @property
    def conn(self) -> sqlite3.Connection:
        assert self._conn is not None
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.commit()
            self._conn.close()

    # --- writes -----------------------------------------------------------
    def add_asset(
        self,
        value: str,
        kind: str,
        source: str = "",
        in_scope: bool = False,
        **data: Any,
    ) -> None:
        assert self._lock is not None
        with self._lock:
            self.conn.execute(
                """INSERT INTO assets(value, kind, source, in_scope, first_seen, data)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(value, kind) DO UPDATE SET
                     source=COALESCE(NULLIF(excluded.source,''), assets.source),
                     in_scope=excluded.in_scope""",
                (value, kind, source, int(in_scope), time.time(), json.dumps(data)),
            )
            self.conn.commit()

    def add_service(self, url: str, **fields: Any) -> None:
        assert self._lock is not None
        cols = {
            "host": fields.get("host"),
            "status": fields.get("status"),
            "title": fields.get("title"),
            "server": fields.get("server"),
            "tech": json.dumps(fields.get("tech", [])),
            "content_length": fields.get("content_length"),
            "data": json.dumps(fields.get("data", {})),
        }
        with self._lock:
            self.conn.execute(
                """INSERT INTO services(url, host, status, title, server, tech,
                        content_length, first_seen, data)
                   VALUES(:url,:host,:status,:title,:server,:tech,:content_length,:ts,:data)
                   ON CONFLICT(url) DO UPDATE SET
                     status=excluded.status, title=excluded.title,
                     server=excluded.server, tech=excluded.tech,
                     content_length=excluded.content_length, data=excluded.data""",
                {"url": url, "ts": time.time(), **cols},
            )
            self.conn.commit()

    def add_finding(
        self,
        target: str,
        module: str,
        name: str,
        severity: str = "info",
        evidence: str = "",
        **data: Any,
    ) -> None:
        assert self._lock is not None
        with self._lock:
            self.conn.execute(
                """INSERT INTO findings(target, module, name, severity, evidence,
                        first_seen, data)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(target, module, name) DO UPDATE SET
                     severity=excluded.severity, evidence=excluded.evidence""",
                (target, module, name, severity, evidence, time.time(), json.dumps(data)),
            )
            self.conn.commit()

    # --- reads ------------------------------------------------------------
    def assets(self, in_scope_only: bool = False) -> list[dict[str, Any]]:
        q = "SELECT * FROM assets"
        if in_scope_only:
            q += " WHERE in_scope=1"
        q += " ORDER BY value"
        return [dict(r) for r in self.conn.execute(q)]

    def services(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM services ORDER BY url")]

    def findings(self) -> list[dict[str, Any]]:
        order = (
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        )
        return [dict(r) for r in self.conn.execute(f"SELECT * FROM findings ORDER BY {order}")]

    def counts(self) -> dict[str, int]:
        c = self.conn.execute
        return {
            "assets": c("SELECT COUNT(*) FROM assets").fetchone()[0],
            "in_scope_assets": c("SELECT COUNT(*) FROM assets WHERE in_scope=1").fetchone()[0],
            "services": c("SELECT COUNT(*) FROM services").fetchone()[0],
            "findings": c("SELECT COUNT(*) FROM findings").fetchone()[0],
        }

    def bulk_add_assets(self, rows: Iterable[tuple[str, str, str, bool]]) -> None:
        for value, kind, source, in_scope in rows:
            self.add_asset(value, kind, source, in_scope)
