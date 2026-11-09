"""Historial de escaneos guardado en SQLite."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  REAL    NOT NULL,
    targets     TEXT    NOT NULL,
    command     TEXT    NOT NULL,
    exit_code   INTEGER,
    duration    REAL,
    hosts_up    INTEGER DEFAULT 0,
    open_ports  INTEGER DEFAULT 0,
    output      TEXT    DEFAULT '',
    xml         TEXT    DEFAULT ''
);
"""


@dataclass
class ScanRecord:
    id: int
    started_at: float
    targets: str
    command: str
    exit_code: int | None
    duration: float | None
    hosts_up: int
    open_ports: int
    output: str = ""
    xml: str = ""

    @property
    def started_text(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))


class History:
    def __init__(self, db_path: str | Path):
        self.path = str(db_path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def add(
        self,
        *,
        started_at: float,
        targets: str,
        command: str,
        exit_code: int | None,
        duration: float | None,
        hosts_up: int,
        open_ports: int,
        output: str,
        xml: str,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans (started_at, targets, command, exit_code, duration,"
            " hosts_up, open_ports, output, xml) VALUES (?,?,?,?,?,?,?,?,?)",
            (started_at, targets, command, exit_code, duration, hosts_up, open_ports, output, xml),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def list(self, limit: int = 500) -> list[ScanRecord]:
        rows = self._conn.execute(
            "SELECT id, started_at, targets, command, exit_code, duration, hosts_up, open_ports"
            " FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [ScanRecord(**dict(r)) for r in rows]

    def get(self, scan_id: int) -> ScanRecord | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return ScanRecord(**dict(row)) if row else None

    def delete(self, scan_id: int) -> None:
        self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self._conn.commit()

    def clear(self) -> None:
        self._conn.execute("DELETE FROM scans")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
