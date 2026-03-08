from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class SessionState:
    session_id: str
    agent_id: str = ""
    prior_actions: List[str] = field(default_factory=list)
    memory_touched: List[str] = field(default_factory=list)
    cumulative_risk: float = 0.0
    prior_decisions: List[str] = field(default_factory=list)
    sensitive_markers: List[str] = field(default_factory=list)
    request_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ended_at: Optional[str] = None


class SQLiteSessionRiskStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._closed = False
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_state (
                    session_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    prior_actions TEXT NOT NULL,
                    memory_touched TEXT NOT NULL,
                    cumulative_risk REAL NOT NULL,
                    prior_decisions TEXT NOT NULL,
                    sensitive_markers TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ended_at TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_session_state_recent ON session_state(updated_at DESC, session_id DESC)"
            )
            self._conn.commit()

    @staticmethod
    def _to_json(values: List[str]) -> str:
        return json.dumps(values, separators=(",", ":"))

    @staticmethod
    def _from_json(raw: str) -> List[str]:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, list):
            return []
        return [str(x) for x in parsed]

    @staticmethod
    def _row_to_state(row: sqlite3.Row) -> SessionState:
        return SessionState(
            session_id=str(row["session_id"]),
            agent_id=str(row["agent_id"]),
            prior_actions=SQLiteSessionRiskStore._from_json(str(row["prior_actions"])),
            memory_touched=SQLiteSessionRiskStore._from_json(str(row["memory_touched"])),
            cumulative_risk=float(row["cumulative_risk"]),
            prior_decisions=SQLiteSessionRiskStore._from_json(str(row["prior_decisions"])),
            sensitive_markers=SQLiteSessionRiskStore._from_json(str(row["sensitive_markers"])),
            request_count=int(row["request_count"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            ended_at=str(row["ended_at"]) if row["ended_at"] is not None else None,
        )

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM session_state WHERE session_id = ?", (session_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_state(row)

    def list_recent(self, limit: int = 100) -> List[SessionState]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM session_state ORDER BY updated_at DESC, session_id DESC LIMIT ?",
                (capped,),
            ).fetchall()
        return [self._row_to_state(r) for r in rows]

    def get_or_create(self, session_id: str, agent_id: str = "") -> SessionState:
        existing = self.get(session_id)
        if existing is not None:
            return existing

        now = datetime.now(timezone.utc).isoformat()
        initial = SessionState(session_id=session_id, agent_id=agent_id, created_at=now, updated_at=now)
        self.upsert(initial)
        return initial

    def upsert(self, state: SessionState) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO session_state (
                    session_id, agent_id, prior_actions, memory_touched,
                    cumulative_risk, prior_decisions, sensitive_markers,
                    request_count, created_at, updated_at, ended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    agent_id=excluded.agent_id,
                    prior_actions=excluded.prior_actions,
                    memory_touched=excluded.memory_touched,
                    cumulative_risk=excluded.cumulative_risk,
                    prior_decisions=excluded.prior_decisions,
                    sensitive_markers=excluded.sensitive_markers,
                    request_count=excluded.request_count,
                    created_at=excluded.created_at,
                    updated_at=excluded.updated_at,
                    ended_at=excluded.ended_at
                """,
                (
                    state.session_id,
                    state.agent_id,
                    self._to_json(state.prior_actions),
                    self._to_json(state.memory_touched),
                    state.cumulative_risk,
                    self._to_json(state.prior_decisions),
                    self._to_json(state.sensitive_markers),
                    state.request_count,
                    state.created_at,
                    state.updated_at,
                    state.ended_at,
                ),
            )
            self._conn.commit()

    def ping(self) -> bool:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.close()
            finally:
                self._closed = True




