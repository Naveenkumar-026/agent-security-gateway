from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


@dataclass(frozen=True)
class AuditEvent:
    event_id: int
    created_at: str
    session_id: str
    turn_id: str
    agent_id: str
    action_type: str
    action_target: str
    decision: str
    total_score: float
    reasons: List[str]
    metadata: Dict[str, Any]


class SQLiteAuditStore:
    def __init__(self, db_path: str) -> None:
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
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_target TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    total_score REAL NOT NULL,
                    reasons_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_recent ON audit_events(created_at DESC, event_id DESC)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id, created_at DESC, event_id DESC)"
            )
            self._conn.commit()

    @staticmethod
    def _to_json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _from_json(raw: str, fallback: Any) -> Any:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return fallback
        return parsed

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> AuditEvent:
        reasons = SQLiteAuditStore._from_json(str(row["reasons_json"]), [])
        metadata = SQLiteAuditStore._from_json(str(row["metadata_json"]), {})
        if not isinstance(reasons, list):
            reasons = []
        if not isinstance(metadata, dict):
            metadata = {}
        return AuditEvent(
            event_id=int(row["event_id"]),
            created_at=str(row["created_at"]),
            session_id=str(row["session_id"]),
            turn_id=str(row["turn_id"]),
            agent_id=str(row["agent_id"]),
            action_type=str(row["action_type"]),
            action_target=str(row["action_target"]),
            decision=str(row["decision"]),
            total_score=float(row["total_score"]),
            reasons=[str(x) for x in reasons],
            metadata={str(k): v for k, v in metadata.items()},
        )

    def append_event(
        self,
        *,
        session_id: str,
        turn_id: str,
        agent_id: str,
        action_type: str,
        action_target: str,
        decision: str,
        total_score: float,
        reasons: List[str],
        metadata: Dict[str, Any],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    created_at, session_id, turn_id, agent_id, action_type,
                    action_target, decision, total_score, reasons_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    session_id,
                    turn_id,
                    agent_id,
                    action_type,
                    action_target,
                    decision,
                    float(total_score),
                    self._to_json([str(x) for x in reasons]),
                    self._to_json(dict(metadata)),
                ),
            )
            self._conn.commit()

    def list_recent(self, limit: int = 100) -> List[AuditEvent]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC, event_id DESC LIMIT ?",
                (capped,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def list_for_session(self, session_id: str, limit: int = 200) -> List[AuditEvent]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM audit_events
                WHERE session_id = ?
                ORDER BY created_at DESC, event_id DESC
                LIMIT ?
                """,
                (session_id, capped),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

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




