"""SQLite event store. All user values are bound parameters."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from .common import LiaError, canonical, digest
from .normalize import Event

SCHEMA_VERSION = 1


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA cache_size=-262144")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=16384")
        self.db.execute("PRAGMA synchronous=NORMAL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA_VERSION):
            self.db.close()
            raise LiaError("unsupported_database_version", 4)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                uid TEXT PRIMARY KEY, time INTEGER NOT NULL, tenant TEXT NOT NULL,
                app TEXT NOT NULL, user TEXT, ip TEXT, action TEXT NOT NULL,
                signature TEXT NOT NULL, valid INTEGER NOT NULL DEFAULT 1, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS event_provenance (
                uid TEXT REFERENCES events(uid), artifact TEXT, line INTEGER, offset INTEGER,
                record_digest TEXT, PRIMARY KEY(artifact,line));
            CREATE TABLE IF NOT EXISTS artifacts (hash TEXT PRIMARY KEY, source_id TEXT, size INTEGER);
            CREATE TABLE IF NOT EXISTS quality_findings (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id TEXT REFERENCES alerts(id), event_uid TEXT REFERENCES events(uid),
                PRIMARY KEY(alert_id,event_uid));
            CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id TEXT REFERENCES cases(id), alert_id TEXT REFERENCES alerts(id), PRIMARY KEY(case_id,alert_id));
            CREATE TABLE IF NOT EXISTS case_history (id INTEGER PRIMARY KEY, case_id TEXT REFERENCES cases(id), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_notes (id INTEGER PRIMARY KEY, case_id TEXT REFERENCES cases(id), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS review_commits (id TEXT PRIMARY KEY);
            PRAGMA user_version=1;
        """)
        self.db.commit()

    def add(self, event: Event) -> tuple[str, int]:
        signature = digest([event.time, event.data, event.precision, event.uncertainty, event.flags])
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO events(uid,time,tenant,app,user,ip,action,signature,payload) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                event.uid,
                event.time,
                event.get("tenant.id"),
                event.get("app.id"),
                event.get("actor.user_id"),
                event.get("network.client_ip"),
                event.get("event.action"),
                signature,
                canonical(event.payload()),
            ),
        )
        state, reclassified = "accepted_unique", 0
        if cursor.rowcount == 0:
            old = self.db.execute("SELECT signature,valid FROM events WHERE uid=?", (event.uid,)).fetchone()
            if old[0] != signature or old[1] == 0:
                reclassified = old[1]
                self.db.execute("UPDATE events SET valid=0 WHERE uid=?", (event.uid,))
                state = "conflicted_rows"
            else:
                state = "duplicate_rows"
        self.db.execute(
            "INSERT OR IGNORE INTO event_provenance VALUES(?,?,?,?,?)",
            (event.uid, event.artifact, event.line, event.offset, event.record_digest),
        )
        return state, reclassified

    def index(self) -> None:
        self.db.executescript("""
            CREATE INDEX IF NOT EXISTS event_time ON events(time,uid);
            CREATE INDEX IF NOT EXISTS event_action ON events(tenant,app,action,time);
            CREATE INDEX IF NOT EXISTS event_user ON events(tenant,app,user,time);
            CREATE INDEX IF NOT EXISTS event_ip ON events(tenant,app,ip,time);
        """)
        self.db.commit()

    @staticmethod
    def decode(payload: str) -> Event:
        p = json.loads(payload)
        return Event(
            p["uid"],
            p["time"],
            p["fields"],
            p["source_id"],
            p["artifact"],
            p["line"],
            p["offset"],
            p["record_digest"],
            p["precision_us"],
            p["uncertainty_us"],
            p["flags"],
        )

    def events(self) -> Iterator[Event]:
        for (payload,) in self.db.execute("SELECT payload FROM events WHERE valid=1 ORDER BY time,uid"):
            yield self.decode(payload)

    def event(self, uid: str) -> Event:
        row = self.db.execute("SELECT payload FROM events WHERE uid=? AND valid=1", (uid,)).fetchone()
        if row is None:
            raise LiaError("evidence_missing", 4)
        return self.decode(row[0])

    def save_results(self, alerts: list[dict], cases: list[dict], findings: list[dict]) -> None:
        with self.db:
            for a in alerts:
                self.db.execute("INSERT INTO alerts VALUES(?,?)", (a["id"], canonical(a)))
                self.db.executemany(
                    "INSERT INTO alert_events VALUES(?,?)", [(a["id"], uid) for uid in a["evidence_ids"]]
                )
            for c in cases:
                self.db.execute("INSERT INTO cases VALUES(?,?)", (c["id"], canonical(c)))
                self.db.executemany(
                    "INSERT INTO case_alerts VALUES(?,?)", [(c["id"], aid) for aid in c["alert_ids"]]
                )
            self.db.executemany(
                "INSERT INTO quality_findings(payload) VALUES(?)", [(canonical(f),) for f in findings]
            )

    def close(self) -> None:
        self.db.close()
