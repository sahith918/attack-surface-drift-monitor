"""
state_store.py

Persists scan snapshots to SQLite so the diff engine can compare
"latest scan" vs "previous scan" per host.

Schema:
    scans(id, host, label, timestamp)
    findings(id, scan_id, port, protocol, state, service, product, version, banner)
    certs(id, scan_id, port, subject, issuer, not_after, fingerprint_sha256)
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    label       TEXT,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    banner      TEXT
);

CREATE TABLE IF NOT EXISTS certs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port                INTEGER NOT NULL,
    subject             TEXT,
    issuer              TEXT,
    not_after           TEXT,
    fingerprint_sha256  TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_host_ts ON scans(host, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_certs_scan ON certs(scan_id);
"""


class StateStore:
    def __init__(self, db_path: str = "./data/snapshots.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def save_snapshot(self, host: str, label: str, findings: list[dict],
                       certs: list[dict] | None = None) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (host, label, timestamp) VALUES (?, ?, ?)",
                (host, label, ts),
            )
            scan_id = cur.lastrowid

            conn.executemany(
                """INSERT INTO findings
                   (scan_id, port, protocol, state, service, product, version, banner)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        scan_id,
                        f["port"],
                        f.get("protocol", "tcp"),
                        f["state"],
                        f.get("service"),
                        f.get("product"),
                        f.get("version"),
                        f.get("banner"),
                    )
                    for f in findings
                ],
            )

            if certs:
                conn.executemany(
                    """INSERT INTO certs
                       (scan_id, port, subject, issuer, not_after, fingerprint_sha256)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            scan_id,
                            c["port"],
                            c.get("subject"),
                            c.get("issuer"),
                            c.get("not_after"),
                            c.get("fingerprint_sha256"),
                        )
                        for c in certs
                    ],
                )

            return scan_id

    def get_last_two_scans(self, host: str) -> tuple[dict | None, dict | None]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, timestamp FROM scans WHERE host = ? "
                "ORDER BY timestamp DESC LIMIT 2",
                (host,),
            ).fetchall()

        if not rows:
            return None, None
        if len(rows) == 1:
            return None, self._load_snapshot(rows[0]["id"], rows[0]["timestamp"])

        latest, previous = rows[0], rows[1]
        return (
            self._load_snapshot(previous["id"], previous["timestamp"]),
            self._load_snapshot(latest["id"], latest["timestamp"]),
        )

    def _load_snapshot(self, scan_id: int, timestamp: str) -> dict:
        with self._conn() as conn:
            findings = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchall()
            ]
            certs = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM certs WHERE scan_id = ?", (scan_id,)
                ).fetchall()
            ]
        return {"scan_id": scan_id, "timestamp": timestamp,
                "findings": findings, "certs": certs}

    def get_all_scans_for_host(self, host: str) -> list[dict]:
        with self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT id, host, label, timestamp FROM scans "
                    "WHERE host = ? ORDER BY timestamp ASC",
                    (host,),
                ).fetchall()
            ]


if __name__ == "__main__":
    store = StateStore("./data/snapshots.db")
    sid = store.save_snapshot(
        host="192.168.56.103",
        label="metasploitable2",
        findings=[
            {"port": 21, "state": "open", "service": "ftp",
             "product": "vsftpd", "version": "2.3.4", "banner": "vsFTPd 2.3.4"},
            {"port": 22, "state": "open", "service": "ssh",
             "product": "OpenSSH", "version": "4.7p1"},
        ],
    )
    print(f"Saved snapshot id={sid}")
    prev, latest = store.get_last_two_scans("192.168.56.103")
    print("previous:", prev)
    print("latest:", latest)
