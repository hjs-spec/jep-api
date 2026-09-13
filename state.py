"""Local durable signing and replay state, shared by API workers on one host."""

from __future__ import annotations

import json
from contextlib import contextmanager
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class LocalState:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "state.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS signing_keys (id TEXT PRIMARY KEY, seed BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS nonces (
                    actor TEXT NOT NULL, audience TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL,
                    PRIMARY KEY (actor, audience, nonce));
                CREATE TABLE IF NOT EXISTS events (hash TEXT PRIMARY KEY, payload TEXT NOT NULL);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def signing_key(self) -> Ed25519PrivateKey:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT seed FROM signing_keys WHERE id = ?", ("default",)
            ).fetchone()
            if row is None:
                key = Ed25519PrivateKey.generate()
                seed = key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
                db.execute("INSERT INTO signing_keys VALUES (?, ?)", ("default", seed))
                return key
            return Ed25519PrivateKey.from_private_bytes(row[0])

    def consume_nonce(
        self, actor: str, audience: str, nonce: str, *, now: int, expires: int
    ) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
            try:
                db.execute(
                    "INSERT INTO nonces VALUES (?, ?, ?, ?)",
                    (actor, audience, nonce, expires),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def save_event(self, event_hash: str, event: dict) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?)",
                (event_hash, json.dumps(event, ensure_ascii=False)),
            )
