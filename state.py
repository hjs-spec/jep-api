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

    def register_public_key(self, kid: str, jwk: dict) -> None:
        payload = json.dumps(jwk, sort_keys=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS public_keys (kid TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO public_keys VALUES (?, ?)", (kid, payload))
            existing = db.execute("SELECT payload FROM public_keys WHERE kid = ?", (kid,)).fetchone()[0]
            if existing != payload:
                raise ValueError("A kid cannot be reassigned to different key material")

    def public_keys(self) -> dict:
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS public_keys (kid TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            return {kid: json.loads(payload) for kid, payload in db.execute("SELECT kid, payload FROM public_keys")}

    def health(self) -> None:
        with self.connect() as db:
            db.execute("SELECT 1").fetchone()


class PostgresState:
    """Transactional state shared across hosts. Private keys never enter this database."""
    def __init__(self, dsn: str):
        import psycopg
        self.dsn = dsn
        self.driver = psycopg
        with self.connect() as db:
            # Serialize bootstrap across simultaneous worker starts.
            db.execute("SELECT pg_advisory_xact_lock(7060601)")
            db.execute("CREATE TABLE IF NOT EXISTS jep_nonces (actor TEXT NOT NULL, audience TEXT NOT NULL, nonce TEXT NOT NULL, expires BIGINT NOT NULL, PRIMARY KEY(actor,audience,nonce))")
            db.execute("CREATE TABLE IF NOT EXISTS jep_events (hash TEXT PRIMARY KEY, payload JSONB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS jep_public_keys (kid TEXT PRIMARY KEY, payload JSONB NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS jep_nonces_expiry ON jep_nonces(expires)")

    @contextmanager
    def connect(self):
        with self.driver.connect(self.dsn, connect_timeout=10, options="-c statement_timeout=10000 -c lock_timeout=10000") as db:
            yield db

    def consume_nonce(self, actor: str, audience: str, nonce: str, *, now: int, expires: int) -> bool:
        with self.connect() as db:
            row = db.execute("INSERT INTO jep_nonces VALUES (%s,%s,%s,%s) ON CONFLICT(actor,audience,nonce) DO UPDATE SET expires=EXCLUDED.expires WHERE jep_nonces.expires < %s RETURNING nonce", (actor,audience,nonce,expires,now)).fetchone()
            return row is not None

    def save_event(self, event_hash: str, event: dict) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO jep_events VALUES (%s,%s::jsonb) ON CONFLICT DO NOTHING", (event_hash,json.dumps(event,ensure_ascii=False)))

    def register_public_key(self, kid: str, jwk: dict) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO jep_public_keys VALUES (%s,%s::jsonb) ON CONFLICT DO NOTHING", (kid,json.dumps(jwk)))
            existing = db.execute("SELECT payload FROM jep_public_keys WHERE kid=%s", (kid,)).fetchone()[0]
            if existing != jwk:
                raise ValueError("A kid cannot be reassigned to different key material")

    def public_keys(self) -> dict:
        with self.connect() as db:
            return dict(db.execute("SELECT kid,payload FROM jep_public_keys").fetchall())

    def health(self) -> None:
        with self.connect() as db:
            db.execute("SELECT 1").fetchone()

    def prune_nonces(self, before: int) -> int:
        # Operators may call this with the present time, never a future cutoff.
        import time
        if before > int(time.time()):
            raise ValueError("Cannot prune future replay records")
        with self.connect() as db:
            return db.execute("DELETE FROM jep_nonces WHERE expires < %s", (before,)).rowcount


def configured_state():
    import os
    url = os.environ.get("JEP_DATABASE_URL")
    path = os.environ.get("JEP_DATABASE_URL_FILE")
    if url and path:
        raise ValueError("Set either JEP_DATABASE_URL or JEP_DATABASE_URL_FILE")
    if path:
        url = Path(path).read_text().strip()
    if url:
        return PostgresState(url)
    if os.environ.get("JEP_DEPLOYMENT_MODE") == "production":
        raise ValueError("Production mode requires PostgreSQL shared state")
    return LocalState(os.environ.get("JEP_STATE_DIR", ".jep-state"))
