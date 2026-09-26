"""Migration must preserve acceptance decisions across a storage change."""

import os
import uuid

import pytest

from manage import migrate
from state import LocalState, PostgresState


pytestmark = pytest.mark.skipif(
    not os.environ.get("JEP_TEST_DATABASE_URL"), reason="CI supplies real PostgreSQL"
)


def source_state(tmp_path):
    source = LocalState(tmp_path / "source")
    actor = "migration:" + str(uuid.uuid4())
    source.save_event(actor, {"claim": "original"})
    source.consume_nonce(actor, "receiver", "legacy-nonce", now=1, expires=100)
    return source, actor


def test_migration_keeps_acceptance_idempotent_and_conflicts_rejected(tmp_path):
    source, actor = source_state(tmp_path)
    source.accept_event_identity(actor, "event-1", "digest-1", "hash-1", now=10)
    dsn = os.environ["JEP_TEST_DATABASE_URL"]

    migrate(source.directory, dsn)
    migrate(source.directory, dsn)
    target = PostgresState(dsn)

    assert target.accept_event_identity(actor, "event-1", "digest-1", "new-signature-hash", now=20) == "already_accepted"
    assert target.accept_event_identity(actor, "event-1", "different-content", "hash-2", now=20) == "conflict"
    assert not target.consume_nonce(actor, "receiver", "legacy-nonce", now=20, expires=120)
    with target.connect() as db:
        row = db.execute(
            "SELECT event_hash,accepted_at FROM jep_accepted_events WHERE actor=%s AND event_id=%s",
            (actor, "event-1"),
        ).fetchone()
        assert row == ("hash-1", 10)
        assert db.execute("SELECT payload FROM jep_events WHERE hash=%s", (actor,)).fetchone()[0] == {"claim": "original"}


def test_identity_conflict_rolls_back_other_migrated_state(tmp_path):
    source, actor = source_state(tmp_path)
    source.accept_event_identity(actor, "event-1", "source-content", "source-hash", now=10)
    dsn = os.environ["JEP_TEST_DATABASE_URL"]
    target = PostgresState(dsn)
    target.accept_event_identity(actor, "event-1", "destination-content", "destination-hash", now=5)

    with pytest.raises(ValueError, match="Accepted Event Identity conflict"):
        migrate(source.directory, dsn)

    with target.connect() as db:
        assert db.execute("SELECT hash FROM jep_events WHERE hash=%s", (actor,)).fetchone() is None
        assert db.execute("SELECT nonce FROM jep_nonces WHERE actor=%s", (actor,)).fetchone() is None
    assert target.accept_event_identity(actor, "event-1", "destination-content", "any-hash", now=20) == "already_accepted"
    assert source.accept_event_identity(actor, "event-1", "source-content", "any-hash", now=20) == "already_accepted"


def test_pre07_database_without_acceptance_table_still_migrates(tmp_path):
    source, actor = source_state(tmp_path)
    with source.connect() as db:
        db.execute("DROP TABLE accepted_events")
    dsn = os.environ["JEP_TEST_DATABASE_URL"]
    migrate(source.directory, dsn)
    target = PostgresState(dsn)
    assert not target.consume_nonce(actor, "receiver", "legacy-nonce", now=20, expires=120)
    assert target.accept_event_identity(actor, "new-event", "digest", "hash", now=20) == "accepted"
