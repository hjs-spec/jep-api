"""Stable create requests survive lost replies, concurrency and storage failures."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
from keys import KeyManager
from state import LocalState


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    state = LocalState(tmp_path / "state")
    monkeypatch.setattr(main, "STATE", state)
    monkeypatch.setattr(main, "KEYS", KeyManager(state))
    return TestClient(main.app), state


def request(**changes):
    return {
        "id": "stable-create",
        "verb": "J",
        "who": "did:example:retry",
        "what": {"claim": "approve"},
        **changes,
    }


def test_retry_preserves_time_signature_privacy_and_ttl_after_restart(isolated, monkeypatch):
    client, state = isolated
    body = request(ttl_minutes=1, digest_only_who=True)
    monkeypatch.setattr(main.time, "time", lambda: 2000000000)
    first = client.post("/v0.7/events/create", json=body)
    assert first.status_code == 200
    monkeypatch.setattr(main.time, "time", lambda: 2000000500)
    reopened = LocalState(state.directory)
    monkeypatch.setattr(main, "STATE", reopened)
    monkeypatch.setattr(
        main, "detached_jws_sign", lambda _: pytest.fail("Retry must not sign again")
    )
    retry = client.post("/v0.7/events/create", json=body)
    assert retry.status_code == 200
    assert retry.json() == first.json()
    assert retry.json()["event"]["ext"][main.EXT_TTL]["expires_at"] == 2000000060
    with reopened.connect() as db:
        rows = db.execute(
            "SELECT request_key,request_digest,response FROM created_requests"
        ).fetchall()
        assert len(rows) == 1
        assert body["who"] not in json.dumps(rows)
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1


def test_concurrent_creates_return_one_exact_artifact(isolated):
    client, state = isolated
    body = request(digest_only_who=True)
    with ThreadPoolExecutor(8) as pool:
        responses = list(
            pool.map(lambda _: client.post("/v0.7/events/create", json=body), range(16))
        )
    assert all(r.status_code == 200 for r in responses)
    assert all(r.json() == responses[0].json() for r in responses)
    with state.connect() as db:
        assert db.execute("SELECT count(*) FROM created_requests").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1


def test_conflicting_request_is_409_and_original_remains_available(isolated):
    client, _ = isolated
    original = client.post("/v0.7/events/create", json=request()).json()
    conflict = client.post("/v0.7/events/create", json=request(what={"claim": "different"}))
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "ERR_CREATE_REQUEST_CONFLICT"
    assert client.post("/v0.7/events/create", json=request()).json() == original
    other_actor = client.post("/v0.7/events/create", json=request(who="did:example:other"))
    assert other_actor.status_code == 200
    assert other_actor.json()["event_hash"] != original["event_hash"]


def test_creation_does_not_accept_and_invalid_request_does_not_bind_id(isolated):
    client, state = isolated
    assert client.post("/v0.7/events/create", json=request(what={})).status_code == 422
    event = client.post("/v0.7/events/create", json=request()).json()["event"]
    with state.connect() as db:
        assert db.execute("SELECT count(*) FROM accepted_events").fetchone()[0] == 0
    first = client.post("/v0.7/events/verify", json={"event": event, "mode": "acceptance"}).json()
    retry = client.post("/v0.7/events/verify", json={"event": event, "mode": "acceptance"}).json()
    assert first["acceptance"]["outcome"] == "accepted"
    assert retry["acceptance"]["outcome"] == "already_accepted"


def test_lost_reply_after_commit_recovers_original(isolated, monkeypatch):
    client, state = isolated
    save = state.save_created_response
    committed = []

    def lose_reply(*args):
        committed.append(save(*args))
        raise sqlite3.OperationalError("simulated connection loss after commit")

    monkeypatch.setattr(state, "save_created_response", lose_reply)
    assert client.post("/v0.7/events/create", json=request()).status_code == 503
    monkeypatch.setattr(
        main, "detached_jws_sign", lambda _: pytest.fail("Committed retry must reuse original")
    )
    retry = client.post("/v0.7/events/create", json=request())
    assert retry.status_code == 200
    assert retry.json() == committed[0]


def test_storage_failure_rolls_back_both_response_and_event(isolated):
    client, state = isolated
    with state.connect() as db:
        db.execute(
            "CREATE TRIGGER fail_created BEFORE INSERT ON created_requests BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    assert client.post("/v0.7/events/create", json=request()).status_code == 503
    with state.connect() as db:
        assert db.execute("SELECT count(*) FROM created_requests").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_created")
    assert client.post("/v0.7/events/create", json=request()).status_code == 200


def test_without_caller_id_creation_remains_new_each_time(isolated):
    client, _ = isolated
    body = request()
    del body["id"]
    one = client.post("/v0.7/events/create", json=body).json()
    two = client.post("/v0.7/events/create", json=body).json()
    assert one["event"]["id"] != two["event"]["id"]


@pytest.mark.parametrize("scope", ["cryptographic", ["cryptographic"]])
def test_v_scope_forms_create_and_verify_without_rewriting(isolated, scope):
    client, _ = isolated
    body = request(
        verb="V",
        what={"verification_scope": scope, "result": "pass"},
        ref={"type": "jep:event", "value": {"who": "a", "id": "target"}},
    )
    created = client.post("/v0.7/events/create", json=body)
    assert created.status_code == 200, created.text
    event = created.json()["event"]
    assert event["what"]["verification_scope"] == scope
    assert client.post("/v0.7/events/verify", json={"event": event}).json()["status"] == "valid"


def test_published_string_scope_vector_is_accepted(isolated, monkeypatch):
    client, state = isolated
    fixtures = Path(__file__).parent / "fixtures/core-v07"
    keys = json.loads((fixtures / "keys.json").read_text())
    monkeypatch.setattr(state, "public_keys", lambda: keys)
    raw = (fixtures / "V-string-scope.json").read_text()
    response = client.post(
        "/v0.7/events/verify",
        content='{"event":' + raw + "}",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "valid"
    assert result["checks"]["cryptographic"] == "pass"
    assert (
        result["event_hash"]
        == "sha256:95d6d17f3fb530c282251eb8c0b9d3885dbc25f6ae01a782390bc7ad98e30765"
    )
