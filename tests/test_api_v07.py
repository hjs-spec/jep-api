from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def create(**overrides):
    body = {
        "verb": "J",
        "who": "did:example:api-07",
        "what": {"claim": "approve", "subject": "urn:example:result:7"},
    }
    body.update(overrides)
    response = client.post("/v0.7/events/create", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_current_metadata_is_07():
    root = client.get("/").json()
    assert root["profile"] == "jep-core-0.7"
    assert "/v0.7/events/create" in root["endpoints"]
    assert "/events/create" in root["legacy_endpoints"]


def test_create_07_has_event_id_and_no_core_nonce():
    created = create()
    event = created["event"]
    assert event["jep"] == "1"
    assert event["id"].startswith("urn:uuid:")
    assert "nonce" not in event
    assert created["validation"]["status"] == "valid"
    assert "level" not in created["validation"]


def test_verify_07_reports_independent_checks():
    event = create()["event"]
    result = client.post("/v0.7/events/verify", json={"event": event}).json()
    assert result["status"] == "valid"
    assert result["profile"] == "jep-core-0.7"
    assert result["checks"]["syntax"] == "pass"
    assert result["checks"]["cryptographic"] == "pass"
    assert result["checks"]["event_identity"] == "pass"
    assert result["checks"]["reference_integrity"] == "not_applicable"


def test_07_acceptance_is_idempotent():
    event = create()["event"]
    payload = {"event": event, "mode": "acceptance"}
    first = client.post("/v0.7/events/verify", json=payload).json()
    retry = client.post("/v0.7/events/verify", json=payload).json()
    assert first["status"] == "valid"
    assert first["acceptance"] == {"outcome": "accepted", "effect_applied": True}
    assert retry["status"] == "valid"
    assert retry["acceptance"] == {"outcome": "already_accepted", "effect_applied": False}


def test_07_identity_conflict_is_rejected():
    event_id = "urn:uuid:00000000-0000-7000-8000-000000000777"
    first = create(id=event_id, what={"claim": "approve"})["event"]
    conflicting = create(id=event_id, what={"claim": "reject"})["event"]

    accepted = client.post("/v0.7/events/verify", json={"event": first, "mode": "acceptance"}).json()
    conflict = client.post("/v0.7/events/verify", json={"event": conflicting, "mode": "acceptance"}).json()

    assert accepted["acceptance"]["outcome"] == "accepted"
    assert conflict["status"] == "invalid"
    assert conflict["acceptance"] == {"outcome": "rejected", "effect_applied": False}
    assert conflict["errors"][0]["code"] == "ERR_EVENT_ID_CONFLICT"


def test_07_verb_minimums_enforced():
    bad_v = create(verb="J")["event"]
    bad_v["verb"] = "V"
    bad_v["what"] = {"verification_scope": ["cryptographic"]}
    result = client.post("/v0.7/events/verify", json={"event": bad_v}).json()
    assert result["status"] == "invalid"
    assert result["errors"][0]["code"] in {"ERR_MISSING_REQUIRED_FIELD", "ERR_INVALID_FIELD_TYPE"}


def test_legacy_06_route_still_operates():
    legacy = client.post("/events/create", json={
        "verb": "J",
        "who": "did:example:legacy",
        "what": {"claim": "legacy"},
    })
    assert legacy.status_code == 200
    event = legacy.json()["event"]
    assert "nonce" in event
    assert "id" not in event
    assert legacy.json()["validation"]["profile"] == "jep-core-0.6"
