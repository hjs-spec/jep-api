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


def test_unresolved_key_is_indeterminate_without_acceptance():
    event = create()["event"]
    header, _, signature = event["sig"].split(".")
    import json
    protected = json.loads(main.b64u_decode(header))
    protected["kid"] = "unresolved-test-key"
    event["sig"] = f'{main.b64u(main.jcs_seed(protected))}..{signature}'
    result = client.post("/v0.7/events/verify", json={"event": event, "mode": "acceptance"}).json()
    assert result["status"] == "indeterminate"
    assert result["checks"]["cryptographic"] == "indeterminate"
    assert result["acceptance"] == {"outcome": "indeterminate", "effect_applied": False}


def test_ascii_identity_matches_reference_schema():
    assert create(id="local event\t7")["validation"]["status"] == "valid"


def test_expired_ttl_is_archivable_but_not_accepted():
    event = create()["event"]
    event["ext"] = {main.EXT_TTL: {"expires_at": 1, "ttl_minutes": 1}}
    event["ext_crit"] = [main.EXT_TTL]
    event["sig"] = main.detached_jws_sign({k: v for k, v in event.items() if k != "sig"})
    assert main.validate_event_07(event)["status"] == "valid"
    result = main.validate_event_07(event, mode="acceptance")
    assert result["errors"][0]["code"] == "ERR_EVENT_EXPIRED"
    assert result["acceptance"]["effect_applied"] is False
    event["ext"][main.EXT_TTL]["expires_at"] = int(main.time.time()) + 60
    event["sig"] = main.detached_jws_sign({k: v for k, v in event.items() if k != "sig"})
    assert main.validate_event_07(event, mode="acceptance")["acceptance"]["outcome"] == "accepted"


def test_known_extensions_are_validated_before_acceptance():
    for ext in ({main.EXT_TTL: {"expires_at": "tomorrow"}},
                {main.EXT_DIGEST_ONLY: {"who_digest": "different"}}):
        event = create()["event"]
        event["ext"] = ext
        event["ext_crit"] = list(ext)
        event["sig"] = main.detached_jws_sign({k: v for k, v in event.items() if k != "sig"})
        result = main.validate_event_07(event, mode="acceptance")
        assert result["checks"]["extension_processing"] == "fail"
        assert result["acceptance"]["effect_applied"] is False


def test_malformed_identity_diagnostics_follow_result_schema():
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator

    schema = Draft202012Validator(json.loads((Path(main.__file__).parent / "jep-validation-result-0.7.schema.json").read_text()))
    base = create()["event"]
    for event in ({}, {**base, "id": 3}, {**base, "id": ""}, {**base, "who": ""}, {**base, "who": []}):
        response = client.post("/v0.7/events/verify", json={"event": event, "mode": "acceptance"})
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "invalid"
        assert result["event_identity"] is None
        schema.validate(result)
        assert result["acceptance"]["effect_applied"] is False
    result = client.post("/v0.7/events/verify", json={"event": base, "mode": "acceptance"}).json()
    assert result["acceptance"] == {"outcome": "accepted", "effect_applied": True}


def test_large_jcs_number_survives_javascript_integer_spelling():
    import json

    original = create(what={"value": 1e20, "shortest": 1.0000000000000001e18, "negative": -1.0000000000000001e18})
    wire = json.dumps(original["event"]).replace('1e+20', '100000000000000000000').replace('1.0000000000000001e+18', '1000000000000000100')
    response = client.post('/v0.7/events/verify', content='{"event":'+wire+'}', headers={"content-type":"application/json"})
    assert response.status_code == 200
    assert response.json()["status"] == "valid"
    assert response.json()["event_hash"] == original["event_hash"]
    for value in (2**53 + 1, 1000000000000000101, 10**400):
        event = {**original["event"], "what":{"value":value}}
        result = client.post('/v0.7/events/verify', json={"event":event}).json()
        assert result["status"] == "invalid"
