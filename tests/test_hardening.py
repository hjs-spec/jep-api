import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def signed(**changes):
    event = client.post("/events/create", json={"verb": "J", "what": {}}).json()["event"]
    event.update(changes)
    event.pop("sig")
    event["sig"] = main.detached_jws_sign(event)
    return event


def test_invalid_signature_cannot_poison_replay_cache():
    event = signed()
    forged = dict(event, what={"forged": True})
    assert not main.validate_event(forged, consume_nonce=True)["valid"]
    assert main.validate_event(event, consume_nonce=True)["valid"]
    assert not main.validate_event(event, consume_nonce=True)["valid"]


def test_acceptance_is_atomic_and_requires_audience():
    event = signed()
    assert not main.validate_event(event, mode="acceptance")["valid"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: main.validate_event(event, mode="acceptance", expected_audience=event["aud"]), range(8)))
    assert sum(r["valid"] for r in results) == 1
    assert all(r["valid"] or r["errors"][0]["code"] == "ERR_NONCE_REPLAY" for r in results)


def test_expired_archive_is_valid_but_cannot_be_accepted():
    event = signed(when=int(time.time()) - 86400, ext={main.EXT_TTL: {"expires_at": 100}})
    assert main.validate_event(event)["valid"]
    assert not main.validate_event(event, mode="acceptance", expected_audience=event["aud"])["valid"]


@pytest.mark.parametrize("changes", [{"who": None}, {"when": True}, {"nonce": ""}, {"verb": "D"}, {"unexpected": 1}])
def test_signed_invalid_structure_rejected(changes):
    result = main.validate_event(signed(**changes))
    assert result["valid"] is False
    assert result["errors"][0]["code"] == "ERR_SCHEMA_INVALID"


def test_malformed_header_is_a_validation_error_not_http_500():
    event = signed()
    event["sig"] = main.b64u(b"[]") + "..AA"
    response = client.post("/events/verify", json={"event": event})
    assert response.status_code == 200
    assert response.json()["valid"] is False


@pytest.mark.parametrize("body", ['{"verb":"T","verb":"J","what":{}}', '{"verb":"J","what":{"x":NaN}}'])
def test_ambiguous_json_rejected(body):
    assert client.post("/events/create", content=body, headers={"content-type": "application/json"}).status_code == 400


def test_jcs_number_and_utf16_key_order():
    assert main.jcs_seed({"\ue000": 1.0, "\U0001f600": 1e-7}) == '{"😀":1e-7,"\ue000":1}'.encode()
