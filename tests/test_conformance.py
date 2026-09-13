"""Regression gate against the public core 0.6 event/result contracts."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

import main
from keys import KeyManager, KeyUnavailable
from state import LocalState

FIXTURES = Path(__file__).parent / "fixtures/core-v06"
CASES = json.loads((FIXTURES / "test-manifest.json").read_text())["cases"]
RESULT_SCHEMA = Draft202012Validator(json.loads(
    (Path(main.__file__).parent / "jep-validation-result.schema.json").read_text()))
client = TestClient(main.app)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_official_event_vectors(case, monkeypatch):
    keys = json.loads((FIXTURES / case["keys"]).read_text())
    monkeypatch.setattr(main.STATE, "public_keys", lambda: keys)
    # Preserve duplicate members; json= would silently remove the negative case.
    raw = (FIXTURES / case["path"]).read_text()
    response = client.post("/events/verify", content='{"mode":"archival","event":' + raw + '}',
                           headers={"content-type": "application/json"})
    assert response.status_code == (400 if case["name"] == "duplicate-member" else 200)
    result = response.json()
    RESULT_SCHEMA.validate(result)
    assert result["valid"] == case["expected_valid"]
    assert result["level"] == case["expected_level"]
    if case["expected_valid"]:
        assert result["event_hash"] == case["expected_event_hash"]
    else:
        assert case["expected_error"] in [e["code"] for e in result["errors"]]


def created():
    response = client.post("/events/create", json={"verb": "J", "what": {"claim": "metadata"}})
    assert response.status_code == 200
    RESULT_SCHEMA.validate(response.json()["validation"])
    return response.json()["event"]


@pytest.mark.parametrize("changes,code", [
    ({"kty": "EC"}, "ERR_ALG_KEY_TYPE_MISMATCH"),
    ({"crv": "P-256"}, "ERR_ALG_KEY_TYPE_MISMATCH"),
    ({"alg": "ES256"}, "ERR_ALG_PROFILE_MISMATCH"),
    ({"use": "enc"}, "ERR_PROHIBITED_SIGNATURE_ALG"),
    ({"key_ops": ["sign"]}, "ERR_PROHIBITED_SIGNATURE_ALG"),
    ({"key_ops": ["verify", "verify"]}, "ERR_PROHIBITED_SIGNATURE_ALG"),
    ({"key_ops": "verify"}, "ERR_PROHIBITED_SIGNATURE_ALG"),
    ({"key_ops": [{}]}, "ERR_PROHIBITED_SIGNATURE_ALG"),
    ({"kid": "another-key"}, "ERR_KEY_UNRESOLVED"),
    ({"x": None}, "ERR_ALG_KEY_TYPE_MISMATCH"),
    ({"x": "AA"}, "ERR_ALG_KEY_TYPE_MISMATCH"),
])
def test_resolver_metadata_cannot_bypass_signature_policy(monkeypatch, changes, code):
    event = created()
    keys = main.STATE.public_keys()
    kid = json.loads(main.b64u_decode(event["sig"].split(".")[0]))["kid"]
    keys[kid] = dict(keys[kid], **changes)
    monkeypatch.setattr(main.STATE, "public_keys", lambda: keys)
    result = client.post("/events/verify", json={"event": event}).json()
    RESULT_SCHEMA.validate(result)
    assert result["valid"] is False and result["level"] == 0
    assert result["errors"][0]["code"] == code


@pytest.mark.parametrize("kid", [None, [], {}, 1, ""])
def test_invalid_header_kid_is_not_http_500(kid):
    event = created()
    event["sig"] = main.b64u(main.jcs_seed({"alg": "Ed25519", "kid": kid})) + "..AA"
    response = client.post("/events/verify", json={"event": event})
    assert response.status_code == 200
    assert response.json()["errors"][0]["code"] == "ERR_SIGNATURE_CONTAINER_INVALID"


def test_acceptance_and_legacy_failures_have_complete_results():
    event = created()
    result = client.post("/events/verify", json={"event": event, "mode": "acceptance",
                                               "expected_audience": event["aud"]}).json()
    RESULT_SCHEMA.validate(result)
    assert result["valid"] and result["warnings"] == []
    result = client.post("/events/verify-legacy", json={"event": {}, "format": "hf-space-v06"}).json()
    RESULT_SCHEMA.validate(result)
    assert result["conformance_class"] == "legacy-integrity-only"
    assert result["profile"] != main.JEP_CORE_PROFILE


@pytest.mark.parametrize("metadata", [{"alg": "ES256"}, {"use": "enc"}, {"key_ops": ["sign"]}])
def test_keyring_rejects_restrictions_before_sanitizing(tmp_path, monkeypatch, metadata):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from keys import b64, public
    private = Ed25519PrivateKey.generate()
    key = public("test-key", private.public_key().public_bytes_raw())
    key.update(d=b64(private.private_bytes_raw()), **metadata)
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({"active_kid": "test-key", "keys": [key]}))
    path.chmod(0o600)
    monkeypatch.setenv("JEP_KEYRING_FILE", str(path))
    with pytest.raises(KeyUnavailable):
        KeyManager(LocalState(tmp_path / "state"))
