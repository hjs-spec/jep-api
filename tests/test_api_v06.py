from fastapi.testclient import TestClient

from main import app, EXT_TTL, EXT_DIGEST_ONLY

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_create_j_event():
    r = client.post("/events/create", json={
        "verb": "J",
        "who": "did:example:agent-789",
        "what": {"claim": "approve", "subject": "demo"},
        "aud": "https://api.example.org",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["event"]["jep"] == "1"
    assert data["event"]["verb"] == "J"
    assert data["event"]["sig"].count(".") == 2
    assert data["event_hash"].startswith("sha256:")
    assert data["validation"]["valid"] is True


def test_verify_created_event():
    created = client.post("/events/create", json={
        "verb": "J",
        "who": "did:example:agent-789",
        "what": "sha256:" + "a" * 64,
    }).json()
    r = client.post("/events/verify", json={"event": created["event"], "mode": "archival"})
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True
    assert data["profile"] == "jep-core-0.6"


def test_ttl_extension_is_under_ext():
    created = client.post("/events/create", json={
        "verb": "J",
        "what": {"claim": "approve"},
        "ttl_minutes": 30
    }).json()
    event = created["event"]
    assert EXT_TTL in event["ext"]
    assert EXT_TTL in event["ext_crit"]
    assert "ttl" not in event


def test_digest_only_extension_does_not_replace_who():
    created = client.post("/events/create", json={
        "verb": "J",
        "who": "did:example:human-123",
        "what": {"claim": "approve"},
        "digest_only_who": True
    }).json()
    event = created["event"]
    assert event["who"] == "did:example:human-123"
    assert EXT_DIGEST_ONLY in event["ext"]
    assert "who_digest" in event["ext"][EXT_DIGEST_ONLY]


def test_unknown_critical_extension_rejected():
    created = client.post("/events/create", json={
        "verb": "J",
        "what": {"claim": "approve"},
        "ext": {"https://unknown.example/ext": {"required": True}},
        "ext_crit": ["https://unknown.example/ext"]
    }).json()
    event = created["event"]
    r = client.post("/events/verify", json={"event": event})
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is False
    assert data["errors"][0]["code"] == "ERR_UNKNOWN_CRITICAL_EXTENSION"
