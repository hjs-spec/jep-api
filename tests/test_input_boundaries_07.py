"""Signed hostile inputs must fail before changing current acceptance state."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def new_event():
    response = client.post('/v0.7/events/create', json={
        'verb': 'J', 'who': 'did:example:boundary-api', 'id': str(uuid.uuid4()),
        'what': {'claim': 'synthetic test'},
    })
    assert response.status_code == 200
    return response.json()['event']


def sign(event, header=None):
    kid, signing = main.KEYS.snapshot()
    if header is None:
        header = json.dumps({'alg': 'Ed25519', 'kid': kid}).encode('utf-8')
    protected = main.b64u(header)
    unsigned = {k: v for k, v in event.items() if k != 'sig'}
    data = (protected + '.' + main.b64u(main.jcs_seed(unsigned))).encode('ascii')
    return {**unsigned, 'sig': protected + '..' + main.b64u(signing(data))}


def assert_rejected_without_consuming(bad, original, check):
    for mode in ('archival', 'acceptance'):
        response = client.post('/v0.7/events/verify', json={'event': bad, 'mode': mode})
        assert response.status_code == 200
        result = response.json()
        assert result['status'] == 'invalid', result
        assert result['checks'][check] == 'fail'
        if mode == 'acceptance':
            assert result['acceptance'] == {'outcome': 'rejected', 'effect_applied': False}
    first = main.validate_event_07(original, mode='acceptance')
    retry = main.validate_event_07(original, mode='acceptance')
    assert first['acceptance'] == {'outcome': 'accepted', 'effect_applied': True}
    assert retry['acceptance'] == {'outcome': 'already_accepted', 'effect_applied': False}


@pytest.mark.parametrize('patch', [
    {'ext': {'': {}}},
    {'what': 'sha256:' + 'a' * 64 + '\n'},
    {'ref': 'sha256:' + 'a' * 64 + '\n'},
    {'ref': {'type': 'evidence', 'value': 'demo', 'hash': 'other:ab\n'}},
])
def test_schema_rejection_precedes_acceptance(patch):
    original = new_event()
    assert_rejected_without_consuming(sign({**original, **patch}), original, 'syntax')


@pytest.mark.parametrize('suffix', [
    b',"extra":"\\ud800"}', b',"extra":{"\\udfff":true}}',
    b',"extra":1e400}', b',"extra":NaN}',
    b',"extra":1,"extra":2}', b',"extra":{"x":1,"x":2}}',
])
def test_current_header_rejection_precedes_acceptance(suffix):
    original = new_event()
    kid, _ = main.KEYS.snapshot()
    header = json.dumps({'alg': 'Ed25519', 'kid': kid}).encode('utf-8')
    assert_rejected_without_consuming(sign(original, header[:-1] + suffix), original, 'cryptographic')


@pytest.mark.parametrize('encoding', ['utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be'])
def test_non_utf8_header_rejected(encoding):
    original = new_event()
    kid, _ = main.KEYS.snapshot()
    raw = json.dumps({'alg': 'Ed25519', 'kid': kid}).encode(encoding)
    assert_rejected_without_consuming(sign(original, raw), original, 'cryptographic')


def test_noncanonical_but_valid_utf8_header_keeps_original_signature():
    original = new_event()
    kid, _ = main.KEYS.snapshot()
    raw = json.dumps({'extra': {'text': '合法', 'number': 1e20}, 'kid': kid, 'alg': 'Ed25519'},
                     ensure_ascii=False, indent=2).encode('utf-8')
    event = sign(original, raw)
    result = main.validate_event_07(event)
    assert result['status'] == 'valid'
    assert result['event_hash'] == main.event_hash(event)


def test_explicit_legacy_header_parsing_is_not_reinterpreted():
    original = new_event()
    kid, _ = main.KEYS.snapshot()
    raw = json.dumps({'alg': 'Ed25519', 'kid': kid}).encode('utf-8')[:-1] + b',"extra":1e400}'
    event = sign(original, raw)
    assert main.detached_jws_verify(event)[0] is True
    assert main.detached_jws_verify(event, strict_current=True)[0] is False
