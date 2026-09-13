# Implementation hardening — September 2026

Prevent false acceptance, replay-cache poisoning and digest-only identity leakage.

## Changes

RFC 8785 and the pinned v0.6 schema check precede verification. Duplicate JSON names and malformed headers are rejected. The signing key identifier must resolve to the configured demo key. Critical extensions must have implemented handlers. Digest-only replaces plaintext who. Invalid creates return HTTP 422 and are not stored. Nonces are consumed atomically only after all checks pass.

## Validation

```sh
PYTHONPATH=. python -m pytest -q
```

## Compatibility and remaining limits

Acceptance now requires expected_audience and automatically consumes scoped nonces. The acceptance window is 300 seconds with 30 seconds future skew. Archival mode checks historical integrity without applying live freshness/TTL rejection; consume_nonce remains an explicit archival opt-in with a bounded cache. Keys, events and replay state are still process-local demo state, unsuitable for multi-worker production. The copied schema is from hjs-spec/jep-v06 at 53caea1091f677e2020b7d6b5f0c00ea9b4b11e2. Unknown JAC/HJS critical extensions are rejected until real handlers exist.
