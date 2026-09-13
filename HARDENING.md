# Implementation hardening — September 2026

Prevent false acceptance, replay-cache poisoning and digest-only identity leakage.

## Changes

RFC 8785 and the pinned v0.6 schema check precede verification. Duplicate JSON names and malformed headers are rejected. The signing key identifier must resolve to the configured demo key. Critical extensions must have implemented handlers. Digest-only replaces plaintext who. Invalid creates return HTTP 422 and are not stored. Nonces are consumed atomically only after all checks pass.

## Validation

```sh
PYTHONPATH=. python -m pytest -q
```

## Compatibility and remaining limits

Acceptance now requires expected_audience and automatically consumes scoped nonces. The acceptance window is 300 seconds with 30 seconds future skew. Archival mode checks historical integrity without applying live freshness/TTL rejection; consume_nonce remains an explicit archival opt-in with a bounded cache. Keys, events and replay state now use a local transactional SQLite store; see the persistence notes below. The copied schema is synchronized with the accompanying jep-v06 conformance repair. Unknown JAC/HJS critical extensions are rejected until real handlers exist.

## Durable API state and schema alignment

The API persists its signing seed, signed events, and consumed nonces in SQLite under JEP_STATE_DIR (default `.jep-state`). Reuse the same directory across local workers and restarts. Transactions serialize nonce consumption and key initialization; failed storage never produces an accepted verification. The database is private to the service account. Back up this directory, protect its signing seed, or migrate using manage.py and configure the implemented PostgreSQL and external keyring/Vault providers for multiple hosts; see DEPLOYMENT.md.

Creation is checked against the same schema shipped by the conformance repair and Action. Empty/null claims and malformed sha256 digests are rejected. Signed member presence remains significant during verification. Input must be UTF-8 without duplicate JSON members. Acceptance requires expected_audience and consumes a nonce after all checks; historical verification does not imply live authority.

Existing in-memory demo keys cannot be recovered after restart. Preserve any already exported public keys for historical verification through the standalone validator. Do not expose this signing API as an authenticated identity or IAM service: caller-provided who is a claim and results declare Level 1 only.

Tests cover persistent keys, multiple SQLite connections, nonce poisoning, privacy, malformed input, and expiry. The cross-repository harness additionally restarts a real API process and verifies previous signatures/replay state.

Shared event schema SHA-256: `5d0527c1649bd49f0de632e660eff46096522ea76a49eb7104ac83522614059f`.

Release 0.7.2 adds 29 API regression checks in CI, including two independent processes with real PostgreSQL, a single winner for concurrent nonce consumption, key rotation history, authenticated signing and explicit legacy verification. Vault request behavior is tested with a protocol mock; a live Vault deployment still requires its own configured endpoint and credentials.
