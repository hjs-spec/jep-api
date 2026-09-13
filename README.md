# JEP-Core-0.6 Reference API

FastAPI implementation for creating and verifying signed J/D/T/V events using RFC 8785 JCS, algorithm-tagged event hashes, and Ed25519 detached JWS.

Protocol profile: `jep-core-0.6`; wire version: `"1"`. The [0.7.3 implementation release](https://github.com/hjs-spec/jep-api/releases/tag/v0.7.3) is versioned separately from the protocol. Live deployment and external database provisioning remain deferred; repository changes do not update hosted services.

## Run locally

With Python 3.10 or newer:

```bash
git clone https://github.com/hjs-spec/jep-api.git
cd jep-api
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open [interactive API documentation](http://127.0.0.1:8000/docs). The default local configuration persists keys, events, and replay state in `.jep-state`; keep that directory to verify earlier events after restarting. For an application example, see the [local quickstart](https://github.com/hjs-spec/jep-quickstart).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | API metadata and current signing public key |
| `GET /.well-known/jwks.json` | Trusted public keys in JWKS format |
| `GET /live` | Process liveness |
| `GET /health` | State and signing-configuration health |
| `POST /events/create` | Create, sign, and store a Core-0.6 event |
| `POST /events/verify` | Verify in archival or acceptance mode |
| `POST /events/verify-legacy` | Explicit historical-format integrity verification |

Production signing and nonce-consuming requests require Bearer authentication. The SDKs/CLI accept API-key options; GitHub Action 0.6.2 uses `jep_api_token`. See [deployment and migration](DEPLOYMENT.md) for PostgreSQL shared state, keyring/Vault signing, key rotation, and compatibility formats. The versioned container is `ghcr.io/hjs-spec/jep-api:0.7.3`.

## Create an event

Submit this body to `POST /events/create`:

```json
{
  "verb": "J",
  "who": "did:example:agent-789",
  "what": {
    "claim": "approve",
    "subject": "demo"
  },
  "aud": "https://api.example.org",
  "ttl_minutes": 30,
  "digest_only_who": false
}
```

The response contains `event`, `event_hash`, and `validation`. To verify it, send the returned event unchanged as `{"event": <returned event>, "mode": "archival"}` to `POST /events/verify`.

## Validation results

A successful archival response has this shape; `event_hash` below is an illustrative digest:

```json
{
  "valid": true,
  "level": 1,
  "mode": "archival",
  "profile": "jep-core-0.6",
  "conformance_class": "JEP-Baseline-Ed25519-JWS-JCS-0.6",
  "scopes": ["syntax", "cryptographic"],
  "event_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "warnings": [
    {
      "code": "ACCEPTANCE_NOT_CHECKED",
      "message": "Historical integrity only; freshness and live authorization were not checked.",
      "level": 1,
      "recoverable": false
    }
  ],
  "errors": []
}
```

Responses follow the [validation result schema](jep-validation-result.schema.json). Diagnostics include `code`, `message`, `level`, and `recoverable`. Core diagnostic codes such as `ERR_MISSING_REQUIRED_FIELD` and `ERR_INVALID_TIMESTAMP` replace the former generic `ERR_SCHEMA_INVALID`. Malformed JSON at `/events/verify` returns HTTP 400 with a structured result and mode `unparsed`. Legacy results use `legacy-integrity-only` and do not assert Core-0.6 conformance.

Archival mode checks historical integrity without applying live freshness or TTL rejection. Acceptance additionally requires `expected_audience`, checks freshness and TTL, and consumes the nonce atomically. Explicit `consume_nonce` also consumes state in archival mode. These checks do not establish actor identity or authority.

## Verification scope

The API reports Level 1 structure and cryptographic checks under its configured trusted keys. It implements TTL and digest-only extensions; unknown critical extensions are rejected. It does not determine external truth, legal liability, regulatory compliance, authorization validity, complete logging, or model correctness.

See [hardening notes](HARDENING.md) for regression coverage and historical changes, and [deployment and migration](DEPLOYMENT.md) for operational requirements. This reference implementation requires deployment-specific trust and security configuration before production use.

## Protocol and related resources

- [Core specification, validators, and test vectors](https://github.com/hjs-spec/jep-v06)
- Public drafts: [Core](https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/) · [Profiles](https://datatracker.ietf.org/doc/draft-wang-jep-profiles/) · [Conformance](https://datatracker.ietf.org/doc/draft-wang-jep-conformance/)
- [Project and resource index](https://github.com/hjs-spec/.github/blob/main/PROJECTS.md)
