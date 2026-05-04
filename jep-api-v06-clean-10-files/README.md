# JEP v0.6 API Seed

A small FastAPI implementation seed for the Judgment Event Protocol v0.6.

This repository upgrades the earlier JEP-04 API demo into a JEP v0.6-style API seed aligned with:

- `draft-wang-jep-judgment-event-protocol-06`
- `draft-wang-jep-profiles-00`
- `draft-wang-jep-conformance-00`

## Status

This is an implementation seed, not a production security service.

It demonstrates:

- J/D/T/V event creation
- JEP wire version `"1"`
- JEP-Core-0.6 profile labels
- JCS-compatible seed canonicalization
- algorithm-tagged event hashes
- detached JWS Compact Serialization shape
- Ed25519 signing and verification
- `ext` / `ext_crit` extension framework
- TTL and digest-only privacy extensions
- JEP-style validation result object
- separated event storage and nonce consumption

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | API metadata and demo public key |
| `GET /health` | Health check |
| `POST /events/create` | Create and sign a JEP-style event |
| `POST /events/verify` | Verify a JEP-style event |

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Example create request

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

## Validation result shape

```json
{
  "valid": true,
  "level": 1,
  "mode": "archival",
  "profile": "jep-core-0.6",
  "scopes": ["syntax", "cryptographic"],
  "event_hash": "sha256:...",
  "warnings": [],
  "errors": []
}
```

## Boundary

This API does not determine:

- external truth;
- legal liability;
- regulatory compliance;
- authorization validity;
- complete-log availability;
- model correctness.

A valid signature proves protocol-level integrity under the API seed's demo trust context.

## Public drafts

- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- JEP-Profiles: https://datatracker.ietf.org/doc/draft-wang-jep-profiles/
- JEP-Conformance: https://datatracker.ietf.org/doc/draft-wang-jep-conformance/

## Related resources

- JEP v0.6 Repository: https://github.com/hjs-spec/jep-v06
- JEP v0.6 Spec Demo: https://huggingface.co/spaces/yuqiangJEP/jep-v06-spec-demo/tree/main
- JEP v0.6 Conformance Suite: https://huggingface.co/datasets/yuqiangJEP/jep-v06-conformance-suite
