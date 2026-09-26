# JEP Core 0.7 Reference API

FastAPI reference implementation for JEP Core 0.7, with explicit pre-0.7
compatibility routes.

Current protocol profile: `jep-core-0.7`. Wire major remains `jep: "1"`.

The API deliberately separates current and historical behavior:

| Route | Semantics |
|---|---|
| `POST /v0.7/events/create` | Current JEP Core 0.7 event creation |
| `POST /v0.7/events/verify` | Current 0.7 archival / acceptance verification |
| `POST /events/create` | Legacy pre-0.7 compatibility creation |
| `POST /events/verify` | Legacy pre-0.7 compatibility verification |
| `POST /events/verify-legacy` | Explicit historical-format integrity verification |

No 0.7 failure triggers automatic fallback to a legacy format.

## JEP Core 0.7 behavior

A created 0.7 event contains:

- `jep: "1"`;
- stable `id`;
- `verb`, `who`, `when`, and verb-specific `what`;
- optional `aud`, `ref`, and extensions;
- `sig`.

Core 0.7 creation does **not** add a mandatory nonce.

Event Identity is `(who,id)`. Event Hash remains the digest of the exact
signed artifact.

### Acceptance

Acceptance state is keyed by Event Identity.

First acceptance:

```json
{
  "status": "valid",
  "acceptance": {
    "outcome": "accepted",
    "effect_applied": true
  }
}
```

Safe retry of the same Event Identity and unsigned content:

```json
{
  "status": "valid",
  "acceptance": {
    "outcome": "already_accepted",
    "effect_applied": false
  }
}
```

Reuse of one Event Identity for different unsigned content is rejected with
`ERR_EVENT_ID_CONFLICT`.

### Validation

0.7 responses report independent checks instead of cumulative Validation
Levels.

Core checks include:

- `syntax`
- `cryptographic`
- `event_identity`
- `reference_integrity`
- `extension_processing`

Audience and freshness are optional request/profile checks. Chain and policy
semantics are not defined by this API as Core behavior.

## Run locally

```bash
git clone https://github.com/hjs-spec/jep-api.git
cd jep-api
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`.

The default local configuration persists keys, signed artifacts, legacy nonce
state, and 0.7 Event Identity acceptance state under `.jep-state`.

## Create a 0.7 event

```json
{
  "verb": "J",
  "who": "did:example:agent-789",
  "what": {
    "claim": "approve",
    "subject": "demo"
  }
}
```

Send to `POST /v0.7/events/create`.

The server assigns an `id` unless one is supplied explicitly.

## Verify a 0.7 event

Archival:

```json
{
  "event": { "...": "..." },
  "mode": "archival"
}
```

Acceptance:

```json
{
  "event": { "...": "..." },
  "mode": "acceptance"
}
```

Optional profile-like checks can be requested with `expected_audience` and
`max_age_seconds`.

## Legacy compatibility

The old unversioned routes preserve the previous nonce / Validation-Level
behavior so historical integrations remain reproducible during migration.

They are not the current JEP Core definition.

Historical signed artifacts are never rewritten or re-signed solely to satisfy
0.7.

## State and multi-host deployment

Local development uses SQLite. Production uses PostgreSQL shared state.

The 0.7 acceptance table is independent from the legacy nonce table. This is
intentional:

```text
pre-0.7 replay compatibility -> nonce state
JEP Core 0.7 acceptance      -> (who,id) acceptance state
```

Both paths use transactional state updates.

## Protocol resources

- [JEP Core canonical repository](https://github.com/hjs-spec/jep-core)
- [Published JEP Core draft](https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/)
- [JEP Conformance](https://datatracker.ietf.org/doc/draft-wang-jep-conformance/)
- [JEP Profiles](https://datatracker.ietf.org/doc/draft-wang-jep-profiles/)

See [DEPLOYMENT.md](DEPLOYMENT.md) for operational hardening and `compatibility.py` for
explicit historical integrity verification.

The current schema is synchronized from `hjs-spec/jep-core` revision `da3fca00be456497f2dbfa045a1bc84aa3ce966d`; its published -07 source remains frozen.
