# JEP Core 0.7 Reference API

HTTP service for creating signed events, verifying them and maintaining acceptance
state. The service owns the signing key; applications and HTTP clients send requests.

Current profile: `jep-core-0.7`; wire major: `jep: "1"`.

| Route | Use |
|---|---|
| `POST /v0.7/events/create` | Create and sign an event |
| `POST /v0.7/events/verify` | Verify an event in archival or acceptance mode |

## Run locally

```bash
git clone https://github.com/hjs-spec/jep-api.git
cd jep-api
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open [interactive API documentation](http://127.0.0.1:8000/docs).
Local development stores keys, signed records and acceptance state in `.jep-state`.

<a id="create-a-07-event"></a>
<a id="verify-a-07-event"></a>

## Create and verify an event

Keep the API running. Run this Python example in a second terminal; it uses only
the standard library:

```python
import json
from urllib.request import Request, urlopen
from uuid import uuid4

base_url = "http://127.0.0.1:8000"

def post(path, payload):
    request = Request(base_url + path, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        return json.load(response)

create_request = {
    "id": "urn:uuid:" + str(uuid4()),
    "verb": "J",
    "who": "did:example:agent-789",
    "what": {"claim": "approve", "subject": "demo"},
}
created = post("/v0.7/events/create", create_request)
verified = post("/v0.7/events/verify", {
    "event": created["event"],
    "mode": "archival",
})
print(verified["status"], verified["checks"]["cryptographic"])
print(verified["event_hash"])
```

Expect `valid pass` followed by the Event Hash. The server assigns an `id` unless
you supply one. For language-specific clients, use the [HTTP Quickstart](https://github.com/hjs-spec/jep-quickstart).

## Recover a creation request

With API **0.8.6+**, choose an `id` once per logical operation and retain the
complete request before sending it. After a timeout or HTTP 503, resend that
unchanged request to the same deployment. It returns the original event,
signature, Event Hash and creation-time validation result, even after a restart
or signing-key rotation. It does not renew the timestamp or expiry; verify again
when you need current freshness or acceptance checks.

The same caller `who` and `id` with different request content returns HTTP 409
with `detail.code: ERR_CREATE_REQUEST_CONFLICT`. Stop and reconcile the original
request; changing the `id` would create a separate event. Without a caller-supplied
`id`, each successful creation is new. Requests first processed by an older API
cannot be recovered through this mechanism; retain any original signed event.

This recovery depends on preserving the database. Creation records and events
are saved together in SQLite or PostgreSQL; creating an event does not accept it
or execute an application action.

<a id="jep-core-07-behavior"></a>

## Validation

Read `status` (`valid`, `invalid` or `indeterminate`), the individual `checks`,
and any `errors`. A passing signature verifies integrity under the selected key;
the caller's claimed identity and authority need application trust policy.

`mode: "archival"` verifies without changing acceptance state. Request audience
or freshness checks explicitly with `expected_audience` or `max_age_seconds`.

## Acceptance

`mode: "acceptance"` also records a decision keyed by Event Identity `(who,id)`.

| Request | Outcome |
|---|---|
| First valid acceptance | `accepted`, `effect_applied: true` |
| Same identity and unsigned content again | `already_accepted`, `effect_applied: false` |
| Same identity with different unsigned content | Rejected with `ERR_EVENT_ID_CONFLICT` |

After an acceptance response is lost, resend the **original signed event**.
An `already_accepted` result confirms the stored acceptance decision; it does not
prove that your separate business action completed. Reconcile that action in
your application before retrying it.

For a failed signature, stop and check the original bytes and selected trusted
key. For `ERR_KEY_UNRESOLVED`, obtain trusted verification material before
continuing. For `ERR_ACCEPTANCE_STATE_UNAVAILABLE`, retry the same event after
storage recovers; do not treat an indeterminate result as acceptance.

## State and multi-host deployment

Use SQLite for local development and shared PostgreSQL state for multiple API
replicas. [Deployment instructions](DEPLOYMENT.md) cover signing keys,
authenticated signing/acceptance access, TLS, rotation and database migration.

## Legacy compatibility

Select these routes only for known historical formats:

| Route | Use |
|---|---|
| `POST /events/create` | Pre-0.7 compatibility creation |
| `POST /events/verify` | Pre-0.7 compatibility verification |
| `POST /events/verify-legacy` | Integrity verification with an explicit historical format |

A failed 0.7 verification never selects a legacy decoder automatically. Preserve
historical signed bytes; see [historical formats](DEPLOYMENT.md#historical-formats).

## Protocol resources

- [Core contract and specification sources](https://github.com/hjs-spec/jep-core#current-contract)
- [Current event schema](https://github.com/hjs-spec/jep-core/blob/main/schemas/jep-event.schema.json)
- [Contributing and private security reports](https://github.com/hjs-spec/.github/blob/main/CONTRIBUTING.md)
