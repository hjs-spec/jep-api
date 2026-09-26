# Release 0.7.3

JEP Core 0.7 is the current default API contract.

- Current creation and verification are exposed under `/v0.7/events/*`.
- Current events use stable `id`; Core does not require a top-level nonce.
- Event Identity is `(who,id)`; Event Hash identifies the exact signed artifact.
- Validation returns `status`, independent `checks`, `event_identity`, and optional `acceptance`.
- First acceptance and safe retry distinguish `accepted` from `already_accepted`.
- Conflicting reuse of one Event Identity is rejected.
- Historical pre-0.7 endpoints remain explicit and retain their historical nonce/level behavior.
- A failed 0.7 validation is never used as a signal to silently retry a legacy decoder.
- Resolved JWK metadata is validated before signature verification.
- Duplicate JSON members and malformed detached JWS inputs are rejected.

The service remains an experimental reference implementation rather than a production trust service.
