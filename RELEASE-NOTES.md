# Software 0.8.7

- Supply the MIT license already declared by the deployment metadata; retain BSD-3-Clause notices for the JEP Core schema and fixture copies.
- Include license texts and scope notices in source releases, container images and the existing deployment bundle.
- Verify distributed license bytes before publishing artifacts.

Runtime behavior and JEP Core 0.7 semantics are unchanged. Existing published artifacts are not overwritten.

# Software 0.8.6

- Accept the Core 0.7 V string-scope and array-scope forms without rewriting signed events.
- Recover creation requests with an explicit caller `id`: the same `who`, `id` and request return the original complete response. Different request content returns HTTP 409 `ERR_CREATE_REQUEST_CONFLICT`.
- Commit the event and recovery response together in SQLite or PostgreSQL; preserve recovery records during database migration and across API restarts and signing-key rotation.
- Document creation and acceptance retries, failure handling and the upgrade boundary. This applies to requests first processed by 0.8.6+; older lost responses cannot be reconstructed.

Creation still does not consume acceptance state or perform a business action. The protocol remains JEP Core 0.7; published drafts and historical signed bytes are unchanged.

# Software 0.8.5

Current Core 0.7 verification now rejects empty extension identifiers and digest
strings with trailing line terminators. The current JWS path validates every
protected-header JSON value for supported finite numbers and well-formed Unicode,
while still verifying the original protected bytes (canonical header JSON is not
required). Explicit historical decoding is unchanged.

Regression tests use real signatures, both archival and acceptance routes, and a
corrected retry with the same Event Identity. Invalid input must not consume
acceptance state. Existing stored events and accepted identities are not rewritten
or reset. The schema copy matches the current Core structural hardening patch.

# Software 0.8.4

Complete the JCS numeric roundtrip repair: accept the canonical shortest decimal spelling of a binary64 number as well as its exact integer value. For example, JavaScript emits `1000000000000000100` for the float whose exact integer value is `1000000000000000128`. Both serialize to the same JCS bytes. Noncanonical precision-losing integers and overflow remain rejected.

Regression coverage includes positive and negative shortest-form numbers, exact large integers, real signatures and unchanged Event Hashes. Published normative artifacts remain unchanged.

# Release 0.8.3

- Read the runtime version from `VERSION` and include it in Docker/HF bundles. The 0.8.2 attempt stopped before publication because its duplicated runtime version was stale; no 0.8.2 release or image was published.
- Preserve JCS signatures when exactly representable large numbers arrive in integer-token form after JavaScript serialization (for example `1e20`). Reject precision-losing integers and keep `when` within its existing interoperable integer range.

Malformed `who` or `id` values were correctly rejected, but some rejection responses copied empty identity members into `event_identity`, violating the advertised result schema.

- Return `event_identity: null` when no well-formed Event Identity is available.
- Validate invalid-event diagnostics against the result schema and verify rejection leaves acceptance state unused.
- Retain the transactional SQLite-to-PostgreSQL acceptance migration repair from 0.8.1.

Software 0.8.3 still implements Core 0.7. Published protocol artifacts and historical signed events are unchanged. Live deployment requires the configured production database and signing provider.
