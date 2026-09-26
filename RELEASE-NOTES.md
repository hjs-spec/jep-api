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
