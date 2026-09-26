# Release 0.8.2

- Preserve JCS signatures when exactly representable large numbers arrive in integer-token form after JavaScript serialization (for example `1e20`). Reject precision-losing integers and keep `when` within its existing interoperable integer range.

Malformed `who` or `id` values were correctly rejected, but some rejection responses copied empty identity members into `event_identity`, violating the advertised result schema.

- Return `event_identity: null` when no well-formed Event Identity is available.
- Validate invalid-event diagnostics against the result schema and verify rejection leaves acceptance state unused.
- Retain the transactional SQLite-to-PostgreSQL acceptance migration repair from 0.8.1.

Software 0.8.2 still implements Core 0.7. Published protocol artifacts and historical signed events are unchanged. Live deployment requires the configured production database and signing provider.
