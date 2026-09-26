# Release 0.8.0

This software release publishes the JEP Core 0.7 API migration. Software version 0.8.0 does not introduce a Core 0.8 protocol.

- Current `/v0.7/events/*` endpoints use stable Event Identity `(who,id)`, independent checks and idempotent acceptance.
- Unresolved verification keys return indeterminate without consuming acceptance state.
- The current schema follows the repaired Core 0.7 reference schema, including ASCII identifiers and digest constraints.
- Recognized TTL and digest-only extensions are validated; expired TTL blocks live acceptance without preventing archival verification.
- Docker and Hugging Face packages include both current and explicit legacy schemas. Container startup, health, version and revision are checked before registry upload.
- Unversioned pre-0.7 endpoints and historical decoders remain explicit. There is no automatic legacy fallback.

The service is an experimental reference implementation. Live Hugging Face deployment requires the existing production storage/signing configuration and is verified separately from source/container release.
