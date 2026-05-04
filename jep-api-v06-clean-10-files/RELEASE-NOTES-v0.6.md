# JEP API v0.6 Release Notes

## Summary

This release upgrades the earlier JEP-04 API demo into a JEP v0.6 API seed.

## Added

- JEP-Core-0.6 profile labeling.
- JEP wire version `"1"`.
- JEP-style event object.
- Detached JWS Compact Serialization shape.
- Ed25519 signing and verification.
- JCS-compatible seed canonicalization.
- Algorithm-tagged event hash.
- `ext` / `ext_crit` support.
- TTL extension under `https://jep.org/ttl`.
- Digest-only privacy extension under `https://jep.org/priv/digest-only`.
- JEP-style validation result object.
- Replay cache separation.
- Tests and CI workflow.

## Changed

- Replaces JEP-04 README and API language with JEP v0.6 terminology.
- Moves TTL semantics from a top-level field into the extension framework.
- Avoids replacing `who` with digest-only identity by default.

## Boundary

This is an API seed and demo implementation. It does not claim full production conformance or full trust-profile coverage.
