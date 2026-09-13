# API 0.7 deployment and compatibility

Wire version remains `1` / JEP-Core-0.6. No business semantics were added.

## Multiple hosts

All API replicas use the same PostgreSQL database (`JEP_DATABASE_URL` or `JEP_DATABASE_URL_FILE`). Unique constraints and transactional upserts consume each actor/audience/nonce once across replicas. PostgreSQL must be private, durable, backed up and configured with TLS (`sslmode=verify-full` for remote connections). Hosts require synchronized clocks. The application connection timeout and statement/lock timeouts are bounded at 10 seconds. A database outage fails verification closed.

Use `JEP_DEPLOYMENT_MODE=production`. Startup then requires PostgreSQL, an external signing provider and `JEP_SIGNING_TOKEN_FILE`. `POST /events/create` and verification requests that consume a nonce (acceptance mode or explicit `consume_nonce`) require that Bearer token. Archival verification without consumption stays read-only and public. This prevents anonymous callers from consuming a published event before its intended receiver. This authenticates access to the signer; it does not certify a caller's claimed `who` identity. Ingress must provide TLS. Do not expose the signing endpoint to anonymous internet callers.

`deploy/compose.yml` accepts existing secret files and a deployed commit SHA. Bind-mounted files must be readable by UID 1000; the private keyring must have mode 0400 or 0600. Compose file secret mode settings do not replace the host file's ownership/mode. Use an existing PostgreSQL service and your load balancer; scale API replicas without sharing a local volume. `/live` is liveness; `/health` checks state and signing configuration. Metadata includes version/revision. JWKS are at `/.well-known/jwks.json`.

## Keys and rotation

Select one provider:

- `JEP_KEYRING_FILE`: private JSON `{ "active_kid": "unique-key-id", "keys": [JWK] }`; each JWK has `kid`, `kty: OKP`, `crv: Ed25519`, `x`, and the active key's `d`, all base64url without padding. Provision with `python manage.py generate-key /private/keyring.json --kid service-key-2026-01`. Distribute through your existing secret manager. Replace the whole file atomically on rotation. Never reuse a `kid` for different key material.
- Vault Transit: `JEP_VAULT_ADDR` (HTTPS), `JEP_VAULT_TOKEN_FILE` (renewed by Vault Agent), `JEP_VAULT_KEY`, `JEP_VAULT_KID_PREFIX`; optionally `JEP_VAULT_MOUNT`, `JEP_VAULT_NAMESPACE`, `JEP_VAULT_CACERT`. Use a non-derived `ed25519` key. The token only needs read on its key metadata and update on its sign path. Private signing material remains in Vault. The application pins the version for each sign request and verifies the returned signature. [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit).

Public key history is retained in PostgreSQL across rotations, so an old signature can still be verified after new keys become active. Deploy the new key to all replicas before retiring its secret version. A missing/corrupt provider never falls back to a generated key. Key revocation policy belongs to the deployment trust layer and is not inferred from deletion of private key material.

## Upgrade from SQLite

1. Pause API writes and acceptance consumers. Back up the complete existing state directory.
2. Run `python manage.py export-key /existing/state /private/keyring.json` to retain the current signing identity. This refuses to overwrite files or invent a missing historical key.
3. Run `python manage.py migrate-postgres /existing/state --database-url-file /private/database-url`. It copies events, trusted public keys and nonce expiries transactionally. It preserves the greatest expiry on retries; it never copies private keys into PostgreSQL.
4. Configure PostgreSQL, keyring and signing authentication on the replicas. Check health, an archived signature and rejection of a previously consumed nonce before reopening traffic. Do not fall back to the old SQLite snapshot after PostgreSQL accepts new events.

## Historical formats

`POST /events/verify-legacy` requires an explicit `format` and `event`:

- `json-sorted-v1`: the historical sorted Python JSON detached-JWS representation, including Agent Blackbox archives.
- `hf-space-v06`: the earlier Hugging Face API representation. Produced events omitted null fields; later unsigned null insertions are rejected.

Trusted historical public keys must be provisioned in the external keyring (public entries need no `d`). No keys are trusted from an event. The response is archival-only with `legacy_signature_integrity`; it does not assert current baseline conformance, acceptance, actor binding, or business truth. There is no automatic legacy fallback or re-signing. JEP-04 embedded-JWS SDK archives and Claude replay packs continue through their existing named SDK/CLI verifiers; they are not detached-JWS events.

The old HF demo generated a private key at every process start and exposed no public-key export endpoint. Keys already lost on restart cannot be reconstructed. Existing independently retained public keys can be imported; otherwise historical verification returns `ERR_KEY_UNRESOLVED`.

## Hugging Face target

Existing Space: `yuqiangJEP/jep-api`, https://yuqiangjep-jep-api.hf.space.
The deployment workflow requires a write-scoped `HF_TOKEN` stored as a GitHub Actions secret and Space secrets configured for external state/keys. It verifies a matching deployed revision after upload. The configured deployment must pass its health probe; merely uploading files is not counted as a successful deployment. A multi-host PostgreSQL/Vault service is not provisioned by the free demo Space itself.

Space configuration: set variable `JEP_DEPLOYMENT_MODE=production`; set secrets `JEP_DATABASE_URL`, `JEP_KEYRING_JSON`, and `JEP_SIGNING_TOKEN` (or Vault variables and `JEP_VAULT_TOKEN`). The container entrypoint materializes secrets into mode-0600 files without printing them. Keep persistent public-key and replay history in PostgreSQL.
