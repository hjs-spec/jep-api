# Release 0.7.2

Includes PostgreSQL shared state, external keyring/Vault signing, retained key history and explicit legacy verification. State-changing verification now requires the configured API Bearer token, preventing anonymous nonce consumption. Read-only archival verification remains public. Metadata uses one key snapshot during rotation. See DEPLOYMENT.md.
