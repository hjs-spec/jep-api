# Release 0.7.1

Includes PostgreSQL shared state, external keyring/Vault signing, retained key history and explicit legacy verification from 0.7.0. Metadata now uses one signing-key snapshot during rotation, so its current public key is never omitted. Deployment verifies the release version from VERSION. See DEPLOYMENT.md.
