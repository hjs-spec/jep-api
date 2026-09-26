# Release 0.8.1

Preserve Core 0.7 acceptance decisions when moving from SQLite to PostgreSQL.

- Migration now copies accepted Event Identities, payload digests, original artifact hashes and acceptance times in the same transaction as other state.
- Repeating migration keeps existing matching decisions. An identity already accepted with different content aborts and rolls back the import.
- Historical databases without the 0.7 acceptance table remain supported.
- Real PostgreSQL regression tests cover retry, conflict, rollback and legacy migration.
- Deployment documentation now describes current `/v0.7` routes, release-triggered deployment and separate source/container/live delivery status.

Software 0.8.1 still implements Core 0.7. Published protocol artifacts and historical signed events are unchanged. Live deployment still requires the configured production database and signing provider.
