# Requirements

This file is a human-oriented mirror and migration entrypoint.

## Migration Notes

- Preserve all legacy `REQ.md` content and meaning.
- Normalize each requirement into `spec/requirements/<REQ-ID>.md`.
- If legacy structure is unclear, preserve source wording under `## Notes`.
- Do not mark `Done` without verification evidence.

## Test-first policy (NFR-015)

- Define expected behavior and failure modes before implementation changes.
- Create or update automated tests before implementation code is created.
- If automated tests are not feasible, document rationale and a manual verification plan in the change record.
- Re-run tests after implementation and attach evidence in CI or equivalent logs.

## Legacy Content

Paste or move original requirement content here during migration if needed.

## Migration Snapshot

- GitSecretVault source specification has been normalized into repository-native records under `spec/requirements/`.
- First split pass created `FR-002` through `FR-018` as domain-grouped requirements.
- Second split pass added finer command-focused records `FR-019` through `FR-028`.
- Third split pass added atomic security/non-functional records `SEC-001` through `SEC-012` and `NFR-001` through `NFR-014`.
- Follow-up split added `NFR-015` to require test-first delivery behavior.
- Source IDs from the provided spec are retained via `acceptance_refs` for traceability.
- Domain-level FR records are treated as umbrella requirements with explicit atomic decomposition notes.

