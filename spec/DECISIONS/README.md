# Architecture Decisions

Architecture Decision Records (ADR) capture significant technical or design choices.

Naming convention:
ADR-0001-title.md
ADR-0002-title.md

Current ADR files:

- `ADR-0001-template.md`
- `ADR-0002-git-secret-vault-safety-and-compatibility.md`

## Create or update ADR when

- Architecture changes
- Significant tradeoff is introduced
- Externally visible behavior changes
- Dependency strategy changes

## Linking policy

- Requirement files should reference related ADR IDs
- Trace events with `change_type: decision` should include ADR path under `spec/DECISIONS/`
- TRACE.md rows should include ADR references where relevant
- ARD documents should list related ADR links in `Linked ADRs`
