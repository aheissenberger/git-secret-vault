# ARD-0001 System Context

## Status

Accepted

## Purpose

Provide a stable architecture baseline so agents can reason about GitSecretVault implementation and process constraints without reverse-engineering details.

## Runtime and Toolchain

- Primary language/runtime: Rust toolchain (stable)
- Supporting runtime: Node.js 25.x for spec-ledger validation and generation scripts
- Package manager usage: minimal; scripts execute directly via shebang

## Topology

- CLI source under `src/`
- Requirement source of truth under `spec/requirements/`
- Trace history under `spec/trace/events/`
- Ownership claims under `spec/trace/claims/`
- Architecture references under `spec/ARCHITECTURE/`
- Decision records under `spec/DECISIONS/`

## Interface Boundaries

- Requirement records define expected behavior and acceptance criteria
- ADRs define architecture-level constraints and decisions
- Trace events/claims define immutable proposal, implementation, and ownership history

## Linked ADRs

- spec/DECISIONS/ADR-0001-template.md
- spec/DECISIONS/ADR-0002-git-secret-vault-safety-and-compatibility.md

## Requirement Links

- FR-001
- FR-002
- FR-003
- FR-004
- FR-005
- FR-006
- FR-007
- FR-008
- FR-009
- FR-010
- FR-011
- FR-012
- FR-013
- FR-014
- FR-015
- FR-016
- FR-017
- FR-018
- FR-019
- FR-020
- FR-021
- FR-022
- FR-023
- FR-024
- FR-025
- FR-026
- FR-027
- FR-028
- SEC-001
- SEC-002
- SEC-003
- SEC-004
- SEC-005
- SEC-006
- SEC-007
- SEC-008
- SEC-009
- SEC-010
- SEC-011
- SEC-012
- NFR-001
- NFR-002
- NFR-003
- NFR-004
- NFR-005
- NFR-006
- NFR-007
- NFR-008
- NFR-009
- NFR-010
- NFR-011
- NFR-012
- NFR-013
- NFR-014
