# ADR-0002 SafeZipVault Safety and Compatibility Constraints

## Status

Proposed

## Context

SafeZipVault has two non-negotiable product constraints:

1. Max-safety defaults to reduce accidental plaintext exposure and unsafe extraction behavior.
2. Vault artifacts remain standards-compatible encrypted ZIP files decryptable by common unzip tools supporting the selected encryption profile.

The requirement split in this repository (`FR-002` through `FR-028`) needs a stable architectural decision reference for these constraints.

## Decision

Adopt the following architecture-level constraints:

- Keep encrypted ZIP as the canonical vault container format.
- Implement encrypt/decrypt behavior internally for deterministic cross-platform CLI behavior.
- Keep metadata minimization as default posture (encrypted in-vault manifest plus minimal outer index without filenames/paths).
- Preserve strong operational guardrails: conflict handling, filesystem safety checks, drift controls, and hardening workflows.
- Retain cross-platform keyring support as required product scope.

## Consequences

Positive:

- Interoperability with common unzip tooling is preserved.
- Safety defaults reduce common operational footguns.
- Requirement-to-architecture traceability becomes explicit.

Negative:

- Implementation/testing complexity increases across platforms.
- Compatibility validation and release discipline become mandatory.

Neutral:

- Some controls remain best-effort due to OS/runtime limitations.

## Requirement Links

- FR-002
- FR-003
- FR-005
- FR-006
- FR-007
- FR-018

## Trace Links

- spec/trace/events/2026-03-01T12-20-01Z-copilot-agent-FR-018.md
