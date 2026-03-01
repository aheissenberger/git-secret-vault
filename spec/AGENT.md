# Agent Working Agreement

## Spec-driven workflow

- Every feature or change must reference a Requirement ID
- Requirements marked Done must have verification evidence
- Do not modify externally visible behavior without updating REQ, TRACE, and ADR as needed

## Requirement layering policy

- Treat domain-level `FR-*` records as umbrella requirements when they summarize multi-clause behavior.
- Prefer atomic `SEC-*` and `NFR-*` records for single security/non-functional clauses from source specs.
- Keep source clause mapping in `acceptance_refs` for both umbrella and atomic records.
- When introducing atomic decomposition, update umbrella `## Notes` with explicit child IDs.
- Do not remove umbrella records when adding atomic records; keep both for navigation and planning.
- Add trace events for any changed requirement-governance docs and keep `spec/TRACE.md` aligned.

## Multi-agent worktree protocol

- Claim requirement ownership via `spec/trace/claims/*-claim-<REQ-ID>.md`
- Keep claims append-only with lifecycle actions: `claim`, `heartbeat`, `release`, `override`
- Append implementation/verification events via `spec/trace/events/*.md`
- Release ownership via a `release` claim event
- Do not proceed on an actively claimed requirement without explicit override policy

## Source-of-truth precedence

- `spec/requirements/<REQ-ID>.md` defines requirement intent
- `spec/DECISIONS/ADR-*.md` defines approved architecture decisions
- `spec/ARCHITECTURE/current-infrastructure.md` + `spec/ARCHITECTURE/ARD-*.md` define system context and constraints
- `spec/trace/events/*.md` are immutable implementation/verification evidence
- `spec/trace/claims/*.md` are immutable ownership/coordination evidence

## Definition of Done

- Tests for the change are created or updated before implementation code is created
- Implementation complete
- Verification added or updated
- TRACE.md updated
- Requirement status updated
- Related ADR added/updated when architecture or behavior decisions changed

## Test-first checklist

- Identify expected behavior and failure modes before touching implementation code.
- Add or update automated tests first; if not feasible, document why and add a manual verification plan.
- Run the new/updated tests and capture evidence in CI or local logs.
- Implement the code change only after tests exist.
- Re-run tests after implementation and include results with the change.

## Repository invariants

- Follow existing architecture and conventions
- Avoid unnecessary dependencies or structural changes
- Preserve backwards compatibility unless explicitly required

## Metadata format guardrails

- Requirement frontmatter `status` must be exactly one of: `Proposed`, `In Progress`, `Done`.
- Never use compact variants such as `InProgress`.
- Trace event frontmatter `timestamp` must be valid UTC RFC3339, e.g. `2026-03-01T15:15:00Z`.
- Use hyphens in the date portion (`YYYY-MM-DD`), never colons (`YYYY:MM:DD`).

## Mandatory pre-commit spec-ledger gate

- Before every commit, agents must run all spec-ledger validation scripts and ensure they pass.
- If requirement files changed, regenerate `spec/requirements/index.md` first using `scripts/spec-ledger/generate-req-index.ts`.
- Do not commit if any of the following scripts fail:
	- `scripts/spec-ledger/validate-req-files.ts`
	- `scripts/spec-ledger/validate-req-index.ts`
	- `scripts/spec-ledger/validate-trace-events.ts`
	- `scripts/spec-ledger/validate-claims.ts`
	- `scripts/spec-ledger/validate-req-trace-coverage.ts`
	- `scripts/spec-ledger/validate-trace-evidence.ts`
	- `scripts/spec-ledger/validate-trace-immutability.ts`
	- `scripts/spec-ledger/validate-architecture-docs.ts`
	- `scripts/spec-ledger/validate-worktree-fresh.ts`
- Recommended one-shot command:
	- `node scripts/spec-ledger/generate-req-index.ts && node scripts/spec-ledger/validate-req-files.ts && node scripts/spec-ledger/validate-req-index.ts && node scripts/spec-ledger/validate-trace-events.ts && node scripts/spec-ledger/validate-claims.ts && node scripts/spec-ledger/validate-req-trace-coverage.ts && node scripts/spec-ledger/validate-trace-evidence.ts && node scripts/spec-ledger/validate-trace-immutability.ts && node scripts/spec-ledger/validate-architecture-docs.ts && node scripts/spec-ledger/validate-worktree-fresh.ts`
