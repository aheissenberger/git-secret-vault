# Architecture Reference

This directory captures stable infrastructure context that agents and humans should consult before implementation.

## Include

- `current-infrastructure.md` for runtime, topology, boundaries, and ownership
- `ARD-*.md` for architecture reference docs
- Links to relevant ADR files under `spec/DECISIONS/`
- Links to requirement IDs that define architecture constraints

## Policy

- Keep documents concise and current
- Link requirement IDs and ADR IDs when architecture changes
- Prefer additive updates to preserve historical context
- Keep architecture docs consistent with `spec/requirements/index.md` and `spec/TRACE.md`
- Requirement layering convention is defined in `spec/AGENT.md` under `## Requirement layering policy`
