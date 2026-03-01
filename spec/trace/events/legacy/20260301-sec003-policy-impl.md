---
req_id: SEC-003
timestamp: 2026-03-01T04:20:00Z
event: implemented
summary: >
  Added 'policy show/set' subcommand backed by .git-secret-vault-policy.json.
  Supports password_min_length with validation (>= 8). Includes unit tests.
files:
  - src/cli/policy.rs
---
