---
id: 20260301-fr022-passwd-impl
req_id: FR-022
timestamp: 2026-03-01T04:00:00Z
kind: implementation
agent: fleet-agent
---
Implemented `passwd` command in src/cli/passwd.rs. Re-encrypts vault with a new password atomically (read all entries with old password, rewrite with new password, update index marker). Supports --rotate checklist output. Tests pass.
