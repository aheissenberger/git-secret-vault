---
id: 20260301-fr024-verify-impl
req_id: FR-024
timestamp: 2026-03-01T04:00:00Z
kind: implementation
agent: fleet-agent
---
Implemented `verify` command in src/cli/verify.rs. Reads manifest, decrypts each entry, compares SHA-256 hash. Reports ok/corrupt/missing per entry. Supports --json output. Exits with code 1 if any entry fails. Tests pass.
