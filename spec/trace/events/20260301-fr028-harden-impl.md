---
id: 20260301-fr028-harden-impl
req_id: FR-028
timestamp: 2026-03-01T04:00:00Z
kind: implementation
agent: fleet-agent
---
Implemented `harden` command in src/cli/harden.rs. Updates .gitignore to add *.env, *.key, *.pem, *.secret (only if missing). Optionally installs .git/hooks/pre-commit that runs `git-secret-vault lock --check`. Supports --dry-run. Tests pass.
