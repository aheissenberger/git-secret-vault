# Exit Code Reference

All CLI commands return one of the following exit codes:

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | General error (bad password, file not found, decryption failure, dirty vault, stale vault, failed doctor checks, etc.) |

## Notes

- `status --fail-if-dirty` exits `1` when any tracked entry differs from the vault.
- `lock --check` exits `1` when a tracked file's local hash does not match the vault.
- `doctor` exits `1` when one or more environment checks fail (use `--json` for machine-readable output).
- There are no reserved codes above `1`; all error conditions map to exit code `1`.
