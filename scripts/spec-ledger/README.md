# Spec Ledger Scripts

These scripts are deterministic and read-only validators/generators.

Run directly via shebang (no build step needed).

## Suggested commands

Scripts are executable via shebang—no `node` prefix needed:

- `scripts/spec-ledger/validate-req-index.ts`
- `scripts/spec-ledger/validate-req-files.ts`
- `scripts/spec-ledger/validate-trace-events.ts`
- `scripts/spec-ledger/validate-claims.ts`
- `scripts/spec-ledger/validate-architecture-docs.ts`
- `scripts/spec-ledger/validate-trace-immutability.ts`
- `scripts/spec-ledger/validate-req-trace-coverage.ts`
- `scripts/spec-ledger/validate-trace-evidence.ts`
- `scripts/spec-ledger/validate-worktree-fresh.ts`
- `scripts/spec-ledger/generate-req-index.ts`
- `scripts/spec-ledger/allocate-req-id.ts`

(On Windows or if needed: `node scripts/spec-ledger/<script>.ts`)

## Design constraints

- Do not mutate source files during validation.
- Fail fast with actionable path + reason output.
- Cap detailed failures to first 20 and print summary count.

## TypeScript IDE support (optional)

For full VS Code IntelliSense and type checking, install Node type definitions:

```bash
npm install --save-dev @types/node
```

This is optional—scripts execute perfectly with `node` without any build step or installed types. The `tsconfig.json` in the template root enables type checking when types are available.
