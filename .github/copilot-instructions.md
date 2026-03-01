# Project Guidelines

## Code Style
- Primary language is Rust (tooling preconfigured in [.devcontainer/devcontainer.json](../.devcontainer/devcontainer.json)).
- Prefer idiomatic Rust with `cargo fmt` formatting and `clippy`-clean code.
- Keep modules focused and small; avoid one-letter variable names.

## Architecture
- This repository is currently a blank workspace and does not yet define crate boundaries.
- Start with a single crate unless requirements explicitly need a workspace with multiple crates.
- If introducing multiple crates later, keep shared contracts in a dedicated library crate.

## Build and Test
- If no crate exists yet, initialize one in repo root: `cargo init --vcs none`.
- Install deps (if any): `cargo fetch`.
- Build: `cargo build`.
- Test: `cargo test`.
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`.
- Format check: `cargo fmt --all -- --check`.

## Project Conventions
- Keep config and automation minimal until real requirements exist.
- Add new tooling only when there is code that benefits from it.
- Prefer explicit `Result` error handling over panics in non-test code.

## Integration Points
- Development runs inside the devcontainer image: `mcr.microsoft.com/devcontainers/rust:1-1-bullseye`.
- VS Code extensions expected in container: Rust Analyzer, LLDB, TOML support.

## Security
- Do not commit secrets, private keys, or `.env` files containing credentials.
- Prefer environment variables for runtime secrets and keep sample values in docs only.

## Requirement and Decision Process
- Use spec ledger files under `spec/`.
- Keep one requirement file per ID with fixed frontmatter in `spec/requirements/*.md`.
- Treat `spec/requirements/index.md` as generated output and read-only in PRs.
- All agent changes must reference a Requirement ID.
- Add append-only trace event files for requirement-related changes in `spec/trace/events/`.
- Add append-only claim lifecycle files (`claim`/`heartbeat`/`release`/`override`) in `spec/trace/claims/` for requirement ownership.
- Update `spec/TRACE.md` for requirement-to-implementation mapping.
- Create or update ADRs under `spec/DECISIONS/` for significant design and architecture decisions.
- Keep `spec/ARCHITECTURE/current-infrastructure.md` current for agent onboarding.
- Never mark requirements `Done` without verification evidence.
- Do not change externally visible behavior without corresponding REQ/TRACE/ADR updates.
- Keep worktrees fresh against `main`; stale worktrees must rebase before merge.
