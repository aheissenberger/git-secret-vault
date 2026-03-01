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
