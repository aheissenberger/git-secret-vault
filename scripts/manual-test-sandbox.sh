#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${GSV_KEYRING_SESSION_ACTIVE:-0}" != "1" ]]; then
  exec "$SCRIPT_DIR/run-with-keyring.sh" "$0" "$@"
fi

BIN_DEFAULT="/workspaces/git-secret-vault/target/debug/git-secret-vault"
BIN="${1:-$BIN_DEFAULT}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
PASS="${GSV_TEST_PASSWORD:-test-pass-123}"

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: binary not found or not executable: $BIN" >&2
  echo "Build first: cargo build" >&2
  exit 1
fi

SANDBOX="$(mktemp -d /tmp/gsv-manual-test-XXXXXX)"

cleanup() {
  if [[ "$KEEP_SANDBOX" == "1" ]]; then
    echo "Sandbox preserved at: $SANDBOX"
    return
  fi
  rm -rf "$SANDBOX"
}
trap cleanup EXIT

echo "Using binary: $BIN"
echo "Sandbox: $SANDBOX"

pushd "$SANDBOX" >/dev/null

git init -q

mkdir -p secrets
printf 'API_KEY=alpha\n' > secrets/.env

echo "[1/6] init"
printf '%s\n' "$PASS" | "$BIN" init --password-stdin

if [[ ! -f "git-secret-vault.zip" ]]; then
  echo "FAIL: git-secret-vault.zip not created" >&2
  exit 1
fi
if [[ ! -f ".git-secret-vault.index.json" ]]; then
  echo "FAIL: .git-secret-vault.index.json not created" >&2
  exit 1
fi

if grep -q "secrets/.env" .git-secret-vault.index.json; then
  echo "FAIL: outer index leaks secret path" >&2
  exit 1
fi

echo "[2/6] lock"
printf '%s\n' "$PASS" | "$BIN" lock secrets/.env --password-stdin

echo "[3/6] status"
"$BIN" status
"$BIN" status --json >/tmp/gsv-status.json
if ! grep -q '"entry_count"' /tmp/gsv-status.json; then
  echo "FAIL: status --json missing entry_count" >&2
  exit 1
fi

echo "[4/6] remove local secret"
rm -f secrets/.env
if [[ -f secrets/.env ]]; then
  echo "FAIL: could not remove plaintext file" >&2
  exit 1
fi

echo "[5/6] unlock"
printf '%s\n' "$PASS" | "$BIN" unlock secrets/.env --password-stdin

if [[ ! -f secrets/.env ]]; then
  echo "FAIL: unlock did not restore secrets/.env" >&2
  exit 1
fi
if ! grep -q '^API_KEY=alpha$' secrets/.env; then
  echo "FAIL: unlocked content mismatch" >&2
  exit 1
fi

echo "[6/6] final checks"
git status --short

echo "PASS: manual sandbox flow completed successfully"

echo "Artifacts in sandbox:"
find . -maxdepth 3 -type f | sort

popd >/dev/null
