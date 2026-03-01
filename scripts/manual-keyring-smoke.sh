#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${GSV_KEYRING_SESSION_ACTIVE:-0}" != "1" ]]; then
  exec "$SCRIPT_DIR/run-with-keyring.sh" "$0" "$@"
fi

MOCK_KEYRING="$SCRIPT_DIR/mock-keyring.sh"
if [[ ! -x "$MOCK_KEYRING" ]]; then
  echo "ERROR: mock backend not executable: $MOCK_KEYRING" >&2
  exit 1
fi

SMOKE_VALUE="${1:-gsv-keyring-smoke-ok}"
SMOKE_ID="gsv-smoke-$(date +%s)-$$"
SMOKE_APP="git-secret-vault"

cleanup() {
  "$MOCK_KEYRING" clear "$SMOKE_APP" "$SMOKE_ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '%s\n' "$SMOKE_VALUE" | "$MOCK_KEYRING" store "$SMOKE_APP" "$SMOKE_ID"

LOOKUP_VALUE="$("$MOCK_KEYRING" lookup "$SMOKE_APP" "$SMOKE_ID")"
if [[ "$LOOKUP_VALUE" != "$SMOKE_VALUE" ]]; then
  echo "FAIL: keyring lookup mismatch" >&2
  echo "Expected: $SMOKE_VALUE" >&2
  echo "Actual:   $LOOKUP_VALUE" >&2
  exit 1
fi

LIST_OUTPUT="$("$MOCK_KEYRING" list "$SMOKE_APP")"
if ! grep -q "$SMOKE_ID" <<< "$LIST_OUTPUT"; then
  echo "FAIL: keyring list missing smoke entry" >&2
  exit 1
fi

"$MOCK_KEYRING" purge
if [[ -n "$("$MOCK_KEYRING" list "$SMOKE_APP")" ]]; then
  echo "FAIL: keyring purge did not clear entries" >&2
  exit 1
fi

echo "PASS: mock keyring smoke test store/lookup/list/purge succeeded"
