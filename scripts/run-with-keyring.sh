#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: scripts/run-with-keyring.sh <command> [args ...]" >&2
  exit 2
fi

if [[ "${GSV_KEYRING_SESSION_ACTIVE:-0}" == "1" ]]; then
  exec "$@"
fi

created_temp_dir=0
if [[ -z "${GSV_MOCK_KEYRING_DIR:-}" ]]; then
  GSV_MOCK_KEYRING_DIR="$(mktemp -d /tmp/gsv-mock-keyring-session-XXXXXX)"
  created_temp_dir=1
fi

export GSV_KEYRING_SESSION_ACTIVE=1
export GSV_KEYRING_BACKEND=mock
export GSV_MOCK_KEYRING_DIR

set +e
"$@"
rc=$?
set -e

if [[ "$created_temp_dir" == "1" && "${GSV_MOCK_KEYRING_KEEP:-0}" != "1" ]]; then
  rm -rf "$GSV_MOCK_KEYRING_DIR"
fi

exit "$rc"
