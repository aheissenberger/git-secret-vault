#!/usr/bin/env bash
set -euo pipefail

STATE_FILE_DEFAULT="${TMPDIR:-/tmp}/gsv-manual-sandbox-${USER:-user}.path"
STATE_FILE="${GSV_SANDBOX_STATE_FILE:-$STATE_FILE_DEFAULT}"
SANDBOX_PREFIX="${TMPDIR:-/tmp}/gsv-manual-sandbox-"

usage() {
  cat <<'EOF'
Usage:
  scripts/manual-sandbox.sh create
  scripts/manual-sandbox.sh destroy

Commands:
  create   Create a temporary Git sandbox for manual testing and record its path.
  destroy  Remove the recorded sandbox and clear the state file.

Environment:
  GSV_SANDBOX_STATE_FILE  Override state file path (default: /tmp/gsv-manual-sandbox-<user>.path)
EOF
}

ensure_safe_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    echo "ERROR: empty sandbox path" >&2
    exit 1
  fi
  case "$path" in
    ${TMPDIR:-/tmp}/gsv-manual-sandbox-*) ;;
    *)
      echo "ERROR: refusing to remove non-sandbox path: $path" >&2
      exit 1
      ;;
  esac
}

command_create() {
  if [[ -f "$STATE_FILE" ]]; then
    local existing
    existing="$(cat "$STATE_FILE")"
    if [[ -n "$existing" && -d "$existing" ]]; then
      echo "Sandbox already exists: $existing"
      echo "Destroy it first: scripts/manual-sandbox.sh destroy"
      return 0
    fi
  fi

  local sandbox
  sandbox="$(mktemp -d "${SANDBOX_PREFIX}XXXXXX")"

  git -C "$sandbox" init -q
  mkdir -p "$sandbox/secrets"
  printf 'API_KEY=alpha\n' > "$sandbox/secrets/.env"
  printf '%s' "$sandbox" > "$STATE_FILE"

  cat <<EOF
Sandbox created: $sandbox
State file: $STATE_FILE

Quick start:
  cd "$sandbox"
  /workspaces/git-secret-vault/target/debug/git-secret-vault init --password-stdin <<< 'test-pass-123'
  /workspaces/git-secret-vault/target/debug/git-secret-vault lock secrets/.env --password-stdin <<< 'test-pass-123'

When finished:
  scripts/manual-sandbox.sh destroy
EOF
}

command_destroy() {
  if [[ ! -f "$STATE_FILE" ]]; then
    echo "No sandbox state file found: $STATE_FILE"
    echo "Nothing to destroy."
    return 0
  fi

  local sandbox
  sandbox="$(cat "$STATE_FILE")"

  if [[ -z "$sandbox" ]]; then
    rm -f "$STATE_FILE"
    echo "State file was empty and has been removed."
    return 0
  fi

  ensure_safe_path "$sandbox"

  if [[ -d "$sandbox" ]]; then
    rm -rf "$sandbox"
    echo "Sandbox destroyed: $sandbox"
  else
    echo "Sandbox path did not exist: $sandbox"
  fi

  rm -f "$STATE_FILE"
  echo "State file removed: $STATE_FILE"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    create)
      command_create
      ;;
    destroy)
      command_destroy
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
