#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${GSV_KEYRING_SESSION_ACTIVE:-0}" != "1" ]]; then
  exec "$SCRIPT_DIR/run-with-keyring.sh" "$0" "$@"
fi

BIN_DEFAULT="/workspaces/git-secret-vault/target/debug/git-secret-vault"
BIN="${GSV_BIN:-$BIN_DEFAULT}"
SANDBOX=""
RCFILE=""

cleanup() {
  if [[ -n "$RCFILE" ]]; then
    rm -f "$RCFILE"
  fi
  if [[ -n "$SANDBOX" ]]; then
    rm -rf "$SANDBOX"
    echo "Sandbox destroyed: $SANDBOX"
  fi
}

usage() {
  cat <<'EOF'
Usage:
  scripts/manual-sandbox-shell.sh create

Behavior:
  - Creates a temporary Git sandbox directory
  - Starts a new shell in that directory
  - Aliases `git-secret-vault` to the built binary path
  - Destroys the sandbox automatically when shell exits

Environment:
  GSV_BIN            Override binary path
  GSV_SHELL_COMMAND  Run a command in the spawned shell and exit (for automation)
EOF
}

command_create() {
  if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found or not executable: $BIN" >&2
    echo "Build first: cargo build" >&2
    exit 1
  fi

  SANDBOX="$(mktemp -d /tmp/gsv-manual-shell-XXXXXX)"
  RCFILE="$(mktemp /tmp/gsv-manual-shell-rc-XXXXXX)"

  trap cleanup EXIT

  git -C "$SANDBOX" init -q
  mkdir -p "$SANDBOX/secrets" "$SANDBOX/.gsv-bin"
  printf 'API_KEY=alpha\n' > "$SANDBOX/secrets/.env"
  ln -sf "$BIN" "$SANDBOX/.gsv-bin/git-secret-vault"

  cat >"$RCFILE" <<EOF
alias git-secret-vault='$BIN'
export GSV_SANDBOX='$SANDBOX'
export PATH='$SANDBOX/.gsv-bin':"\$PATH"
cd '$SANDBOX'
echo

echo 'Sandbox: $SANDBOX'
echo 'Alias:   git-secret-vault -> $BIN'
echo 'PATH shim: $SANDBOX/.gsv-bin/git-secret-vault'
echo 'Tip: run git-secret-vault --help'
echo 'Exit this shell to destroy the sandbox.'
echo
EOF

  if [[ -n "${GSV_SHELL_COMMAND:-}" ]]; then
    bash --noprofile --rcfile "$RCFILE" -ic "$GSV_SHELL_COMMAND"
  else
    bash --noprofile --rcfile "$RCFILE" -i
  fi
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    create)
      command_create
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
