#!/usr/bin/env bash
set -euo pipefail

STORE_DIR="${GSV_MOCK_KEYRING_DIR:-${TMPDIR:-/tmp}/gsv-mock-keyring-default}"
ITEMS_DIR="$STORE_DIR/items"

usage() {
  cat <<'EOF'
Usage:
  scripts/mock-keyring.sh store <app> <id>    # reads secret from stdin
  scripts/mock-keyring.sh lookup <app> <id>
  scripts/mock-keyring.sh clear <app> <id>
  scripts/mock-keyring.sh list [app]
  scripts/mock-keyring.sh purge

Environment:
  GSV_MOCK_KEYRING_DIR  Override storage directory for mock keyring items.
EOF
}

ensure_store() {
  mkdir -p "$ITEMS_DIR"
}

key_file() {
  local app="$1"
  local id="$2"
  local key
  key="$(printf '%s' "$app::$id" | sha256sum | awk '{print $1}')"
  printf '%s/%s' "$ITEMS_DIR" "$key"
}

command_store() {
  local app="$1"
  local id="$2"
  local file
  local secret

  ensure_store
  file="$(key_file "$app" "$id")"
  secret="$(cat)"

  {
    printf '%s\n' "$app"
    printf '%s\n' "$id"
    printf '%s\n' "$secret"
  } > "$file"
}

command_lookup() {
  local app="$1"
  local id="$2"
  local file

  file="$(key_file "$app" "$id")"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  sed -n '3p' "$file"
}

command_clear() {
  local app="$1"
  local id="$2"
  local file

  file="$(key_file "$app" "$id")"
  rm -f "$file"
}

command_list() {
  local filter_app="${1:-}"

  if [[ ! -d "$ITEMS_DIR" ]]; then
    return 0
  fi

  local file
  for file in "$ITEMS_DIR"/*; do
    [[ -f "$file" ]] || continue
    local app
    local id
    app="$(sed -n '1p' "$file")"
    id="$(sed -n '2p' "$file")"
    if [[ -n "$filter_app" && "$app" != "$filter_app" ]]; then
      continue
    fi
    printf '%s %s\n' "$app" "$id"
  done
}

command_purge() {
  rm -rf "$ITEMS_DIR"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    store)
      [[ $# -eq 3 ]] || { usage; exit 2; }
      command_store "$2" "$3"
      ;;
    lookup)
      [[ $# -eq 3 ]] || { usage; exit 2; }
      command_lookup "$2" "$3"
      ;;
    clear)
      [[ $# -eq 3 ]] || { usage; exit 2; }
      command_clear "$2" "$3"
      ;;
    list)
      [[ $# -le 2 ]] || { usage; exit 2; }
      command_list "${2:-}"
      ;;
    purge)
      [[ $# -eq 1 ]] || { usage; exit 2; }
      command_purge
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
