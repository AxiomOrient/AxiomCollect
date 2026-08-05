#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRY_RUN=false

case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=true ;;
  *)
    echo "usage: clean.sh [--dry-run]" >&2
    exit 2
    ;;
esac

removed=0

remove_path() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || return 0

  if "$DRY_RUN"; then
    printf 'WOULD_REMOVE: %s\n' "${path#"$ROOT"/}"
  else
    rm -rf "$path"
    printf 'REMOVED: %s\n' "${path#"$ROOT"/}"
  fi
  removed=$((removed + 1))
}

remove_path "$ROOT/target"
remove_path "$ROOT/artifacts"
remove_path "$ROOT/puppeteer-rescue/node_modules"

while IFS= read -r -d '' path; do
  remove_path "$path"
done < <(
  find "$ROOT" \
    -path "$ROOT/.git" -prune -o \
    -path "$ROOT/target" -prune -o \
    -path "$ROOT/artifacts" -prune -o \
    -path "$ROOT/puppeteer-rescue/node_modules" -prune -o \
    -type f -name '.DS_Store' -print0
)

if [[ "$removed" -eq 0 ]]; then
  printf 'PASS: clean: nothing to remove\n'
elif "$DRY_RUN"; then
  printf 'PASS: clean dry-run: %d path(s)\n' "$removed"
else
  printf 'PASS: clean: removed %d path(s)\n' "$removed"
fi
