#!/usr/bin/env bash
set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "${AXIOM_COLLECT_BIN:-}" ]]; then
  [[ -x "$AXIOM_COLLECT_BIN" ]] || {
    echo "FAIL: AXIOM_COLLECT_BIN is not executable: $AXIOM_COLLECT_BIN" >&2
    exit 2
  }
  exec "$AXIOM_COLLECT_BIN" "$@"
fi

if [[ -x "$SKILL_ROOT/bin/axiom-collect" ]]; then
  exec "$SKILL_ROOT/bin/axiom-collect" "$@"
fi

if [[ -n "${AXIOM_COLLECT_ROOT:-}" ]]; then
  for candidate in \
    "$AXIOM_COLLECT_ROOT/target/release/axiom-collect" \
    "$AXIOM_COLLECT_ROOT/target/debug/axiom-collect"; do
    if [[ -x "$candidate" ]]; then
      exec "$candidate" "$@"
    fi
  done
  echo "FAIL: no Axiom Collect binary found under AXIOM_COLLECT_ROOT: $AXIOM_COLLECT_ROOT" >&2
  exit 2
fi

if command -v axiom-collect >/dev/null 2>&1; then
  exec "$(command -v axiom-collect)" "$@"
fi

cat >&2 <<'EOF'
FAIL: Axiom Collect runtime not found.
Set AXIOM_COLLECT_BIN to an executable, install one at the skill's bin/axiom-collect,
or build the source checkout with: cargo build --release --locked
EOF
exit 127
