#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_files=(
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  README.md
  SECURITY.md
  AGENTS.md
  docs/ARCHITECTURE.md
  docs/SPECIFICATION.md
  skills/axiom-collect/SKILL.md
  skills/axiom-collect/agents/openai.yaml
  skills/axiom-collect/scripts/run.sh
  src/main.rs
  src/lib.rs
  tests/http_integration.rs
  tests/mcp_integration.rs
  tests/provider_integration.rs
  puppeteer-rescue/package.json
  puppeteer-rescue/package-lock.json
  puppeteer-rescue/puppeteer-helper.mjs
  scripts/clean.sh
  scripts/verify.sh
)

for path in "${required_files[@]}"; do
  [[ -f "$path" ]] || {
    echo "FAIL: required file missing: $path" >&2
    exit 1
  }
done

if [[ -e "$ROOT/.github/workflows" || -L "$ROOT/.github/workflows" ]]; then
  echo "FAIL: GitHub Actions/CI workflows are forbidden: .github/workflows" >&2
  exit 1
fi

extra_script="$(find "$ROOT/scripts" -maxdepth 1 -type f -name '*.sh' \
  ! -name 'clean.sh' ! -name 'verify.sh' -print -quit)"
if [[ -n "$extra_script" ]]; then
  echo "FAIL: only scripts/clean.sh and scripts/verify.sh are supported: ${extra_script#"$ROOT/"}" >&2
  exit 1
fi

if find . \
  -path './.git' -prune -o \
  -path './target' -prune -o \
  -path './artifacts' -prune -o \
  -path './puppeteer-rescue/node_modules' -prune -o \
  -type f -name '.DS_Store' -print -quit | grep -q .; then
  echo "FAIL: source tree contains .DS_Store; run ./scripts/clean.sh" >&2
  exit 1
fi

for script in scripts/*.sh; do
  bash -n "$script"
done
bash -n skills/axiom-collect/scripts/run.sh

for tool in cargo rustc rustfmt; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "NOT_RUN_TOOLCHAIN: missing $tool" >&2
    exit 2
  }
done

cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked

if command -v node >/dev/null 2>&1; then
  node --check puppeteer-rescue/puppeteer-helper.mjs
else
  echo "NOT_RUN_NODE: Puppeteer helper syntax check unavailable"
fi

# Tests that need an installed browser or public network are `#[ignore]`d so this
# script stays deterministic offline. Run those tests explicitly with cargo when
# the required browser and, for rescue coverage, external Node runtime are ready.
echo "NOT_RUN_RENDERED: browser-dependent integration tests are #[ignore]d"

echo "PASS: repository policy, format, build, lint, and tests"
