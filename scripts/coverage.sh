#!/usr/bin/env bash
#
# Line and region coverage for the workspace, with a hard floor.
#
#   scripts/coverage.sh            # summary against the floor
#   scripts/coverage.sh --missing  # list the uncovered lines
#   scripts/coverage.sh --html     # write target/llvm-cov/html/index.html
#
# Requires cargo-llvm-cov and the llvm-tools-preview component:
#   rustup component add llvm-tools-preview
#   cargo install cargo-llvm-cov --locked

set -euo pipefail

FLOOR="${COVERAGE_FLOOR:-100}"
cd "$(dirname "$0")/.."

args=(--workspace --locked --ignore-filename-regex 'examples/')
case "${1:-}" in
  --missing) args+=(--show-missing-lines) ;;
  --html) args+=(--html) ;;
  "" )
    args+=(--fail-under-lines "$FLOOR")
    ;;
  *) printf 'usage: %s [--missing|--html]\n' "$0" >&2; exit 2 ;;
esac

exec cargo llvm-cov "${args[@]}"
