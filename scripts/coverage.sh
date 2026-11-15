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
#
# The floor is 99.1 rather than 100 because eight guard lines cannot be reached by any input; they
# are listed here so the reason is visible with the gate:
#
#   syncspin-client/src/client.rs:710        sink_failed + a clean close cannot coexist
#   syncspin-client/src/session.rs:407-408   deadline combinations the state machine never builds
#   syncspin-client/src/session.rs:487       a burst is always started before it is due
#   syncspin-client/src/session.rs:744-745   a decode session never opens a non-PCM stream
#   syncspin-core/src/framing.rs:263         the in-flight message was just checked as present
#   syncspin-core/src/noise.rs:408           a 43-character canonical key always decodes to 32 bytes

set -euo pipefail

FLOOR="${COVERAGE_FLOOR:-99.1}"
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
