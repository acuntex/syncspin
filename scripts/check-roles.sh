#!/usr/bin/env bash
#
# Build, test and lint `syncspin-client` for the role feature sets that `--all-features` never
# builds. A feature that is off removes code and test files, and a test file that guards itself on
# a missing feature (`not(feature = "controller")`) compiles only in a set that lacks it, so the
# default and all-feature runs prove nothing about those sets.
#
#   scripts/check-roles.sh          # everything: the per-commit gate
#   scripts/check-roles.sh test     # tests, test builds and docs; no clippy needed (CI `test` job)
#   scripts/check-roles.sh lint     # clippy only (CI `lint` job)
#
# Every set builds with `--no-default-features`, so the default roles do not leak into it.

set -euo pipefail

cd "$(dirname "$0")/.."

mode="${1:-all}"
case "$mode" in
  all | test | lint) ;;
  *) printf 'usage: %s [test|lint]\n' "$0" >&2; exit 2 ;;
esac

# Sets of role features. An empty entry is `--no-default-features` alone.
role_sets=("" "player" "controller" "metadata" "player,controller" "player,metadata" "controller,metadata")

# Sets that combine the other features with no role or a single one. They are compiled and linted;
# the headless advertisement path runs for `discovery,metadata`. `pairing-code` also forwards to
# `syncspin-core`, and `mdns` pulls in the `mdns-sd` dependency; both stay compile-only.
build_sets=("discovery" "storage-file" "pairing-code" "discovery,mdns")
test_sets=("discovery,metadata")

flags() {
  if [ -n "$1" ]; then
    printf -- '--no-default-features --features %s' "$1"
  else
    printf -- '--no-default-features'
  fi
}

step() {
  printf '\n### %s\n' "$*"
  "$@"
}

run_test() {
  local set="$1"
  # shellcheck disable=SC2046
  step cargo test -p syncspin-client $(flags "$set") --locked
  # shellcheck disable=SC2046
  RUSTDOCFLAGS="-D warnings" step cargo doc -p syncspin-client --no-deps $(flags "$set") --locked
}

run_check() {
  local set="$1"
  # shellcheck disable=SC2046
  step cargo check -p syncspin-client --lib --tests $(flags "$set") --locked
}

run_lint() {
  local set="$1"
  # shellcheck disable=SC2046
  step cargo clippy -p syncspin-client --all-targets $(flags "$set") --locked -- -D warnings
}

if [ "$mode" != lint ]; then
  for set in "${role_sets[@]}"; do run_test "$set"; done
  for set in "${build_sets[@]}"; do run_check "$set"; done
  for set in "${test_sets[@]}"; do run_test "$set"; done
fi

if [ "$mode" != test ]; then
  for set in "${role_sets[@]}" "${build_sets[@]}" "${test_sets[@]}"; do run_lint "$set"; done
fi

printf '\ncheck-roles: all sets passed\n'
