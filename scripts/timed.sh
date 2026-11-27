#!/usr/bin/env bash
#
# Run one command under a wall-clock limit.
#
#   scripts/timed.sh SECONDS -- command [args...]
#
# SECONDS is a whole number of seconds from 1 to 7200, the largest phase budget: 0 would mean no
# limit at all, and a limit above the largest budget could outlive every phase. The command is
# executed directly, so its own exit code passes through; 124 and 137 mean the limit was hit.
#
# The command must be one of the factory's own deterministic commands:
#
#   cargo
#   scripts/gate.sh
#   scripts/test-factory.sh
#   scripts/factory-sync.sh --check|--list
#   scripts/check-roles.sh
#   scripts/check-example-versions.sh
#
# Anything else is refused with a usage error before it runs. This is what makes the wrapper safe:
# the permission layer allows `scripts/*`, so a wrapper that exec'd arbitrary arguments would carry
# `git push`, `gh pr merge`, `git commit --no-verify` or `rm` past every rule that denies those
# commands. A bare `timeout` is still not allowed: a `timeout *` rule would allow `timeout 1 rm -rf
# ...`, and the wrapper's allowlist would not apply to it. `scripts/factory-sync.sh` is accepted only
# with `--check` or `--list`: without an argument it writes the generated agent files, which are
# protected.
#
# Exit codes: the command's own, 2 on bad usage or a refused command.

set -euo pipefail

usage() {
  printf 'usage: %s SECONDS -- command [args...] (SECONDS is 1 to 7200)\n' "$0" >&2
  printf 'commands: cargo, scripts/gate.sh, scripts/test-factory.sh, scripts/factory-sync.sh --check|--list, scripts/check-roles.sh, scripts/check-example-versions.sh\n' >&2
  exit 2
}

allowed() {
  case "$1" in
    cargo | scripts/gate.sh | scripts/test-factory.sh | scripts/check-roles.sh | scripts/check-example-versions.sh)
      return 0
      ;;
    scripts/factory-sync.sh)
      # The generated files are protected: a read-only agent may check or list them, never write them.
      [ "$#" = 2 ] || return 1
      case "$2" in
        --check | --list) return 0 ;;
      esac
      return 1
      ;;
  esac
  return 1
}

[ "$#" -ge 3 ] || usage
[ "$2" = -- ] || usage
[ -n "$3" ] || usage
[[ "$1" =~ ^[1-9][0-9]*$ ]] || usage
[ "$1" -le 7200 ] || usage
if ! allowed "${@:3}"; then
  printf '%s: refused: %s is not an allowed timed command\n' "$0" "$3" >&2
  usage
fi

exec timeout -k 10 "$1" "${@:3}"
