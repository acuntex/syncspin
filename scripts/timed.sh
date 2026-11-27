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
# This is the only timed form a factory agent may use: `scripts/*` is allowed, a bare `timeout` is
# not, because `timeout 1 rm -rf ...` would be allowed as a whole by a `timeout *` rule.
#
# Exit codes: the command's own, 2 on bad usage.

set -euo pipefail

usage() {
  printf 'usage: %s SECONDS -- command [args...] (SECONDS is 1 to 7200)\n' "$0" >&2
  exit 2
}

[ "$#" -ge 3 ] || usage
[ "$2" = -- ] || usage
[ -n "$3" ] || usage
[[ "$1" =~ ^[1-9][0-9]*$ ]] || usage
[ "$1" -le 7200 ] || usage

exec timeout -k 10 "$1" "${@:3}"
