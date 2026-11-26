#!/usr/bin/env bash
#
# Detach a code factory run. A run (scripts/factory.sh) takes tens of minutes, so a caller that
# cannot wait, such as an agent's bash tool call behind an OpenCode client, starts it through this
# launcher and gets a short summary back at once. The same script reports on runs and stops them.
#
#   scripts/factory-launch.sh [--env-file PATH] --task-file FILE [driver options...]
#   scripts/factory-launch.sh [--env-file PATH] --resume RUN_ID [--decisions-file FILE] [driver options...]
#   scripts/factory-launch.sh --status [RUN_ID]    the configuration, the launches and the runs, or one run
#   scripts/factory-launch.sh --stop LAUNCH_ID     stop a detached launch (the id the launch printed)
#
#     --env-file PATH         a file with OPENCODE_SERVER_USERNAME and OPENCODE_SERVER_PASSWORD (and
#                             any variable named in FACTORY_PASS_ENV) for the detached run, default
#                             $FACTORY_LAUNCH_ENVFILE. The launcher never reads it: systemd loads it
#                             (EnvironmentFile), or the detached shell sources it (fallback).
#     --task-file FILE        the task text, as a file; the text itself never reaches a command line
#     --resume RUN_ID         continue a run that stopped with exit 10 or exit 20
#     --decisions-file FILE   with --resume: copied to .factory/runs/RUN_ID/decisions.md first
#     --no-attach             do not forward FACTORY_OPENCODE_ATTACH: the run starts its own server
#
# Driver options passed through (a fixed list, each value checked like the driver checks it):
#   --backend B  --opencode-attach URL  --opencode-bin PATH  --model-main M  --model-helper M
#   --variant-main V  --variant-helper V  --stop-after S  --plan-rounds N  --code-rounds N
#   --phase-timeout SECS  --no-push
# Everything else, --allow-protected and --dry-run included, is a usage error.
#
# The environment names FACTORY_BACKEND, FACTORY_MODEL_MAIN, FACTORY_MODEL_HELPER,
# FACTORY_VARIANT_MAIN, FACTORY_VARIANT_HELPER, FACTORY_OPENCODE_BIN, FACTORY_OPENCODE_ATTACH and
# FACTORY_PASS_ENV are forwarded when set, after the same checks; nothing else is.
#
# Detaching: `systemd-run --user --unit=factory-<id>` when a user manager answers, else `setsid`
# with a log file under .factory/launch/. FACTORY_LAUNCH_NO_SYSTEMD=1 forces the fallback. Every
# launch leaves .factory/launch/<id>.meta (mode, process id, start time) for --status and --stop.
#
# --status and --stop read only the files under .factory/ and ask systemd or the process table; no
# model and no network. Their output holds no credential: the configuration lines show only the
# validated, non-secret values and whether an env file is set.
#
# Exit codes: 0 launched (or reported, or stopped), 1 the launch or the stop itself failed, 2 usage
# error, 3 prerequisites missing.

set -euo pipefail

cd "$(dirname "$0")/.."

# Patterns of the values the driver checks (scripts/factory.sh) are copied, not loosened. The driver
# has no pattern for a model or a client path; the launcher holds them to a conservative one.
VARIANT_RE='^[a-z0-9][a-z0-9._-]*$'
ATTACH_RE='^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?$'
MODEL_RE='^[A-Za-z0-9][A-Za-z0-9._:/#@+-]*$'
BIN_RE='^[A-Za-z0-9_./+-]+$'
PASS_ENV_RE='^[A-Za-z_][A-Za-z0-9_]*( [A-Za-z_][A-Za-z0-9_]*)*$'
RUN_ID_RE='^[0-9A-Za-z][0-9A-Za-z._-]*$'
LAUNCH_ID_RE='^(factory-)?[0-9a-f]{8}$'
ENVFILE_RE='^[A-Za-z0-9_./+@:,-]+$'
MAX_FILE_BYTES=262144

usage() {
  awk '/^#   scripts\/factory-launch.sh/ { f = 1 } f { sub(/^# ?/, ""); print } /^# Everything else/ { exit }' "${BASH_SOURCE[0]}" >&2
  exit "${1:-2}"
}

die_usage() {
  printf 'factory-launch: %s\n' "$1" >&2
  exit 2
}

die_missing() {
  printf 'factory-launch: %s\n' "$1" >&2
  exit 3
}

warn() {
  printf 'factory-launch: warning: %s\n' "$1" >&2
}

need_value() {
  [ "$#" -ge 2 ] && [ -n "$2" ] || die_usage "$1 needs a value"
}

# regular_file <what> <path>: a regular, non-empty file that is not a symlink and not too big.
regular_file() {
  local what=$1 path=$2 size
  [[ "$path" != -* ]] || die_usage "$what: the path must not start with a dash"
  [ ! -L "$path" ] || die_usage "$what: refusing a symbolic link: $path"
  [ -f "$path" ] || die_usage "$what: not a regular file: $path"
  size=$(stat -c %s -- "$path")
  [ "$size" -gt 0 ] || die_usage "$what: the file is empty: $path"
  [ "$size" -le "$MAX_FILE_BYTES" ] || die_usage "$what: the file is larger than $MAX_FILE_BYTES bytes: $path"
}

env_file=${FACTORY_LAUNCH_ENVFILE:-}
task_file=""
resume_id=""
decisions_file=""
no_attach=0
env_flag=0
mode=launch
status_id=""
stop_id=""
attach_flag=0
passthrough=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file) need_value "$@"; env_file=$2; env_flag=1; shift 2 ;;
    --task-file) need_value "$@"; task_file=$2; shift 2 ;;
    --resume) need_value "$@"; resume_id=$2; shift 2 ;;
    --decisions-file) need_value "$@"; decisions_file=$2; shift 2 ;;
    --no-attach) no_attach=1; shift ;;
    --status)
      mode=status
      shift
      if [ "$#" -gt 0 ] && [[ "$1" != --* ]]; then
        status_id=$1
        shift
      fi
      ;;
    --stop) need_value "$@"; mode=stop; stop_id=$2; shift 2 ;;
    --backend)
      need_value "$@"
      case "$2" in opencode | claude) ;; *) die_usage "--backend takes opencode or claude" ;; esac
      passthrough+=("$1" "$2"); shift 2 ;;
    --opencode-attach)
      need_value "$@"
      [[ "$2" =~ $ATTACH_RE ]] || die_usage "--opencode-attach takes http(s)://host[:port] with no user, path or query"
      attach_flag=1
      passthrough+=("$1" "$2"); shift 2 ;;
    --opencode-bin)
      need_value "$@"
      [[ "$2" =~ $BIN_RE ]] && [[ "$2" != -* ]] || die_usage "--opencode-bin takes a path of letters, digits and . _ / + -"
      passthrough+=("$1" "$2"); shift 2 ;;
    --model-main | --model-helper)
      need_value "$@"
      [[ "$2" =~ $MODEL_RE ]] || die_usage "$1 takes letters, digits and . _ : / # @ + -, starting with a letter or digit"
      passthrough+=("$1" "$2"); shift 2 ;;
    --variant-main | --variant-helper)
      need_value "$@"
      [[ "$2" =~ $VARIANT_RE ]] || die_usage "$1 takes lowercase letters, digits, dot, underscore and dash, starting with a letter or digit"
      passthrough+=("$1" "$2"); shift 2 ;;
    --stop-after)
      need_value "$@"
      case "$2" in plan | implement | review | pr) ;; *) die_usage "--stop-after takes plan, implement, review or pr" ;; esac
      passthrough+=("$1" "$2"); shift 2 ;;
    --plan-rounds)
      need_value "$@"
      [[ "$2" =~ ^[1-4]$ ]] || die_usage "--plan-rounds takes 1 to 4 (the cap can only be lowered)"
      passthrough+=("$1" "$2"); shift 2 ;;
    --code-rounds)
      need_value "$@"
      [[ "$2" =~ ^[1-3]$ ]] || die_usage "--code-rounds takes 1 to 3 (the cap can only be lowered)"
      passthrough+=("$1" "$2"); shift 2 ;;
    --phase-timeout)
      need_value "$@"
      [[ "$2" =~ ^[0-9]{1,7}$ ]] && [ "$((10#$2))" -ge 1 ] || die_usage "--phase-timeout takes a number of seconds"
      passthrough+=("$1" "$2"); shift 2 ;;
    --no-push) passthrough+=("$1"); shift ;;
    -h | --help) usage 0 ;;
    *) die_usage "unknown or not allowed option: $1" ;;
  esac
done

case "$mode" in
  status)
    [ -z "$task_file$resume_id$decisions_file" ] && [ "$env_flag" = 0 ] && [ "${#passthrough[@]}" -eq 0 ] && [ "$no_attach" = 0 ] ||
      die_usage "--status takes at most a run id"
    [ -z "$status_id" ] || [[ "$status_id" =~ $RUN_ID_RE ]] || die_usage "--status takes a run id of letters, digits, dot, underscore and dash, starting with a letter or digit"
    ;;
  stop)
    [ -z "$task_file$resume_id$decisions_file" ] && [ "$env_flag" = 0 ] && [ "${#passthrough[@]}" -eq 0 ] && [ "$no_attach" = 0 ] ||
      die_usage "--stop takes only a launch id"
    [[ "$stop_id" =~ $LAUNCH_ID_RE ]] || die_usage "--stop takes the launch id the launch printed: 8 hexadecimal digits"
    stop_id=${stop_id#factory-}
    ;;
  launch)
    [ "$no_attach" = 0 ] || [ "$attach_flag" = 0 ] || die_usage "--no-attach and --opencode-attach exclude each other"
    if [ -n "$resume_id" ]; then
      [ -z "$task_file" ] || die_usage "--resume takes no --task-file"
      [[ "$resume_id" =~ $RUN_ID_RE ]] || die_usage "--resume takes a run id of letters, digits, dot, underscore and dash, starting with a letter or digit"
    else
      [ -z "$decisions_file" ] || die_usage "--decisions-file needs --resume"
      [ -n "$task_file" ] || { usage 2; }
    fi
    ;;
esac

# ---------------------------------------------------------------------------------------------
# Prerequisites and the forwarded environment

root=$(pwd -P)
[ -f scripts/factory.sh ] || die_missing "scripts/factory.sh not found: run this from the repository root"
top=$(git rev-parse --show-toplevel 2>/dev/null || true)
[ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$root" ] || die_missing "$root is not the root of a git working tree"

fwd=()
forward() {
  local name=$1 re=$2 value=${!1:-}
  [ -n "$value" ] || return 0
  [[ "$value" =~ $re ]] || die_usage "the value of $name does not match the pattern the driver accepts"
  fwd+=("$name=$value")
}
forward FACTORY_BACKEND '^(opencode|claude)$'
forward FACTORY_MODEL_MAIN "$MODEL_RE"
forward FACTORY_MODEL_HELPER "$MODEL_RE"
forward FACTORY_VARIANT_MAIN "$VARIANT_RE"
forward FACTORY_VARIANT_HELPER "$VARIANT_RE"
forward FACTORY_OPENCODE_BIN "$BIN_RE"
if [ "$no_attach" = 0 ]; then forward FACTORY_OPENCODE_ATTACH "$ATTACH_RE"; fi
forward FACTORY_PASS_ENV "$PASS_ENV_RE"

# ---------------------------------------------------------------------------------------------
# Status and stop

# meta_get <file> <key>: one value of a .meta file (key=value lines, never sourced).
meta_get() {
  sed -n "s/^$2=//p" "$1" | head -n 1
}

# state_get <file> <key>
state_get() {
  sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1 | tr -d '[:cntrl:]' | cut -c1-200
}

# pid_is_run <pid>: the process exists and is the driver (or the detached shell before its exec).
pid_is_run() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ -r "/proc/$1/cmdline" ] || return 1
  tr '\0' ' ' <"/proc/$1/cmdline" | grep -Eq 'scripts/factory\.sh|factory-launch'
}

# launch_active <id>: succeeds while the launch is running.
launch_active() {
  local meta=.factory/launch/$1.meta how
  [ -f "$meta" ] && [ ! -L "$meta" ] || return 1
  how=$(meta_get "$meta" mode)
  case "$how" in
    systemd) systemctl --user is-active --quiet "factory-$1" >/dev/null 2>&1 ;;
    fallback) pid_is_run "$(meta_get "$meta" pid)" ;;
    *) return 1 ;;
  esac
}

exit_name() {
  case "$1" in
    0) printf 'done' ;;
    2) printf 'usage' ;;
    3) printf 'preflight' ;;
    10) printf 'owner decisions open' ;;
    11) printf 'plan review cap' ;;
    12) printf 'code review cap' ;;
    13) printf 'sandbox violation' ;;
    14) printf 'bad commits' ;;
    15) printf 'final gate failed' ;;
    16) printf 'pull request text lint' ;;
    20) printf 'phase failure' ;;
    *) printf 'unknown' ;;
  esac
}

# fmt_duration <seconds>
fmt_duration() {
  local s=$1
  if [ "$s" -ge 3600 ]; then
    printf '%dh%02dm%02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
  else
    printf '%dm%02ds' $((s / 60)) $((s % 60))
  fi
}

# phase_durations <run dir>: one line per phase log. The driver writes `== <phase> HH:MM:SS` (UTC)
# at the start of every attempt and appends output, so the last header gives the start and the
# file's modification time the last activity. The date comes from the modification time; a start
# later than that belongs to the day before.
phase_durations() {
  local dir=$1 log name header hms mtime day start
  for log in $(ls -1tr "$dir"/logs/*.log 2>/dev/null || true); do
    name=$(basename "$log" .log)
    header=$(grep -E '^== [^ ]+ [0-9]{2}:[0-9]{2}:[0-9]{2}$' "$log" | tail -n 1 || true)
    if [ -z "$header" ]; then
      printf '  %-14s no start time in the log\n' "$name"
      continue
    fi
    hms=${header##* }
    mtime=$(stat -c %Y "$log")
    day=$(date -u -d "@$mtime" +%F)
    start=$(date -u -d "$day $hms" +%s)
    if [ "$start" -gt "$mtime" ]; then start=$((start - 86400)); fi
    printf '  %-14s started %s UTC, last output %s later\n' "$name" "$hms" "$(fmt_duration $((mtime - start)))"
  done
}

status_run() {
  local id=$1 dir=.factory/runs/$1 st code reason
  [ ! -L "$dir" ] && [ -d "$dir" ] || die_usage "no such run: $id"
  st=$dir/state
  printf 'run %s\n' "$id"
  if [ ! -f "$st" ]; then
    printf '  no state file yet (the driver has not passed preflight)\n'
    return 0
  fi
  code=$(state_get "$st" exit_code)
  printf '  status:   %s\n' "$(state_get "$st" status)"
  printf '  phase:    %s (step %s)\n' "$(state_get "$st" phase)" "$(state_get "$st" step)"
  printf '  rounds:   plan %s, code %s\n' "$(state_get "$st" plan_round)" "$(state_get "$st" code_round)"
  printf '  backend:  %s\n' "$(state_get "$st" backend)"
  printf '  branch:   %s\n' "$(state_get "$st" branch)"
  if [ -n "$code" ]; then printf '  exit:     %s (%s)\n' "$code" "$(exit_name "$code")"; fi
  if [ -n "$(state_get "$st" stopped_at)" ]; then printf '  stopped:  %s\n' "$(state_get "$st" stopped_at)"; fi
  case "$code" in
    10) printf '  next:     owner decisions are open: answer them, then resume\n' ;;
    20) printf '  next:     a phase failed; read the handoff, then resume\n' ;;
    "" | 0) ;;
    *) printf '  next:     not resumable; read the handoff\n' ;;
  esac
  if [ -f "$dir/handoff.md" ] && [ ! -L "$dir/handoff.md" ]; then
    reason=$(sed -n 's/^Reason: //p' "$dir/handoff.md" | head -n 1 | tr -d '[:cntrl:]' | cut -c1-200)
    if [ -n "$reason" ]; then printf '  reason:   %s\n' "$reason"; fi
    printf '  handoff:  %s/handoff.md\n' "$dir"
  fi
  printf 'phases (from the logs):\n'
  phase_durations "$dir"
}

status_all() {
  local meta id kind rid how act started n=0 d
  printf 'configuration:\n'
  printf '  backend:  %s\n' "$(printf '%s\n' "${fwd[@]}" | sed -n 's/^FACTORY_BACKEND=//p' | head -n 1 | grep . || printf 'not set')"
  printf '  server:   %s\n' "$(printf '%s\n' "${fwd[@]}" | sed -n 's/^FACTORY_OPENCODE_ATTACH=//p' | head -n 1 | grep . || printf 'not set (a run starts its own server)')"
  printf '  models:   main %s, helper %s\n' \
    "$(printf '%s\n' "${fwd[@]}" | sed -n 's/^FACTORY_MODEL_MAIN=//p' | head -n 1 | grep . || printf 'default')" \
    "$(printf '%s\n' "${fwd[@]}" | sed -n 's/^FACTORY_MODEL_HELPER=//p' | head -n 1 | grep . || printf 'default')"
  if [ -n "$env_file" ]; then printf '  env file: set\n'; else printf '  env file: not set\n'; fi
  printf 'launches (newest first):\n'
  # shellcheck disable=SC2012  # names are checked against a pattern in the loop
  for meta in $(ls -1t .factory/launch/*.meta 2>/dev/null | head -n 5 || true); do
    id=$(basename "$meta" .meta)
    [[ "$id" =~ ^[0-9a-f]{8}$ ]] || continue
    kind=$(meta_get "$meta" kind)
    rid=$(meta_get "$meta" run)
    how=$(meta_get "$meta" mode)
    started=$(meta_get "$meta" started)
    if launch_active "$id"; then act=running; else act=finished; fi
    [[ "$started" =~ ^[0-9]+$ ]] || started=0
    printf '  %s  %s%s  %s  %s  started %s UTC\n' "$id" "$kind" "${rid:+ $rid}" "$how" "$act" "$(date -u -d "@$started" '+%F %T')"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || printf '  none\n'
  printf 'runs (newest first):\n'
  n=0
  # shellcheck disable=SC2012  # names are checked against a pattern in the loop
  for d in $(ls -1t .factory/runs 2>/dev/null | head -n 5 || true); do
    [[ "$d" =~ $RUN_ID_RE ]] && [ -f ".factory/runs/$d/state" ] && [ ! -L ".factory/runs/$d" ] || continue
    printf '  %s  status %s, phase %s, exit %s\n' "$d" "$(state_get ".factory/runs/$d/state" status)" "$(state_get ".factory/runs/$d/state" phase)" "$(state_get ".factory/runs/$d/state" exit_code)"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || printf '  none\n'
}

stop_launch() {
  local id=$1 meta=.factory/launch/$1.meta how pid
  [ -f "$meta" ] && [ ! -L "$meta" ] || die_usage "no such launch: $id (see --status)"
  how=$(meta_get "$meta" mode)
  case "$how" in
    systemd)
      if systemctl --user stop "factory-$id" >/dev/null 2>&1; then
        printf 'factory-launch: stopped factory-%s\n' "$id"
      else
        printf 'factory-launch: could not stop factory-%s (already finished?)\n' "$id" >&2
        exit 1
      fi
      ;;
    fallback)
      pid=$(meta_get "$meta" pid)
      if pid_is_run "$pid"; then
        kill -TERM -- "-$pid"
        printf 'factory-launch: stopped launch %s (process group %s); an agent phase may run on until its own timeout\n' "$id" "$pid"
      else
        printf 'factory-launch: launch %s is not running\n' "$id"
      fi
      ;;
    *) die_usage "the launch record of $id is unreadable" ;;
  esac
}

case "$mode" in
  status)
    if [ -n "$status_id" ]; then status_run "$status_id"; else status_all; fi
    exit 0
    ;;
  stop)
    stop_launch "$stop_id"
    exit 0
    ;;
esac

# ---------------------------------------------------------------------------------------------
# Launch

command -v setsid >/dev/null 2>&1 || die_missing "setsid not found (util-linux)"

if [ -n "$task_file" ]; then regular_file "--task-file" "$task_file"; fi

# The credentials file: checked, never read.
if [ -n "$env_file" ]; then
  [[ "$env_file" =~ $ENVFILE_RE ]] && [[ "$env_file" != -* ]] || die_usage "--env-file: the path may hold only letters, digits and . _ / + @ : , -"
  [[ "$env_file" = /* ]] || env_file=$root/$env_file
  [ -f "$env_file" ] && [ -r "$env_file" ] || die_missing "the env file does not exist or is not readable: $env_file"
  fmode=$(stat -L -c %a -- "$env_file")
  if [ $((8#$fmode & 8#077)) -ne 0 ]; then
    warn "the env file is readable by group or others (mode $fmode); run: chmod 600 $env_file"
  fi
fi

mkdir -p .factory/launch
chmod 700 .factory/launch

# Resume: the decisions file becomes the run's decisions.md before the driver starts.
if [ -n "$resume_id" ]; then
  run_dir=.factory/runs/$resume_id
  [ ! -L "$run_dir" ] && [ -d "$run_dir" ] || die_usage "no such run directory: $run_dir"
  if [ -n "$decisions_file" ]; then
    regular_file "--decisions-file" "$decisions_file"
    tmpdec=$run_dir/.decisions.$$
    cp -- "$decisions_file" "$tmpdec"
    mv -f -- "$tmpdec" "$run_dir/decisions.md"
  fi
  driver_args=(--resume "$resume_id")
else
  driver_args=(--task-file "$task_file")
fi
driver_args+=("${passthrough[@]}")

id=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
unit=factory-$id
driver=$root/scripts/factory.sh
meta=.factory/launch/$id.meta

use_systemd=0
if [ "${FACTORY_LAUNCH_NO_SYSTEMD:-0}" != 1 ] && command -v systemd-run >/dev/null 2>&1 &&
  command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  use_systemd=1
fi

write_meta() {
  (
    umask 077
    {
      printf 'kind=%s\n' "$([ -n "$resume_id" ] && printf resume || printf task)"
      if [ -n "$resume_id" ]; then printf 'run=%s\n' "$resume_id"; fi
      printf 'mode=%s\n' "$1"
      if [ -n "${2:-}" ]; then printf 'pid=%s\n' "$2"; fi
      printf 'started=%s\n' "$(date -u +%s)"
    } >"$meta"
  )
}

if [ "$use_systemd" = 1 ]; then
  sd=(systemd-run --user --quiet "--unit=$unit" --collect "--working-directory=$root")
  # The user manager has its own PATH; the run needs the caller's to find its tools.
  case "$PATH" in *$'\n'*) die_usage "PATH holds a newline" ;; esac
  sd+=("--setenv=PATH=$PATH")
  for kv in "${fwd[@]}"; do sd+=("--setenv=$kv"); done
  if [ -n "$env_file" ]; then sd+=(-p "EnvironmentFile=$env_file"); fi
  if ! "${sd[@]}" -- "$driver" "${driver_args[@]}"; then
    printf 'factory-launch: systemd-run failed to start %s\n' "$unit" >&2
    exit 1
  fi
  write_meta systemd
  follow="journalctl --user -u $unit -f"
  how="systemd user unit $unit"
else
  log=.factory/launch/$id.log
  (umask 077 && : >"$log")
  envargs=(env -i "PATH=$PATH" "HOME=${HOME:-/}")
  for var in LANG TERM; do
    if [ -n "${!var+x}" ]; then envargs+=("$var=${!var}"); fi
  done
  envargs+=("${fwd[@]}")
  # The detached shell sources the credentials file itself, so its content never passes through here.
  # shellcheck disable=SC2016  # expanded by the inner bash
  "${envargs[@]}" setsid bash -c 'if [ -n "$1" ]; then set -a; . "$1"; set +a; fi; shift; exec "$@"' \
    factory-launch "$env_file" "$driver" "${driver_args[@]}" >>"$log" 2>&1 </dev/null &
  pid=$!
  disown "$pid" 2>/dev/null || true
  write_meta fallback "$pid"
  follow="tail -f $log"
  how="detached process $pid, log $log"
fi

printf 'factory-launch: started %s (%s)\n' "$unit" "$how"
printf '  launch:  %s\n' "$id"
printf '  follow:  %s\n' "$follow"
printf '  status:  scripts/factory-launch.sh --status\n'
printf '  stop:    scripts/factory-launch.sh --stop %s\n' "$id"
printf '  runs:    .factory/runs/ (the run directory appears there once the driver passes preflight)\n'
if [ -n "$resume_id" ]; then
  printf '  run:     %s\n' "$resume_id"
else
  printf '  resume:  after exit 10 or 20: scripts/factory-launch.sh --resume <run id> [--decisions-file FILE]\n'
fi
