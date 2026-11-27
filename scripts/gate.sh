#!/usr/bin/env bash
#
# The tool-independent gate: one command that runs what CI runs, in a fixed order, with a stable
# output format. The code factory, the code reviewer and a human all call it.
#
# The steps are selected from the paths a run has to consider: the staged index with `--commit`, and
# the branch since `origin/main` plus untracked files otherwise. Rust paths add the cargo steps, shell
# paths shellcheck, factory paths the generator check and the factory tests, and prettier runs in
# every mode (staged markup with `--commit`, the whole tree otherwise). `--full` adds msrv, deny and
# package for Rust paths and always runs secrets. A failing `merge-base`, a missing `origin/main` or an
# empty change set means the set is unknown, and every step the mode can select is selected.
#
#   scripts/gate.sh --commit       per-commit check: fmt, clippy, example versions, tests and
#                                  doc-default for Rust paths, shellcheck for shell files, the factory
#                                  steps for factory paths, prettier for staged markup, and deny and
#                                  MSRV when a Cargo manifest is staged
#   scripts/gate.sh                standard: the CI lint, test, docs and arm steps the paths need
#   scripts/gate.sh --full         standard plus msrv, deny, package (Rust paths) and secrets
#   scripts/gate.sh --list         print the change set, the selected steps and why, run nothing
#   scripts/gate.sh --keep-going   do not stop at the first failing step
#   scripts/gate.sh --require-all  a skipped step is a failure
#
# Environment:
#   GATE_ROOT         run in this directory instead of the repository root (tests aim it at a fixture)
#   GATE_PRETTIER     0 skips the prettier step (default 1); prettier is a local pre-commit hook, not a CI job
#   GATE_PRETTIER_CMD the prettier command (default: npx --yes prettier@3.9.10)
#
# Output: `==> <step> (<command>)` per step, a log per step in target/gate/<step>.log, the last 40 lines
# of a failing step, and a final table of PASS, FAIL and SKIP lines. A step whose input is absent is
# skipped with its reason, never failed (which is why the deny step skips without `deny.toml`: the
# advisory database is fetched over the network, and the factory tests must stay offline). Exit 0
# without a FAIL (and without a SKIP under --require-all), 1 on a failure, 2 on bad usage. The gate
# never formats or edits files.
#
# A passing run stamps the index tree hash in `.git/syncspin-gate-ok` when the worktree matches the
# index; `.githooks/pre-commit` compares it. The stamp is a speed bump, not a control: it lives in
# `.git`, covers only the tree hash, and anything with a shell can write it.

set -euo pipefail

cd "${GATE_ROOT:-$(dirname "$0")/..}"

usage() {
  printf 'usage: %s [--commit | --full] [--list] [--keep-going] [--require-all]\n' "$0" >&2
  exit 2
}

mode=standard
mode_set=0
list=0
keep_going=0
require_all=0
for arg in "$@"; do
  case "$arg" in
    --commit | --full)
      if [ "$mode_set" = 1 ]; then usage; fi
      mode_set=1
      mode="${arg#--}"
      ;;
    --list) list=1 ;;
    --keep-going) keep_going=1 ;;
    --require-all) require_all=1 ;;
    *) usage ;;
  esac
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  printf '%s: not a git repository: %s\n' "$0" "$PWD" >&2
  exit 2
fi

arm_target=armv7-unknown-linux-gnueabihf
prettier_cmd="${GATE_PRETTIER_CMD:-npx --yes prettier@3.9.10}"

staged=""
if [ "$mode" = commit ]; then
  staged=$(git diff --cached --name-only --diff-filter=ACMRD || true)
fi
staged_match() {
  grep -Eq "$1" <<<"$staged"
}

# The change set: the paths this run has to consider, one per line, and where they came from.
# `--commit` looks at the staged index. Standard and `--full` look at everything since the merge base
# with `origin/main` (committed, staged and unstaged) plus the untracked files. A failing merge-base
# (no `origin/main`) and an empty set leave the selection unknown.
changed=""
paths_state=unknown
paths_src="commit index"
if [ "$mode" = commit ]; then
  changed=$staged
  if [ -n "$changed" ]; then paths_state=known; fi
else
  paths_src="branch since origin/main"
  merge_base=$(git merge-base HEAD refs/remotes/origin/main 2>/dev/null) || merge_base=""
  if [ -n "$merge_base" ]; then
    changed=$({
      git diff --name-only --diff-filter=ACMRD "$merge_base" || true
      git ls-files --others --exclude-standard || true
    } | LC_ALL=C sort -u)
    if [ -n "$changed" ]; then paths_state=known; fi
  fi
fi

# The path classes the selection is built from.
class_rust=0
class_shell=0
class_factory=0
if [ "$paths_state" = known ]; then
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
      *.rs | Cargo.toml | */Cargo.toml | Cargo.lock | */Cargo.lock | rust-toolchain.toml | */rust-toolchain.toml | .cargo/* | deny.toml | crates/* | examples/*)
        class_rust=1
        ;;
    esac
    case "$path" in
      *.sh | .githooks/*) class_shell=1 ;;
    esac
    case "$path" in
      scripts/* | docs/factory/* | .githooks/* | .opencode/* | .claude/* | opencode.json | opencode.jsonc | AGENTS.md | CLAUDE.md | .gitignore)
        class_factory=1
        ;;
    esac
  done <<<"$changed"
fi

# Staged markdown, yaml and json files that exist and are not symlinks (prettier refuses an
# explicit symlink argument).
prettier_files() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [[ "$f" =~ \.(md|ya?ml|json|json5)$ ]] || continue
    if [ -f "$f" ] && [ ! -L "$f" ]; then printf '%s\n' "$f"; fi
  done < <(git diff --cached --name-only --diff-filter=ACMR)
}

sel_names=()
sel_why=()
add() {
  sel_names+=("$1")
  sel_why+=("$2")
}

# Rust paths, or an unknown change set, select the cargo steps of the mode.
if [ "$class_rust" = 1 ] || [ "$paths_state" = unknown ]; then
  add fmt "CI lint: cargo fmt"
  add clippy "CI lint: clippy with all targets and features"
  add example-versions "CI lint: example manifests"
  if [ "$mode" != commit ]; then
    add roles "CI lint and test: client role feature sets"
  fi
  add test "CI test: workspace tests"
  if [ "$mode" != commit ]; then
    add test-pairing "CI test: pairing-code and storage-file features"
    add test-lib-defaults "CI test: library crates with their own defaults"
    add test-mdns "CI test: the mdns-pair flow"
  fi
  add doc-default "CI docs: default features, warnings denied"
  if [ "$mode" != commit ]; then
    add doc-all "CI docs: all features, warnings denied"
    add arm "CI arm: armv7 compile guard"
  fi
fi
if [ "$class_shell" = 1 ] || [ "$paths_state" = unknown ]; then
  add shellcheck "CI lint: shell scripts and hooks"
fi
if [ "$class_factory" = 1 ] || [ "$paths_state" = unknown ]; then
  add factory-sync "CI lint: generated agent files match their sources"
  add factory-tests "CI lint: factory tests with stub CLIs"
fi
add prettier "LOCAL ONLY: a pre-commit hook, not a CI job"
if [ "$mode" = full ]; then
  if [ "$class_rust" = 1 ] || [ "$paths_state" = unknown ]; then
    add msrv "CI msrv: tests on Rust 1.85"
    add deny "CI deny: licences, advisories, sources"
    add package "CI package: cargo package for syncspin-core"
  fi
  add secrets "CI secrets: gitleaks over the history"
elif [ "$mode" = commit ]; then
  # A staged Cargo manifest keeps today's deny and MSRV steps; an unknown index selects them too.
  if [ "$paths_state" = unknown ] || staged_match '(^|/)Cargo\.(toml|lock)$'; then
    add deny "licences, advisories, sources"
    add msrv "tests on Rust 1.85"
  fi
fi

step_command() {
  case "$1" in
    fmt) printf 'cargo fmt --all -- --check' ;;
    clippy) printf 'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings' ;;
    example-versions) printf 'scripts/check-example-versions.sh' ;;
    roles) printf 'scripts/check-roles.sh' ;;
    test) printf 'cargo test --workspace --locked' ;;
    test-pairing) printf 'cargo test --workspace --features pairing-code,storage-file --locked' ;;
    test-lib-defaults) printf 'cargo test -p syncspin-core -p syncspin-client --locked' ;;
    test-mdns) printf 'cargo test -p mdns-pair --features mdns --locked' ;;
    doc-default) printf "RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked" ;;
    doc-all) printf "RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --all-features" ;;
    arm)
      printf 'cargo check -p syncspin-core -p syncspin-client -p syncspin-server --all-features --target %s --locked' "$arm_target"
      printf ' && cargo check -p syncspin-client --target %s --locked' "$arm_target"
      printf ' && cargo check -p syncspin-client --no-default-features --target %s --locked' "$arm_target"
      ;;
    shellcheck) printf "git ls-files -z '*.sh' '.githooks/*' | xargs -0 shellcheck" ;;
    factory-sync) printf 'scripts/factory-sync.sh --check' ;;
    factory-tests)
      if [ "${GATE_PRETTIER:-1}" != 0 ] && command -v npx >/dev/null 2>&1; then
        printf 'FACTORY_TEST_PRETTIER=1 '
      fi
      printf 'scripts/test-factory.sh'
      ;;
    prettier)
      if [ "$mode" = commit ]; then
        local f
        printf '%s --check' "$prettier_cmd"
        while IFS= read -r f; do printf ' %q' "$f"; done < <(prettier_files)
      else
        printf '%s --check .' "$prettier_cmd"
      fi
      ;;
    msrv)
      printf 'RUSTUP_TOOLCHAIN=1.85.0 cargo test --workspace --locked'
      printf ' && RUSTUP_TOOLCHAIN=1.85.0 cargo test --workspace --features pairing-code,storage-file --locked'
      ;;
    deny) printf 'cargo deny check' ;;
    package) printf 'cargo package -p syncspin-core --locked' ;;
    secrets) printf 'gitleaks git --redact --no-banner' ;;
    *) return 1 ;;
  esac
}

have_pkg() {
  cargo pkgid -p "$1" >/dev/null 2>&1
}

# Prints the reason to skip a step, or nothing when it runs.
skip_reason() {
  local first
  case "$1" in
    example-versions)
      [ -f scripts/check-example-versions.sh ] || printf 'not present'
      ;;
    roles)
      if [ ! -f scripts/check-roles.sh ]; then
        printf 'not present'
      elif ! have_pkg syncspin-client; then
        printf 'package not present'
      fi
      ;;
    test-pairing)
      have_pkg syncspin-core || printf 'package not present'
      ;;
    test-lib-defaults)
      if ! have_pkg syncspin-core || ! have_pkg syncspin-client; then printf 'package not present'; fi
      ;;
    test-mdns)
      have_pkg mdns-pair || printf 'package not present'
      ;;
    arm)
      if ! have_pkg syncspin-core || ! have_pkg syncspin-client || ! have_pkg syncspin-server; then
        printf 'package not present'
      elif [[ "$(rustup target list --installed 2>/dev/null || true)" != *"$arm_target"* ]]; then
        printf 'target %s not installed (rustup target add %s)' "$arm_target" "$arm_target"
      fi
      ;;
    shellcheck)
      if [ -z "$(git ls-files '*.sh' '.githooks/*')" ]; then
        printf 'no shell files'
      elif ! command -v shellcheck >/dev/null 2>&1; then
        printf 'shellcheck not installed'
      fi
      ;;
    factory-sync)
      [ -f scripts/factory-sync.sh ] || printf 'not present'
      ;;
    factory-tests)
      [ -f scripts/test-factory.sh ] || printf 'not present'
      ;;
    prettier)
      read -r first _ <<<"$prettier_cmd"
      if [ "${GATE_PRETTIER:-1}" = 0 ]; then
        printf 'disabled'
      elif ! command -v "$first" >/dev/null 2>&1; then
        printf '%s not found' "$first"
      elif [ "$mode" = commit ] && [ -z "$(prettier_files)" ]; then
        printf 'no md, yaml or json files staged'
      fi
      ;;
    msrv)
      if [[ "$(rustup toolchain list 2>/dev/null || true)" != *1.85.0* ]]; then
        printf 'toolchain 1.85.0 not installed (rustup toolchain install 1.85.0)'
      fi
      ;;
    deny)
      if [ ! -f deny.toml ]; then
        printf 'deny.toml not present'
      elif ! command -v cargo-deny >/dev/null 2>&1; then
        printf 'cargo-deny not installed'
      fi
      ;;
    package)
      have_pkg syncspin-core || printf 'package not present'
      ;;
    secrets)
      command -v gitleaks >/dev/null 2>&1 || printf 'gitleaks not installed'
      ;;
  esac
}

if [ "$list" = 1 ]; then
  if [ "$paths_state" = known ]; then
    printf 'paths: %s changed (%s)\n' "$(printf '%s\n' "$changed" | grep -c . || true)" "$paths_src"
  else
    printf 'paths: unknown (every step of this mode)\n'
  fi
  for i in "${!sel_names[@]}"; do
    name="${sel_names[$i]}"
    printf '%-18s %s\n' "$name" "${sel_why[$i]}"
    printf '%-18s $ %s\n' "" "$(step_command "$name")"
  done
  exit 0
fi

stamp_path=$(git rev-parse --git-path syncspin-gate-ok)
rm -f "$stamp_path"
mkdir -p target/gate

results=()
failed=0
skipped=0
for i in "${!sel_names[@]}"; do
  name="${sel_names[$i]}"
  reason=$(skip_reason "$name")
  if [ -n "$reason" ]; then
    printf 'SKIP %s %s\n' "$name" "$reason"
    results+=("SKIP|$name|0|$reason")
    skipped=$((skipped + 1))
    continue
  fi
  cmd=$(step_command "$name")
  printf '==> %s (%s)\n' "$name" "$cmd"
  start=$SECONDS
  if bash -euo pipefail -c "$cmd" >"target/gate/$name.log" 2>&1; then
    results+=("PASS|$name|$((SECONDS - start))|")
  else
    results+=("FAIL|$name|$((SECONDS - start))|")
    failed=1
    printf 'FAIL %s, last 40 lines of target/gate/%s.log:\n' "$name" "$name"
    tail -n 40 "target/gate/$name.log"
    if [ "$keep_going" = 0 ]; then break; fi
  fi
done

printf '\n'
for r in "${results[@]}"; do
  IFS='|' read -r status name secs reason <<<"$r"
  printf '%-4s %-18s %ss %s\n' "$status" "$name" "$secs" "$reason"
done

if [ "$failed" = 1 ]; then
  printf 'gate: FAILED (logs in target/gate/)\n' >&2
  exit 1
fi
if [ "$require_all" = 1 ] && [ "$skipped" -gt 0 ]; then
  printf 'gate: %s step(s) skipped and --require-all is set\n' "$skipped" >&2
  exit 1
fi

if git diff --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  tree=$(git write-tree)
  printf '%s\n' "$tree" >"$stamp_path"
  printf 'gate: passed, stamped tree %s\n' "$tree"
else
  printf 'gate: passed, not stamped (the worktree differs from the index)\n'
fi
