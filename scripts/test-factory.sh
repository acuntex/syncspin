#!/usr/bin/env bash
#
# Hermetic tests for the code factory: the gate, the hooks and (as they land) the generator, the
# permission files and the driver. No network, no model: every CLI the factory could start is a stub
# on PATH, and the one real-cargo test builds its own fixture workspace in a temporary directory.
#
#   scripts/test-factory.sh              all sections
#   scripts/test-factory.sh gate hooks   only the named sections
#
# Sections: gate, fixture, hooks, static.
#
# FACTORY_TEST_PRETTIER=1 enables the checks that need prettier (the gate sets it when npx exists);
# without it they run only when prettier is already installed.

# The driver exports the hook variables and its children inherit them, and `gate.sh` runs this script
# inside such a child. Without this reset every `git commit` in a temporary fixture would run the
# real pre-commit stamp check.
unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE
unset GATE_ROOT GATE_PRETTIER GATE_PRETTIER_CMD

set -euo pipefail

cd "$(dirname "$0")/.."
repo=$PWD

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0
failed=0

ok() {
  passed=$((passed + 1))
}
bad() {
  failed=$((failed + 1))
  printf 'FAIL: %s\n' "$1" >&2
}
# assert <description> <command...>
assert() {
  local desc=$1
  shift
  if "$@"; then ok; else bad "$desc"; fi
}
# refute <description> <command...>
refute() {
  local desc=$1
  shift
  if "$@"; then bad "$desc"; else ok; fi
}
has() { grep -Eq -- "$2" <<<"$1"; }
hasnt() { ! grep -Eq -- "$2" <<<"$1"; }

# ---------------------------------------------------------------------------
# Fixtures

# A git repository with an ignored target directory and one commit.
new_repo() {
  local dir=$1
  mkdir -p "$dir"
  git init -q "$dir"
  git -C "$dir" config user.name "Test"
  git -C "$dir" config user.email "test@example.invalid"
  git -C "$dir" config commit.gpgsign false
  printf '/target\n' >"$dir/.gitignore"
  git -C "$dir" add .gitignore
  git -C "$dir" commit -q -m "chore: init"
}

# Stub tools for the gate tests. `cargo pkgid -p <name>` fails for names in STUB_ABSENT, any other
# cargo call fails when its arguments contain STUB_FAIL, and every call is appended to STUB_LOG.
make_stubs() {
  local bin=$1
  mkdir -p "$bin"
  cat >"$bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${STUB_LOG:?}"
if [ "${1:-}" = pkgid ]; then
  case " ${STUB_ABSENT:-} " in *" ${3:-} "*) exit 101 ;; esac
  exit 0
fi
if [ -n "${STUB_FAIL:-}" ] && [[ "$*" == *"$STUB_FAIL"* ]]; then
  echo "stub cargo: failing on purpose"
  exit 101
fi
exit 0
STUB
  cat >"$bin/rustup" <<'STUB'
#!/usr/bin/env bash
printf 'rustup %s\n' "$*" >>"${STUB_LOG:?}"
case "$*" in
  "target list --installed") if [ "${STUB_ARM:-0}" = 1 ]; then echo armv7-unknown-linux-gnueabihf; fi ;;
  "toolchain list") echo "stable-x86_64-unknown-linux-gnu (default)" ;;
esac
exit 0
STUB
  chmod +x "$bin/cargo" "$bin/rustup"
}

stub_script() {
  local path=$1
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$0 $*" >>"${STUB_LOG:?}"
exit 0
STUB
  chmod +x "$path"
}

# Run the repo's gate against a root with the stubs first on PATH.
# Sets gate_out and gate_rc; the full output is also kept in $gate_out.
run_gate() {
  local root=$1
  shift
  gate_rc=0
  gate_out=$(cd "$root" && GATE_ROOT="$root" GATE_PRETTIER=0 STUB_LOG="$tmp/stub.log" PATH="$tmp/bin:$PATH" "$repo/scripts/gate.sh" "$@" 2>&1) || gate_rc=$?
}

section_gate() {
  local root

  make_stubs "$tmp/bin"

  # G1: fail-fast versus --keep-going.
  root=$tmp/g1
  new_repo "$root"
  : >"$tmp/stub.log"
  STUB_FAIL="clippy" run_gate "$root"
  assert "G1 a failing step exits 1" test "$gate_rc" = 1
  assert "G1 the table has FAIL clippy" has "$gate_out" '^FAIL +clippy '
  assert "G1 the failing step names its log" has "$gate_out" 'target/gate/clippy.log'
  assert "G1 fail-fast stops before the test step" hasnt "$gate_out" '^(PASS|FAIL) +test '
  refute "G1 fail-fast never ran cargo test" grep -q '^test --workspace --locked' "$tmp/stub.log"
  : >"$tmp/stub.log"
  STUB_FAIL="clippy" run_gate "$root" --keep-going
  assert "G1 --keep-going still exits 1" test "$gate_rc" = 1
  assert "G1 --keep-going runs the later test step" has "$gate_out" '^PASS +test '

  # G2: --require-all turns a SKIP into a failure.
  root=$tmp/g2
  new_repo "$root"
  run_gate "$root"
  assert "G2 skips alone do not fail" test "$gate_rc" = 0
  assert "G2 a skip is reported with its reason" has "$gate_out" '^SKIP +example-versions +not present'
  run_gate "$root" --require-all
  assert "G2 --require-all fails on a skip" test "$gate_rc" = 1

  # G3: --list runs nothing and marks prettier local-only.
  root=$tmp/g3
  new_repo "$root"
  : >"$tmp/stub.log"
  run_gate "$root" --list
  assert "G3 --list exits 0" test "$gate_rc" = 0
  assert "G3 --list ran no tool" test ! -s "$tmp/stub.log"
  assert "G3 --list marks prettier local only" has "$gate_out" '^prettier +LOCAL ONLY'
  assert "G3 --list shows the step command" has "$gate_out" 'cargo fmt --all -- --check'
  assert "G3 --list wrote no log" test ! -e "$root/target/gate"

  # G4: --commit selects steps by staged paths.
  root=$tmp/g4
  new_repo "$root"
  run_gate "$root" --list --commit
  assert "G4 nothing staged selects no factory tests" hasnt "$gate_out" '^factory-tests '
  assert "G4 nothing staged selects no deny" hasnt "$gate_out" '^deny '
  mkdir -p "$root/scripts"
  printf '#!/usr/bin/env bash\n' >"$root/scripts/x.sh"
  git -C "$root" add scripts/x.sh
  run_gate "$root" --list --commit
  assert "G4 staged scripts select factory tests" has "$gate_out" '^factory-tests '
  assert "G4 staged scripts select the generator check" has "$gate_out" '^factory-sync '
  assert "G4 staged scripts do not select deny" hasnt "$gate_out" '^deny '
  git -C "$root" reset -q
  printf 'x\n' >"$root/Cargo.lock"
  git -C "$root" add Cargo.lock
  run_gate "$root" --list --commit
  assert "G4 staged Cargo.lock selects deny" has "$gate_out" '^deny '
  assert "G4 staged Cargo.lock selects msrv" has "$gate_out" '^msrv '
  assert "G4 Cargo.lock does not select factory tests" hasnt "$gate_out" '^factory-tests '
  run_gate "$root" --list
  assert "G4 standard mode has no deny" hasnt "$gate_out" '^deny '
  run_gate "$root" --list --full
  assert "G4 --full lists deny" has "$gate_out" '^deny '
  assert "G4 --full lists msrv" has "$gate_out" '^msrv '
  assert "G4 --full lists package" has "$gate_out" '^package '
  assert "G4 --full lists secrets" has "$gate_out" '^secrets '

  # G5: a script-backed step with an absent script is SKIP not present, and runs once it exists.
  root=$tmp/g5
  new_repo "$root"
  run_gate "$root"
  assert "G5 absent generator script is skipped" has "$gate_out" '^SKIP +factory-sync +not present'
  assert "G5 absent factory tests are skipped" has "$gate_out" '^SKIP +factory-tests +not present'
  assert "G5 absent roles script is skipped" has "$gate_out" '^SKIP +roles +not present'
  assert "G5 absent example script is skipped" has "$gate_out" '^SKIP +example-versions +not present'
  stub_script "$root/scripts/factory-sync.sh"
  stub_script "$root/scripts/check-example-versions.sh"
  git -C "$root" add scripts
  git -C "$root" commit -q -m "chore: add scripts"
  : >"$tmp/stub.log"
  run_gate "$root"
  assert "G5 the generator step runs once the script exists" has "$gate_out" '^PASS +factory-sync '
  assert "G5 the example step runs once the script exists" has "$gate_out" '^PASS +example-versions '
  assert "G5 the generator ran with --check" grep -q 'factory-sync.sh --check' "$tmp/stub.log"
  STUB_ABSENT="syncspin-core" run_gate "$root"
  assert "G5 an absent package is skipped with its reason" has "$gate_out" '^SKIP +test-pairing +package not present'

  # G6: the stamp is written only on a full pass with a clean worktree.
  root=$tmp/g6
  new_repo "$root"
  local stamp
  stamp=$(git -C "$root" rev-parse --git-path syncspin-gate-ok)
  run_gate "$root"
  assert "G6 a passing run writes the stamp" test -f "$root/$stamp"
  assert "G6 the stamp is the index tree hash" test "$(cat "$root/$stamp")" = "$(git -C "$root" write-tree)"
  STUB_FAIL="clippy" run_gate "$root"
  assert "G6 a failing run removes the stamp" test ! -e "$root/$stamp"
  printf 'changed\n' >>"$root/.gitignore"
  run_gate "$root"
  assert "G6 a dirty worktree passes" test "$gate_rc" = 0
  assert "G6 a dirty worktree is not stamped" test ! -e "$root/$stamp"
  assert "G6 the missing stamp is explained" has "$gate_out" 'not stamped'
  git -C "$root" checkout -q .gitignore
  printf 'junk\n' >"$root/untracked.txt"
  run_gate "$root"
  assert "G6 an untracked file is not stamped" test ! -e "$root/$stamp"
  rm "$root/untracked.txt"
  run_gate "$root" --require-all
  assert "G6 --require-all with skips is not stamped" test ! -e "$root/$stamp"

  # G7: GATE_ROOT is honoured.
  root=$tmp/g7
  new_repo "$root"
  run_gate "$root"
  assert "G7 logs land in the aimed root" test -f "$root/target/gate/fmt.log"

  # G8: a missing ARM target is a SKIP with the install hint.
  root=$tmp/g8
  new_repo "$root"
  run_gate "$root"
  assert "G8 missing arm target is skipped" has "$gate_out" '^SKIP +arm +target armv7-unknown-linux-gnueabihf not installed \(rustup target add'
  assert "G8 the skip does not fail the gate" test "$gate_rc" = 0
  run_gate "$root" --require-all
  assert "G8 --require-all fails on the skip" test "$gate_rc" = 1
  STUB_ARM=1 run_gate "$root"
  assert "G8 an installed target runs the arm step" has "$gate_out" '^PASS +arm '

  # G9: no step formats or edits files.
  : >"$tmp/stub.log"
  run_gate "$tmp/g8"
  assert "G9 cargo fmt is only ever a check" grep -q '^fmt --all -- --check$' "$tmp/stub.log"
  assert "G9 no cargo fmt call without --check" test -z "$(grep '^fmt' "$tmp/stub.log" | grep -v -- '--check' || true)"
  refute "G9 the script never writes with prettier" grep -q -- '--write' "$repo/scripts/gate.sh"

  # G10: GATE_PRETTIER=0 and an empty shell-file list are SKIPs with reasons.
  root=$tmp/g10
  new_repo "$root"
  run_gate "$root"
  assert "G10 disabled prettier is skipped" has "$gate_out" '^SKIP +prettier +disabled'
  assert "G10 no shell files is skipped" has "$gate_out" '^SKIP +shellcheck +no shell files'
}

section_fixture() {
  if ! command -v cargo >/dev/null 2>&1 || ! cargo fmt --version >/dev/null 2>&1 || ! cargo clippy --version >/dev/null 2>&1; then
    printf 'skip: fixture test needs cargo, rustfmt and clippy\n'
    return
  fi
  local root=$tmp/fx out rc
  mkdir -p "$root/crates/fx/src"
  cat >"$root/Cargo.toml" <<'TOML'
[workspace]
resolver = "2"
members = ["crates/fx"]
TOML
  cat >"$root/crates/fx/Cargo.toml" <<'TOML'
[package]
name = "fx"
version = "0.1.0"
edition = "2021"
publish = false
TOML
  cat >"$root/crates/fx/src/lib.rs" <<'RS'
//! A fixture crate for the gate test.

/// Adds two numbers.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds() {
        assert_eq!(add(1, 2), 3);
    }
}
RS
  printf '/target\n' >"$root/.gitignore"
  (cd "$root" && cargo generate-lockfile --offline >/dev/null 2>&1)
  git init -q "$root"
  git -C "$root" config user.name "Test"
  git -C "$root" config user.email "test@example.invalid"
  git -C "$root" config commit.gpgsign false
  git -C "$root" add -A
  git -C "$root" commit -q -m "chore: fixture"

  rc=0
  out=$(cd "$root" && GATE_ROOT="$root" GATE_PRETTIER=0 "$repo/scripts/gate.sh" --commit 2>&1) || rc=$?
  assert "fixture --commit passes" test "$rc" = 0
  assert "fixture --commit PASS fmt" has "$out" '^PASS +fmt '
  assert "fixture --commit PASS clippy" has "$out" '^PASS +clippy '
  assert "fixture --commit PASS test" has "$out" '^PASS +test '
  assert "fixture --commit SKIP example-versions" has "$out" '^SKIP +example-versions +not present'
  assert "fixture --commit SKIP prettier" has "$out" '^SKIP +prettier +disabled'
  assert "fixture --commit SKIP shellcheck" has "$out" '^SKIP +shellcheck +no shell files'
  assert "fixture worktree is clean after --commit" test -z "$(git -C "$root" status --porcelain)"

  rc=0
  out=$(cd "$root" && GATE_ROOT="$root" GATE_PRETTIER=0 "$repo/scripts/gate.sh" 2>&1) || rc=$?
  assert "fixture standard passes" test "$rc" = 0
  assert "fixture standard PASS doc-default" has "$out" '^PASS +doc-default '
  assert "fixture standard PASS doc-all" has "$out" '^PASS +doc-all '
  for step in test-pairing test-lib-defaults test-mdns arm; do
    assert "fixture standard SKIP $step" has "$out" "^SKIP +$step +package not present"
  done
  assert "fixture standard SKIP roles" has "$out" '^SKIP +roles +not present'
  assert "fixture worktree is clean after standard" test -z "$(git -C "$root" status --porcelain)"
}

section_hooks() {
  local root=$tmp/h1 remote=$tmp/h2.git clone=$tmp/h2 stamp tree

  # shellcheck disable=SC2329  # called through assert and refute
  hook_commit() {
    git -C "$root" commit -q -m "$1" >/dev/null 2>&1
  }

  # H1: pre-commit compares the stamp with the index tree.
  new_repo "$root"
  stamp=$(git -C "$root" rev-parse --git-path syncspin-gate-ok)
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0="$repo/.githooks"
  printf 'one\n' >"$root/a.txt"
  git -C "$root" add a.txt
  refute "H1 a commit without a stamp is rejected" hook_commit "feat: a"
  tree=$(git -C "$root" write-tree)
  printf '%s\n' "$tree" >"$root/$stamp"
  assert "H1 a commit with a matching stamp is accepted" hook_commit "feat: a"
  printf 'two\n' >"$root/b.txt"
  git -C "$root" add b.txt
  refute "H1 a stale stamp is rejected" hook_commit "feat: b"
  printf 'wrong\n' >"$root/$stamp"
  refute "H1 a wrong stamp is rejected" hook_commit "feat: b"
  git -C "$root" write-tree >"$root/$stamp"
  assert "H1 the matching stamp is accepted again" hook_commit "feat: b"
  unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0

  # H2: pre-push refusals and the fast-forward of a factory branch.
  git init -q --bare "$remote"
  git clone -q "$remote" "$clone" 2>/dev/null
  git -C "$clone" config user.name "Test"
  git -C "$clone" config user.email "test@example.invalid"
  git -C "$clone" config commit.gpgsign false
  printf 'x\n' >"$clone/f.txt"
  git -C "$clone" add f.txt
  git -C "$clone" commit -q -m "chore: base"
  # shellcheck disable=SC2329  # called through assert and refute
  hook_push() {
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0="$repo/.githooks" git -C "$clone" push -q "$@" >/dev/null 2>&1
  }
  refute "H2 a push to main is refused" hook_push origin HEAD:refs/heads/main
  refute "H2 a push to master is refused" hook_push origin HEAD:refs/heads/master
  assert "H2 a new factory branch is accepted" hook_push origin HEAD:refs/heads/factory/x
  printf 'y\n' >>"$clone/f.txt"
  git -C "$clone" commit -q -a -m "chore: more"
  assert "H2 a fast-forward is accepted" hook_push origin HEAD:refs/heads/factory/x
  git -C "$clone" commit -q --amend -m "chore: amended"
  refute "H2 a non-fast-forward is refused" hook_push origin +HEAD:refs/heads/factory/x
  refute "H2 a deletion is refused" hook_push origin :refs/heads/factory/x
  git -C "$clone" tag v-test
  refute "H2 a tag push is refused" hook_push origin refs/tags/v-test
  assert "H2 the remote branch survived" git -C "$remote" show-ref --verify --quiet refs/heads/factory/x
  refute "H2 the remote has no main" git -C "$remote" show-ref --verify --quiet refs/heads/main
}

section_static() {
  if command -v shellcheck >/dev/null 2>&1; then
    assert "static: shellcheck is clean over scripts and hooks" bash -c "git -C '$repo' ls-files -z '*.sh' '.githooks/*' | (cd '$repo' && xargs -0 shellcheck)"
  else
    printf 'skip: shellcheck is not installed\n'
  fi
}

sections=("$@")
if [ ${#sections[@]} -eq 0 ]; then
  sections=(gate fixture hooks static)
fi
for s in "${sections[@]}"; do
  case "$s" in
    gate | fixture | hooks | static) "section_$s" ;;
    *)
      printf 'usage: %s [gate] [fixture] [hooks] [static]\n' "$0" >&2
      exit 2
      ;;
  esac
done

printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" = 0 ]
