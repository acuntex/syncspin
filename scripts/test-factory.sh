#!/usr/bin/env bash
#
# Hermetic tests for the code factory: the gate, the hooks and (as they land) the generator, the
# permission files and the driver. No network, no model: every CLI the factory could start is a stub
# on PATH, and the one real-cargo test builds its own fixture workspace in a temporary directory.
#
#   scripts/test-factory.sh              all sections
#   scripts/test-factory.sh gate hooks   only the named sections
#
# Sections: gate, fixture, hooks, sync, perm, driver, probes, static.
#
# FACTORY_TEST_SKIP_CLI=1 skips every check that starts a real opencode or claude binary (they only
# print configuration, never run a model, but a contributor may not want them started).
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

have_cargo_tools() {
  command -v cargo >/dev/null 2>&1 && cargo fmt --version >/dev/null 2>&1 && cargo clippy --version >/dev/null 2>&1
}

# Write a one-crate workspace (no dependencies, rustfmt-clean, one passing test) and its lock file.
write_fx_workspace() {
  local root=$1
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
}

section_fixture() {
  if ! have_cargo_tools; then
    printf 'skip: fixture test needs cargo, rustfmt and clippy\n'
    return
  fi
  local root=$tmp/fx out rc
  write_fx_workspace "$root"
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

# The prettier command the tests may use, or nothing: an explicit FACTORY_TEST_PRETTIER_CMD, a
# prettier already on PATH, or (only with FACTORY_TEST_PRETTIER=1, which the gate sets when npx
# exists) the version pinned for the repository. Tests never fetch anything on their own.
prettier_for_tests() {
  if [ -n "${FACTORY_TEST_PRETTIER_CMD:-}" ]; then
    printf '%s' "$FACTORY_TEST_PRETTIER_CMD"
  elif command -v prettier >/dev/null 2>&1; then
    printf 'prettier'
  elif [ "${FACTORY_TEST_PRETTIER:-0}" = 1 ] && command -v npx >/dev/null 2>&1; then
    printf 'npx --yes prettier@3.9.10'
  fi
}

# Top-level frontmatter keys of a generated file, one per line; fails without a closing fence.
frontmatter_keys() {
  awk 'NR==1 { if ($0 != "---") exit 1; next } /^---$/ { closed=1; exit } /^[A-Za-z]/ { sub(/:.*/, ""); print } END { exit !closed }' "$1"
}

section_sync() {
  local root=$tmp/sync out rc f key allowed
  mkdir -p "$root/scripts" "$root/docs" "$root/.claude"
  cp "$repo/scripts/factory-sync.sh" "$root/scripts/"
  cp -r "$repo/docs/factory" "$root/docs/"
  cp -r "$repo/.opencode" "$root/"
  cp -r "$repo/.claude/agents" "$repo/.claude/commands" "$root/.claude/"

  # The committed files match their sources.
  rc=0
  (cd "$repo" && scripts/factory-sync.sh --check >/dev/null 2>&1) || rc=$?
  assert "sync: --check is clean in the repository" test "$rc" = 0

  rc=0
  out=$(cd "$root" && scripts/factory-sync.sh --check 2>&1) || rc=$?
  assert "sync: --check is clean in the copy" test "$rc" = 0

  # Idempotent: writing twice changes nothing.
  local before after
  before=$(cd "$root" && find .opencode .claude -type f -exec sha256sum {} + | LC_ALL=C sort)
  (cd "$root" && scripts/factory-sync.sh && scripts/factory-sync.sh)
  after=$(cd "$root" && find .opencode .claude -type f -exec sha256sum {} + | LC_ALL=C sort)
  assert "sync: writing is idempotent" test "$before" = "$after"

  # Drift in a generated file.
  printf 'x' >>"$root/.claude/agents/factory-planner.md"
  rc=0
  out=$(cd "$root" && scripts/factory-sync.sh --check 2>&1) || rc=$?
  assert "sync: a changed generated file fails --check" test "$rc" = 1
  assert "sync: the stale file is named" has "$out" '\.claude/agents/factory-planner\.md'
  assert "sync: the fix command is named" has "$out" 'scripts/factory-sync\.sh'
  (cd "$root" && scripts/factory-sync.sh)

  # Drift in a source.
  printf '\nExtra line.\n' >>"$root/docs/factory/roles/implementer.md"
  rc=0
  out=$(cd "$root" && scripts/factory-sync.sh --check 2>&1) || rc=$?
  assert "sync: a changed source fails --check" test "$rc" = 1
  assert "sync: the OpenCode file of the changed source is named" has "$out" '\.opencode/agents/factory-implementer\.md'
  assert "sync: the Claude file of the changed source is named" has "$out" '\.claude/agents/factory-implementer\.md'
  (cd "$root" && scripts/factory-sync.sh)
  rc=0
  (cd "$root" && scripts/factory-sync.sh --check >/dev/null 2>&1) || rc=$?
  assert "sync: regenerating after a source change is clean" test "$rc" = 0

  # A missing file and a stale file.
  rm "$root/.opencode/agents/factory-pr-writer.md"
  printf 'old\n' >"$root/.opencode/agents/factory-gone.md"
  rc=0
  out=$(cd "$root" && scripts/factory-sync.sh --check 2>&1) || rc=$?
  assert "sync: a missing file fails --check" has "$out" 'factory-pr-writer\.md'
  assert "sync: a stale file fails --check" has "$out" 'factory-gone\.md'
  (cd "$root" && scripts/factory-sync.sh)
  assert "sync: writing removes the stale file" test ! -e "$root/.opencode/agents/factory-gone.md"
  assert "sync: writing restores the missing file" test -f "$root/.opencode/agents/factory-pr-writer.md"

  # A bad source is a usage error, not a generated file.
  printf 'surprise=1\n' >>"$root/docs/factory/meta/planner.conf"
  rc=0
  (cd "$root" && scripts/factory-sync.sh --check >/dev/null 2>&1) || rc=$?
  assert "sync: an unknown conf key is rejected" test "$rc" = 2

  # Frontmatter fence and key whitelist of every generated file in the repository.
  for f in "$repo"/.opencode/agents/factory-*.md; do
    allowed=" description mode permission "
    assert "sync: $(basename "$f") (opencode) has a closed fence" frontmatter_keys "$f" >/dev/null
    for key in $(frontmatter_keys "$f"); do
      assert "sync: opencode key $key is whitelisted" has "$allowed" " $key "
    done
    assert "sync: $(basename "$f") (opencode) bash rules start with the deny baseline" test "$(grep -A1 '^  bash:$' "$f" | tail -n 1)" = '    "*": "deny"'
    refute "sync: $(basename "$f") (opencode) has no ask rule" grep -q '": "ask"' "$f"
    assert "sync: $(basename "$f") (opencode) orders baseline, allows, denies" has "$(sed -n '/^  bash:$/,/^---$/p' "$f" | grep -o '": "\(allow\|deny\)"' | tr -d '\n')" '^": "deny"(": "allow")+(": "deny")+$'
  done
  for f in "$repo"/.claude/agents/factory-*.md; do
    allowed=" name description tools model maxTurns "
    assert "sync: $(basename "$f") (claude agent) has a closed fence" frontmatter_keys "$f" >/dev/null
    for key in $(frontmatter_keys "$f"); do
      assert "sync: claude agent key $key is whitelisted" has "$allowed" " $key "
    done
  done
  allowed=" description argument-hint allowed-tools "
  for key in $(frontmatter_keys "$repo/.claude/commands/factory.md"); do
    assert "sync: command key $key is whitelisted" has "$allowed" " $key "
  done
  # shellcheck disable=SC2016  # a literal $ARGUMENTS, not a shell expansion
  assert "sync: the command passes the task as data once" test "$(grep -c '^\$ARGUMENTS$' "$repo/.claude/commands/factory.md")" = 1
  refute "sync: the command never uses the task in a shell block" grep -q '!`' "$repo/.claude/commands/factory.md"
  assert "sync: every generated file starts with a fence" test -z "$(for f in "$repo"/.opencode/agents/*.md "$repo"/.claude/agents/*.md "$repo"/.claude/commands/*.md; do head -n1 "$f" | grep -qx -- '---' || echo "$f"; done)"
  assert "sync: every generated file names its source" test -z "$(for f in "$repo"/.opencode/agents/*.md "$repo"/.claude/agents/*.md "$repo"/.claude/commands/*.md; do grep -q 'generated by scripts/factory-sync.sh from docs/factory/roles/' "$f" || echo "$f"; done)"

  # Prettier stability of the generated files and the sources.
  local pcmd
  pcmd=$(prettier_for_tests)
  if [ -n "$pcmd" ]; then
    rc=0
    # shellcheck disable=SC2086  # the command is a word list on purpose
    (cd "$repo" && $pcmd --check docs/factory .opencode .claude/agents .claude/commands >/dev/null 2>&1) || rc=$?
    assert "sync: generated files and sources are prettier-clean" test "$rc" = 0
  else
    printf 'skip: prettier is not installed and FACTORY_TEST_PRETTIER is not set\n'
  fi
}


# ---------------------------------------------------------------------------
# Driver tests (cases D1 to D38). The driver runs in a clone of a fake origin whose main branch is a
# copy of the files the factory needs. There are two origins: one whose gate is a stub that only
# stamps the tree (the default), and one whose gate is the real scripts/gate.sh (the real-gate cases).
# The agent CLIs are stubs on PATH: they write canned artifacts and log their argv and environment.

make_driver_stubs() {
  local bin=$tmp/dbin
  mkdir -p "$bin"
  cat >"$bin/opencode" <<'STUB'
#!/usr/bin/env bash
# Stub agent CLI (installed as opencode and as claude). Behaviour is steered by files in $STUB_DIR:
#   q-<queue>        first line is popped as the next verdict line (queues: plan-review, post, code)
#   hook-<kind>.sh   sourced first; set handled=1 to skip the default action
#   noop-<kind>      skip the default action;  exit-<kind>  exit with that code afterwards
#   owner-open       the plan leaves an owner decision open
#   commits          number of commits the implementer makes (default 1)
d=${STUB_DIR:?}
name=$(basename "$0")
args=("$@")
role=""
prompt=""
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --agent) role=${args[$((i + 1))]#factory-} ;;
    -p) prompt=${args[$((i + 1))]} ;;
    --allowedTools) allowed=${args[$((i + 1))]} ;;
    --disallowedTools) denied=${args[$((i + 1))]} ;;
  esac
done
if [ "$name" = opencode ]; then prompt=${args[$((${#args[@]} - 1))]}; fi
art=${FACTORY_ARTIFACT:-}
n=$(($(cat "$d/count" 2>/dev/null || echo 0) + 1))
echo "$n" >"$d/count"
kind=""
case "$art" in
  */plan.md) case "$prompt" in "Revise the plan"*) kind=plan-revise ;; *) kind=plan ;; esac ;;
  */review-plan-post.md) kind=plan-review-post ;;
  */review-plan-*.md) kind=plan-review ;;
  */review-code-*.md) kind=code-review ;;
  */pr.md) kind=pr ;;
  "") case "$prompt" in "Address the findings"*) kind=fix ;; *) kind=implement ;; esac ;;
esac
{
  echo "CALL $n $name role=$role kind=$kind artifact=$art"
  printf 'ARGV'
  printf ' %q' "$@"
  echo
  echo "ALLOWED ${allowed:-}"
  echo "DENIED ${denied:-}"
  echo "ENVNAMES $(env | cut -d= -f1 | LC_ALL=C sort | tr '\n' ' ')"
  env | grep '^GIT_CONFIG' | LC_ALL=C sort | sed 's/^/ENV /'
  echo "PROMPT $(printf '%s' "$prompt" | tr '\n' '~')"
} >>"$d/calls.log"

pop() {
  local f="$d/q-$1" line
  if [ -s "$f" ]; then
    line=$(head -n 1 "$f")
    tail -n +2 "$f" >"$f.t"
    mv "$f.t" "$f"
    printf '%s' "$line"
  else
    printf '%s' "$2"
  fi
}

handled=0
if [ -f "$d/hook-$kind.sh" ]; then
  # shellcheck disable=SC1090
  . "$d/hook-$kind.sh"
fi
if [ "$handled" != 1 ] && [ ! -f "$d/noop-$kind" ]; then
  case "$kind" in
    plan)
      {
        printf '# Plan\n\n## Goal\n\nDo it.\n\n## Owner decisions\n\n'
        if [ -f "$d/owner-open" ]; then printf -- '- Which licence?\n'; else printf 'None.\n'; fi
      } >"$art"
      ;;
    plan-revise)
      printf '\n## Changelog\n\n- revised by call %s\n' "$n" >>"$art"
      if [ -s "$FACTORY_RUN_DIR/decisions.md" ]; then sed -i 's/^- Which licence?$/None./' "$art"; fi
      ;;
    plan-review) printf '# Review\n\nChecked.\n\n%s\n' "$(pop plan-review 'VERDICT: APPROVED')" >"$art" ;;
    plan-review-post) printf '# Review\n\nChecked.\n\n%s\n' "$(pop post 'VERDICT: APPROVED')" >"$art" ;;
    code-review) printf '# Review\n\n## Observed\n\n- ran the gate\n\n## Blocker\n\n- none\n\n%s\n' "$(pop code 'VERDICT: APPROVED')" >"$art" ;;
    implement)
      for ((i = 1; i <= $(cat "$d/commits" 2>/dev/null || echo 1); i++)); do
        echo "change $i" >"impl-$i.txt"
        git add "impl-$i.txt"
        scripts/gate.sh --commit >/dev/null
        git commit -q -m "feat: stub change $i"
      done
      ;;
    fix)
      echo "fix $n" >"fix-$n.txt"
      git add "fix-$n.txt"
      scripts/gate.sh --commit >/dev/null
      git commit -q -m "fix: stub fix $n"
      ;;
    pr) printf 'feat: stub change\n\n## Summary\n\n- stub\n\n## Not verified\n\n- everything\n' >"$art" ;;
  esac
fi
if [ -f "$d/exit-$kind" ]; then exit "$(cat "$d/exit-$kind")"; fi
exit 0
STUB
  cp "$bin/opencode" "$bin/claude"
  cat >"$bin/gh" <<'STUB'
#!/usr/bin/env bash
d=${STUB_DIR:?}
printf 'gh %s\n' "$*" >>"$d/gh.log"
case "${1:-} ${2:-}" in
  "pr list") if [ -f "$d/pr-url" ]; then cat "$d/pr-url"; fi ;;
  "pr create")
    if [ -f "$d/push-main" ]; then git push -q --no-verify origin "$(cat "$d/push-main"):refs/heads/main"; fi
    if [ -f "$d/break-origin" ]; then git remote set-url origin /nonexistent-origin; fi
    if [ -f "$d/gh-create-fail" ]; then
      echo "stub gh: failing on purpose" >&2
      exit 1
    fi
    echo "https://example.invalid/pr/1" | tee "$d/pr-url"
    ;;
esac
exit 0
STUB
  chmod +x "$bin/opencode" "$bin/claude" "$bin/gh"
}

# make_origin <stub|real>: a bare repository whose main branch holds the files the factory needs.
make_origin() {
  local kind=$1 work=$tmp/origin-$1-work bare=$tmp/origin-$1.git
  mkdir -p "$work/scripts" "$work/docs" "$work/.github" "$work/.claude"
  git init -q -b main "$work"
  git -C "$work" config user.name "Test"
  git -C "$work" config user.email "test@example.invalid"
  git -C "$work" config commit.gpgsign false
  cp "$repo/scripts/factory.sh" "$repo/scripts/gate.sh" "$repo/scripts/factory-sync.sh" "$work/scripts/"
  cp -r "$repo/docs/factory" "$work/docs/"
  cp -r "$repo/.githooks" "$repo/.opencode" "$work/"
  cp -r "$repo/.claude/agents" "$repo/.claude/commands" "$repo/.claude/settings.json" "$work/.claude/"
  cp "$repo/opencode.json" "$repo/AGENTS.md" "$repo/.gitignore" "$work/"
  cp -P "$repo/CLAUDE.md" "$work/CLAUDE.md"
  cp "$repo/.github/pull_request_template.md" "$work/.github/"
  if [ "$kind" = stub ]; then
    cat >"$work/scripts/gate.sh" <<'STUB'
#!/usr/bin/env bash
# Stub gate: stamps the tree so the pre-commit hook accepts it.
cd "$(dirname "$0")/.."
if [ -n "${STUB_DIR:-}" ] && [ -f "$STUB_DIR/gate-fail" ]; then
  echo "FAIL stub"
  exit 1
fi
echo "PASS fmt"
echo "SKIP arm target not installed"
git write-tree >"$(git rev-parse --git-path syncspin-gate-ok)"
STUB
    chmod +x "$work/scripts/gate.sh"
    printf '[workspace]\nmembers = []\n' >"$work/Cargo.toml"
  else
    write_fx_workspace "$work"
    printf '/target\n/.factory/\n/.claude/settings.local.json\nCLAUDE.local.md\n' >"$work/.gitignore"
  fi
  git -C "$work" add -A
  git -C "$work" commit -q -m "chore: fixture main"
  git clone -q --bare "$work" "$bare"
  cat >"$bare/hooks/pre-receive" <<'STUB'
#!/usr/bin/env bash
if [ -n "${STUB_DIR:-}" ] && [ -f "$STUB_DIR/push-fail" ]; then
  echo "stub origin: rejecting the push" >&2
  exit 1
fi
STUB
  chmod +x "$bare/hooks/pre-receive"
}

case_n=0
# new_case <stub|real>: sets clone, sd (the stub directory) and origin_dir.
new_case() {
  case_n=$((case_n + 1))
  origin_dir=$tmp/origin-$1.git
  local cdir=$tmp/case$case_n
  sd=$cdir/stub
  clone=$cdir/repo
  mkdir -p "$sd"
  git clone -q "$origin_dir" "$clone" 2>/dev/null
  git -C "$clone" config user.name "Test"
  git -C "$clone" config user.email "test@example.invalid"
  git -C "$clone" config commit.gpgsign false
  : >"$sd/calls.log"
  : >"$sd/gh.log"
}

drv_extra=()
# drive <args...>: run the clone's driver with the stubs first on PATH; sets drv_out and drv_rc.
drive() {
  drv_rc=0
  drv_out=$(cd "$clone" && env "${drv_extra[@]}" PATH="$tmp/dbin:$PATH" STUB_DIR="$sd" FACTORY_PASS_ENV="STUB_DIR" scripts/factory.sh "$@" 2>&1) || drv_rc=$?
}

run_dir_of() {
  local d
  for d in "$clone"/.factory/runs/*; do
    [ -d "$d" ] && printf '%s' "$d"
  done
}

state_of() {
  sed -n "s/^$1=//p" "$(run_dir_of)/state"
}

count_calls() {
  grep -c "$1" "$sd/calls.log" || true
}

call_roles() {
  sed -n 's/^CALL [0-9]* [a-z]* role=\([^ ]*\) .*/\1/p' "$sd/calls.log" | paste -sd, -
}

origin_main() {
  git -C "$origin_dir" rev-parse refs/heads/main
}

# lib <function> <args...>: run a function of the driver in a subshell, sourced without running it.
lib() {
  (
    export FACTORY_LIB_ONLY=1
    # shellcheck disable=SC1091
    . "$repo/scripts/factory.sh"
    "$@"
  )
}

section_driver() {
  local be before id mut
  # Built at runtime so that no home-directory path or personal-looking name sits in the repository.
  local hm=/ho rp=quasi
  hm+=me
  rp+=name
  local zh=zxqv
  zh+=whost

  make_driver_stubs
  make_origin stub
  if have_cargo_tools; then make_origin real; fi
  unset FACTORY_BACKEND FACTORY_MODEL_HELPER FACTORY_MODEL_MAIN FACTORY_PASS_ENV

  # D1 and D18: the happy path on both backends, and what no call may ever contain.
  for be in opencode claude; do
    new_case stub
    before=$(origin_main)
    drive --backend "$be" "add a small thing"
    assert "D1 [$be] the happy path exits 0" test "$drv_rc" = 0
    assert "D1 [$be] roles run in order" test "$(call_roles)" = "planner,plan-reviewer,implementer,code-reviewer,pr-writer"
    assert "D1 [$be] exactly one pull request is created" test "$(grep -c '^gh pr create' "$sd/gh.log")" = 1
    assert "D1 [$be] the pull request targets main" has "$(grep '^gh pr create' "$sd/gh.log")" '--base main --head factory/'
    refute "D1 [$be] no merge call" grep -q 'pr merge' "$sd/gh.log"
    assert "D1 [$be] origin main did not move" test "$(origin_main)" = "$before"
    assert "D1 [$be] the factory branch is on origin" test -n "$(git -C "$origin_dir" for-each-ref "refs/heads/$(git -C "$clone" rev-parse --abbrev-ref HEAD)")"
    assert "D1 [$be] state is done" test "$(state_of status)" = "done"
    assert "D1 [$be] local main did not move" test "$(git -C "$clone" rev-parse main)" = "$before"
    refute "D18 [$be] no forbidden flag in any call" bash -c "sed -E -e '/^DENIED /d' -e 's/ --disallowedTools (\\\\ |[^ ])+//' '$sd/calls.log' | grep -Eq -- '--auto|--bare|--dangerously-skip-permissions|bypassPermissions'"
    refute "D18 [$be] no continue, session or resume flag" grep -Eq -- '^ARGV.*(--continue|--session|--resume)' "$sd/calls.log"
    if [ "$be" = claude ]; then
      id=$(basename "$(run_dir_of)")
      assert "D35 every claude phase passes --strict-mcp-config" test "$(grep -c '^ARGV.* --strict-mcp-config' "$sd/calls.log")" = "$(grep -c '^CALL ' "$sd/calls.log")"
      refute "D35 no claude phase passes --mcp-config" grep -Eq '^ARGV.* --mcp-config' "$sd/calls.log"
      assert "D17 the readonly grant starts with the run-directory Edit rule" test "$(sed -n 's/^ALLOWED //p' "$sd/calls.log" | head -n 1 | cut -d, -f1)" = "Edit(/.factory/runs/$id/plan.md)"
      refute "D17 no Write rule in a readonly grant" grep -q '^ALLOWED Edit(/.factory/runs/.*Write(' "$sd/calls.log"
      refute "D17 no double slash or home path in a grant" grep -Eq "^ALLOWED .*(//|$hm/|/Users/)" "$sd/calls.log"
      refute "D17 a readonly grant has no mutating git command" grep -Eq '^ALLOWED Edit\(/.factory/.*(git (add|commit|rm|mv|restore)|mkdir|chmod)' "$sd/calls.log"
      refute "D17 no agent gets pull request creation" grep -Eq '^ALLOWED .*(gh pr|git push|git fetch|git switch)' "$sd/calls.log"
      assert "D37 every claude phase passes --disallowedTools" test "$(grep -c '^ARGV.* --disallowedTools' "$sd/calls.log")" = "$(grep -c '^CALL ' "$sd/calls.log")"
      assert "D37 the deny list holds the factory-layer denies" has "$(sed -n 's/^DENIED //p' "$sd/calls.log" | head -n 1)" 'Bash\(git config \*\),Bash\(git -c \*\).*Bash\(python\*\).*Bash\(rm -rf \*\)'
      assert "D37 the deny list holds the AGENTS.md denies" has "$(sed -n 's/^DENIED //p' "$sd/calls.log" | head -n 1)" '^Bash\(gh pr merge \*\),Bash\(gh pr \*--auto\*\)'
      assert "D37 the deny list is the same in every phase" test "$(sed -n 's/^DENIED //p' "$sd/calls.log" | sort -u | wc -l)" = 1
      assert "D17 the implementer grant is Edit and Write" has "$(grep -A2 'role=implementer' "$sd/calls.log" | grep '^ALLOWED' || true)" '^ALLOWED Edit,Write,'
    fi
  done
  refute "D18 the driver never calls gh pr merge" grep -Eq 'gh +pr +merge' "$repo/scripts/factory.sh"
  refute "D18 the driver never passes --auto or --bare" grep -Eq -- '--(auto|bare|dangerously-skip-permissions)([^a-z-]|$)' "$repo/scripts/factory.sh"
  assert "D24 every KILL is guarded by a kill -0 probe" test -z "$(grep -- '-KILL' "$repo/scripts/factory.sh" | grep -v 'kill -0' || true)"

  # D2: changes needed, then approved: a fresh reviewer per round and distinct artifacts.
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n' >"$sd/q-plan-review"
  drive --backend opencode "t"
  assert "D2 exits 0" test "$drv_rc" = 0
  assert "D2 the reviewer ran twice" test "$(count_calls 'role=plan-reviewer')" = 2
  assert "D2 the plan was revised once" test "$(count_calls 'kind=plan-revise')" = 1
  assert "D2 round 1 artifact" has "$(cat "$sd/calls.log")" 'artifact=.*/review-plan-1\.md'
  assert "D2 round 2 artifact" has "$(cat "$sd/calls.log")" 'artifact=.*/review-plan-2\.md'

  # D3: the plan cap is 4.
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n%.0s' 1 2 3 4 5 >"$sd/q-plan-review"
  drive --backend opencode "t"
  assert "D3 exits 11" test "$drv_rc" = 11
  assert "D3 exactly 4 plan reviews" test "$(count_calls 'role=plan-reviewer')" = 4
  assert "D3 nothing was implemented" test "$(count_calls 'role=implementer')" = 0
  assert "D3 the state is stopped with exit 11" test "$(state_of exit_code)" = 11
  local d3run
  d3run=$(basename "$(run_dir_of)")
  drive --resume "$d3run"
  assert "D6 --resume after exit 11 is refused" test "$drv_rc" = 2

  # D4: the code cap is 3.
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n%.0s' 1 2 3 4 >"$sd/q-code"
  drive --backend opencode "t"
  assert "D4 exits 12" test "$drv_rc" = 12
  assert "D4 exactly 3 code reviews" test "$(count_calls 'role=code-reviewer')" = 3
  assert "D4 one implement and two fixes" test "$(count_calls 'role=implementer')" = 3

  # D5: the verdict table.
  local vf=$tmp/verdict.txt v
  assert "D5 a missing file is CHANGES" test "$(lib parse_verdict "$tmp/no-such-file")" = CHANGES
  : >"$vf"
  assert "D5 an empty file is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  printf 'looks fine to me\n' >"$vf"
  assert "D5 garbled text is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  printf 'VERDICT: APPROVED because it is good\n' >"$vf"
  assert "D5 trailing text is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  printf 'verdict: approved\n' >"$vf"
  assert "D5 wrong case is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  printf 'VERDICT: APPROVED\nand one more thing\n' >"$vf"
  assert "D5 a verdict that is not last is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  printf 'VERDICT: CHANGES NEEDED\n' >"$vf"
  assert "D5 CHANGES NEEDED is CHANGES" test "$(lib parse_verdict "$vf")" = CHANGES
  for v in 'VERDICT: APPROVED' 'VERDICT: APPROVED   ' $'VERDICT: APPROVED\r'; do
    printf 'text\n%s\n\n\n' "$v" >"$vf"
    assert "D5 an approved verdict with trailing blanks and spaces is APPROVED" test "$(lib parse_verdict "$vf")" = APPROVED
  done

  # D6 and D20: the owner gate.
  new_case stub
  : >"$sd/owner-open"
  drive --backend opencode "t"
  assert "D6 exit 10 with open decisions" test "$drv_rc" = 10
  assert "D6 the implementer did not run" test "$(count_calls 'role=implementer')" = 0
  assert "D6 a handoff exists" test -f "$(run_dir_of)/handoff.md"
  id=$(basename "$(run_dir_of)")
  drive --resume "$id"
  assert "D20 resume without decisions.md exits 3" test "$drv_rc" = 3
  printf 'Use MIT OR Apache-2.0.\n' >"$(run_dir_of)/decisions.md"
  drive --resume "$id"
  assert "D6 resume with decisions exits 0" test "$drv_rc" = 0
  assert "D6 resume revised the plan once" test "$(count_calls 'kind=plan-revise')" = 1
  assert "D6 exactly one post-decision review" test "$(count_calls 'kind=plan-review-post')" = 1
  assert "D6 the post review flag persisted" test "$(state_of post_decision_review)" = 1
  assert "D6 the plan round persisted" test "$(state_of plan_round)" = 1

  new_case stub
  : >"$sd/owner-open"
  printf 'VERDICT: CHANGES NEEDED\n%.0s' 1 2 3 >"$sd/q-plan-review"
  drive --backend opencode "t"
  assert "D6 approved at round 4 with open decisions still stops at the gate" test "$drv_rc" = 10
  assert "D6 the plan round is 4" test "$(state_of plan_round)" = 4
  id=$(basename "$(run_dir_of)")
  printf 'Decided.\n' >"$(run_dir_of)/decisions.md"
  drive --resume "$id"
  assert "D6 round 4 plus decisions finishes" test "$drv_rc" = 0
  assert "D6 round 4 still gets the post review" test "$(count_calls 'kind=plan-review-post')" = 1
  assert "D6 the plan reviewer ran 4 plus 1 times" test "$(count_calls 'role=plan-reviewer')" = 5

  # D7: a readonly phase changes state.
  local -a mutations=(
    'echo x >>.gitignore'
    'echo x >untracked-by-stub.txt'
    'git commit --no-verify --allow-empty -q -m "chore: sneaky"'
    'git config user.name evil'
    'printf "#!/bin/sh\n" >.git/hooks/post-commit'
    'echo x >>.git/info/attributes'
    'echo "# x" >>.githooks/pre-commit'
  )
  for mut in "${mutations[@]}"; do
    new_case stub
    printf '%s\n' "$mut" >"$sd/hook-plan.sh"
    drive --backend opencode "t"
    assert "D7 a readonly phase doing '$mut' exits 13" test "$drv_rc" = 13
    assert "D7 nothing was implemented after '$mut'" test "$(count_calls 'role=implementer')" = 0
  done

  # D23: snapshot sensitivity, and what must not count.
  mutations=(
    'rm opencode.json'
    'ln -sfn opencode.json CLAUDE.md'
    'chmod 755 AGENTS.md'
    'echo x >>.gitignore; git add .gitignore'
    'mkdir nested; git init -q nested; echo x >nested/f; git -C nested add f'
    'git branch evil-branch'
  )
  for mut in "${mutations[@]}"; do
    new_case stub
    printf '%s\n' "$mut" >"$sd/hook-plan.sh"
    drive --backend opencode "t"
    assert "D23 a readonly phase doing '$mut' exits 13" test "$drv_rc" = 13
  done
  new_case stub
  local other=$tmp/other$case_n
  git clone -q "$origin_dir" "$other" 2>/dev/null
  git -C "$other" config user.name "Test"
  git -C "$other" config user.email "test@example.invalid"
  git -C "$other" push -q origin "HEAD:refs/heads/unrelated-$case_n" 2>/dev/null
  printf 'git fetch -q origin\n' >"$sd/hook-plan.sh"
  drive --backend opencode "t"
  assert "D23 a fetch that only moves remote refs is not a violation" test "$drv_rc" = 0
  assert "D23 the fetch really moved a remote ref" test -n "$(git -C "$clone" for-each-ref "refs/remotes/origin/unrelated-$case_n")"

  # D8: the implementer touches the protected set.
  cat >"$tmp/hook-protected.sh" <<'HOOK'
echo "# edit" >>AGENTS.md
git add AGENTS.md
scripts/gate.sh --commit >/dev/null
git commit -q -m "docs: touch a protected file"
handled=1
HOOK
  new_case stub
  cp "$tmp/hook-protected.sh" "$sd/hook-implement.sh"
  drive --backend opencode "t"
  assert "D8 a protected-path diff exits 13" test "$drv_rc" = 13
  new_case stub
  cp "$tmp/hook-protected.sh" "$sd/hook-implement.sh"
  drive --backend opencode --allow-protected "t"
  assert "D8 --allow-protected lets the run continue" test "$drv_rc" = 0
  assert "D8 the protected diff is listed in the pull request body" has "$(cat "$(run_dir_of)/pr-body.md")" 'Protected paths changed'
  assert "D8 the protected diff names the file" has "$(cat "$(run_dir_of)/pr-body.md")" 'AGENTS.md'

  # D9: bad commits.
  local -a bad_commits=(
    'git commit -q -m "wip"'
    'git commit -q -m "feat: add x" -m "Co-Authored-By: A Person <a@example.invalid>"'
    'git commit -q -m "feat: reference #12"'
    "git commit -q -m \"feat: see $hm/$rp/project/\""
  )
  for mut in "${bad_commits[@]}"; do
    new_case stub
    printf 'echo f >bad.txt\ngit add bad.txt\nscripts/gate.sh --commit >/dev/null\n%s\nhandled=1\n' "$mut" >"$sd/hook-implement.sh"
    drive --backend opencode "t"
    assert "D9 [$mut] exits 14" test "$drv_rc" = 14
  done
  new_case stub
  # shellcheck disable=SC2016  # the hook text is expanded by the stub, not here
  printf 'echo f >f.txt\ngit add f.txt\nscripts/gate.sh --commit >/dev/null\ngit commit -q -m "feat: part"\necho "blocked: need a command" >"$FACTORY_RUN_DIR/blocked.md"\nhandled=1\n' >"$sd/hook-implement.sh"
  drive --backend opencode "t"
  assert "D9 blocked.md exits 14" test "$drv_rc" = 14

  # D10: the hooks apply to the agent's commits through the driver.
  new_case stub
  cat >"$sd/hook-implement.sh" <<'HOOK'
echo a >a.txt
git add a.txt
if git commit -q -m "feat: no stamp" >/dev/null 2>&1; then echo accepted >"$STUB_DIR/unstamped"; else echo rejected >"$STUB_DIR/unstamped"; fi
scripts/gate.sh --commit >/dev/null
git commit -q -m "feat: stamped"
handled=1
HOOK
  drive --backend opencode "t"
  assert "D10 the run finishes" test "$drv_rc" = 0
  assert "D10 a commit without a stamp was rejected by the real hook" test "$(cat "$sd/unstamped")" = rejected
  assert "D10 the stamped commit exists" test "$(git -C "$clone" log --format=%s | grep -c 'feat: stamped')" = 1

  # D11: the child environment, and hooks planted in .git are never consulted.
  new_case stub
  printf '#!/bin/sh\necho ran >"%s/ref-hook-ran"\n' "$tmp" >"$clone/.git/hooks/reference-transaction"
  chmod +x "$clone/.git/hooks/reference-transaction"
  rm -f "$tmp/ref-hook-ran"
  drv_extra=(GH_TOKEN=dummy-not-a-token GITHUB_TOKEN=dummy-not-a-token)
  drive --backend opencode "t"
  drv_extra=()
  assert "D11 the run finishes" test "$drv_rc" = 0
  assert "D11 the hook count variable" has "$(cat "$sd/calls.log")" '^ENV GIT_CONFIG_COUNT=1$'
  assert "D11 the hook key variable" has "$(cat "$sd/calls.log")" '^ENV GIT_CONFIG_KEY_0=core.hooksPath$'
  assert "D11 the hook path variable" has "$(cat "$sd/calls.log")" "^ENV GIT_CONFIG_VALUE_0=$clone/.githooks\$"
  refute "D11 no token reaches a child" grep -Eq '^ENVNAMES .*(GH_TOKEN|GITHUB_TOKEN)' "$sd/calls.log"
  assert "D11 no unexpected variable reaches a child" test -z "$(grep -E '^ENVNAMES' "$sd/calls.log" | tr ' ' '\n' | grep -Ev '^(ENVNAMES|PATH|HOME|TERM|LANG|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_0|GIT_CONFIG_VALUE_0|FACTORY_RUN_DIR|FACTORY_ARTIFACT|FACTORY_BASE_SHA|STUB_DIR|PWD|OLDPWD|SHLVL|_|)$' || true)"
  assert "D11 the planted reference-transaction hook never ran" test ! -e "$tmp/ref-hook-ran"

  # D12: pull request text lint.
  local -a bad_prs=(
    'printf "feat: fix #12\n\n## Not verified\n\n- x\n"'
    "printf \"feat: x\\n\\nSee $hm/$rp/x/\\n\\n## Not verified\\n\\n- x\\n\""
    'printf "feat: x\n\nCo-Authored-By: A <a@example.invalid>\n\n## Not verified\n\n- x\n"'
    'printf "feat: x\n\n## Summary\n\n- x\n"'
  )
  for mut in "${bad_prs[@]}"; do
    new_case stub
    # shellcheck disable=SC2016  # the hook text is expanded by the stub, not here
    printf '%s >"$FACTORY_ARTIFACT"\nhandled=1\n' "$mut" >"$sd/hook-pr.sh"
    drive --backend opencode "t"
    assert "D12 a bad pull request text exits 16" test "$drv_rc" = 16
    refute "D12 nothing was pushed" git -C "$origin_dir" rev-parse -q --verify "refs/heads/$(state_of branch)"
    refute "D12 no pull request was created" grep -q 'pr create' "$sd/gh.log"
  done

  # D38: the OpenCode reasoning variant and the attach option. A dummy credential is built at runtime.
  local pw_dummy user_dummy att="http://127.0.0.1:4096"
  pw_dummy="pw-$(printf 'q%.0s' 1 2 3 4 5)-$RANDOM"
  user_dummy="u-$(printf 'z%.0s' 1 2 3)-$RANDOM"
  # argv_of <role>: the argv lines the stub logged for that role.
  argv_of() {
    awk -v r="role=$1" '/^CALL /{cur=$4} /^ARGV/ && cur==r {print}' "$sd/calls.log"
  }
  new_case stub
  drive --backend opencode --variant-main high --variant-helper minimal "t"
  assert "D38 variants: the run exits 0" test "$drv_rc" = 0
  assert "D38 variants: the planner gets the main variant" has "$(argv_of planner)" ' --variant high '
  assert "D38 variants: the implementer gets the main variant" has "$(argv_of implementer)" ' --variant high '
  assert "D38 variants: the plan reviewer gets the helper variant" has "$(argv_of plan-reviewer)" ' --variant minimal '
  assert "D38 variants: the code reviewer gets the helper variant" has "$(argv_of code-reviewer)" ' --variant minimal '
  assert "D38 variants: the pr writer gets the helper variant" has "$(argv_of pr-writer)" ' --variant minimal '
  new_case stub
  drive --backend opencode "t"
  refute "D38 variants: no --variant when none is set" grep -q -- '--variant' "$sd/calls.log"
  refute "D38 attach: no --attach when none is set" grep -q -- '--attach' "$sd/calls.log"
  new_case stub
  drv_extra=(FACTORY_VARIANT_MAIN=max)
  drive --backend opencode "t"
  drv_extra=()
  assert "D38 variants: the environment variable works" has "$(argv_of planner)" ' --variant max '
  refute "D38 variants: an unset helper variant is absent" has "$(argv_of plan-reviewer)" '--variant'
  # shellcheck disable=SC2016  # a literal command substitution is the point of the case
  for bad in 'high;x' 'High' 'a b' '-x' '$(id)'; do
    new_case stub
    drive --backend opencode --variant-main "$bad" "t"
    assert "D38 variants: '$bad' is a usage error" test "$drv_rc" = 2
    assert "D38 variants: '$bad' started nothing" test ! -s "$sd/calls.log"
  done
  new_case stub
  drive --backend claude --variant-main high --variant-helper low "t"
  assert "D38 variants: claude runs on" test "$drv_rc" = 0
  assert "D38 variants: claude warns once" test "$(grep -c 'variant.*OpenCode backend only' <<<"$drv_out")" = 1
  refute "D38 variants: claude never sees --variant" grep -q -- '--variant' "$sd/calls.log"
  drive --dry-run --backend opencode --variant-main high --opencode-attach "$att" "t"
  assert "D38 dry run shows the variants" has "$drv_out" 'variants: main=high helper=\(none\)'
  assert "D38 dry run shows the attach URL" has "$drv_out" "opencode server: $att"
  assert "D38 dry run shows --variant in the command" has "$drv_out" 'command \(plan\): opencode run --attach .* --variant high '

  new_case stub
  drv_extra=("OPENCODE_SERVER_PASSWORD=$pw_dummy" "OPENCODE_SERVER_USERNAME=$user_dummy")
  drive --backend opencode --opencode-attach "$att" "t"
  drv_extra=()
  assert "D38 attach: the run exits 0" test "$drv_rc" = 0
  assert "D38 attach: every phase has --attach URL --dir <abs>" test "$(grep -c "^ARGV run --attach $att --agent " "$sd/calls.log" || true)" = "$(grep -c '^CALL ' "$sd/calls.log")"
  assert "D38 attach: every phase has an absolute --dir" test "$(grep -c "^ARGV.* --dir $clone " "$sd/calls.log" || true)" = "$(grep -c '^CALL ' "$sd/calls.log")"
  refute "D38 attach: the password is never in argv" grep -q -- "$pw_dummy" "$sd/calls.log"
  refute "D38 attach: the user name is never in argv" grep -q -- "$user_dummy" "$sd/calls.log"
  assert "D38 attach: the password reaches the phase environment" test "$(grep -c '^ENVNAMES .*OPENCODE_SERVER_PASSWORD ' "$sd/calls.log")" = "$(grep -c '^CALL ' "$sd/calls.log")"
  assert "D38 attach: the user name reaches the phase environment" test "$(grep -c '^ENVNAMES .*OPENCODE_SERVER_USERNAME ' "$sd/calls.log")" = "$(grep -c '^CALL ' "$sd/calls.log")"
  refute "D38 attach: the password is not in the driver output" has "$drv_out" "$pw_dummy"
  # Without --opencode-attach the credentials are not passed on.
  new_case stub
  drv_extra=("OPENCODE_SERVER_PASSWORD=$pw_dummy" "OPENCODE_SERVER_USERNAME=$user_dummy")
  drive --backend opencode "t"
  drv_extra=()
  refute "D38 attach: no credentials without --opencode-attach" grep -q '^ENVNAMES .*OPENCODE_SERVER_' "$sd/calls.log"
  # Attached but no credentials set: nothing is passed.
  new_case stub
  drive --backend opencode --opencode-attach "$att/" "t"
  assert "D38 attach: a trailing slash and no credentials work" test "$drv_rc" = 0
  refute "D38 attach: no credential variable when none is set" grep -q '^ENVNAMES .*OPENCODE_SERVER_' "$sd/calls.log"
  # A phase that prints the credentials and fails: handoff.md and stderr withhold them.
  new_case stub
  # shellcheck disable=SC2016  # the hook expands the variables inside the stub
  printf 'echo "login $OPENCODE_SERVER_USERNAME:$OPENCODE_SERVER_PASSWORD"\necho "other line"\nhandled=1\n' >"$sd/hook-plan.sh"
  drv_extra=("OPENCODE_SERVER_PASSWORD=$pw_dummy" "OPENCODE_SERVER_USERNAME=$user_dummy")
  drive --backend opencode --opencode-attach "$att" "t"
  drv_extra=()
  assert "D38 attach: the failing phase exits 20" test "$drv_rc" = 20
  assert "D38 attach: the other log line is quoted" has "$(cat "$(run_dir_of)/handoff.md")" 'other line'
  refute "D38 attach: the password is not in handoff.md" grep -q -- "$pw_dummy" "$(run_dir_of)/handoff.md"
  refute "D38 attach: the user name is not in handoff.md" grep -q -- "$user_dummy" "$(run_dir_of)/handoff.md"
  refute "D38 attach: the password is not on stderr" has "$drv_out" "$pw_dummy"
  refute "D38 attach: the user name is not on stderr" has "$drv_out" "$user_dummy"
  for bad in 'ftp://localhost:4096' 'http://user:x@localhost:4096' 'http://localhost:4096/path' 'http://localhost:4096?x=1' 'localhost:4096' 'http://localhost:99999x' 'http://local host'; do
    new_case stub
    drive --backend opencode --opencode-attach "$bad" "t"
    assert "D38 attach: '$bad' is a usage error" test "$drv_rc" = 2
    assert "D38 attach: '$bad' started nothing" test ! -s "$sd/calls.log"
  done
  new_case stub
  drive --backend claude --opencode-attach "$att" "t"
  assert "D38 attach: claude runs on" test "$drv_rc" = 0
  assert "D38 attach: claude warns once" test "$(grep -c 'opencode-attach.*OpenCode backend only' <<<"$drv_out")" = 1
  refute "D38 attach: claude never sees --attach" grep -q -- '--attach' "$sd/calls.log"

  # D13: dry run.
  new_case stub
  drive --dry-run --backend claude "t"
  assert "D13 dry run exits 0" test "$drv_rc" = 0
  assert "D13 it names the caps" has "$drv_out" 'plan review 4 rounds, code review 3 rounds'
  assert "D13 it names the phases" has "$drv_out" 'phases: plan, plan-review, owner-gate, implement, code-review, final-gate, pr'
  assert "D13 it shows the claude command shape" has "$drv_out" 'claude -p .*--permission-mode dontAsk .*--allowedTools'
  assert "D13 it shows the strict MCP flag for claude" has "$drv_out" '--strict-mcp-config'
  refute "D13 it passes no --mcp-config" has "$drv_out" '--mcp-config'
  drive --dry-run --backend opencode "t"
  assert "D13 it shows the opencode command shape" has "$drv_out" 'opencode run --agent factory-planner'
  assert "D13 it called nothing" test ! -s "$sd/calls.log"
  assert "D13 it created no run directory" test ! -e "$clone/.factory"
  assert "D13 it stayed on main" test "$(git -C "$clone" rev-parse --abbrev-ref HEAD)" = main

  # D14: the caps can only be lowered.
  new_case stub
  drive --backend opencode --plan-rounds 5 "t"
  assert "D14 --plan-rounds 5 is a usage error" test "$drv_rc" = 2
  drive --backend opencode --code-rounds 4 "t"
  assert "D14 --code-rounds 4 is a usage error" test "$drv_rc" = 2
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n%.0s' 1 2 3 4 >"$sd/q-plan-review"
  drive --backend opencode --plan-rounds 2 "t"
  assert "D14 --plan-rounds 2 lowers the cap" test "$drv_rc" = 11
  assert "D14 exactly 2 plan reviews" test "$(count_calls 'role=plan-reviewer')" = 2

  # D15: a timeout reaps the whole process group.
  new_case stub
  printf 'sleep 3017 &\nsleep 3017\n' >"$sd/hook-plan.sh"
  drive --backend opencode --phase-timeout 2 "t"
  assert "D15 a timeout exits 20" test "$drv_rc" = 20
  assert "D15 the step is recorded" test "$(state_of step)" = write
  sleep 1
  refute "D15 no grandchild survives" pgrep -f 'sleep 3017'

  # D16: a missing backend is a preflight failure.
  new_case stub
  local minbin=$tmp/minbin t
  mkdir -p "$minbin"
  for t in git setsid timeout sha256sum od cut tr sed awk grep head tail date mv rm mkdir cat wc find sort stat readlink id hostname basename dirname env sleep ls cp paste bash; do
    if command -v "$t" >/dev/null 2>&1; then ln -sf "$(command -v "$t")" "$minbin/$t"; fi
  done
  drv_rc=0
  drv_out=$(cd "$clone" && env PATH="$minbin" STUB_DIR="$sd" "$minbin/bash" scripts/factory.sh --backend claude "t" 2>&1) || drv_rc=$?
  assert "D16 an absent backend exits 3" test "$drv_rc" = 3
  assert "D16 the message names the backend" has "$drv_out" 'backend not found: claude'

  # D19: resume after a timeout in implement with a dirty tree and existing commits.
  new_case stub
  cat >"$sd/hook-implement.sh" <<'HOOK'
attempt=$(($(cat "$STUB_DIR/attempt" 2>/dev/null || echo 0) + 1))
echo "$attempt" >"$STUB_DIR/attempt"
if [ "$attempt" = 1 ]; then
  echo one >one.txt
  git add one.txt
  scripts/gate.sh --commit >/dev/null
  git commit -q -m "feat: first part"
  echo dirty >dirty-leftover.txt
  sleep 3019 &
  sleep 3019
else
  git add -A
  scripts/gate.sh --commit >/dev/null
  git commit -q -m "feat: second part"
fi
handled=1
HOOK
  drive --backend opencode --phase-timeout 3 "t"
  assert "D19 the timeout in implement exits 20" test "$drv_rc" = 20
  assert "D19 the tree is dirty" test -n "$(git -C "$clone" status --porcelain)"
  id=$(basename "$(run_dir_of)")
  local branch_before
  branch_before=$(git -C "$clone" rev-parse --abbrev-ref HEAD)
  git -C "$clone" switch -q main
  drive --resume "$id" --phase-timeout 60
  assert "D19 resume finishes" test "$drv_rc" = 0
  assert "D19 the recorded branch is used" test "$(git -C "$clone" rev-parse --abbrev-ref HEAD)" = "$branch_before"
  assert "D19 the prompt says the attempt was interrupted" has "$(cat "$sd/calls.log")" 'PROMPT .*previous attempt was interrupted'
  assert "D19 the prompt carries git status" has "$(cat "$sd/calls.log")" 'dirty-leftover.txt'
  assert "D19 the prompt carries the commits since the base" has "$(cat "$sd/calls.log")" 'feat: first part'
  assert "D19 preflight did not create a second branch" test "$(git -C "$clone" for-each-ref --format='%(refname)' 'refs/heads/factory/*' | wc -l)" = 1

  # D21: a push failure is resumable and never re-runs the pr-writer.
  new_case stub
  : >"$sd/push-fail"
  drive --backend opencode "t"
  assert "D21 a push failure exits 20" test "$drv_rc" = 20
  assert "D21 the step is push" test "$(state_of step)" = push
  id=$(basename "$(run_dir_of)")
  rm "$sd/push-fail"
  drive --resume "$id"
  assert "D21 resume pushes and finishes" test "$drv_rc" = 0
  assert "D21 the pr-writer ran once" test "$(count_calls 'role=pr-writer')" = 1
  assert "D21 one pull request" test "$(grep -c '^gh pr create' "$sd/gh.log")" = 1

  # D22: a pull request creation failure; resume skips the push and, when one exists, the creation.
  new_case stub
  : >"$sd/gh-create-fail"
  drive --backend opencode "t"
  assert "D22 a creation failure exits 20" test "$drv_rc" = 20
  assert "D22 the step is pr-create" test "$(state_of step)" = pr-create
  id=$(basename "$(run_dir_of)")
  rm "$sd/gh-create-fail"
  drive --resume "$id"
  assert "D22 resume finishes" test "$drv_rc" = 0
  assert "D22 the pr-writer ran once" test "$(count_calls 'role=pr-writer')" = 1
  assert "D22 the second creation succeeded" test "$(grep -c '^gh pr create' "$sd/gh.log")" = 2
  new_case stub
  : >"$sd/gh-create-fail"
  drive --backend opencode "t"
  id=$(basename "$(run_dir_of)")
  rm "$sd/gh-create-fail"
  sed -i -e 's/^step=pr-create$/step=push/' "$(run_dir_of)/state"
  drive --resume "$id"
  assert "D22 a push step whose remote already has HEAD is skipped" has "$drv_out" 'skipping the push'
  assert "D22 that resume finishes" test "$drv_rc" = 0
  new_case stub
  : >"$sd/gh-create-fail"
  drive --backend opencode "t"
  id=$(basename "$(run_dir_of)")
  rm "$sd/gh-create-fail"
  printf 'https://example.invalid/pr/7\n' >"$sd/pr-url"
  drive --resume "$id"
  assert "D22 an existing pull request is reused" has "$drv_out" 'already exists'
  assert "D22 no second creation" test "$(grep -c '^gh pr create' "$sd/gh.log")" = 1

  # D24: SIGTERM kills the child process group and leaves the run resumable.
  new_case stub
  printf 'sleep 3021 &\nsleep 3021\n' >"$sd/hook-plan.sh"
  (cd "$clone" && exec env PATH="$tmp/dbin:$PATH" STUB_DIR="$sd" FACTORY_PASS_ENV=STUB_DIR scripts/factory.sh --backend opencode "t" >"$sd/driver.out" 2>&1) &
  # shellcheck disable=SC2031  # $! here is the background driver started just above
  local dpid=$! waited=0
  while [ ! -s "$sd/calls.log" ] && [ "$waited" -lt 100 ]; do
    sleep 0.2
    waited=$((waited + 1))
  done
  sleep 0.5
  kill -TERM "$dpid"
  drv_rc=0
  wait "$dpid" || drv_rc=$?
  assert "D24 the driver exits 130 on SIGTERM" test "$drv_rc" = 130
  assert "D24 the state is stopped" test "$(state_of status)" = stopped
  assert "D24 the exit code is 20, resumable" test "$(state_of exit_code)" = 20
  sleep 1
  refute "D24 no grandchild survives" pgrep -f 'sleep 3021'

  # D25: the Claude hint when the artifact is missing.
  new_case stub
  : >"$sd/noop-plan"
  drive --backend claude "t"
  assert "D25 a missing artifact exits 20" test "$drv_rc" = 20
  assert "D25 the rule-form hint is printed for claude" has "$drv_out" 'rule form may be wrong'
  new_case stub
  : >"$sd/noop-plan"
  drive --backend opencode "t"
  refute "D25 no claude hint for opencode" has "$drv_out" 'rule form may be wrong'

  # D36: a phase that ends without its artifact names its cause in handoff.md. The stub prints the
  # log lines of each known case (with ANSI codes, the home directory, a second home-style path, a
  # very long line and filler); the driver must classify, cut and scrub them.
  local esc cause_case cause_line cause_sum cause_fix long_line handoff n
  esc=$(printf '\033')
  long_line="longline$(printf ' abcdefghij%.0s' $(seq 1 30))"
  for cause_case in login trust limit unknown; do
    case "$cause_case" in
      login)
        cause_line="${esc}[31mNot logged in${esc}[0m - Please run /login"
        cause_sum='not logged in'
        cause_fix='log in once'
        ;;
      trust)
        cause_line="${esc}[1mWarning:${esc}[0m this workspace has not been trusted"
        cause_sum='workspace not trusted'
        cause_fix='accept the workspace trust dialog'
        ;;
      limit)
        cause_line="API Error: 429 rate_limit_error"
        cause_sum='rate or usage limit'
        cause_fix='wait until the limit resets or switch backend'
        ;;
      unknown)
        cause_line="${esc}[2Ksomething odd happened"
        cause_sum='no known cause in the log'
        cause_fix='read logs/plan.log'
        ;;
    esac
    new_case stub
    {
      printf '%s\n' "$cause_line" "cwd=$HOME/work" "other=$hm/$rp/work" "$long_line"
      for n in $(seq 1 14); do printf 'filler %s\n' "$n"; done
    } >"$sd/loglines"
    # shellcheck disable=SC2016  # the hook expands STUB_DIR inside the stub
    printf 'cat "$STUB_DIR/loglines"\nhandled=1\n' >"$sd/hook-plan.sh"
    printf '1\n' >"$sd/exit-plan"
    drive --backend claude "t"
    handoff=$(cat "$(run_dir_of)/handoff.md")
    assert "D36 [$cause_case] exits 20, resumable" test "$drv_rc" = 20
    assert "D36 [$cause_case] handoff.md has a cause section" has "$handoff" '^## Cause$'
    assert "D36 [$cause_case] the cause is named" has "$handoff" "$cause_sum"
    assert "D36 [$cause_case] the fix is named" has "$handoff" "$cause_fix"
    assert "D36 [$cause_case] the first log lines are quoted" has "$handoff" 'filler 8'
    refute "D36 [$cause_case] at most 12 log lines are quoted" has "$handoff" 'filler 9'
    refute "D36 [$cause_case] no ANSI escape in handoff.md" grep -q "$esc" "$(run_dir_of)/handoff.md"
    refute "D36 [$cause_case] no home directory in handoff.md" has "$handoff" "$HOME"
    refute "D36 [$cause_case] no home-style path in handoff.md" has "$handoff" "$hm/$rp"
    refute "D36 [$cause_case] no quoted line is longer than 200 characters" test -n "$(awk 'length > 204' "$(run_dir_of)/handoff.md")"
    assert "D36 [$cause_case] the long line is cut, not dropped" has "$handoff" 'longline abcdefghij'
    assert "D36 [$cause_case] the driver prints one cause line" has "$drv_out" 'factory: (cause: |artifact missing: )'
    if [ "$cause_case" = unknown ]; then
      assert "D36 [unknown] the rule-form hint is the fallback" has "$handoff" 'rule form may be wrong'
    else
      refute "D36 [$cause_case] no rule-form hint when the cause is known" has "$handoff$drv_out" 'rule form may be wrong'
    fi
  done
  # An unknown cause on OpenCode never shows the Claude rule-form hint.
  new_case stub
  # shellcheck disable=SC2016  # the hook expands STUB_DIR inside the stub
  printf 'cat "$STUB_DIR/loglines"\nhandled=1\n' >"$sd/hook-plan.sh"
  printf 'nothing known here\n' >"$sd/loglines"
  drive --backend opencode "t"
  assert "D36 [opencode] exits 20" test "$drv_rc" = 20
  refute "D36 [opencode] no rule-form hint" has "$(cat "$(run_dir_of)/handoff.md")$drv_out" 'rule form may be wrong'
  assert "D36 [opencode] the log is quoted" has "$(cat "$(run_dir_of)/handoff.md")" 'nothing known here'

  # D36 tokens and prose: a token-like string is withheld, and a login URL or the word login in prose
  # is not "not logged in". The tokens are built from pieces so no secret-looking literal is stored.
  local tok_a tok_b
  tok_a="gh"
  tok_a+="p_$(printf 'A1b2%.0s' $(seq 1 10))"
  tok_b=$(printf 'Zq9%.0s' $(seq 1 12))
  new_case stub
  printf '%s\n' "visit https://example.invalid/login to sign in" "please login again later" "token=$tok_a" "key $tok_b" "plain line kept" >"$sd/loglines"
  # shellcheck disable=SC2016  # the hook expands STUB_DIR inside the stub
  printf 'cat "$STUB_DIR/loglines"\nhandled=1\n' >"$sd/hook-plan.sh"
  drive --backend claude "t"
  handoff=$(cat "$(run_dir_of)/handoff.md")
  assert "D36 [token] exits 20" test "$drv_rc" = 20
  refute "D36 [token] the prefixed token is not in handoff.md" has "$handoff" "${tok_a:0:12}"
  refute "D36 [token] the long token is not in handoff.md" has "$handoff" "${tok_b:0:12}"
  refute "D36 [token] the token is not on stderr" has "$drv_out" "${tok_b:0:12}"
  assert "D36 [token] the lines are withheld" has "$handoff" 'line withheld'
  assert "D36 [token] ordinary lines are kept" has "$handoff" 'plain line kept'
  assert "D36 [login prose] a login URL is quoted" has "$handoff" 'example.invalid/login'
  refute "D36 [login prose] a login URL or the word login is not 'not logged in'" has "$handoff" 'not logged in'
  assert "D36 [login prose] the cause stays unknown" has "$handoff" 'no known cause in the log'

  # D26: the personal-data scrub.
  # shellcheck disable=SC2329  # called through assert and refute
  # The scrub reads the base tree of the repository it runs in: use a fixture clone that holds one
  # runtime-built word, so nothing depends on what the real repository contains.
  new_case stub
  local kw=quirk
  kw+=host
  printf '%s\n' "$kw" >"$clone/word.txt"
  git -C "$clone" add word.txt
  git -C "$clone" commit -q -m "chore: add a word"
  # shellcheck disable=SC2329  # called through assert and refute
  scrub_in() { # <home> <user> <host> <text>
    (cd "$clone" && HOME=$1 FACTORY_SCRUB_USER=$2 FACTORY_SCRUB_HOST=$3 lib scrub <<<"$4" >/dev/null)
  }
  assert "D26 HOME=/root skips the home check" scrub_in /root nobody-here host1 "see /root/project"
  assert "D26 a short user name is skipped" scrub_in "$hm/x/y" abcd efgh "abcd and efgh"
  assert "D26 a generic user name is skipped" scrub_in /root runner ubuntu "the runner on ubuntu"
  assert "D26 an empty user is skipped" scrub_in /root "" "" "nothing to see"
  assert "D26 a placeholder path is fine" scrub_in /root nobody-here host1 "see $hm/<name>/project and $hm/you/x"
  refute "D26 a real home-directory path is flagged" scrub_in /root nobody-here host1 "see $hm/$rp/project/"
  refute "D26 a long user name as a whole word is flagged" scrub_in /root "$rp" host1 "written by $rp today"
  assert "D26 a user name inside another word is not flagged" scrub_in /root "$rp" host1 "un${rp}al"
  refute "D26 the real home path is flagged" scrub_in "$hm/someone/work" nobody-here host1 "in $hm/someone/work/x"
  # A host named like a word the base tree already uses is not a leak (cwd is the repository).
  assert "D26 a host called like an ordinary word of the tree is skipped" scrub_in /root nobody-here "$kw" "the $kw answered"
  refute "D26 an unknown host name is still flagged" scrub_in /root nobody-here "$zh" "built on $zh"

  # D27: an artifact phase that fails without its artifact is exit 20 with the step recorded.
  local -a cases=(plan:plan:write plan-review:plan-review:review code-review:code-review:review pr:pr:pr-write)
  local c kind phase_want step_want
  for c in "${cases[@]}"; do
    IFS=: read -r kind phase_want step_want <<<"$c"
    new_case stub
    : >"$sd/noop-$kind"
    printf '1\n' >"$sd/exit-$kind"
    drive --backend opencode "t"
    assert "D27 [$kind] a failing artifact phase exits 20" test "$drv_rc" = 20
    assert "D27 [$kind] the phase is recorded" test "$(state_of phase)" = "$phase_want"
    assert "D27 [$kind] the step is recorded" test "$(state_of step)" = "$step_want"
  done
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n' >"$sd/q-plan-review"
  : >"$sd/noop-plan-revise"
  printf '1\n' >"$sd/exit-plan-revise"
  drive --backend opencode "t"
  assert "D27 [plan-revise] exits 20" test "$drv_rc" = 20
  assert "D27 [plan-revise] the step is revise" test "$(state_of step)" = revise

  # D29: implement and fix success criteria.
  new_case stub
  : >"$sd/noop-implement"
  printf '1\n' >"$sd/exit-implement"
  drive --backend opencode "t"
  assert "D29a non-zero exit and no commit is exit 20" test "$drv_rc" = 20
  new_case stub
  printf '1\n' >"$sd/exit-implement"
  drive --backend opencode "t"
  assert "D29b non-zero exit with a good commit continues" test "$drv_rc" = 0
  new_case stub
  printf 'echo f >f.txt\ngit add f.txt\nscripts/gate.sh --commit >/dev/null\ngit commit -q -m "feat: part"\nsleep 3023 &\nsleep 3023\nhandled=1\n' >"$sd/hook-implement.sh"
  drive --backend opencode --phase-timeout 3 "t"
  assert "D29c a timeout with commits is exit 20" test "$drv_rc" = 20
  new_case stub
  printf 'sleep 3023 &\nsleep 3023\nhandled=1\n' >"$sd/hook-implement.sh"
  drive --backend opencode --phase-timeout 3 "t"
  assert "D29c a timeout without commits is exit 20" test "$drv_rc" = 20
  new_case stub
  : >"$sd/noop-implement"
  drive --backend opencode "t"
  assert "D29d a clean exit without a commit is exit 14 in implement" test "$drv_rc" = 14
  new_case stub
  printf 'VERDICT: CHANGES NEEDED\n' >"$sd/q-code"
  : >"$sd/noop-fix"
  drive --backend opencode "t"
  assert "D29e a clean exit without a commit is exit 14 in fix" test "$drv_rc" = 14
  refute "D29 no leftover sleepers" pgrep -f 'sleep 302[0-9]'

  # D30: files that decide what the tools may do are watched even when git ignores them.
  local -a local_cfg_mutations=(
    'mkdir -p .claude; echo "{}" >.claude/settings.local.json'
    'echo "be nice" >CLAUDE.local.md'
  )
  for mut in "${local_cfg_mutations[@]}"; do
    new_case stub
    printf '%s\n' "$mut" >"$sd/hook-plan.sh"
    drive --backend claude "t"
    assert "D30 a readonly phase doing '$mut' exits 13" test "$drv_rc" = 13
    new_case stub
    printf 'echo f >f.txt\ngit add f.txt\nscripts/gate.sh --commit >/dev/null\ngit commit -q -m "feat: part"\n%s\nhandled=1\n' "$mut" >"$sd/hook-implement.sh"
    drive --backend claude "t"
    assert "D30 the implementer doing '$mut' exits 13" test "$drv_rc" = 13
  done
  for mut in 'echo "{}" >opencode.jsonc' 'echo "{}" >.mcp.json'; do
    new_case stub
    printf 'echo f >f.txt\ngit add f.txt\nscripts/gate.sh --commit >/dev/null\ngit commit -q -m "feat: part"\n%s\nhandled=1\n' "$mut" >"$sd/hook-implement.sh"
    drive --backend opencode "t"
    assert "D30 the implementer creating an untracked config file ($mut) exits 13" test "$drv_rc" = 13
  done
  # The run directory documents: a reviewer may not edit the plan it judges, nobody the task.
  # shellcheck disable=SC2016  # the hook text is expanded by the stub, not here
  local plan_edit='echo x >>"$FACTORY_RUN_DIR/plan.md"'
  new_case stub
  printf '%s\n' "$plan_edit" >"$sd/hook-plan-review.sh"
  drive --backend opencode "t"
  assert "D30 a plan reviewer editing plan.md exits 13" test "$drv_rc" = 13
  new_case stub
  printf '%s\n' "$plan_edit" >"$sd/hook-code-review.sh"
  drive --backend opencode "t"
  assert "D30 a code reviewer editing plan.md exits 13" test "$drv_rc" = 13
  new_case stub
  # shellcheck disable=SC2016  # the hook text is expanded by the stub, not here
  printf 'echo f >f.txt\ngit add f.txt\nscripts/gate.sh --commit >/dev/null\ngit commit -q -m "feat: part"\necho x >>"$FACTORY_RUN_DIR/task.md"\nhandled=1\n' >"$sd/hook-implement.sh"
  drive --backend opencode "t"
  assert "D30 an implementer editing task.md exits 13" test "$drv_rc" = 13

  # D31: the resume context stays small however dirty the tree is.
  new_case stub
  for ((i = 1; i <= 600; i++)); do : >"$clone/untracked-file-with-a-long-name-$i.txt"; done
  # shellcheck disable=SC2329  # called through lib
  rc_probe() {
    cd "$clone"
    # shellcheck disable=SC2034  # read by resume_context
    resuming=1
    # shellcheck disable=SC2034  # read by resume_context
    base_sha=$(git rev-parse HEAD)
    resume_context
  }
  local probe
  probe=$(lib rc_probe)
  assert "D31 the resume context is truncated" has "$probe" '\(truncated\)'
  assert "D31 the resume context is far below the argument limit" test "${#probe}" -lt 8000

  # D32: a pull request creation that finds the branch on remote main is a violation.
  local pushed
  for pushed in HEAD HEAD~1; do
    new_case stub
    before=$(origin_main)
    printf '2\n' >"$sd/commits"
    printf '%s\n' "$pushed" >"$sd/push-main"
    drive --backend opencode "t"
    git -C "$origin_dir" update-ref refs/heads/main "$before"
    assert "D32 a branch commit ($pushed) on remote main exits 13" test "$drv_rc" = 13
  done
  new_case stub
  : >"$sd/break-origin"
  drive --backend opencode "t"
  assert "D32 a failed fetch of main is exit 20, not a silent pass" test "$drv_rc" = 20

  # D33: tampering during a phase that timed out is caught when the run is resumed.
  local -a tampering=(
    'echo x >>.git/info/attributes'
    'printf "#!/bin/sh\n" >.git/hooks/post-commit'
    'git config user.name evil'
    'mkdir -p .claude; echo "{}" >.claude/settings.local.json'
  )
  for mut in "${tampering[@]}"; do
    new_case stub
    printf '%s\nsleep 3029 &\nsleep 3029\n' "$mut" >"$sd/hook-plan.sh"
    drive --backend opencode --phase-timeout 2 "t"
    assert "D33 a timed-out phase doing '$mut' exits 20 first" test "$drv_rc" = 20
    id=$(basename "$(run_dir_of)")
    drive --resume "$id"
    assert "D33 the resume after '$mut' exits 13" test "$drv_rc" = 13
  done
  refute "D33 no leftover sleepers" pgrep -f 'sleep 3029'

  # D34: a readonly phase must not launder a commit or a protected edit through a timeout and resume
  # (an interrupted implement or fix may leave both: D19 resumes one with a dirty tree).
  local -a launder=(
    'plan-review:git commit --no-verify --allow-empty -q -m "chore: sneaky"'
    'plan-review:echo "# x" >>AGENTS.md'
    'code-review:git commit --no-verify --allow-empty -q -m "chore: sneaky"'
    'code-review:echo "# x" >>AGENTS.md'
    'pr:git commit --no-verify --allow-empty -q -m "chore: late"'
    'pr:echo "# x" >>scripts/gate.sh'
  )
  local lk lm
  for mut in "${launder[@]}"; do
    lk=${mut%%:*}
    lm=${mut#*:}
    new_case stub
    printf '%s\nsleep 3033 &\nsleep 3033\n' "$lm" >"$sd/hook-$lk.sh"
    drive --backend opencode --phase-timeout 2 "t"
    assert "D34 [$lk] a timed-out phase doing '$lm' exits 20 first" test "$drv_rc" = 20
    id=$(basename "$(run_dir_of)")
    drive --resume "$id"
    assert "D34 [$lk] the resume after '$lm' exits 13" test "$drv_rc" = 13
    refute "D34 [$lk] nothing was pushed after '$lm'" git -C "$origin_dir" rev-parse -q --verify "refs/heads/$(state_of branch)"
  done
  refute "D34 no leftover sleepers" pgrep -f 'sleep 3033'

  # D28: the snapshot must be identical before and after the real gate (no false exit 13).
  if have_cargo_tools; then
    new_case real
    local snap_a=$tmp/snap-a snap_b=$tmp/snap-b grc=0
    (cd "$clone" && lib take_snapshot >"$snap_a")
    (cd "$clone" && GATE_PRETTIER=0 scripts/gate.sh --commit >"$tmp/d28.log" 2>&1) || grc=$?
    (cd "$clone" && lib take_snapshot >"$snap_b")
    assert "D28 the real gate passes in the clone" test "$grc" = 0
    assert "D28 the snapshot is identical around the real gate" cmp -s "$snap_a" "$snap_b"
    assert "D28 the gate left a clean tree" test -z "$(git -C "$clone" status --porcelain)"
  else
    printf 'skip: D28 needs cargo, rustfmt and clippy\n'
  fi
}

# Probes of the installed CLIs: flags the driver uses must exist. Skipped when a binary is absent or
# FACTORY_TEST_SKIP_CLI=1. They only print help text.
section_probes() {
  local flag help
  if [ "${FACTORY_TEST_SKIP_CLI:-0}" = 1 ]; then
    printf 'skip: FACTORY_TEST_SKIP_CLI is set, no CLI probe runs\n'
    return
  fi
  if command -v claude >/dev/null 2>&1; then
    help=$(claude --help 2>&1 || true)
    for flag in -p --agent --model --permission-mode --allowedTools --strict-mcp-config --no-session-persistence --output-format; do
      assert "probe: claude lists $flag" has "$help" "(^|[^A-Za-z-])$flag([^A-Za-z-]|$)"
    done
  else
    printf 'skip: claude is not installed\n'
  fi
  if command -v opencode >/dev/null 2>&1; then
    help=$(opencode run --help 2>&1 || true)
    for flag in --agent --model --title --dir; do
      assert "probe: opencode run lists $flag" has "$help" "(^|[^A-Za-z-])$flag([^A-Za-z-]|$)"
    done
  else
    printf 'skip: opencode is not installed\n'
  fi
}
# Permission tests: the two configuration files, the generated OpenCode agent overlays and, when
# OpenCode is installed, the rules it resolves for each agent. The evaluator is
# scripts/test-factory-perm.py (python3, standard library only).
section_perm() {
  local line role agents_dir=$tmp/agents
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'skip: python3 is not installed, the permission evaluator is not run\n'
    return
  fi
  if [ "${FACTORY_TEST_SKIP_CLI:-0}" != 1 ] && command -v opencode >/dev/null 2>&1; then
    mkdir -p "$agents_dir"
    # The output holds the contributor's global configuration: parse it, never print it.
    assert "perm: the OpenCode config resolves" bash -c "cd '$repo' && opencode debug config >/dev/null 2>&1"
    for role in planner plan-reviewer implementer code-reviewer pr-writer; do
      assert "perm: the OpenCode agent factory-$role resolves" bash -c "cd '$repo' && opencode debug agent factory-$role >'$agents_dir/factory-$role.json' 2>/dev/null"
    done
  else
    agents_dir=""
    printf 'skip: opencode is not installed, its resolved rules are not checked\n'
  fi
  while IFS= read -r line; do
    case "$line" in
      "PASS "*) ok ;;
      "FAIL "*) bad "perm: ${line#FAIL }" ;;
      "SKIP "*) printf '%s\n' "$line" ;;
    esac
  done < <(python3 -I "$repo/scripts/test-factory-perm.py" "$repo" "$agents_dir")
}

section_static() {
  if command -v shellcheck >/dev/null 2>&1; then
    assert "static: shellcheck is clean over scripts and hooks" bash -c "git -C '$repo' ls-files -z '*.sh' '.githooks/*' | (cd '$repo' && xargs -0 shellcheck)"
  else
    printf 'skip: shellcheck is not installed\n'
  fi

  # CLAUDE.md is a symlink to AGENTS.md, with no content of its own.
  assert "static: CLAUDE.md is a git symlink" has "$(git -C "$repo" ls-files -s CLAUDE.md)" '^120000 '
  assert "static: CLAUDE.md points at AGENTS.md" test "$(readlink "$repo/CLAUDE.md")" = AGENTS.md
  assert "static: CLAUDE.md and AGENTS.md have identical bytes" cmp -s "$repo/CLAUDE.md" "$repo/AGENTS.md"

  # Files that ship with the factory hold no credentials, no local paths and no personal names.
  # docs/factory, scripts/factory.sh and this script necessarily contain the patterns they look for.
  local files f hits="" user host word generic=" root runner ubuntu user admin build home test dev github docker localhost "
  files=$(git -C "$repo" ls-files scripts/gate.sh scripts/factory-sync.sh scripts/test-factory-perm.py .githooks .opencode .claude opencode.json)
  user=$(id -un 2>/dev/null || true)
  host=$(hostname -s 2>/dev/null || true)
  for f in $files; do
    if grep -Eq 'apiKey|\bsk-[A-Za-z0-9]|ghp_' "$repo/$f"; then hits="$hits $f(credential)"; fi
    if grep -E '/(home|Users)/[A-Za-z0-9._-]{3,}/' "$repo/$f" | grep -Evq '/(home|Users)/(<name>|you|user|alice|runner|name)/'; then hits="$hits $f(path)"; fi
    if [ -n "${HOME:-}" ] && [ "$(tr -cd '/' <<<"$HOME" | wc -c)" -ge 2 ] && grep -Fq -- "$HOME" "$repo/$f"; then hits="$hits $f(home)"; fi
    for word in $user $host; do
      if [ "${#word}" -le 4 ]; then continue; fi
      case "$generic" in *" $word "*) continue ;; esac
      if grep -iqw -- "$word" "$repo/$f"; then hits="$hits $f(name)"; fi
    done
  done
  assert "static: no credential, local path or personal name in factory files:$hits" test -z "$hits"
  refute "static: generated prompts never claim to be official" grep -rilE 'official' "$repo/.opencode" "$repo/.claude/agents" "$repo/.claude/commands" "$repo/docs/factory"

  local pcmd
  pcmd=$(prettier_for_tests)
  if [ -n "$pcmd" ]; then
    # Explicit paths only: prettier refuses a symlink argument, and CLAUDE.md is one.
    assert "static: configuration files are prettier-clean" bash -c "cd '$repo' && $pcmd --check opencode.json .claude/settings.json >/dev/null 2>&1"
  fi
}

sections=("$@")
if [ ${#sections[@]} -eq 0 ]; then
  sections=(gate fixture hooks sync perm driver probes static)
fi
for s in "${sections[@]}"; do
  case "$s" in
    gate | fixture | hooks | sync | perm | driver | probes | static) "section_$s" ;;
    *)
      printf 'usage: %s [gate] [fixture] [hooks] [sync] [perm] [driver] [probes] [static]\n' "$0" >&2
      exit 2
      ;;
  esac
done

printf '%s passed, %s failed\n' "$passed" "$failed"
[ "$failed" = 0 ]
