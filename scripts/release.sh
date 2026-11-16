#!/usr/bin/env bash
#
# Prepare a release: bump the workspace version, update the version tripwires,
# prepend the changelog section for it, and refuse to leave the previous version
# anywhere but the changelog and the tag list.
#
#   scripts/release.sh 0.2.0            # prepare and commit
#   scripts/release.sh 0.2.0 --dry-run  # print what would change
#
# Then push the branch, merge, and push the tag; `.github/workflows/release.yml`
# publishes and writes the GitHub release from the section this script added.
#
# Why not `git cliff --tag` alone: that renders every section from the tags, and
# a tag created out of order (as v0.1.1 was, after the commits it points at) is
# dropped, folding its commits into the previous release. `--unreleased` renders
# exactly the commits since the latest tag, which is the section a release needs,
# so this script prepends it and leaves history untouched.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  printf 'usage: %s <version> [--dry-run]\n' "$0" >&2
  exit 2
fi

version="$1"
dry_run=false
if [ "${2:-}" = "--dry-run" ]; then
  dry_run=true
fi

if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  printf 'not a version: %s\n' "$version" >&2
  exit 2
fi

previous=$(grep -E '^version = "[0-9]+\.[0-9]+\.[0-9]+"$' Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
if [ "$version" = "$previous" ]; then
  printf 'the workspace is already at %s\n' "$version" >&2
  exit 2
fi

if ! command -v git-cliff >/dev/null; then
  printf 'git-cliff is not on PATH; install it as CONTRIBUTING.md describes\n' >&2
  exit 2
fi

run() {
  if $dry_run; then printf '+ %s\n' "$*"; else "$@"; fi
}

# 1. Workspace version, and the tests that pin it. The tripwire is deliberate:
#    a release that forgets the bump has to fail in CI, not at the tag.
run sed -i "s/^version = \"${previous}\"$/version = \"${version}\"/" Cargo.toml
for crate in syncspin-core syncspin-client syncspin-server; do
  run sed -i "s/assert_eq!(version(), \"${previous}\");/assert_eq!(version(), \"${version}\");/" \
    "crates/${crate}/src/lib.rs"
done

# The lock file pins the workspace members' versions, so it has to move with the
# manifest before the gates run under --locked.
run cargo update --workspace --offline --quiet

# 2. The changelog section, from the commits since the latest tag.
section=$(git cliff --unreleased --tag "v${version}" | sed -n '/^## \[/,$p')
if [ -z "$section" ] || ! printf '%s' "$section" | grep -q '^- '; then
  printf 'git-cliff produced an empty section; is HEAD already tagged?\n' >&2
  exit 1
fi

if $dry_run; then
  printf '+ prepend this to CHANGELOG.md:\n%s\n' "$section"
else
  SECTION="$section" python3 - <<'PY'
import os
import pathlib

section = os.environ["SECTION"].strip()
path = pathlib.Path("CHANGELOG.md")
text = path.read_text()
marker = text.index("\n## [")
path.write_text(f"{text[: marker + 1]}{section}\n\n{text[marker + 1 :]}")
PY
fi

# 3. Nothing outside the changelog and the lock file may still name the previous
#    version: that is how a published README advertised 0.1.0 while the crate was
#    0.1.1.
# `-F`: a version is a literal, and a bare regex would also match hex such as
# 000102. A dry run has not applied the sed edits yet, so the check would only
# report its own planned changes.
if ! $dry_run; then
  stale=$(grep -rnF --exclude-dir=.git --exclude-dir=target --exclude-dir=.superpowers \
    --exclude=Cargo.lock --exclude=CHANGELOG.md --exclude=release.sh "${previous}" . 2>/dev/null || true)
  if [ -n "$stale" ]; then
    printf 'the previous version is still named here:\n%s\n' "$stale" >&2
    printf 'edit those files, then run this script again\n' >&2
    exit 1
  fi
fi

# 4. Gates before the commit exists.
run cargo fmt --all -- --check
run cargo test --workspace --locked

if $dry_run; then
  printf '\ndry run: nothing changed\n'
  exit 0
fi

git add -A
git commit -m "chore(release): ${version}"
printf '\nprepared %s; push the branch, merge, then push tag v%s\n' "$version" "$version"
