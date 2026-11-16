#!/usr/bin/env bash
#
# Prepare a release: bump the workspace version, update the version tripwires,
# prepend the changelog section for it, and refuse to leave the previous version
# anywhere but the changelog and the tag list.
#
#   scripts/release.sh 0.2.0                 # prepare and commit
#   scripts/release.sh 0.2.0 --dry-run       # print what would change
#   scripts/release.sh 0.2.0 --section docs/0.2.0.md   # hand-written section
#
# Then push the branch, merge, and push the tag; `.github/workflows/release.yml`
# publishes and writes the GitHub release from the section this script added.
#
# Why not `git cliff --tag` alone: that renders every section from the tags, and
# a tag created out of order (as v0.1.1 was, after the commits it points at) is
# dropped, folding its commits into the previous release. `--unreleased` renders
# exactly the commits since the latest tag, which is the section a release needs,
# so this script prepends it and leaves history untouched.
#
# `--section <file>` prepends that file instead of rendering one. It exists for a
# release whose only content is documentation: `git cliff` skips `docs` commits
# (Keep a Changelog has no section for them), so a docs-only release renders an
# empty section and aborts. A curated sentence beats an empty section, and the
# release then needs no `git-cliff` on PATH. The file's first non-blank line must
# be `## [<version>]` or `## [<version>] - <date>`, and it must carry at least one
# `- ` bullet.

set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  printf 'usage: %s <version> [--dry-run] [--section <file>]\n' "$0" >&2
  exit 2
}

version=""
dry_run=false
section_file=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --section)
      if [ $# -lt 2 ] || [ "${2#-}" != "$2" ]; then
        printf '%s needs a file argument\n' "$1" >&2
        usage
      fi
      section_file="$2"
      shift 2
      ;;
    -*)
      usage
      ;;
    *)
      if [ -n "$version" ]; then
        usage
      fi
      version="$1"
      shift
      ;;
  esac
done

if [ -z "$version" ]; then
  usage
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

# The section is produced and checked before anything is written, so a failure on
# either path leaves the tree untouched and the user can fix it and re-run. The
# rendered section does not depend on the version bump - `git cliff --unreleased
# --tag v${version}` takes the tag as an argument - so producing it first is safe.
section=""
if [ -n "$section_file" ]; then
  # A hand-written section: its first non-blank line must be the heading for this
  # release - `## [<version>]` or `## [<version>] - <date>` - and it must carry at
  # least one bullet.
  if [ ! -f "$section_file" ]; then
    printf 'section file does not exist: %s\n' "$section_file" >&2
    exit 1
  fi
  heading=$(awk 'NF { sub(/[[:space:]]+$/, ""); print; exit }' "$section_file")
  # Escape the version's dots so the `.` in the pattern matches a literal dot, not
  # any character; `[` and `]` are literals. `.+` keeps the date non-empty, so a
  # heading that stops at ` - ` is refused.
  version_re=$(printf '%s' "$version" | sed 's/\./\\./g')
  if ! printf '%s\n' "$heading" | grep -Eq "^## \\[${version_re}\\]( - .+)?$"; then
    printf 'section must start with "## [%s]" or "## [%s] - <date>"; first non-blank line is: %s\n' \
      "$version" "$version" "$heading" >&2
    exit 1
  fi
  if ! grep -q '^- ' "$section_file"; then
    printf 'section has no "- " bullet\n' >&2
    exit 1
  fi
  section=$(cat "$section_file")
else
  # Rendering needs git-cliff; a hand-written section does not, so a docs-only
  # release works without it.
  if ! command -v git-cliff >/dev/null; then
    printf 'git-cliff is not on PATH; install it as CONTRIBUTING.md describes\n' >&2
    exit 2
  fi
  section=$(git cliff --unreleased --tag "v${version}" | sed -n '/^## \[/,$p')
  if [ -z "$section" ] || ! printf '%s' "$section" | grep -q '^- '; then
    printf 'git-cliff produced an empty section; is HEAD already tagged?\n' >&2
    printf 'if this release is documentation only, pass --section <file> with a hand-written section\n' >&2
    exit 1
  fi
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

# The internal path dependencies state their own version requirement. A patch
# release keeps satisfying `^0.1.0`, but 0.2.0 does not, so every requirement
# moves with the workspace version before Cargo resolves the lock file.
for manifest in crates/*/Cargo.toml examples/*/Cargo.toml; do
  run sed -i -E \
    "s/(syncspin-(core|client|server) = \{ version = )\"[0-9]+\.[0-9]+\.[0-9]+\"/\1\"${version}\"/" \
    "$manifest"
done

# The lock file pins the workspace members' versions, so it has to move with the
# manifest before the gates run under --locked.
run cargo update --workspace --offline --quiet

# Prepend the section produced above, or print it in a dry run.
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

# 2. Nothing outside the changelog and the lock file may still name the previous
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

  # Catching the previous version is not enough, and a series is not a version either.
  # 0.3.0 shipped a README that still advertised `syncspin-client = "0.2"`: only `0.2.0`
  # was checked, and `0.2` is not `0.2.0`. So the README that lands on every crates.io
  # page (`readme.workspace = true`) must name this release in full - a series such as
  # `0.3` would pass this check and then quietly outlive the patch releases under it.
  if ! grep -qF "${version}" README.md; then
    printf 'README.md does not name %s; the crates.io page would describe another release\n' \
      "${version}" >&2
    printf 'write the full version there, then run this script again\n' >&2
    exit 1
  fi
fi

# 3. Gates before the commit exists.
run cargo fmt --all -- --check
run cargo test --workspace --locked

if $dry_run; then
  printf '\ndry run: nothing changed\n'
  exit 0
fi

git add -A
git commit -m "chore(release): ${version}"
printf '\nprepared %s; push the branch, merge, then push tag v%s\n' "$version" "$version"
