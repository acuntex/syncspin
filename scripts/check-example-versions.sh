#!/bin/sh
# Refuses an example manifest whose Sendspin dependency does not name the workspace version.
#
# The release script rewrites exactly these lines, so a dependency that omits `version`, or names
# a stale one, is one the release cannot bring along: the example would keep resolving whatever
# the path points at while the published crates move. The examples are read, not published, and
# they must show the released version a reader would put in their own manifest.
set -eu

cd "$(dirname "$0")/.."

version=$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml |
  sed -n 's/^version = "\([0-9][0-9.]*\)"$/\1/p' | head -1)
if [ -z "$version" ]; then
  printf 'could not read the workspace version from Cargo.toml\n' >&2
  exit 1
fi

status=0
for manifest in examples/*/Cargo.toml; do
  awk -v want="$version" -v file="$manifest" '
    /^syncspin-(core|client|server)[[:space:]]*=/ {
      if (index($0, "version = \"" want "\"") == 0) {
        printf "%s: expected version = \"%s\": %s\n", file, want, $0
        bad = 1
      }
      if (index($0, "path =") == 0) {
        printf "%s: the dependency needs a path too: %s\n", file, $0
        bad = 1
      }
    }
    END { exit bad ? 1 : 0 }
  ' "$manifest" || status=1
done

if [ "$status" -ne 0 ]; then
  printf 'an example dependency must name the workspace version %s\n' "$version" >&2
fi
exit "$status"
