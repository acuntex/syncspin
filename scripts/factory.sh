#!/usr/bin/env bash
#
# The code factory driver: plan, plan review, implement, code review, pull request, with the control
# flow in this script and the thinking in the agents. It is the only OpenCode path and the unattended
# path for Claude Code. The specification is docs/factory/process.md; the usage text is below.
#
#   scripts/factory.sh [options] "task text"
#   scripts/factory.sh [options] --task-file FILE
#   scripts/factory.sh --resume RUN_ID
#
#     --backend opencode|claude     default $FACTORY_BACKEND, else the first installed
#     --resume ID                   continue a run stopped with exit 10 or exit 20
#     --stop-after plan|implement|review|pr
#                                   stop after the plan (reviewed, or not on the light path), the
#                                   implement phase, the code review loop, or run everything (default).
#                                   `plan` leaves the branch that preflight created in the local
#                                   repository.
#     --no-push                     do not push and do not open the pull request
#     --dry-run                     print the path, the phases and command shapes, call nothing
#     --allow-protected             let the implementer change the protected paths (default off)
#     --plan-rounds N               lower the plan review cap (4) to N
#     --code-rounds N               lower the code review cap (3) to N
#     --model-helper M              model for the reviewers, the pr-writer and the light planner
#                                   ($FACTORY_MODEL_HELPER)
#     --model-main M                model for the full-path planner and the implementer
#                                   ($FACTORY_MODEL_MAIN)
#     --variant-helper V            OpenCode reasoning variant for the helper roles ($FACTORY_VARIANT_HELPER)
#     --variant-main V              OpenCode reasoning variant for the main roles ($FACTORY_VARIANT_MAIN)
#     --opencode-bin PATH           the OpenCode client to run (default $FACTORY_OPENCODE_BIN, else
#                                   `opencode`); its --version selects the 1.x or 2.x command shape
#     --opencode-attach URL         run every OpenCode phase against a running OpenCode server
#                                   ($FACTORY_OPENCODE_ATTACH); http(s)://host[:port], nothing else. The
#                                   server password travels only as $OPENCODE_SERVER_PASSWORD.
#     --phase-timeout SECS          override every phase budget: plan 1200, plan-revise and
#                                   plan-review 900, plan-review-post 600, implement 7200, fix 5400,
#                                   code-review 1500, pr 600, final-gate 7200, anything else 2700
#
# The variant, client and attach options apply to the OpenCode backend only; the Claude backend
# ignores them with a warning.
#
# Exit codes: 0 done, 2 usage, 3 preflight, 10 owner decisions open, 11 plan review cap, 12 code
# review cap, 13 sandbox violation, 14 bad commits, 15 final gate failed, 16 pull request text lint,
# 20 phase failure (resumable). Environment: FACTORY_BACKEND, FACTORY_MODEL_HELPER, FACTORY_MODEL_MAIN,
# FACTORY_VARIANT_HELPER, FACTORY_VARIANT_MAIN, FACTORY_OPENCODE_BIN, FACTORY_OPENCODE_ATTACH,
# FACTORY_PASS_ENV (names of
# variables to pass to the agent, for a model-provider key), OPENCODE_SERVER_PASSWORD (passed to the
# OpenCode phases only together with --opencode-attach).
#
# Test knobs: FACTORY_LIB_ONLY=1 (source the functions without running), FACTORY_SCRUB_USER and
# FACTORY_SCRUB_HOST (override the names the personal-data scrub looks for).

# shellcheck disable=SC2034  # the run state variables are read back through ${!name} in save_state
# shellcheck disable=SC2209,SC1010,SC2100  # phase and step names (pr, done, review) are plain values
set -euo pipefail
# A literal `&` in a replacement must stay a literal `&` (bash 5.2 changed the default).
shopt -u patsub_replacement 2>/dev/null || true

PLAN_CAP=4
CODE_CAP=3
# The limits of the light path: a task whose text is short, names at most three files from the
# allowlist and no code, and whose real diff stays below these limits keeps the short plan, the
# missing plan review and the one short code review. A task that breaks a limit on its text starts on
# the full path; the classifier is a cost heuristic, and the measured diff and the protected-path
# check decide after the implementer call.
LIGHT_MAX_TASK_BYTES=1200
LIGHT_MAX_TASK_LINES=12
LIGHT_MAX_FILES=3
LIGHT_MAX_DIFF_LINES=80
LIGHT_MAX_COMMITS=1
# A path named by a light task has to be the canonical spelling; a longer one is rejected, so the
# task starts on the full path.
LIGHT_MAX_PATH_BYTES=512
# Configuration the tools read at project level, and the files that decide what they may do.
# `.claude/settings.local.json` and `CLAUDE.local.md` are gitignored, so git status never shows them;
# take_snapshot hashes them separately (the `localcfg` component).
PROTECTED=(.githooks scripts .opencode .claude opencode.json opencode.jsonc .mcp.json AGENTS.md CLAUDE.md .github)
# The same entries lowercased: the light path compares names without regard to case, because on a
# case-insensitive file system (`macOS` APFS by default) `Agents.md` is `AGENTS.md`.
PROTECTED_LC=()
for _protected in "${PROTECTED[@]}"; do
  PROTECTED_LC+=("$(printf '%s' "$_protected" | tr '[:upper:]' '[:lower:]')")
done
unset _protected
# Unsafe for the light path but not in PROTECTED: paths whose content is code, generated output or
# the factory's own state. The step-2 prefilter of `classify_task` and its generated tests both read
# these lists, together with PROTECTED, so a name added to one cannot drift away from the other.
UNSAFE_DIRS=(docs/factory .factory .superpowers .git target crates examples src)
UNSAFE_FILES=(Cargo.toml Cargo.lock rust-toolchain.toml deny.toml cliff.toml Makefile)
LOCAL_CONFIG=(.claude/settings.local.json CLAUDE.local.md)
CONVENTIONAL='^(feat|fix|docs|test|refactor|perf|chore|build|ci|style|revert)(\([a-z0-9._-]+\))?!?: .+'
GENERIC_NAMES=" root runner ubuntu user admin build home test dev github docker localhost "

# ---------------------------------------------------------------------------------------------
# Small helpers

hash_stdin() {
  sha256sum | cut -d' ' -f1
}

hash_file() {
  if [ -e "$1" ] || [ -L "$1" ]; then hash_stdin <"$1"; else printf 'absent'; fi
}

# Verdict of a review file: APPROVED only when the last non-empty line, trailing spaces and carriage
# returns stripped, is exactly `VERDICT: APPROVED`. Everything else counts as CHANGES.
parse_verdict() {
  local file=$1 last
  if [ ! -s "$file" ]; then
    printf 'CHANGES'
    return 0
  fi
  last=$(grep -v '^[[:space:]]*$' "$file" | tail -n 1 | sed -e 's/[[:space:]]*$//' || true)
  if [ "$last" = "VERDICT: APPROVED" ]; then printf 'APPROVED'; else printf 'CHANGES'; fi
}

# The lines of the `## Owner decisions` section of a plan, blank lines dropped.
owner_section() {
  awk '/^## Owner decisions[[:space:]]*$/ { f = 1; next } f && /^## / { exit } f' "$1" | tr -d '\r' | grep -v '^[[:space:]]*$' || true
}

owner_section_closed() {
  [ "$(owner_section "$1")" = "None." ]
}

# The lines of `## Owner decisions` that are not marked `BLOCKING`, so the exit-10 report can name a
# question that would otherwise stop the run without saying why. The marker is reported, not trusted:
# `owner_section_closed` still requires exactly `None.`.
unmarked_owner_lines() {
  owner_section "$1" | grep -Ev '^(None\.$|([[:space:]]*-[[:space:]]+)?BLOCKING:[[:space:]]*[^[:space:]])' || true
}

# plan_body <file>: the plan without its `## Owner decisions` and `## Changelog` sections, with
# trailing whitespace stripped and blank lines squeezed, so a revision that merely answers a question
# hashes the same as before.
plan_body() {
  awk '
    /^## (Owner decisions|Changelog)[[:space:]]*$/ { skip = 1; next }
    skip && /^## / { skip = 0 }
    !skip { print }
  ' "$1" | sed -e 's/[[:space:]]*$//' | awk '
    /^$/ { if (blank) next; blank = 1; print; next }
    { blank = 0; print }
  '
}

# A user or host name that already occurs as a whole word in the base tree is an ordinary word there
# (a machine called `server` or `laptop`), not a leak: it is not scrubbed. Cached per name.
SCRUB_KNOWN_WORDS=" "
SCRUB_UNKNOWN_WORDS=" "
word_in_base_tree() {
  case "$SCRUB_KNOWN_WORDS" in *" $1 "*) return 0 ;; esac
  case "$SCRUB_UNKNOWN_WORDS" in *" $1 "*) return 1 ;; esac
  if git grep -qiwF -e "$1" "${base_sha:-HEAD}" -- 2>/dev/null; then
    SCRUB_KNOWN_WORDS="$SCRUB_KNOWN_WORDS$1 "
    return 0
  fi
  SCRUB_UNKNOWN_WORDS="$SCRUB_UNKNOWN_WORDS$1 "
  return 1
}

# Personal-data scrub: reads text on stdin, prints what it found, returns 1 when anything matched.
scrub() {
  local text found=0 home user host word seg
  text=$(cat)
  home=${HOME:-}
  seg=$(printf '%s' "$home" | tr -cd '/' | wc -c)
  if [ "$seg" -ge 2 ] && grep -Fq -- "$home" <<<"$text"; then
    printf 'the home directory path\n'
    found=1
  fi
  user=${FACTORY_SCRUB_USER-$(id -un 2>/dev/null || true)}
  host=${FACTORY_SCRUB_HOST-$(hostname -s 2>/dev/null || true)}
  for word in $user $host; do
    if [ "${#word}" -le 4 ]; then continue; fi
    case "$GENERIC_NAMES" in *" $word "*) continue ;; esac
    if word_in_base_tree "$word"; then continue; fi
    if grep -qw -- "$word" <<<"$text"; then
      printf 'the user or host name "%s"\n' "$word"
      found=1
    fi
  done
  if grep -Eo '/(home|Users)/[A-Za-z0-9._-]{3,}/' <<<"$text" | grep -Evq '^/(home|Users)/(you|user|alice|runner|name)/$'; then
    printf 'a /home/<name>/ or /Users/<name>/ path\n'
    found=1
  fi
  [ "$found" = 0 ]
}

slugify() {
  local words slug user host
  # The first four words, skipping a path-like token, a secret-shaped token and the current user or
  # host name (unless it is a generic word), also when punctuation or a possessive is attached: a
  # task that starts with `/home/<name>/...`, carries a token such as `ghp_...` or names the user as
  # a possessive, a comma, a period or after a hyphen must not put any of it in a branch name, a
  # session title or a run header.
  user=${FACTORY_SCRUB_USER-$(id -un 2>/dev/null || true)}
  host=${FACTORY_SCRUB_HOST-$(hostname -s 2>/dev/null || true)}
  words=$(printf '%s' "$1" | tr '\n' ' ' | awk -v user="$user" -v host="$host" -v generic="$GENERIC_NAMES" '
    # named(w, name): 1 when the lowercased token contains the name as a whole word, with a
    # non-alphanumeric character (or either end) on both sides, so a name after punctuation is
    # recognised, not only the token that starts with the name.
    function named(w, name,   n, rest, off, i, pos) {
      if (length(name) <= 4) return 0
      n = tolower(name)
      if (index(generic, " " n " ") != 0) return 0
      off = 0
      rest = w
      while ((i = index(rest, n)) > 0) {
        pos = off + i
        if ((pos == 1 || substr(w, pos - 1, 1) !~ /[a-z0-9]/) &&
            (pos + length(n) > length(w) || substr(w, pos + length(n), 1) !~ /[a-z0-9]/)) return 1
        off = pos
        rest = substr(w, pos + 1)
      }
      return 0
    }
    function private(word,   w) {
      if (word ~ /[\/~@\\]/) return 1
      if (length(word) >= 32 && word ~ /^[A-Za-z0-9_-]+$/) return 1
      if (word ~ /(^|[^A-Za-z0-9])(sk-|ghp_|gho_|github_pat_|xox)/) return 1
      w = tolower(word)
      gsub(/^[^a-z0-9]+/, "", w)
      gsub(/[^a-z0-9]+$/, "", w)
      if (named(w, user) || named(w, host)) return 1
      return 0
    }
    {
      n = 0
      for (i = 1; i <= NF; i++) {
        if (private($i)) continue
        printf "%s ", $i
        if (++n == 4) break
      }
    }')
  slug=$(printf '%s' "$words" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9]\{1,\}/-/g' -e 's/^-*//' -e 's/-*$//' | cut -c1-30 | sed -e 's/-*$//')
  printf '%s' "${slug:-task}"
}

shortid() {
  od -An -N3 -tx1 /dev/urandom | tr -d ' \n'
}

# fmt_duration <seconds>: the launcher's format, so `--status` and the driver's summary agree.
fmt_duration() {
  local s=$1
  if [ "$s" -ge 3600 ]; then
    printf '%dh%02dm%02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
  else
    printf '%dm%02ds' $((s / 60)) $((s % 60))
  fi
}

# ---------------------------------------------------------------------------------------------
# The light path: whether a task is trivial enough for the short plan, the missing plan review and
# the one short code review. The classification is a cost heuristic in shell code: it picks the
# starting path, and a name it cannot read (prose, an escape, a look-alike) may still start light.
# The measured diff and the protected-path check are the safety net, not the classifier.

# canonical_path <path>: return 0 when the path already has the only form the light path accepts:
# segments of ASCII letters, digits, `.`, `_` and `-`, separated by single slashes, none empty and
# none `.` or `..`; no leading `/`, `~` or `-`; no backslash, colon or control character; at most
# LIGHT_MAX_PATH_BYTES bytes. A name the function rejects is treated as full by its callers.
canonical_path() {
  local p=$1
  [ -n "$p" ] || return 1
  [ "${#p}" -le "$LIGHT_MAX_PATH_BYTES" ] || return 1
  case "$p" in /* | "~"* | -* | *\\* | *:*) return 1 ;; esac
  # The character check below is line-based, so a newline would let `a<newline>b.md` pass: reject it
  # before, because a diff name is one name and a newline is never part of a canonical segment.
  case "$p" in *$'\n'* | *$'\r'*) return 1 ;; esac
  case "/$p/" in *//* | */./* | */../*) return 1 ;; esac
  if printf '%s' "$p" | LC_ALL=C grep -q '[^A-Za-z0-9._/-]'; then return 1; fi
  return 0
}

# normalize_path <path>: print the path a light task names, or return 1 when it is not canonical. A
# single leading `./` is the only spelling that is canonicalised: it is stripped once and the result
# must pass canonical_path from the start. Every other spelling (a repeated slash, a `/./` or `..`
# segment, a backslash, a colon, a leading `-`) is left as written and rejected, so a caller that
# treats a rejected name as full never sees a normalised form of an unsafe path.
normalize_path() {
  local p=$1
  case "$p" in ./*) p=${p#./} ;; esac
  canonical_path "$p" || return 1
  printf '%s' "$p"
}

# light_path_ok <path>: the allowlist of the light path. A file whose basename ends in `.md` or
# `.txt`, and `.gitignore`, may change; prosa and nothing else. The path has to be canonical (see
# normalize_path), the protected names and directory prefixes are compared without regard to case,
# and a name equal to or under a protected entry is protected whatever its extension.
light_path_ok() {
  local p=$1 entry base lower
  # normalize_path already returns the validated canonical form, so no second pass is needed.
  p=$(normalize_path "$1") || return 1
  lower=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')
  for entry in "${PROTECTED_LC[@]}"; do
    case "$lower" in "$entry" | "$entry"/*) return 1 ;; esac
  done
  case "$lower" in
    docs/factory/* | .factory/* | .superpowers/* | .git/* | target/* | crates/* | examples/* | src/*) return 1 ;;
  esac
  [ "$lower" = .gitignore ] && return 0
  base=${p##*/}
  case "$base" in *.md | *.txt) return 0 ;; esac
  return 1
}

# clean_word <word>: the word without quotes, brackets and backticks, and without trailing
# punctuation, so that "`README.md`," becomes README.md.
clean_word() {
  local w=$1
  w=${w//[\"\'\`]/}
  w=${w//\(/}
  w=${w//\)/}
  w=${w//\[/}
  w=${w//\]/}
  w=${w//\{/}
  w=${w//\}/}
  w=${w//</}
  w=${w//>/}
  while [ -n "$w" ]; do
    case "${w: -1}" in
      . | , | ';' | ':') w=${w%?} ;;
      *) break ;;
    esac
  done
  printf '%s' "$w"
}

# light_size_reason <files> <lines>: the reason of a light task, without a repeated "light".
light_size_reason() {
  local files=$1 lines=$2
  printf '%s file%s, %s line%s' "$files" "$([ "$files" = 1 ] || printf s)" "$lines" \
    "$([ "$lines" = 1 ] || printf s)"
}

# classify_task: reads the task text on stdin and sets class_path and class_reason. Trailing newlines
# are not part of the text (command substitution drops them), so a 13-line text without a final
# newline is 13 lines. Never calls a model and never touches the tree.
classify_task() {
  local text scan_text bytes lines word w w_norm w_lc tok esc entry candidate first_dir="" files=0 reject="" oldifs=$IFS had_glob=0
  text=$(cat)
  class_path=full
  bytes=$(printf '%s' "$text" | wc -c)
  lines=$(printf '%s' "$text" | awk 'END { print NR }')
  if [ "$bytes" -gt "$LIGHT_MAX_TASK_BYTES" ] || [ "$lines" -gt "$LIGHT_MAX_TASK_LINES" ]; then
    class_reason="the task text is too large ($bytes bytes, $lines lines)"
    return 0
  fi
  # A copy for the line-based scans: a newline becomes a space and a Markdown link's text and
  # target are separated, so `AGENTS` followed by a line break and `.md`, and `[guide](AGENTS.md)`,
  # cannot hide a name between two pieces read one at a time.
  scan_text=$(printf '%s' "$text" | tr '\n' ' ')
  scan_text=${scan_text//']('/']( '}
  # A path the light path may never touch, named anywhere in the text as a whole word. The names
  # come from PROTECTED and the unsafe lists above, and the match ignores case, because on a
  # case-insensitive file system `agents.md` is `AGENTS.md`.
  for tok in "${PROTECTED[@]}" "${UNSAFE_DIRS[@]}" "${UNSAFE_FILES[@]}"; do
    esc=${tok//./\\.}
    if LC_ALL=C grep -Eiq "(^|[^[:alnum:]_.-])$esc([^[:alnum:]_.-]|$)" <<<"$scan_text"; then
      class_reason="the task text names $tok"
      return 0
    fi
  done
  # A protected stem split from its extension (`AGENTS md`, `AGENTS .md`, or a line break between
  # them, which the scan copy turned into a space) names the same file.
  for tok in AGENTS CLAUDE .mcp; do
    esc=${tok//./\\.}
    if LC_ALL=C grep -Eiq "(^|[^[:alnum:]_.-])${esc}[[:space:]]*\.?(md|json)([^[:alnum:]_.-]|$)" <<<"$scan_text"; then
      class_reason="the task text names $tok"
      return 0
    fi
  done
  case $- in *f*) had_glob=1 ;; esac
  IFS=$' \t\n'
  set -f
  for word in $scan_text; do
    w=$(clean_word "$word")
    [ -n "$w" ] || continue
    case "$w" in
      */)
        # A directory mention has to be canonical too: only one leading `./` is stripped, and a
        # repeated slash, a `/./` segment or a `..` segment makes the task full. An absolute or
        # home-path mention is not a repository directory and stays a mention; a rejected mention
        # is full.
        case "$w" in
          /* | "~"*) ;;
          *)
            if w_norm=$(normalize_path "${w%/}"); then
              w=$w_norm/
            else
              reject=${w%/}
              break
            fi
            ;;
        esac
        # A canonical directory mention: the protected directories and prefixes are matched without
        # regard to case, because `Scripts/` is `scripts/` on a case-insensitive file system.
        w_lc=$(printf '%s' "$w" | tr '[:upper:]' '[:lower:]')
        case "$w_lc" in
          scripts/* | crates/* | examples/* | src/* | docs/factory/* | .github/* | .githooks/* | .opencode/* | .claude/* | .factory/* | .superpowers/* | .git/* | target/*)
            reject=$w
            break
            ;;
        esac
        for entry in "${PROTECTED_LC[@]}"; do
          case "$w_lc" in "$entry"/*) reject=$w ;; esac
        done
        if [ -n "$reject" ]; then break; fi
        if [ -z "$first_dir" ]; then first_dir=$w; fi
        ;;
      *)
        # A URL is not a repository file, however much it looks like one: a token with a scheme
        # (`https:`, `file:`) or a protocol-relative `//host` path. Checked before the candidate
        # test, so `file:AGENTS.md` never reaches the allowlist.
        if [[ "$w" =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]] || [[ "$w" == //* ]]; then
          reject=$w
          break
        fi
        candidate=0
        if [[ "$w" == */* ]] || [[ "$w" =~ ^[[:alnum:]_.+-]*\.[[:alpha:]][[:alnum:]]{0,9}$ ]]; then
          candidate=1
        fi
        if [ "$candidate" = 0 ]; then
          # Prose normally ends here. A token that carries a backslash, a percent or a byte outside
          # ASCII is a spelling the scanner cannot read as a name (`AGENTS\.md`, `AGENTS%2Emd`,
          # `AGENTS。md`), so it rejects the task instead of being ignored.
          case "$w" in *\\* | *%*) reject=$w; break ;; esac
          if printf '%s' "$w" | LC_ALL=C grep -q '[^ -~]'; then
            reject=$w
            break
          fi
          continue
        fi
        if light_path_ok "$w"; then
          files=$((files + 1))
        elif [ -z "$reject" ]; then
          reject=$w
        fi
        ;;
    esac
  done
  IFS=$oldifs
  if [ "$had_glob" = 0 ]; then set +f; fi
  if [ -n "$reject" ]; then
    class_reason="the task text names $reject"
  elif [ "$files" = 0 ]; then
    if [ -n "$first_dir" ]; then
      class_reason="the task text names only the directory $first_dir"
    else
      class_reason="the task text names no file"
    fi
  elif [ "$files" -gt "$LIGHT_MAX_FILES" ]; then
    class_reason="the task text names $files files"
  else
    class_path=light
    class_reason=$(light_size_reason "$files" "$lines")
  fi
}

# light_diff_check: prints nothing and returns 0 when the real diff since the base stays within the
# light limits, otherwise prints one reason and returns 1. `--no-renames` keeps both sides of a
# rename visible, so a code or script file renamed to a `.md` name is still caught. NUL-separated
# names keep a name with a space or a newline in one piece, and a failed git command escalates.
light_diff_check() {
  local base=$base_sha p lines=0 commits numstat names_file
  local -a changed_names=() untracked_names=()
  names_file="${run_dir:-${TMPDIR:-/tmp}}/light-diff.$$"
  if ! git diff --name-only -z --no-renames --diff-filter=ACMRD "$base" >"$names_file" 2>/dev/null; then
    rm -f "$names_file"
    printf 'the diff against %s could not be read' "$base"
    return 1
  fi
  while IFS= read -r -d '' p; do
    if [ -n "$p" ]; then changed_names+=("$p"); fi
  done <"$names_file"
  if ! git ls-files -z --others --exclude-standard >"$names_file" 2>/dev/null; then
    rm -f "$names_file"
    printf 'the untracked files could not be read'
    return 1
  fi
  while IFS= read -r -d '' p; do
    if [ -n "$p" ]; then
      changed_names+=("$p")
      untracked_names+=("$p")
    fi
  done <"$names_file"
  rm -f "$names_file"
  if [ "${#changed_names[@]}" = 0 ]; then
    printf 'the change touched no file'
    return 1
  fi
  for p in "${changed_names[@]}"; do
    if ! light_path_ok "$p"; then
      printf 'the change touches %s' "$p"
      return 1
    fi
  done
  if [ "${#changed_names[@]}" -gt "$LIGHT_MAX_FILES" ]; then
    printf 'the change touches %s files' "${#changed_names[@]}"
    return 1
  fi
  if ! numstat=$(git diff --numstat --no-renames "$base" 2>/dev/null); then
    printf 'the diff against %s could not be read' "$base"
    return 1
  fi
  lines=$(awk '{ a += $1; d += $2 } END { print a + d }' <<<"$numstat")
  for p in "${untracked_names[@]}"; do
    if [ -f "$p" ]; then lines=$((lines + $(awk 'END { print NR }' "$p"))); fi
  done
  if [ "$lines" -gt "$LIGHT_MAX_DIFF_LINES" ]; then
    printf 'the change is %s added and deleted lines' "$lines"
    return 1
  fi
  commits=$(git rev-list --count "$base..HEAD")
  if [ "$commits" -gt "$LIGHT_MAX_COMMITS" ]; then
    printf 'the change is %s commits' "$commits"
    return 1
  fi
  return 0
}

# detect_opencode_generation <bin>: print the major version (1 or 2) from `<bin> --version`, and fail
# on anything else. Only the version output is read; no model is started.
detect_opencode_generation() {
  local out major
  out=$("$1" --version 2>/dev/null || true)
  out=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$out" | head -n1 || true)
  major=${out%%.*}
  case "$major" in
    1 | 2) printf '%s' "$major" ;;
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

# ---------------------------------------------------------------------------------------------
# Snapshot: what a phase must not change. Computed from refs, config, hooks, the worktree and the
# protected set, and from nothing else. The worktree part is `git status` (a staged change shows as
# `M ` against a clean baseline, so staging hides nothing) plus the content of every path it lists.

snap_paths() {
  local p
  while IFS= read -r -d '' p; do
    if [ -L "$p" ]; then
      printf '%s link:%s\n' "$p" "$(readlink "$p")"
    elif [ ! -e "$p" ]; then
      printf '%s deleted\n' "$p"
    elif [ -d "$p" ]; then
      printf '%s repo:%s:%s\n' "$p" "$(git -C "$p" rev-parse HEAD 2>/dev/null || printf none)" \
        "$(find "$p" -type f -printf '%P %s %m\n' 2>/dev/null | LC_ALL=C sort | hash_stdin)"
    else
      printf '%s %s %s\n' "$p" "$(git hash-object --no-filters -- "$p")" "$(stat -c %a -- "$p")"
    fi
  done
}

# take_snapshot [exclude-branch]: one `name value` line per component.
take_snapshot() {
  local exclude=${1:-} f
  printf 'refs %s\n' "$(git for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags | hash_stdin)"
  printf 'refs-code %s\n' "$(git for-each-ref --format='%(refname) %(objectname)' | grep -v '^refs/remotes/' | { if [ -n "$exclude" ]; then grep -v "^refs/heads/$exclude "; else cat; fi; } | hash_stdin)"
  printf 'head %s\n' "$(git symbolic-ref -q HEAD || printf detached)"
  printf 'tip %s\n' "$(git rev-parse -q --verify "refs/heads/${exclude:-__none__}" || printf none)"
  printf 'config %s\n' "$({
    git config --local --list
    for f in config config.worktree info/attributes info/exclude; do
      printf '%s %s\n' "$f" "$(hash_file "$(git rev-parse --git-path "$f")")"
    done
  } | hash_stdin)"
  printf 'hooks %s\n' "$({
    local hooks_dir
    # Not `--git-path hooks`: that follows core.hooksPath, and the driver points it at .githooks.
    hooks_dir=$(git rev-parse --git-dir)/hooks
    if [ -d "$hooks_dir" ]; then
      for f in "$hooks_dir"/*; do
        [ -e "$f" ] || continue
        case "$f" in *.sample) continue ;; esac
        printf '%s %s\n' "$(basename "$f")" "$(hash_file "$f")"
      done
    fi
  } | hash_stdin)"
  printf 'worktree %s\n' "$({
    git status --porcelain=v1 -z --untracked-files=all | tr '\0' '\n'
    git ls-files -m -o --exclude-standard -z | snap_paths
  } | hash_stdin)"
  printf 'localcfg %s\n' "$(for f in "${LOCAL_CONFIG[@]}"; do printf '%s %s\n' "$f" "$(hash_file "$f")"; done | hash_stdin)"
  printf 'taskdoc %s\n' "$(hash_file "${run_dir:+$run_dir/task.md}")"
  printf 'plandoc %s\n' "$(hash_file "${run_dir:+$run_dir/plan.md}")"
  printf 'protected %s\n' "$(git ls-files -z -- "${PROTECTED[@]}" | snap_paths | hash_stdin)"
  if [ -L CLAUDE.md ] && [ "$(readlink CLAUDE.md)" = AGENTS.md ] && [[ "$(git ls-files -s CLAUDE.md)" == 120000* ]]; then
    printf 'symlink ok\n'
  else
    printf 'symlink broken\n'
  fi
}

# compare_snapshots <readonly|code> <before> <after> [names]: prints the names of changed components.
compare_snapshots() {
  local mode=$1 before=$2 after=$3 names=${4:-} name changed=1
  if [ -n "$names" ]; then
    :
  elif [ "$mode" = readonly ]; then
    names="refs head config hooks worktree protected symlink localcfg taskdoc plandoc"
  else
    names="refs-code head config hooks symlink localcfg taskdoc plandoc"
  fi
  for name in $names; do
    # The planner legitimately rewrites the plan.
    if [ "$name" = plandoc ] && [ "${snap_skip_plandoc:-0}" = 1 ]; then continue; fi
    if [ "$(grep "^$name " "$before")" != "$(grep "^$name " "$after")" ]; then
      printf '%s ' "$name"
      changed=0
    fi
  done
  [ "$changed" = 1 ]
}

# Commit checks over base..HEAD; prints each problem, returns 1 when there is one.
check_commits() {
  local base=$1 problems=0 commits h subject body added
  commits=$(git rev-list --reverse "$base..HEAD")
  if [ -z "$commits" ]; then
    printf 'no commit above the base\n'
    return 1
  fi
  for h in $commits; do
    subject=$(git log -n1 --format=%s "$h")
    body=$(git log -n1 --format=%B "$h")
    if ! grep -Eq "$CONVENTIONAL" <<<"$subject"; then
      printf 'commit %s: subject is not a Conventional Commits title\n' "${h:0:8}"
      problems=1
    fi
    if grep -Eiq '^(Co-Authored-By:|.*Generated (with|by) )' <<<"$body"; then
      printf 'commit %s: attribution line\n' "${h:0:8}"
      problems=1
    fi
    if grep -Eq '#[0-9]+' <<<"$body"; then
      printf 'commit %s: a #<number> reference\n' "${h:0:8}"
      problems=1
    fi
    if ! what=$(scrub <<<"$body"); then
      printf 'commit %s: personal data in the message (%s)\n' "${h:0:8}" "$(tr '\n' ';' <<<"$what")"
      problems=1
    fi
  done
  added=$(git diff --no-color -U0 "$base..HEAD" | grep '^+' | grep -v '^+++' || true)
  if ! what=$(scrub <<<"$added"); then
    printf 'personal data in added lines (%s)\n' "$(tr '\n' ';' <<<"$what")"
    problems=1
  fi
  [ "$problems" = 0 ]
}

# Lint of the pull request text; prints each problem, returns 1 when there is one.
lint_pr() {
  local file=$1 title problems=0 what
  title=$(head -n 1 "$file")
  if ! grep -Eq "$CONVENTIONAL" <<<"$title" || [ "${#title}" -gt 72 ]; then
    printf 'the title is not a Conventional Commits title of at most 72 characters\n'
    problems=1
  fi
  if grep -Eq '#[0-9]+' "$file"; then
    printf 'a #<number> reference (GitHub would link it to another pull request)\n'
    problems=1
  fi
  if grep -Eiq '(Co-Authored-By:|Generated (with|by) )' "$file"; then
    printf 'an attribution line\n'
    problems=1
  fi
  if ! grep -Eiq '^#{1,6}[[:space:]]+Not verified[[:space:]]*$' "$file"; then
    printf 'no "Not verified" heading\n'
    problems=1
  fi
  if ! what=$(scrub <"$file"); then
    printf 'personal data (%s)\n' "$(tr '\n' ';' <<<"$what")"
    problems=1
  fi
  [ "$problems" = 0 ]
}

# Replace {{NAME}} placeholders in a template read from stdin. Values come from P_* variables.
render() {
  local s
  s=$(cat)
  s=${s//'{{TASK_FILE}}'/${P_TASK_FILE-}}
  s=${s//'{{ARTIFACT}}'/${P_ARTIFACT-}}
  s=${s//'{{PLAN}}'/${P_PLAN-}}
  s=${s//'{{REVIEW}}'/${P_REVIEW-}}
  s=${s//'{{DECISIONS}}'/${P_DECISIONS-}}
  s=${s//'{{ROUND}}'/${P_ROUND-}}
  s=${s//'{{MAX_ROUNDS}}'/${P_MAX-}}
  s=${s//'{{BASE_SHA}}'/${P_BASE-}}
  s=${s//'{{BRANCH}}'/${P_BRANCH-}}
  s=${s//'{{RUN_DIR}}'/${P_RUN_DIR-}}
  s=${s//'{{GATE_CMD}}'/${P_GATE-}}
  s=${s//'{{RESUME_CONTEXT}}'/${P_RESUME-}}
  printf '%s\n' "$s"
}

# truncate_text <bytes> <text>
truncate_text() {
  if [ "${#2}" -le "$1" ]; then
    printf '%s' "$2"
  else
    printf '%s\n(truncated)' "${2:0:$1}"
  fi
}

resume_context() {
  if [ "$resuming" = 1 ]; then
    # One argv element: keep it far below the kernel limit for a single argument.
    printf 'A previous attempt was interrupted; inspect the tree and continue.\n\nGit status:\n%s\n\nCommits since the base:\n%s\n' \
      "$(truncate_text 3000 "$(git status --porcelain)")" "$(truncate_text 3000 "$(git log --oneline "$base_sha..HEAD")")"
  fi
}

# The log of the last invocation of a phase, ANSI escape sequences removed.
phase_log_text() {
  local file=$1 esc bel
  esc=$(printf '\033')
  bel=$(printf '\007')
  [ -f "$file" ] || return 0
  awk '/^== / { n = 0; delete a; next } { a[++n] = $0 } END { for (i = 1; i <= n; i++) print a[i] }' "$file" |
    LC_ALL=C sed -e "s#${esc}\\[[0-9;?]*[ -/]*[@-~]##g" -e "s#${esc}\\][^${bel}]*${bel}##g" -e 's/\r$//' || true
}

# classify_log: reads the cleaned log on stdin, prints one of login, trust, limit, unknown.
classify_log() {
  local text
  text=$(cat)
  if grep -Eiq 'Not logged in|run /login|Please run /login' <<<"$text"; then
    printf 'login'
  elif grep -Eiq 'has not been trusted|trust dialog' <<<"$text"; then
    printf 'trust'
  elif grep -Eiq 'rate_limit|usage limit|spend limit|(^|[^0-9])429([^0-9]|$)' <<<"$text"; then
    printf 'limit'
  else
    printf 'unknown'
  fi
}

# log_head <lines>: the first lines of the cleaned log on stdin, each cut at 200 characters. A line
# that holds personal data (see scrub) is replaced, not shortened, so nothing of it is kept.
log_head() {
  local max=$1 line count=0
  while IFS= read -r line && [ "$count" -lt "$max" ]; do
    [ -n "${line//[[:space:]]/}" ] || continue
    if { [ -n "${OPENCODE_SERVER_PASSWORD:-}" ] && [[ "$line" == *"$OPENCODE_SERVER_PASSWORD"* ]]; } || { [ -n "${OPENCODE_SERVER_USERNAME:-}" ] && [[ "$line" == *"$OPENCODE_SERVER_USERNAME"* ]]; }; then
      line='[line withheld: it holds personal data or a token]'
    elif ! scrub <<<"$line" >/dev/null || grep -Eq '[A-Za-z0-9_-]{32,}|(^|[^A-Za-z0-9])(sk-|ghp_|gho_|github_pat_|xox)' <<<"$line"; then
      line='[line withheld: it holds personal data or a token]'
    fi
    printf '%s\n' "${line:0:200}"
    count=$((count + 1))
  done
}

cause_md=""

# diagnose <phase-name> <artifact-missing 0|1> [report]: sets cause_md for handoff.md and prints one
# line to stderr. Called only when a phase is about to stop the run; the exit code is the caller's
# business. `report` names a phase that exited 0 and never wrote its artifact, retry included.
diagnose() {
  local name=$1 missing=$2 why=${3:-} kind text fix summary head_lines line
  text=$(phase_log_text "$run_dir/logs/$name.log")
  kind=$(classify_log <<<"$text")
  if [ "$why" = report ]; then
    summary="ended without its report"
    fix="the phase exited 0 and wrote nothing; read logs/$name.log and resume"
  else
    case "$kind" in
      login)
        summary="not logged in"
        fix="log in once (run the backend interactively and sign in; Claude Code: /login), then resume"
        ;;
      trust)
        summary="workspace not trusted"
        fix="open claude in this clone once and accept the workspace trust dialog, then resume"
        ;;
      limit)
        summary="rate or usage limit"
        fix="wait until the limit resets or switch backend (--backend), then resume"
        ;;
      *)
        summary="no known cause in the log"
        fix="read logs/$name.log"
        if [ "$backend" = claude ] && [ "$missing" = 1 ]; then
          fix="$fix; the Edit(...) rule form may be wrong for this Claude Code version"
        fi
        ;;
    esac
  fi
  head_lines=$(log_head 12 <<<"$text")
  cause_md=$(
    printf '## Cause\n\n%s. Fix: %s.\n\n' "$summary" "$fix"
    printf 'First lines of logs/%s.log:\n\n' "$name"
    if [ -n "$head_lines" ]; then
      while IFS= read -r line; do printf '    %s\n' "$line"; done <<<"$head_lines"
    else
      printf '    (the log is empty)\n'
    fi
  )
  if [ "$kind" = unknown ] && [ "$backend" = claude ] && [ "$missing" = 1 ]; then
    printf 'factory: artifact missing: the Edit(...) rule form may be wrong for this Claude Code version\n' >&2
  else
    printf 'factory: cause: %s; %s\n' "$summary" "$fix" >&2
  fi
}

if [ "${FACTORY_LIB_ONLY:-0}" = 1 ]; then
  # shellcheck disable=SC2317  # reached when the file is sourced
  return 0 2>/dev/null || exit 0
fi

# ---------------------------------------------------------------------------------------------
# Usage and options

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD

usage() {
  awk '/^#   scripts\/factory.sh \[options\]/ { f = 1 } f { sub(/^# ?/, ""); print } /--phase-timeout/ { exit }' "${BASH_SOURCE[0]}" >&2
  exit "${1:-2}"
}

die_usage() {
  printf 'factory: %s\n' "$1" >&2
  exit 2
}

die_preflight() {
  printf 'factory: %s\n' "$1" >&2
  exit 3
}

backend=${FACTORY_BACKEND:-}
resume_id=""
stop_after=pr
no_push=0
dry_run=0
allow_protected=0
plan_cap=$PLAN_CAP
code_cap=$CODE_CAP
model_helper=${FACTORY_MODEL_HELPER:-}
model_main=${FACTORY_MODEL_MAIN:-}
variant_helper=${FACTORY_VARIANT_HELPER:-}
variant_main=${FACTORY_VARIANT_MAIN:-}
opencode_bin=${FACTORY_OPENCODE_BIN:-opencode}
opencode_bin_explicit=0
[ -z "${FACTORY_OPENCODE_BIN:-}" ] || opencode_bin_explicit=1
opencode_gen=""
opencode_attach=${FACTORY_OPENCODE_ATTACH:-}
phase_timeout=""
task_text=""
task_file=""

need_value() {
  [ "$#" -ge 2 ] && [ -n "$2" ] || die_usage "$1 needs a value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --backend) need_value "$@"; backend=$2; shift 2 ;;
    --resume) need_value "$@"; resume_id=$2; shift 2 ;;
    --stop-after) need_value "$@"; stop_after=$2; shift 2 ;;
    --no-push) no_push=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --allow-protected) allow_protected=1; shift ;;
    --plan-rounds) need_value "$@"; plan_cap=$2; shift 2 ;;
    --code-rounds) need_value "$@"; code_cap=$2; shift 2 ;;
    --model-helper) need_value "$@"; model_helper=$2; shift 2 ;;
    --model-main) need_value "$@"; model_main=$2; shift 2 ;;
    --variant-helper) need_value "$@"; variant_helper=$2; shift 2 ;;
    --variant-main) need_value "$@"; variant_main=$2; shift 2 ;;
    --opencode-bin) need_value "$@"; opencode_bin=$2; opencode_bin_explicit=1; shift 2 ;;
    --opencode-attach) need_value "$@"; opencode_attach=$2; shift 2 ;;
    --phase-timeout) need_value "$@"; phase_timeout=$2; shift 2 ;;
    --task-file) need_value "$@"; task_file=$2; shift 2 ;;
    -h | --help) usage 0 ;;
    --*) die_usage "unknown option $1" ;;
    *)
      [ -z "$task_text" ] || die_usage "more than one task text"
      task_text=$1
      shift
      ;;
  esac
done

case "$stop_after" in plan | implement | review | pr) ;; *) die_usage "--stop-after takes plan, implement, review or pr" ;; esac
[[ "$plan_cap" =~ ^[0-9]+$ ]] && [ "$plan_cap" -ge 1 ] && [ "$plan_cap" -le "$PLAN_CAP" ] || die_usage "--plan-rounds takes 1 to $PLAN_CAP (the cap can only be lowered)"
[[ "$code_cap" =~ ^[0-9]+$ ]] && [ "$code_cap" -ge 1 ] && [ "$code_cap" -le "$CODE_CAP" ] || die_usage "--code-rounds takes 1 to $CODE_CAP (the cap can only be lowered)"
if [ -n "$phase_timeout" ]; then
  [[ "$phase_timeout" =~ ^[0-9]+$ ]] && [ "$phase_timeout" -ge 1 ] || die_usage "--phase-timeout takes a number of seconds"
fi
case "$backend" in "" | opencode | claude) ;; *) die_usage "--backend takes opencode or claude" ;; esac
# A variant reaches `opencode run --variant` as one argument: a conservative pattern keeps anything
# else out of the command line. The attach URL has no user, path or query.
[ -z "$variant_helper" ] || [[ "$variant_helper" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die_usage "--variant-helper takes lowercase letters, digits, dot, underscore and dash, starting with a letter or digit"
[ -z "$variant_main" ] || [[ "$variant_main" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || die_usage "--variant-main takes lowercase letters, digits, dot, underscore and dash, starting with a letter or digit"
[ -z "$opencode_attach" ] || [[ "$opencode_attach" =~ ^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?$ ]] || die_usage "--opencode-attach takes http(s)://host[:port] with no user, path or query"
if [ -n "$resume_id" ]; then
  [ -z "$task_text" ] && [ -z "$task_file" ] || die_usage "--resume takes no task"
else
  [ -z "$task_text" ] || [ -z "$task_file" ] || die_usage "give a task text or --task-file, not both"
  [ -n "$task_text" ] || [ -n "$task_file" ] || { usage 2; }
  [ -z "$task_file" ] || [ -f "$task_file" ] || die_usage "no such task file: $task_file"
fi

# ---------------------------------------------------------------------------------------------
# Backends: the only place that knows a flag.

role_class() {
  sed -n 's/^model_class=//p' "docs/factory/meta/$1.conf"
}

model_for() {
  local role=$1 class
  class=$(role_class "$role")
  # The light planner plans on the helper model: the short plan does not need the strong one.
  if [ "$role" = planner ] && [ "${path:-full}" = light ]; then class=helper; fi
  case "$class" in
    helper) printf '%s' "$model_helper" ;;
    *) printf '%s' "$model_main" ;;
  esac
}

variant_for() {
  local role=$1 class
  class=$(role_class "$role")
  if [ "$role" = planner ] && [ "${path:-full}" = light ]; then class=helper; fi
  case "$class" in
    helper) printf '%s' "$variant_helper" ;;
    *) printf '%s' "$variant_main" ;;
  esac
}

claude_tools() {
  local access=$1 artifact=${2:-.factory/runs/${run_id:-RUN_ID}/<artifact>} list line f
  local -a files=(common)
  if [ "$access" = readonly ]; then
    # Exactly the one file the phase writes, anchored at the repository root: state, snapshots and
    # the other run files are not agent-writable.
    list="Edit(/$artifact)"
  else
    list="Edit,Write"
    files+=(code)
  fi
  # The orchestrator grant (fetch, branch creation, pull request commands) is never given to an
  # agent: only the driver pushes and opens the pull request.
  for f in "${files[@]}"; do
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      list="$list,$line"
    done <"docs/factory/meta/claude-allow-$f.txt"
  done
  printf '%s' "$list"
}

# claude_denies: the deny rules of the factory layer as one comma-separated Bash(...) list. They are
# passed per phase (--disallowedTools) and not committed in .claude/settings.json, so interactive
# sessions in this repository are not restricted by them.
claude_denies() {
  local list="" line f
  for f in project factory; do
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      list="$list${list:+,}Bash($line)"
    done <"docs/factory/meta/deny-$f.txt"
  done
  printf '%s' "$list"
}

# The value of --model. The 2.x CLI carries the reasoning variant in it; 1.x takes --variant.
opencode_model() {
  local role=$1 model variant
  model=$(model_for "$role")
  variant=$(variant_for "$role")
  if [ "${opencode_gen:-}" = 2 ] && [ -n "$variant" ]; then
    [ -n "$model" ] || die_usage "OpenCode 2.x takes the variant in the model (provider/model#variant): set --model-main/--model-helper for the $role role"
    printf '%s#%s' "$model" "$variant"
  else
    printf '%s' "$model"
  fi
}

# A 2.x variant needs a model to travel in; without one there is no flag to carry it.
check_variant_models() {
  [ "${opencode_gen:-}" = 2 ] || return 0
  [ -z "$variant_main" ] || [ -n "$model_main" ] ||
    die_usage "OpenCode 2.x takes the variant in the model (provider/model#variant): set --model-main or FACTORY_MODEL_MAIN"
  [ -z "$variant_helper" ] || [ -n "$model_helper" ] ||
    die_usage "OpenCode 2.x takes the variant in the model (provider/model#variant): set --model-helper or FACTORY_MODEL_HELPER"
}

# build_cmd_opencode1: the 1.x shape. --dir names the working directory and --variant is its own flag.
# The session name comes from the first line of the prompt (run_phase writes it): no --title is passed.
build_cmd_opencode1() {
  local role=$1 prompt=$4 model variant
  model=$(model_for "$role")
  cmd=("$opencode_bin" run)
  if [ -n "$opencode_attach" ]; then cmd+=(--attach "$opencode_attach"); fi
  cmd+=(--agent "factory-$role")
  if [ -n "$model" ]; then cmd+=(--model "$model"); fi
  variant=$(variant_for "$role")
  if [ -n "$variant" ]; then cmd+=(--variant "$variant"); fi
  cmd+=(--dir "$PWD" "$prompt")
}

# build_cmd_opencode2: the 2.x shape. No --dir (the phase runs in the repository root the driver has
# entered), the variant lives in --model, --server attaches to a long-lived server and --standalone
# starts a private one otherwise, and --archived keeps the scripted sessions of a private server out of
# session lists (an attached run is not archived: it is meant to be followed).
build_cmd_opencode2() {
  local role=$1 prompt=$4 model
  model=$(opencode_model "$role")
  cmd=("$opencode_bin" run)
  if [ -n "$opencode_attach" ]; then cmd+=(--server "$opencode_attach"); else cmd+=(--standalone); fi
  cmd+=(--agent "factory-$role")
  if [ -n "$model" ]; then cmd+=(--model "$model"); fi
  # An attached session stays visible in the server's lists so that a run can be followed there.
  if [ -z "$opencode_attach" ]; then cmd+=(--archived); fi
  cmd+=("$prompt")
}

build_cmd_claude() {
  local role=$1 access=$2 prompt=$4 artifact=${5:-} model
  model=$(model_for "$role")
  cmd=(claude -p "$prompt" --agent "factory-$role")
  if [ -n "$model" ]; then cmd+=(--model "$model"); fi
  # --strict-mcp-config without --mcp-config: no MCP server is loaded, so nothing from the user's
  # own configuration runs inside a factory run or creates files the snapshot would flag.
  cmd+=(--permission-mode dontAsk --allowedTools "$(claude_tools "$access" "$artifact")" --disallowedTools "$(claude_denies)" --strict-mcp-config --no-session-persistence --output-format text)
}

# build_cmd <role> <access> <phase> <prompt> [artifact]: fills the global array `cmd`.
build_cmd() {
  case "$backend" in
    opencode)
      case "${opencode_gen:-}" in
        1) build_cmd_opencode1 "$@" ;;
        2) build_cmd_opencode2 "$@" ;;
        *) die_usage "the OpenCode client generation is not resolved" ;;
      esac
      ;;
    claude) build_cmd_claude "$@" ;;
  esac
}

need_opencode_client() {
  command -v "$opencode_bin" >/dev/null 2>&1 ||
    die_preflight "opencode client not found: $opencode_bin (install it, set --opencode-bin, or choose --backend claude)"
}

# resolve_opencode_generation: read the major version and validate the variant options against it.
resolve_opencode_generation() {
  opencode_gen=$(detect_opencode_generation "$opencode_bin") ||
    die_usage "cannot read the OpenCode generation from '$opencode_bin --version'; this factory supports major 1 and 2"
  check_variant_models
}

if [ -z "$backend" ]; then
  for candidate in opencode claude; do
    if command -v "$candidate" >/dev/null 2>&1; then
      backend=$candidate
      break
    fi
  done
fi

# The variant, client and attach options are OpenCode flags; build_cmd only passes them to that
# backend.
if [ "$backend" = claude ]; then
  if [ -n "$variant_helper$variant_main" ]; then
    printf 'factory: warning: --variant-main/--variant-helper apply to the OpenCode backend only; ignored for claude\n' >&2
  fi
  if [ "$opencode_bin_explicit" = 1 ]; then
    printf 'factory: warning: --opencode-bin applies to the OpenCode backend only; ignored for claude\n' >&2
  fi
  if [ -n "$opencode_attach" ]; then
    printf 'factory: warning: --opencode-attach applies to the OpenCode backend only; ignored for claude\n' >&2
  fi
fi

if [ "$dry_run" = 1 ]; then
  [ -n "$backend" ] || backend=opencode
  if [ "$backend" = opencode ]; then
    need_opencode_client
    resolve_opencode_generation
  fi
  # The command-line form and the file form both classify.
  if [ -n "$task_file" ]; then task_text=$(cat "$task_file"); fi
  classify_task <<<"$task_text"
  path=$class_path
  printf 'factory dry run: nothing is called, nothing is changed\n'
  printf 'backend: %s\n' "$backend"
  if [ "$path" = light ]; then
    printf 'path: light (%s)\n' "$class_reason"
  else
    printf 'path: full (%s)\n' "$class_reason"
  fi
  printf 'caps: plan review %s rounds, code review %s rounds\n' "$plan_cap" "$code_cap"
  if [ "$path" = light ]; then
    printf 'phases: plan, owner-gate, implement, code-review, final-gate, pr\n'
  else
    printf 'phases: plan, plan-review, owner-gate, implement, code-review, final-gate, pr\n'
  fi
  printf 'stop after: %s%s\n' "$stop_after" "$( [ "$no_push" = 1 ] && printf ', no push' || true)"
  if [ "$backend" = opencode ]; then
    printf 'opencode client: %s (generation %s)\n' "$opencode_bin" "$opencode_gen"
    printf 'variants: main=%s helper=%s\n' "${variant_main:-(none)}" "${variant_helper:-(none)}"
    printf 'opencode server: %s\n' "${opencode_attach:-(own, started per phase)}"
  fi
  for entry in planner:readonly:plan plan-reviewer:readonly:plan-review implementer:code:implement code-reviewer:readonly:code-review pr-writer:readonly:pr; do
    IFS=: read -r r a p <<<"$entry"
    build_cmd "$r" "$a" "$p" "<prompt>"
    printf 'command (%s): ' "$p"
    printf '%q ' "${cmd[@]}"
    printf '\n'
  done
  exit 0
fi

# ---------------------------------------------------------------------------------------------
# Run state

run_id=""
branch=""
base_sha=""
phase=preflight
step=""
plan_round=0
code_round=0
post_decision_review=0
status=running
exit_code=""
stopped_at=""
run_dir=""
child_pgid=""
resuming=0
head_before=""
main_before=""
path=full
slug=""
plan_material=0

save_state() {
  [ -n "$run_dir" ] || return 0
  local k
  {
    for k in run_id backend branch base_sha phase step plan_round code_round post_decision_review status exit_code stopped_at opencode_bin opencode_gen path slug plan_material; do
      printf '%s=%s\n' "$k" "${!k}"
    done
  } >"$run_dir/state.tmp"
  mv "$run_dir/state.tmp" "$run_dir/state"
}

load_state() {
  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^([a-z_]+)=(.*)$ ]] || continue
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    case "$key" in
      run_id | backend | branch | base_sha | phase | step | plan_round | code_round | post_decision_review | status | exit_code | stopped_at | opencode_bin | opencode_gen | path | slug | plan_material)
        printf -v "$key" '%s' "$value"
        ;;
    esac
  done <"$run_dir/state"
}

# escalate_light <reason>: the light path becomes a full one. State only: every caller sets its own
# next phase and step. The reason is kept in the run directory and in the state.
escalate_light() {
  path=full
  printf '%s\n' "$1" >"$run_dir/light-escalation.txt"
  save_state
  printf 'factory: the light path escalated to full: %s\n' "$1"
}

last_review_file() {
  local f newest=""
  for f in "$run_dir"/review-*.md; do
    [ -e "$f" ] || continue
    if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then newest=$f; fi
  done
  printf '%s' "$newest"
}

# plan_reviewed: a plan review artifact exists. The light path has none: its plan goes unreviewed.
plan_reviewed() {
  local f
  for f in "$run_dir"/review-plan-*.md; do
    if [ -e "$f" ]; then return 0; fi
  done
  return 1
}

write_handoff() {
  local code=$1 reason=$2 review resume f tname tsecs trc
  review=$(last_review_file)
  if [ "$code" = 10 ] || [ "$code" = 20 ]; then
    resume="scripts/factory.sh --resume $run_id"
  else
    resume="not resumable"
  fi
  {
    printf '# Handoff\n\n'
    printf 'Run: %s\n' "$run_id"
    printf 'Branch: %s\n' "$branch"
    printf 'Stopped at: %s, step %s\n' "$phase" "${step:-none}"
    printf 'Exit code: %s (%s)\n\n' "$code" "$(exit_name "$code")"
    printf 'Reason: %s\n\n' "$reason"
    if [ -n "$cause_md" ]; then printf '%s\n\n' "$cause_md"; fi
    printf 'Artifacts:\n'
    for f in "$run_dir"/*; do
      [ -e "$f" ] && printf -- '- %s\n' "${f#"$ROOT"/}"
    done
    printf '\nOpen findings:\n'
    if [ -n "$review" ]; then
      printf '%s\n\n' "${review#"$ROOT"/}"
      if grep -q '^## Blocker' "$review"; then
        awk '/^## Blocker/ { f = 1; print; next } f && /^## / { exit } f' "$review"
      else
        cat "$review"
      fi
    else
      printf 'none\n'
    fi
    if [ -s "$run_dir/protected-diff.txt" ]; then
      printf '\nProtected paths changed (--allow-protected):\n'
      sed -e 's/^/- /' "$run_dir/protected-diff.txt"
    fi
    if [ -s "$run_dir/phases.tsv" ]; then
      printf '\n## Timings\n\n'
      while IFS=$'\t' read -r tname tsecs trc; do
        printf -- '- %s %s (exit %s)\n' "$tname" "$(fmt_duration "$tsecs")" "$trc"
      done <"$run_dir/phases.tsv"
    fi
    printf '\nResume: %s\n' "$resume"
  } >"$run_dir/handoff.md"
}

# print_summary: the path, the number of phase runs and the time spent inside phases, then one line
# per phase. Called by finish, stop and on_signal, so an interrupted run summarises too.
print_summary() {
  local total=0 runs=0 escalated="" tname tsecs trc
  [ -n "$run_dir" ] || return 0
  if [ -s "$run_dir/phases.tsv" ]; then
    while IFS=$'\t' read -r tname tsecs trc; do
      total=$((total + tsecs))
      runs=$((runs + 1))
    done <"$run_dir/phases.tsv"
  fi
  if [ -f "$run_dir/light-escalation.txt" ]; then escalated=" (escalated)"; fi
  printf 'factory: summary: path %s%s, %s phase run%s, %s\n' "${path:-full}" "$escalated" "$runs" \
    "$([ "$runs" = 1 ] || printf s)" "$(fmt_duration "$total")"
  if [ -s "$run_dir/phases.tsv" ]; then
    while IFS=$'\t' read -r tname tsecs trc; do
      printf '  %s %s\n' "$tname" "$(fmt_duration "$tsecs")"
    done <"$run_dir/phases.tsv"
  fi
}

stop() {
  local code=$1
  shift
  exit_code=$code
  status=stopped
  stopped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  save_state
  write_handoff "$code" "$*"
  print_summary
  printf 'factory: stopped, exit %s (%s): %s\n' "$code" "$(exit_name "$code")" "$*" >&2
  printf 'factory: see %s/handoff.md\n' "${run_dir#"$ROOT"/}" >&2
  exit "$code"
}

finish() {
  phase=done
  step=""
  status=done
  exit_code=0
  stopped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  save_state
  print_summary
  printf 'factory: done (%s)\n' "$*"
  exit 0
}

kill_group() {
  if [ -n "$child_pgid" ]; then
    kill -TERM -- "-$child_pgid" 2>/dev/null || true
    sleep 0.2
    if kill -0 -- "-$child_pgid" 2>/dev/null; then
      sleep 1
      if kill -0 -- "-$child_pgid" 2>/dev/null; then kill -KILL -- "-$child_pgid" 2>/dev/null || true; fi
    fi
  fi
}

on_signal() {
  trap '' INT TERM
  kill_group
  exit_code=20
  status=stopped
  stopped_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  save_state
  write_handoff 20 "interrupted by a signal; the agent process group was terminated"
  print_summary
  exit 130
}

# ---------------------------------------------------------------------------------------------
# Preflight and resume

export_hooks() {
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0=core.hooksPath
  export GIT_CONFIG_VALUE_0="$ROOT/.githooks"
}

rel() {
  printf '%s' "${1#"$ROOT"/}"
}

need_tools() {
  local t
  for t in git setsid timeout sha256sum od; do
    command -v "$t" >/dev/null 2>&1 || die_preflight "required tool not found: $t"
  done
  [ -n "$backend" ] || die_preflight "neither opencode nor claude is installed (install one, or set --backend)"
  if [ "$backend" = opencode ]; then
    need_opencode_client
  else
    command -v "$backend" >/dev/null 2>&1 || die_preflight "backend not found: $backend (install it or choose the other with --backend)"
  fi
  if [ "$no_push" = 0 ] && [ "$stop_after" = pr ]; then
    command -v gh >/dev/null 2>&1 || die_preflight "gh not found (needed to open the pull request; install it or use --no-push)"
  fi
}

snap_take_to() {
  take_snapshot "$branch" >"$1"
}

if [ -z "$resume_id" ]; then
  export_hooks
  need_tools
  if [ "$backend" = opencode ]; then resolve_opencode_generation; fi
  git rev-parse --show-toplevel >/dev/null 2>&1 || die_preflight "not a git repository"
  [ -z "$(git status --porcelain)" ] || die_preflight "the working tree is not clean; commit or stash first"
  git remote get-url origin >/dev/null 2>&1 || die_preflight "no remote named origin"
  git fetch -q origin main || die_preflight "git fetch origin main failed"
  git rev-parse --verify -q refs/remotes/origin/main >/dev/null || die_preflight "origin/main does not exist"
  if [ -n "$task_file" ]; then task_text=$(cat "$task_file"); fi
  [ -n "$task_text" ] || die_preflight "the task is empty"
  slug=$(slugify "$task_text")
  # The path is chosen from the task text once, before any phase runs.
  classify_task <<<"$task_text"
  path=$class_path
  sid=$(shortid)
  branch="factory/$slug-$sid"
  if git show-ref --verify -q "refs/heads/$branch"; then
    sid=$(shortid)
    branch="factory/$slug-$sid"
    ! git show-ref --verify -q "refs/heads/$branch" || die_preflight "branch $branch exists"
  fi
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$sid"
  run_dir="$ROOT/.factory/runs/$run_id"
  mkdir -p "$run_dir/logs"
  main_before=$(git rev-parse -q --verify refs/heads/main || true)
  git switch -q -c "$branch" --no-track origin/main
  base_sha=$(git rev-parse HEAD)
  printf '%s\n' "$task_text" >"$run_dir/task.md"
  if [ "$backend" = opencode ] && [ -z "$model_helper" ]; then
    printf 'factory: warning: no helper model set (FACTORY_MODEL_HELPER); the reviewers run on the OpenCode default\n' >&2
  fi
  phase=plan
  step=write
  save_state
  printf '%s\n' "$main_before" >"$run_dir/main-before"
  snap_take_to "$run_dir/snap.base"
  printf 'factory: run %s on branch %s (backend %s)\n' "$run_id" "$branch" "$backend"
  printf 'factory: %s path (%s)\n' "$path" "$class_reason"
else
  export_hooks
  run_dir="$ROOT/.factory/runs/$resume_id"
  [ -f "$run_dir/state" ] || die_usage "no such run: $resume_id"
  opencode_bin_requested=$opencode_bin
  load_state
  # A state written by an older driver carries none of these keys.
  path=${path:-full}
  # A missing plan_material may sit at owner-gate:post after a material revision: run the review
  # rather than skip it. Only an explicit 0 written after a revision skips it.
  if ! grep -q '^plan_material=' "$run_dir/state"; then plan_material=1; fi
  slug=${slug:-$(slugify "$(cat "$run_dir/task.md")")}
  if [ "$status" != stopped ] || { [ "$exit_code" != 10 ] && [ "$exit_code" != 20 ]; }; then
    die_usage "run $resume_id cannot be resumed (status $status, exit code ${exit_code:-none}); see $(rel "$run_dir")/handoff.md"
  fi
  need_tools
  if [ "$backend" = opencode ]; then
    if [ "$opencode_bin_explicit" = 1 ] && [ "$opencode_bin_requested" != "$opencode_bin" ]; then
      die_usage "the run was started with --opencode-bin $opencode_bin; a resume uses that client"
    fi
    now_gen=$(detect_opencode_generation "$opencode_bin") ||
      die_preflight "cannot read the OpenCode generation from '$opencode_bin --version'; the run was started with generation ${opencode_gen:-unknown}"
    if [ -n "$opencode_gen" ]; then
      [ "$now_gen" = "$opencode_gen" ] ||
        die_preflight "the run was started with OpenCode generation $opencode_gen, but $opencode_bin now reports generation $now_gen; resume with the recorded client"
    else
      opencode_gen=$now_gen
    fi
    check_variant_models
  fi
  if [ "$exit_code" = 10 ]; then
    [ -s "$run_dir/decisions.md" ] || die_preflight "write the owner decisions to $(rel "$run_dir")/decisions.md first"
  fi
  git show-ref --verify -q "refs/heads/$branch" || die_preflight "the branch $branch is gone"
  git switch -q "$branch" || die_preflight "cannot switch to $branch"
  git merge-base --is-ancestor "$base_sha" HEAD || die_preflight "the base commit is not an ancestor of HEAD"
  main_before=$(cat "$run_dir/main-before" 2>/dev/null || true)
  status=running
  exit_code=""
  stopped_at=""
  resuming=1
  # An interrupted phase skipped its snapshot check: compare the baseline of the last verified
  # phase with the present state before it is retaken. HEAD is left out (the resume switches to the
  # branch). Only an interrupted implement or fix may legitimately move the branch tip, change
  # protected files (the post-phase checks then judge them) and leave a dirty tree; after any other
  # phase the tip, the protected files and the worktree must be as verified, or a readonly phase
  # could commit or edit and have it accepted as the new baseline.
  if [ -f "$run_dir/snap.base" ]; then
    resume_names="refs-code config hooks symlink localcfg taskdoc"
    case "$step" in
      implement | fix) ;;
      *) resume_names="$resume_names tip protected worktree" ;;
    esac
    snap_take_to "$run_dir/snap.now"
    if changed=$(compare_snapshots code "$run_dir/snap.base" "$run_dir/snap.now" "$resume_names"); then :; else
      stop 13 "the interrupted phase changed state it must not touch: ${changed}"
    fi
  fi
  snap_take_to "$run_dir/snap.base"
  save_state
  printf 'factory: resuming run %s at %s, step %s\n' "$run_id" "$phase" "$step"
fi

trap on_signal INT TERM

# ---------------------------------------------------------------------------------------------
# Running one phase

timeout_for() {
  if [ -n "$phase_timeout" ]; then printf '%s' "$phase_timeout"; return; fi
  case "$1" in
    plan) printf '1200' ;;
    plan-revise) printf '900' ;;
    plan-review) printf '900' ;;
    plan-review-post) printf '600' ;;
    implement) printf '7200' ;;
    fix) printf '5400' ;;
    code-review) printf '1500' ;;
    pr) printf '600' ;;
    final-gate) printf '7200' ;;
    *) printf '2700' ;;
  esac
}

# run_phase <role> <access> <phase-name> <template> <artifact-path-or-empty> <timeout-kind>
# Sets phase_rc, phase_timed_out and phase_secs. Template values come from the P_* variables.
run_phase() {
  local role=$1 access=$2 name=$3 template=$4 artifact=$5 tkind=$6 prompt secs rc=0 var
  local -a envargs
  P_ARTIFACT=$artifact
  P_BASE=$base_sha
  P_BRANCH=$branch
  P_RUN_DIR=$(rel "$run_dir")
  P_TASK_FILE=$(rel "$run_dir")/task.md
  prompt=$(render <"docs/factory/phases/$template.md")
  # The first line names the session: OpenCode derives a title from the prompt, so the driver passes
  # no --title. One blank line follows the header.
  prompt=$(printf 'Factory %s: %s %s\n\n%s' "$slug" "$name" "${P_ROUND:-1}" "$prompt")
  build_cmd "$role" "$access" "$name" "$prompt" "$artifact"
  secs=$(timeout_for "$tkind")
  phase_secs=$secs
  envargs=(env -i)
  for var in PATH HOME TERM LANG; do
    if [ -n "${!var+x}" ]; then envargs+=("$var=${!var}"); fi
  done
  envargs+=("GIT_CONFIG_COUNT=$GIT_CONFIG_COUNT" "GIT_CONFIG_KEY_0=$GIT_CONFIG_KEY_0" "GIT_CONFIG_VALUE_0=$GIT_CONFIG_VALUE_0")
  envargs+=("FACTORY_RUN_DIR=$(rel "$run_dir")" "FACTORY_ARTIFACT=$artifact" "FACTORY_BASE_SHA=$base_sha")
  for var in ${FACTORY_PASS_ENV:-}; do
    if [ -n "${!var+x}" ]; then envargs+=("$var=${!var}"); fi
  done
  printf 'factory: phase %s (%s, round %s/%s, budget %s s)\n' "$name" "$role" "${P_ROUND:-0}" "${P_MAX:-0}" "$secs"
  printf '== %s %s\n' "$name" "$(date -u +%H:%M:%S)" >>"$run_dir/logs/$name.log"
  local started_at=$SECONDS
  if [ "$backend" = opencode ] && [ -n "$opencode_attach" ] && [ -n "${OPENCODE_SERVER_PASSWORD:-}${OPENCODE_SERVER_USERNAME:-}" ]; then
    # The server credentials never go on a command line (the process list shows it): they travel
    # through file descriptor 3 and a one-line shim that exports them inside the scrubbed environment.
    # shellcheck disable=SC2016  # the shim is expanded by the inner bash, not here
    setsid timeout -k 30 "$secs" "${envargs[@]}" bash -c '
      IFS= read -r user <&3 || true
      IFS= read -r pass <&3 || true
      exec 3<&-
      if [ -n "$user" ]; then export OPENCODE_SERVER_USERNAME=$user; fi
      if [ -n "$pass" ]; then export OPENCODE_SERVER_PASSWORD=$pass; fi
      unset user pass
      exec "$@"' factory-attach "${cmd[@]}" 3< <(printf '%s\n%s\n' "${OPENCODE_SERVER_USERNAME:-}" "${OPENCODE_SERVER_PASSWORD:-}") >>"$run_dir/logs/$name.log" 2>&1 &
  else
    setsid timeout -k 30 "$secs" "${envargs[@]}" "${cmd[@]}" >>"$run_dir/logs/$name.log" 2>&1 &
  fi
  child_pgid=$!
  wait "$child_pgid" || rc=$?
  # Reap grandchildren: TERM the group, poll, KILL only if something still answers.
  kill -TERM -- "-$child_pgid" 2>/dev/null || true
  local waited=0
  while kill -0 -- "-$child_pgid" 2>/dev/null && [ "$waited" -lt 30 ]; do
    sleep 0.2
    waited=$((waited + 1))
  done
  if kill -0 -- "-$child_pgid" 2>/dev/null; then kill -KILL -- "-$child_pgid" 2>/dev/null || true; fi
  child_pgid=""
  phase_rc=$rc
  phase_timed_out=0
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then phase_timed_out=1; fi
  local took=$((SECONDS - started_at))
  printf '%s\t%s\t%s\n' "$name" "$took" "$rc" >>"$run_dir/phases.tsv"
  printf 'factory: phase %s took %ss (exit %s)\n' "$name" "$took" "$rc"
}

# Verify the snapshot after a phase and retake the baseline. readonly|code.
verify_phase() {
  local mode=$1 changed
  case "$phase:$step" in
    plan:write | plan-review:revise | owner-gate:revise) snap_skip_plandoc=1 ;;
    *) snap_skip_plandoc=0 ;;
  esac
  take_snapshot "$branch" >"$run_dir/snap.now"
  if changed=$(compare_snapshots "$mode" "$run_dir/snap.base" "$run_dir/snap.now"); then :; else
    stop 13 "the $phase phase changed state it must not touch: ${changed}"
  fi
  if [ "$mode" = code ]; then
    [ "$(git symbolic-ref -q HEAD)" = "refs/heads/$branch" ] || stop 13 "HEAD is no longer on $branch"
    git merge-base --is-ancestor "$head_before" HEAD || stop 13 "the history of $branch was rewritten"
    git diff --name-only "$base_sha..HEAD" -- "${PROTECTED[@]}" >"$run_dir/protected-diff.txt"
    { git status --porcelain -- "${PROTECTED[@]}" | sed -e 's/^...//'; } >>"$run_dir/protected-diff.txt" || true
    if [ -s "$run_dir/protected-diff.txt" ]; then
      if [ "$allow_protected" = 0 ]; then
        stop 13 "protected paths changed without --allow-protected: $(tr '\n' ' ' <"$run_dir/protected-diff.txt")"
      fi
    else
      rm -f "$run_dir/protected-diff.txt"
    fi
  fi
  take_snapshot "$branch" >"$run_dir/snap.base"
}

# Artifact phases: the backend must leave its artifact behind. A clean exit without one is retried
# once. Returns 1 only on a light-path timeout, so the caller can retry the unit on the full template;
# every other stop ends the run.
artifact_phase() {
  local role=$1 name=$2 template=$3 artifact=$4 attempt=0
  rm -f "${ROOT:?}/$artifact"
  while :; do
    attempt=$((attempt + 1))
    run_phase "$role" readonly "$name" "$template" "$artifact" "$name"
    if [ "$phase_timed_out" = 1 ]; then
      if [ "$path" = light ]; then
        escalate_light "the $name phase used its budget of $phase_secs s"
        return 1
      fi
      stop 20 "the $name phase used its budget of $phase_secs s (exit 20)"
    fi
    if [ -s "$ROOT/$artifact" ]; then
      verify_phase readonly
      return 0
    fi
    if [ "$phase_rc" = 0 ] && [ "$attempt" = 1 ]; then
      printf '# retry: the phase exited 0 without its artifact\n' >>"$run_dir/logs/$name.log"
      printf 'factory: the %s phase ended without its report; retrying once\n' "$name" >&2
      continue
    fi
    if [ "$phase_rc" = 0 ]; then
      diagnose "$name" 1 report
      stop 20 "the $name phase ended without its report (exit $phase_rc)"
    fi
    diagnose "$name" 1
    stop 20 "the $name phase ended (exit $phase_rc) without its artifact $artifact"
  done
}

# revise_unit <name>: one plan revision. A light timeout escalates and runs the unit again on the full
# path; a clean exit that leaves the plan byte-identical is retried once; a non-zero exit or a second
# miss stops 20. Returns 0 when the plan changed.
revise_unit() {
  local name=$1 attempt=0 before
  before=$(hash_file "$ROOT/$plan_file")
  while :; do
    attempt=$((attempt + 1))
    run_phase planner readonly "$name" "$name" "$plan_file" "$name"
    if [ "$phase_timed_out" = 1 ]; then
      if [ "$path" = light ] && [ "$attempt" = 1 ]; then
        escalate_light "the $name phase used its budget of $phase_secs s"
        continue
      fi
      stop 20 "the $name phase used its budget of $phase_secs s (exit 20)"
    fi
    if [ "$(hash_file "$ROOT/$plan_file")" != "$before" ]; then return 0; fi
    if [ "$phase_rc" = 0 ] && [ "$attempt" = 1 ]; then
      printf '# retry: the phase exited 0 without a revised plan\n' >>"$run_dir/logs/$name.log"
      printf 'factory: the %s phase ended without its report; retrying once\n' "$name" >&2
      continue
    fi
    if [ "$phase_rc" = 0 ]; then
      diagnose "$name" 1 report
      stop 20 "the $name phase ended without its report (exit $phase_rc)"
    fi
    diagnose "$name" 1
    stop 20 "the $name phase ended (exit $phase_rc) without a revised plan"
  done
}

# Code phases (implement, fix): success criteria and post-phase checks.
code_phase() {
  local role=implementer name=$1 template=$2 progress
  head_before=$(git rev-parse HEAD)
  run_phase "$role" code "$name" "$template" "" "$name"
  if [ "$phase_timed_out" = 1 ]; then
    if [ "$path" = light ]; then
      escalate_light "the $name phase used its budget of $phase_secs s"
      stop 20 "the $name phase used its budget of $phase_secs s; resume to continue on the full path"
    fi
    stop 20 "the $name phase used its budget of $phase_secs s (exit 20)"
  fi
  progress=$(git rev-list --count "$head_before..HEAD")
  if [ "$phase_rc" != 0 ] && [ "$progress" = 0 ]; then
    diagnose "$name" 0
    stop 20 "the backend exited with $phase_rc and made no commit"
  fi
  verify_phase code
  if [ -e "$run_dir/blocked.md" ]; then
    stop 14 "the implementer stopped and wrote blocked.md: $(head -c 400 "$run_dir/blocked.md" | tr '\n' ' ')"
  fi
  if [ "$phase_rc" = 0 ] && [ "$progress" = 0 ]; then
    stop 14 "the $name phase exited cleanly but made no commit"
  fi
  local problems
  if ! problems=$(check_commits "$base_sha"); then
    stop 14 "commit checks failed: $(tr '\n' ';' <<<"$problems")"
  fi
}

# ---------------------------------------------------------------------------------------------
# The state machine: one unit of work per iteration. A stop records the unit, so a resume repeats it.

plan_file=$(rel "$run_dir")/plan.md
decisions_file=$(rel "$run_dir")/decisions.md

while :; do
  save_state
  P_PLAN=$plan_file
  P_DECISIONS=""
  P_REVIEW=""
  P_ROUND=""
  P_MAX=""
  P_GATE=""
  P_RESUME=""
  case "$phase:$step" in
    plan:write)
      P_RESUME=$(resume_context)
      if [ "$path" = light ]; then
        artifact_phase planner plan plan-light "$plan_file" || continue
      else
        artifact_phase planner plan plan "$plan_file" || continue
      fi
      resuming=0
      plan_round=1
      if [ "$path" = light ]; then
        # The short plan is not reviewed: the owner gate follows it at once.
        phase=owner-gate
        step=check
      else
        phase=plan-review
        step=review
      fi
      ;;
    plan-review:review)
      P_ROUND=$plan_round
      P_MAX=$plan_cap
      review_file=$(rel "$run_dir")/review-plan-$plan_round.md
      artifact_phase plan-reviewer plan-review plan-review "$review_file" || continue
      resuming=0
      if [ "$(parse_verdict "$ROOT/$review_file")" = APPROVED ]; then
        phase=owner-gate
        step=check
      elif [ "$plan_round" -lt "$plan_cap" ]; then
        step=revise
      else
        stop 11 "the plan was not approved within $plan_cap review rounds"
      fi
      ;;
    plan-review:revise)
      P_ROUND=$plan_round
      P_MAX=$plan_cap
      P_REVIEW=$(rel "$run_dir")/review-plan-$plan_round.md
      cp "$ROOT/$plan_file" "$run_dir/plan-before-revision-$plan_round.md"
      revise_unit plan-revise
      verify_phase readonly
      resuming=0
      plan_round=$((plan_round + 1))
      step=review
      ;;
    owner-gate:check)
      if owner_section_closed "$ROOT/$plan_file"; then
        if [ "$stop_after" = plan ]; then
          if plan_reviewed; then finish "reviewed plan, stopped after plan"; fi
          finish "plan written without review, stopped after plan"
        fi
        phase=implement
        step=implement
      else
        step=revise
        reason="owner decisions are open; answer them in $decisions_file and run scripts/factory.sh --resume $run_id. Questions: $(owner_section "$ROOT/$plan_file" | tr '\n' ' ')"
        unmarked=$(unmarked_owner_lines "$ROOT/$plan_file")
        if [ -n "$unmarked" ]; then
          reason="$reason Unmarked lines (only a '- BLOCKING:' question belongs in ## Owner decisions): $(tr '\n' ' ' <<<"$unmarked")"
        fi
        stop 10 "$reason"
      fi
      ;;
    owner-gate:revise)
      P_DECISIONS=$decisions_file
      P_ROUND=$plan_round
      P_MAX=$plan_cap
      # The light path has no review findings: an empty path says so.
      if [ "$path" = light ]; then P_REVIEW=""; else P_REVIEW=$(rel "$run_dir")/review-plan-$plan_round.md; fi
      body_before=$(plan_body "$ROOT/$plan_file" | hash_stdin)
      revise_unit plan-revise
      verify_phase readonly
      resuming=0
      if [ "$(plan_body "$ROOT/$plan_file" | hash_stdin)" = "$body_before" ]; then
        plan_material=0
      else
        plan_material=1
      fi
      # A light plan whose body changed is no longer trivial: the full post-decision review follows.
      if [ "$plan_material" = 1 ] && [ "$path" = light ]; then
        escalate_light "the owner decisions changed the plan"
      fi
      step=post
      ;;
    owner-gate:post)
      if [ "$plan_material" = 1 ]; then
        P_DECISIONS=$decisions_file
        P_ROUND=$((plan_cap + 1))
        P_MAX=$((plan_cap + 1))
        artifact_phase plan-reviewer plan-review-post plan-review-post "$(rel "$run_dir")/review-plan-post.md" || continue
        resuming=0
        post_decision_review=1
        if [ "$(parse_verdict "$run_dir/review-plan-post.md")" != APPROVED ]; then
          stop 11 "the post-decision review did not approve the plan"
        fi
      else
        printf 'factory: the plan did not change materially; the post-decision review is skipped\n'
      fi
      if [ "$stop_after" = plan ]; then
        if plan_reviewed; then finish "reviewed plan, stopped after plan"; fi
        finish "plan written without review, stopped after plan"
      fi
      phase=implement
      step=implement
      ;;
    implement:implement)
      P_GATE="scripts/gate.sh --commit"
      P_RESUME=$(resume_context)
      code_phase implement implement
      resuming=0
      # The real diff decides, before a `--stop-after implement` can end the run.
      if [ "$path" = light ]; then
        reason=$(light_diff_check) || escalate_light "$reason"
      fi
      if [ "$stop_after" = implement ]; then finish "implemented, stopped after implement"; fi
      phase=code-review
      step=review
      code_round=1
      ;;
    code-review:review)
      P_ROUND=$code_round
      P_MAX=$code_cap
      P_GATE="scripts/gate.sh"
      review_template=code-review
      # One short review of a light change; every later round is the full one. Its index is clean,
      # so the gate reads the committed range instead of falling back to the unknown full set.
      if [ "$path" = light ] && [ "$code_round" = 1 ]; then
        review_template=code-review-light
        P_GATE="scripts/gate.sh --since $base_sha"
      fi
      review_file=$(rel "$run_dir")/review-code-$code_round.md
      artifact_phase code-reviewer code-review "$review_template" "$review_file" || continue
      resuming=0
      if [ "$(parse_verdict "$ROOT/$review_file")" = APPROVED ]; then
        if [ "$stop_after" = review ]; then finish "reviewed, stopped after review"; fi
        phase=final-gate
        step=gate
      elif [ "$code_round" -lt "$code_cap" ]; then
        if [ "$path" = light ]; then
          escalate_light "the light review asked for changes"
        fi
        step=fix
      else
        stop 12 "the code was not approved within $code_cap review rounds"
      fi
      ;;
    code-review:fix)
      P_ROUND=$code_round
      P_MAX=$code_cap
      P_GATE="scripts/gate.sh --commit"
      P_REVIEW=$(rel "$run_dir")/review-code-$code_round.md
      P_RESUME=$(resume_context)
      code_phase fix fix
      resuming=0
      code_round=$((code_round + 1))
      step=review
      ;;
    final-gate:gate)
      gate_budget=$(timeout_for final-gate)
      printf 'factory: final gate (scripts/gate.sh --full, budget %s s)\n' "$gate_budget"
      gate_rc=0
      gate_started=$SECONDS
      timeout -k 30 "$gate_budget" scripts/gate.sh --full >"$run_dir/logs/final-gate.log" 2>&1 || gate_rc=$?
      gate_secs=$((SECONDS - gate_started))
      printf 'final-gate\t%s\t%s\n' "$gate_secs" "$gate_rc" >>"$run_dir/phases.tsv"
      printf 'factory: phase final-gate took %ss (exit %s)\n' "$gate_secs" "$gate_rc"
      if [ "$gate_rc" = 124 ] || [ "$gate_rc" = 137 ]; then
        stop 20 "the final gate used its budget of $gate_budget s (exit $gate_rc)"
      fi
      grep '^SKIP' "$run_dir/logs/final-gate.log" >"$run_dir/gate-skips.txt" || true
      if [ "$gate_rc" != 0 ]; then
        stop 15 "scripts/gate.sh --full failed (exit $gate_rc); no automatic fix is attempted; see $(rel "$run_dir")/logs/final-gate.log"
      fi
      phase=pr
      step=pr-write
      ;;
    pr:pr-write)
      P_RESUME=""
      artifact_phase pr-writer pr pr "$(rel "$run_dir")/pr.md" || continue
      resuming=0
      if ! problems=$(lint_pr "$run_dir/pr.md"); then
        stop 16 "the pull request text failed its lint: $(tr '\n' ';' <<<"$problems")"
      fi
      pr_title=$(head -n 1 "$run_dir/pr.md")
      tail -n +2 "$run_dir/pr.md" | sed -e '1{/^[[:space:]]*$/d}' >"$run_dir/pr-body.md"
      if [ -s "$run_dir/protected-diff.txt" ]; then
        {
          printf '\n## Protected paths changed (--allow-protected)\n\n'
          sed -e 's/^/- /' "$run_dir/protected-diff.txt"
        } >>"$run_dir/pr-body.md"
      fi
      if [ "$no_push" = 1 ] || [ "$stop_after" != pr ]; then
        finish "pull request text written to $(rel "$run_dir")/pr.md, not pushed"
      fi
      step=push
      ;;
    pr:push)
      remote_head=$(git ls-remote origin "refs/heads/$branch" | cut -f1 || true)
      if [ "$remote_head" = "$(git rev-parse HEAD)" ]; then
        printf 'factory: %s is already on origin at HEAD, skipping the push\n' "$branch"
      else
        if ! git push -q -u origin "$branch" >>"$run_dir/logs/push.log" 2>&1; then
          stop 20 "git push failed; see $(rel "$run_dir")/logs/push.log"
        fi
        # The push wrote the upstream into .git/config: the resume check must not see that as tampering.
        take_snapshot "$branch" >"$run_dir/snap.base"
      fi
      step=pr-create
      ;;
    pr:pr-create)
      pr_title=$(head -n 1 "$run_dir/pr.md")
      existing=$(gh pr list --head "$branch" --json url --jq '.[0].url // empty' 2>>"$run_dir/logs/pr-create.log" || true)
      if [ -n "$existing" ]; then
        pr_url=$existing
        printf 'factory: a pull request already exists\n'
      else
        if ! pr_url=$(gh pr create --base main --head "$branch" --title "$pr_title" --body-file "$run_dir/pr-body.md" 2>>"$run_dir/logs/pr-create.log"); then
          stop 20 "gh pr create failed; see $(rel "$run_dir")/logs/pr-create.log"
        fi
      fi
      [ "$(git rev-parse -q --verify refs/heads/main || true)" = "$main_before" ] || stop 13 "local main moved during the run"
      # A commit of this branch reachable from fresh remote main means something pushed it there,
      # whichever commit of the branch it was. A stale ref would hide that, so a failed fetch fails.
      git fetch -q origin main || stop 20 "git fetch origin main failed; cannot check that main is untouched"
      if [ "$(git rev-list --count refs/remotes/origin/main..HEAD)" != "$(git rev-list --count "$base_sha..HEAD")" ]; then
        stop 13 "a commit of the branch is on remote main"
      fi
      printf '%s\n' "$pr_url" >"$run_dir/pr-url.txt"
      finish "pull request: $pr_url"
      ;;
    *)
      stop 3 "unknown state $phase:$step"
      ;;
  esac
done
