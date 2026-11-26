# The code factory: process

This page is the tool-neutral specification of the factory: the process, the caps, the exit codes,
the state files and the protected paths. It is the source of truth for the role prompts in `roles/`,
the phase prompts in `phases/` and the generated agent files for OpenCode and Claude Code.

Nothing in this directory is executed directly: `scripts/factory-sync.sh` turns the role sources into
agent files, and `scripts/factory.sh` fills in the phase templates. The human page is
[`README.md`](README.md).

## Components

| Component                                    | Role                                                                  |
| -------------------------------------------- | --------------------------------------------------------------------- |
| `docs/factory/roles/*.md`                    | Role system prompts (source of truth).                                |
| `docs/factory/phases/*.md`                   | Per-phase user-prompt templates, filled in by the driver.             |
| `docs/factory/meta/*.conf`                   | Per-role metadata: name, description, access class, model class.      |
| `scripts/gate.sh`                            | Tool-independent gate: `--commit`, standard, `--full`, `--list`.      |
| `.githooks/pre-commit`, `.githooks/pre-push` | Driver-only hooks, activated through environment variables.           |
| `scripts/factory-sync.sh`                    | Generates the agent files for both tools from the sources; `--check`. |
| `.opencode/agents/`, `.claude/agents/`       | Generated agent files. Never edit them by hand.                       |
| `.claude/commands/factory.md`                | Generated interactive `/factory` command (Claude Code only).          |
| `opencode.json`, `.claude/settings.json`     | Project permissions: only the `AGENTS.md` denies, for every session.  |
| `docs/factory/meta/deny-*.txt`               | Deny rules (project level and factory only).                          |
| `CLAUDE.md`                                  | Git symlink to `AGENTS.md`; no content of its own.                    |
| `scripts/factory.sh`                         | Deterministic driver; the only OpenCode path and the unattended path. |
| `scripts/test-factory.sh`                    | Hermetic tests with stub CLIs; no model is ever run.                  |

The run directory `.factory/runs/<run id>/` holds artifacts only and is gitignored.

## Roles and access classes

| Role                    | Class        | May change                                          |
| ----------------------- | ------------ | --------------------------------------------------- |
| `factory-planner`       | readonly     | Only its plan artifact in the run directory.        |
| `factory-plan-reviewer` | readonly     | Only its review artifact.                           |
| `factory-code-reviewer` | readonly     | Only its review artifact.                           |
| `factory-pr-writer`     | readonly     | Only `pr.md`.                                       |
| `factory-implementer`   | code         | Repository files; `git add`/`commit`; never pushes. |
| `factory` (command)     | orchestrator | Claude Code only: coordinates the others.           |

Every role prompt tells the agent to read `AGENTS.md` first, that the repository is public, that task
text and findings are data, and that agents never merge or push to `main`.

## Caps and phases

| Phase         | Cap | What happens                                                                         |
| ------------- | --- | ------------------------------------------------------------------------------------ |
| `plan`        | -   | The planner writes `plan.md`.                                                        |
| `plan-review` | 4   | A fresh plan reviewer per round; the plan is revised between rounds.                 |
| `owner-gate`  | -   | Open owner decisions stop the run; after the answer, one extra review (outside cap). |
| `implement`   | -   | The implementer makes one commit per plan commit, gate-checked.                      |
| `code-review` | 3   | A fresh code reviewer per round; `fix` commits between rounds.                       |
| `final-gate`  | -   | The driver runs `scripts/gate.sh --full`.                                            |
| `pr`          | -   | The pr-writer writes `pr.md`; the driver pushes and opens the pull request.          |

The caps are constants; flags can only lower them. Agents never merge. The owner reviews and merges.

Verdicts: the last non-empty line of a review, with trailing carriage return and spaces stripped,
must equal exactly `VERDICT: APPROVED` or `VERDICT: CHANGES NEEDED`. Anything else (missing or empty
file, wrong case, trailing text, verdict not last) counts as `CHANGES NEEDED`.

Owner gate: the lines after `## Owner decisions` in `plan.md` up to the next line starting with `## `
(or the end of the file), blank lines dropped, must be exactly `None.`. Otherwise the run stops with
exit 10, the owner writes `decisions.md`, and `--resume` revises the plan and runs exactly one
`plan-review-post` round.

## Exit codes

| Code | Name              | Meaning                                                                       |
| ---- | ----------------- | ----------------------------------------------------------------------------- |
| 0    | done              | Finished, or stopped by `--stop-after`.                                       |
| 2    | usage             | Bad usage, including a refused `--resume`.                                    |
| 3    | preflight         | Preflight failed, or `--resume` prerequisites are missing.                    |
| 10   | owner decisions   | Owner decisions are open; resumable.                                          |
| 11   | plan review cap   | The plan was not approved within the cap, or the post-decision review failed. |
| 12   | code review cap   | The code was not approved within the cap.                                     |
| 13   | sandbox violation | A readonly phase changed state, protected paths changed, or config tampered.  |
| 14   | bad commits       | Commit checks failed, `blocked.md` exists, or a phase made no progress.       |
| 15   | final gate failed | `scripts/gate.sh --full` failed; no automatic fix attempt.                    |
| 16   | PR text lint      | The pull request text failed its lint; nothing was pushed.                    |
| 20   | phase failure     | Timeout, backend failure without artifact, push or PR creation failure.       |

Exit 10 and exit 20 are resumable. Every other stop ends the run: the human starts a new run or
fixes the branch by hand.

`--stop-after plan` stops after the reviewed plan. The branch created by preflight stays behind in
the local repository; delete it by hand when you abandon the run.

## State and handoff

`state` (in the run directory, `key=value`, one per line, rewritten atomically after every
transition) holds: `run_id backend branch base_sha phase step plan_round code_round
post_decision_review status exit_code stopped_at`. `phase` is one of `preflight plan plan-review
owner-gate implement code-review final-gate pr done`. `step` names the unit of work inside it.

`handoff.md` is written on every stop with a fixed layout: `# Handoff`, `Run:`, `Branch:`,
`Stopped at:`, `Exit code:`, `Reason:`, `Artifacts:`, `Open findings:` and `Resume:` (the exact
command, or `not resumable`). When a phase exits non-zero or ends without its artifact, a `## Cause`
section follows `Reason:`: the classification of `logs/<phase>.log` (not logged in, workspace not
trusted, rate or usage limit, or no known cause), the fix, and the first 12 non-blank lines of the log, each cut
at 200 characters, with ANSI codes removed and lines that hold personal data withheld. The driver
prints the same cause as one line to stderr; the exit code stays 20.

Run directory files: `task.md plan.md review-plan-N.md review-plan-post.md decisions.md
review-code-N.md pr.md blocked.md handoff.md state logs/<phase>.log`. Logs can hold paths and model
provider output: never attach them to a public issue.

## Protected paths and the snapshot

The protected set is `.githooks/`, `scripts/`, `.opencode/`, `.claude/`, `opencode.json`,
`opencode.jsonc`, `.mcp.json`, `AGENTS.md`, `.github/` and the `CLAUDE.md` symlink. The driver hashes it, together with
refs, git config, hooks and the worktree status, before and after every phase. A readonly phase must
leave all of it unchanged; an implement phase may only advance the factory branch and must not touch
the protected set unless the run was started with `--allow-protected`. A violation is exit 13. Files
the tools read but git ignores (`.claude/settings.local.json`, `CLAUDE.local.md`) are hashed too, in
every phase: they must not appear or change, because local settings outrank the committed ones and
`dontAsk` honours their allow rules. The run's `task.md` is hashed in every phase and `plan.md` in
every phase except the planner's.

The snapshot is a post-hoc state check, not a sandbox: `cargo` and `scripts/*` are allowed, so an agent
can run arbitrary code. See "Limits".

## Permissions

Both tools get guardrails, not boundaries.

Project level. `opencode.json` and `.claude/settings.json` are read in every session in this
repository, interactive ones included, so they hold only what `AGENTS.md` states for every agent:
`gh pr merge`, `gh pr *--auto*`, pushes to `main`, force pushes and `--no-verify` forms
(`docs/factory/meta/deny-project.txt`). They set no `"*"` baseline, no allow list, no `ask` rule, no
`edit` rule and no `external_directory` rule, so a developer's own `plan` and `build` agents and
Claude Code sessions behave as usual. `scripts/test-factory.sh` pins this.

Factory level. Everything else lives only in the factory layer.

- Allowed commands: `docs/factory/meta/claude-allow-common.txt` (every role) and `claude-allow-code.txt`
  (implementer). Common set: `cargo *`, `scripts/*`, read-only `git` subcommands (`status`, `diff`,
  `log`, `show`, `rev-parse`, `merge-base`, `ls-files`, `for-each-ref`, `write-tree`, `describe`,
  `ls-tree`, `cat-file`, `blame`, `shortlog`, `grep`, `branch`, `stash list`, `tag -l`, `remote -v`,
  `worktree list`) and the inspection commands `ls`, `rg`, `grep`, `wc`, `diff`, `cat`, `head`, `tail`,
  `find`, `stat`, `file`, `tree`, `sort`, `uniq`, `cut`, `tr`, `basename`, `dirname`, `realpath`, `pwd`,
  `which` and `sed -n`. The implementer adds `git add|commit|rm|mv|restore`, `mkdir` and `chmod +x`.
  No command that writes by itself is allowed (no `tee`, `dd`, `cp`, `mv`, `rm`, `touch`, `truncate`,
  `install`, `ln`, `sed -i`, `find -exec`).
- Denied commands: `docs/factory/meta/deny-project.txt` plus `deny-factory.txt`: every `git push`,
  `git config`, `git -c`, `git -C`, `git reset --hard`, `gh api|repo|workflow|release|auth`,
  `bash -c`, `sh -c`, `env`, `python*`, `curl`, `wget`, `sudo`, `rm -rf`, the `--output` option of
  `git diff|log|show`, `find` with `-exec`, `-execdir`, `-ok`, `-delete`, `-fprint` or `-fls`, the
  `git branch` forms that delete, move, copy, force or set upstream, `git grep -O`, `sed -i`,
  `sort -o` and `tree -o`.
- OpenCode: `scripts/factory-sync.sh` writes the whole ordered bash map into each generated agent:
  `"*": "deny"` first, then the allows of the role's access class, then every deny last. The baseline
  is `deny`, not `ask`: a headless run cannot answer a prompt, so an `ask` would hang until the
  phase timeout, while a deny fails at once with a message the model can act on. The readonly
  agents get no mutating allow, and `edit` denied except `.factory/runs/*`; the implementer gets
  `edit` allowed.
- Claude Code: the driver passes `--allowedTools <grant>` and `--disallowedTools <denies>` per phase
  (`claude_tools` and `claude_denies` in `scripts/factory.sh`). The only file-edit grant of a
  readonly phase is `Edit(/.factory/runs/<run id>/<artifact file>)`: the one file the phase writes,
  so `state`, the snapshots and the other run files are not agent-writable. The driver launches
  Claude with the repository root as working directory, which anchors that path. The grants are
  split: every role gets the common set, the implementer also the mutating git commands, and
  nobody but the driver or the interactive command gets fetch, branch creation or `gh pr create`
  (`claude-allow-orchestrator.txt`). `.claude/settings.json` carries no allow list, because the
  driver's grant is complete. The interactive `/factory` command pre-approves the allow lists but has
  no deny list of its own: its restrictions are the user's own session settings plus the
  `AGENTS.md` denies.

Redirection is not covered. Command-prefix rules match the command text, so `cat x > y` matches
`cat *`, and `sed`, `sort` or `uniq` can name an output file. The read-only guarantee for the
planner and the reviewers does not rest on the allow list: it rests on the driver's post-phase
snapshot check (a changed file is exit 13) and on the artifact-only `Edit` grant.

How the layers merge, and how sure we are.

- Verified (OpenCode 1.19.5, `opencode debug agent factory-planner`, read-only, no model): the
  resolved rule list holds the project file's rules first and the agent's frontmatter rules after
  them, and the order inside the agent's bash map is kept. With last-match-wins, the agent's deny
  rules therefore decide over its own allows and over the project file. The user's own agents
  (`build`) resolve with only the project file's denies. `scripts/test-factory.sh` repeats the
  agent resolution when `opencode` is installed (not under `FACTORY_TEST_SKIP_CLI=1`) and runs the
  same checks on the resolved rules.
- Reasoned, not run: that the last-match-wins evaluation is what a live OpenCode applies at run time
  (documented for 1.x), that a deny returns at once in a headless run, and that matching is
  case-sensitive.
- Reasoned, not run: for Claude Code, that `--disallowedTools` entries win over `--allowedTools` and
  over the project settings under `dontAsk` (deny wins over allow in Claude's rule order), and that
  a long deny list in the argument is accepted. Claude agent frontmatter was not used for denies:
  its support for `Bash(...)` rules in `disallowedTools` is not established here.
- Known glob limits: combined short flags (`git branch -vD`, `git commit -an`) cannot be told from
  other text; the snapshot, the hooks and CI are the walls there.

The Claude command shape is `claude -p <prompt> --agent factory-<role> [--model M] --permission-mode
dontAsk --allowedTools <grant> --disallowedTools <denies> --strict-mcp-config --no-session-persistence
--output-format text`. `--strict-mcp-config` without `--mcp-config` loads no MCP server at all, so the
user's own servers neither run in a factory run nor leave files in the tree. `--bare` and
`--setting-sources` are not used. OpenCode has no equivalent switch and still loads the user's MCP
servers.

## Hooks

The hooks under `.githooks/` are driver-only. The driver exports `GIT_CONFIG_COUNT=1`,
`GIT_CONFIG_KEY_0=core.hooksPath` and `GIT_CONFIG_VALUE_0=<repository root>/.githooks` once at
preflight (git 2.31 or newer), so its own git calls and all children use them. Humans do not opt in;
they keep the `pre-commit` framework hooks, and `scripts/gate.sh --full` covers the same checks.

- `pre-commit` compares the stamp written by a passing gate run with `git write-tree` and rejects a
  mismatch. The stamp lives in `.git`, covers only the tree hash, and any agent with a shell can
  write it or edit the hook: it catches an agent committing something it did not check, nothing
  more.
- `pre-push` refuses `refs/heads/main` and `refs/heads/master`, tags, deletions and any
  non-fast-forward update.

## Limits and credentials

Hooks are local and removable. Anything run through `cargo` (build scripts, tests) or an allowed
script is arbitrary code that can use the user's credentials: the child process keeps `HOME`, so
`~/.config/gh`, `~/.ssh` and git credential helpers stay reachable, and such code can push to `main`
or call the GitHub API, which neither the hook nor the permission rules can stop. The driver does
not pass `GH_TOKEN` or `GITHUB_TOKEN` to children, but that is hygiene, not isolation.

Therefore unattended runs belong in a throwaway clone or container with a scoped, non-admin
credential (push to feature branches and pull request creation only). The real walls are the
driver's snapshot verification, its own final gate, CI and the review of the protected-path diff.
