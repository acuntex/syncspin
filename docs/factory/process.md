# The code factory: process

This page is the tool-neutral specification of the factory: the process, the caps, the exit codes,
the state files and the protected paths. It is the source of truth for the role prompts in `roles/`,
the phase prompts in `phases/` and the generated agent files for OpenCode and Claude Code.

Components that do not exist yet in the commit that introduces this page are marked "(introduced in
commit N of the factory series)". Nothing in this directory is executed; the scripts that read it
arrive in later commits.

## Components

| Component                                               | Role                                                                  |
| ------------------------------------------------------- | --------------------------------------------------------------------- |
| `docs/factory/roles/*.md`                               | Role system prompts (source of truth).                                |
| `docs/factory/phases/*.md`                              | Per-phase user-prompt templates, filled in by the driver.             |
| `docs/factory/meta/*.conf`                              | Per-role metadata: name, description, access class, model class.      |
| `scripts/gate.sh` (commit 3)                            | Tool-independent gate: `--commit`, standard, `--full`, `--list`.      |
| `.githooks/pre-commit`, `.githooks/pre-push` (commit 3) | Driver-only hooks, activated through environment variables.           |
| `scripts/factory-sync.sh` (commit 4)                    | Generates the agent files for both tools from the sources; `--check`. |
| `.opencode/agents/`, `.claude/agents/` (commit 4)       | Generated agent files. Never edit them by hand.                       |
| `.claude/commands/factory.md` (commit 4)                | Generated interactive `/factory` command (Claude Code only).          |
| `opencode.json`, `.claude/settings.json` (commit 5)     | Project permissions for the two tools.                                |
| `CLAUDE.md` (commit 5)                                  | Git symlink to `AGENTS.md`; no content of its own.                    |
| `scripts/factory.sh` (commit 6)                         | Deterministic driver; the only OpenCode path and the unattended path. |
| `scripts/test-factory.sh` (commit 3, grows)             | Hermetic tests with stub CLIs; no model is ever run.                  |

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
command, or `not resumable`).

Run directory files: `task.md plan.md review-plan-N.md review-plan-post.md decisions.md
review-code-N.md pr.md blocked.md handoff.md state logs/<phase>.log`. Logs can hold paths and model
provider output: never attach them to a public issue.

## Protected paths and the snapshot

The protected set is `.githooks/`, `scripts/`, `.opencode/`, `.claude/`, `opencode.json`,
`AGENTS.md`, `.github/` and the `CLAUDE.md` symlink. The driver (commit 6) hashes it, together with
refs, git config, hooks and the worktree status, before and after every phase. A readonly phase must
leave all of it unchanged; an implement phase may only advance the factory branch and must not touch
the protected set unless the run was started with `--allow-protected`. A violation is exit 13. The
gitignored `.claude/settings.local.json` is excluded from the hash.

The snapshot is a post-hoc state check, not a sandbox: `cargo` and `scripts/*` are allowed, so an agent
can run arbitrary code. See "Limits".

## Permissions

Both tools get guardrails, not boundaries. Commands the implementer may run without asking: `cargo *`,
`scripts/*`, `git status|diff|log|show|rev-parse|merge-base|ls-files|for-each-ref|write-tree`,
`git add|commit|rm|mv|restore`, `ls`, `mkdir`, `rg`, `grep`, `wc`, `diff`, `chmod +x`. Everything else
that could change state is denied or needs approval; `git push`, `gh pr merge`, `gh api`, `git config`,
`bash -c`, `curl`, `sudo` and `rm -rf` are denied.

Readonly overlay for OpenCode: the generated readonly agents add only edit rules (`"*"` denied, the
run directory allowed) and a deny-only bash overlay for `git fetch *`, `git add *`, `git commit *`,
`git rm *`, `git mv *` and `git restore *`. The overlay never repeats a `"*"` rule: OpenCode appends
agent rules after the global ones and the last matching rule wins, so a repeated `"*": "ask"` would
override the global allows for `git diff`, `rg` and `grep` and hang a headless reviewer.

Claude Code readonly phases get a per-phase `--allowedTools` grant: the only file-edit grant is
`Edit(/.factory/runs/<run id>/**)`. The driver launches Claude with the repository root as working
directory, which is what anchors that path.

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
