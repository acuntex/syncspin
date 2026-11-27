# The code factory

A small, tool-neutral process that takes a task text to a reviewed pull request: a planner writes a
plan, a fresh reviewer checks it, an implementer makes small verified commits, a fresh code reviewer
checks them, and a pull request is opened. It works in OpenCode and in Claude Code. Agents never
merge: the owner reviews and merges.

The specification (process, caps, exit codes, state files, protected paths, hooks) is
[`process.md`](process.md). This page is the human guide.

## Prerequisites

- `opencode` and/or `claude` installed, `git` 2.31 or newer, `gh`, `shellcheck`. Every tool you use
  must be logged in: the agent CLIs (log in once, interactively) and `gh`. The ARMv7 target
  (`rustup target add armv7-unknown-linux-gnueabihf`) is optional: the gate skips that step without it
  and says so.
- Claude Code: open every fresh clone once, interactively (`claude` in the clone), and accept the
  workspace trust dialog. Without that, a headless run ignores the project permission rules and the
  phases end without their artifacts (see Troubleshooting).
- Claude Code: the driver passes `--strict-mcp-config` and no `--mcp-config`, so no MCP server is
  loaded in a factory run, including the ones from your user-level configuration. Tools from your
  personal setup do not run inside a run, and they cannot create files that trip the snapshot
  check. The driver does not use `--bare` (it would also skip hooks and agents) and does not restrict
  `--setting-sources`.
- For unattended runs, a throwaway clone or container and a scoped, non-admin credential (push to
  feature branches and pull request creation only). The agent process keeps `HOME`, so
  `~/.config/gh`, `~/.ssh` and git credential helpers stay reachable, and anything run through
  `cargo` (build scripts, tests) is arbitrary code that can use them. The driver does not pass
  `GH_TOKEN` or `GITHUB_TOKEN` to the agents, but that is hygiene, not isolation.

## Starting a run

|                       | OpenCode                                                    | Claude Code                                                                  |
| --------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Interactive           | `/factory`, `/factory-resume`, `/factory-status`; see below | `/factory <task text>` in a session                                          |
| Driver (unattended)   | `scripts/factory.sh --backend opencode "..."`               | `scripts/factory.sh --backend claude "..."`                                  |
| Agents                | `.opencode/agents/factory-*.md`, `.opencode/commands/`      | `.claude/agents/factory-*.md` and `.claude/commands/factory.md`              |
| Permissions           | generated agents (`opencode.json`: `AGENTS.md` denies only) | driver flags (`.claude/settings.json`: `AGENTS.md` denies only)              |
| Project rules         | reads `AGENTS.md` directly                                  | reads `CLAUDE.md`, a symlink to `AGENTS.md`                                  |
| Non-interactive slash | -                                                           | `claude -p "/factory ..."` stops at the push request (not approved headless) |

OpenCode has no `/factory` command that runs the phases inside the session: its subagents run in the
background and report when idle, and there is no documented way to wait for one. The driver is the
OpenCode path. The OpenCode commands described under "Starting from an OpenCode client" only start,
resume and follow the driver. A run can still be
followed and steered interactively: with `--opencode-attach URL` every phase is a session on that
server, visible in its interface, and a person there can answer a permission prompt instead of the
phase waiting for its timeout. Attached 2.x sessions are not archived, so they show in the server's
session lists.

`claude -p "/factory ..."` expands the command, but a headless run has nobody to approve the `ask`
rule on `git push` (a `-p` run denies a call that needs approval unless a hook or tool approves it), so
such a run stops before the push. The driver is the unattended path for both tools.

## Deterministic driver or prompt-driven command

`scripts/factory.sh` is the deterministic path: the control flow, the round caps (4 plan reviews, 3
code reviews, flags can only lower them), the verdict parsing, the snapshot checks, the commit and
pull request text checks and the push are shell code with tests. The agents do the thinking.

`scripts/gate.sh` runs only the steps the changed paths need: Rust paths select the cargo steps,
shell paths `shellcheck`, factory paths (including `.github/`, `.mcp.json` and the ignore files) the
generator check and the factory tests, while a docs or markup path selects no cargo step. A rename
keeps both sides visible. A path in no class, a failed `merge-base` or an empty index leaves the set
unknown, which selects every step of the mode. A changed `deny.toml` selects the `deny` step in every
mode, so deleting the policy fails the gate instead of skipping the step. `--since REF` selects the
per-commit steps for a committed range; the light code review uses it because its index is clean. CI
still runs the whole set on every pull request, so a step the local gate skipped cannot reach `main`
unchecked.

The Claude Code `/factory` command is prompt-driven: the same procedure, but the caps and checks are
instructions to a model. Prefer the driver when the outcome matters.

## Light path

A trivial task does not need the full path. The driver classifies the task text itself, in shell code
and without a model:

- **light** when the text is at most 1200 bytes and 12 lines, names one to three files, and every
  named file is `.gitignore` or has a `.md` or `.txt` name. A URL with a scheme, a `//host` path or a
  directory mention is not a named file. The names are normalised first, so `./AGENTS.md`,
  `docs/./factory/process.md` and `docs//factory/process.md` are the protected paths they name. A
  light run writes a short plan on the helper model, skips the plan review, makes one implementer call
  and then measures the real diff: it stays light while that diff touches at most three such files,
  adds and deletes at most 80 lines and is a single commit.
- **full** otherwise, including a task that names no file, names only directories, names more than
  three files, or mentions `scripts`, `crates`, `src`, `.github`, `Cargo.toml` or any other protected
  path or code. A directory mention beside a named file does not by itself make the task full unless
  it is protected. Anything unclear is full.

A light run that leaves those limits after the implementer call — a code file, a protected path, too
many lines — escalates: `light-escalation.txt` in the run directory records why, the state says
`path=full`, and the run continues on the full path from the code review on. An answer to an owner
decision that changes the plan body escalates the same way before the post-decision review. The
skipped plan review cannot be added back, which is why the classifier is conservative: the owner gate,
the one review and CI remain. `--dry-run` prints the path, its reason and the light schedule.

```sh
scripts/factory.sh --backend claude "add a --list flag to the player example"
scripts/factory.sh --backend opencode --no-push --stop-after review --task-file task.md
scripts/factory.sh --dry-run --backend claude "anything"   # print the phases and command shapes, call nothing
```

`--allow-protected`, `--plan-rounds N`, `--code-rounds N`, `--model-helper M`, `--model-main M`,
`--variant-helper V`, `--variant-main V`, `--opencode-attach URL`, `--opencode-bin PATH` and
`--phase-timeout SECS` (overrides every phase budget) are the other options. `FACTORY_PASS_ENV` names
the variables to pass to the agent (for a model provider key); everything else is removed from its
environment.

`--stop-after plan` stops after the plan: reviewed on the full path, unreviewed and short on the light
path, where the driver says so. It leaves the branch that preflight created in the local repository.
Delete it by hand when you abandon the run.

## Writing a task text

A task text is data, not a command: it is the owner's request in a few sentences. Name the outcome,
the crate or file if you know it, and what must not change. Put long requests in a file and use
`--task-file`. The planner turns it into a plan with commits, tests and open owner decisions.

## What the human decides

- Owner decisions: the planner asks only questions that change what will be built, each written
  `- BLOCKING: <question>`; everything else goes under `## Notes` and runs on. When the section is not
  `None.` the run stops with exit 10; write the answers to `decisions.md` in the run directory and run
  `scripts/factory.sh --resume <run id>`. The stop lists the questions and names any line that is not
  marked blocking, so a misplaced non-blocking question costs a stop rather than passing silently. The
  plan is revised, and reviewed once more only when the revision changed the plan outside the owner
  decisions and the changelog; answering a question in place is not a change. On the light path such a
  change also escalates the run to the full path.
- Everything after a stop that is not resumable (exit 11 to 16): read `handoff.md`, then fix by hand
  or start a new run.
- The pull request: read it, in particular the protected-path diff, and merge it yourself.

## Run directory and artifacts

`.factory/runs/<run id>/` is gitignored and holds `task.md`, `plan.md`, `review-plan-N.md`,
`review-plan-post.md`, `decisions.md`, `review-code-N.md`, `pr.md`, `blocked.md`, `handoff.md`,
`state`, `phases.tsv`, `light-escalation.txt` and `logs/<phase>.log`. Logs can contain paths and model
provider output: never attach them to a public issue.

## Exit codes

| Code | Meaning                                                 | Resumable |
| ---- | ------------------------------------------------------- | --------- |
| 0    | Done, or stopped by `--stop-after`                      | -         |
| 2    | Usage error, including a refused `--resume`             | -         |
| 3    | Preflight failed, or resume prerequisites are missing   | -         |
| 10   | Owner decisions are open                                | yes       |
| 11   | Plan review cap reached, or post-decision review failed | no        |
| 12   | Code review cap reached                                 | no        |
| 13   | Sandbox violation (state changed that must not change)  | no        |
| 14   | Bad commits, `blocked.md`, or a phase made no progress  | no        |
| 15   | The final `scripts/gate.sh --full` failed               | no        |
| 16   | The pull request text failed its lint                   | no        |
| 20   | Timeout, backend failure, push or pull request failure  | yes       |

## Model and cost

The Claude agents use `sonnet`. For OpenCode no model is committed: set `FACTORY_MODEL_HELPER` (the
reviewers, the pull request writer and the light planner) and `FACTORY_MODEL_MAIN` (the full-path
planner and the implementer) or the flags above; without a helper model the driver warns once and the
reviewers use the session default. A full run makes one planner call, one to five plan reviews, one
implementer call, one to three code reviews (plus fixes) and one pull request writer call; a light run
makes one planner call on the helper model, no plan review, one implementer call and at most one short
review.
Every phase kind has its own budget: 20 minutes for the plan, 15 for a plan revision and a plan
review, 10 for the post-decision review and the pull request text, two hours for the implementer,
90 minutes for a fix, 25 for a code review and two hours for the final gate, 45 minutes for anything
else. `--phase-timeout SECS` overrides every one of them.

### Reasoning variant (OpenCode)

`opencode run --variant` selects a provider-specific reasoning effort (for example `minimal`, `high` or
`max`). Set `FACTORY_VARIANT_MAIN` (the full-path planner and the implementer) and
`FACTORY_VARIANT_HELPER` (reviewers and pull request writer), or `--variant-main V` and
`--variant-helper V`. A variant is passed as
`--variant V` to the OpenCode backend only, and only when set; it must match `^[a-z0-9][a-z0-9._-]*$`, so
nothing else can reach the command line. The Claude backend ignores it with a one-line warning. The
driver does not know which variants a model supports: an unsupported one fails in OpenCode. `--dry-run`
prints the variants and the command shapes.

### Running against a long-lived OpenCode server

`FACTORY_OPENCODE_ATTACH` or `--opencode-attach URL` makes every OpenCode phase run as
`opencode run --attach URL --dir <repository root> ...` instead of starting its own server, so the
phases show up as sessions in that server and a run can be followed from its web UI. The URL must be
`http://host[:port]` or `https://host[:port]`, for example `http://localhost:4096` or
`http://127.0.0.1:4096`, with no user, path or query; anything else is a usage error. The Claude
backend ignores the option with a warning. `--dry-run` prints the URL.

Credentials: for a server with basic auth, export `OPENCODE_SERVER_PASSWORD` (and, if the server needs
one, `OPENCODE_SERVER_USERNAME`) in the shell that starts the driver. The driver passes them to the
OpenCode phases only when `--opencode-attach` is used and the variable is set. They are handed to the
phase through a file descriptor, never on a command line (the process list would show them), and a
log line that holds either value is withheld from `handoff.md` and from stderr. The phase logs under
`.factory/runs/` are raw agent output and are not scrubbed.

What changes, honestly:

- The server runs in its own environment, with its own user-level configuration, MCP servers and
  OpenCode version. The driver's environment scrub and its MCP isolation do not apply, and the
  permission semantics are those of the server's version.
- Attaching works only if the client and the server API versions interoperate. This is unverified: try
  `opencode run --attach http://localhost:4096 --dir <absolute path> "say ok"` by hand once before a
  real run. A server of another major generation may read the configuration format differently.
- The snapshot checks still apply: they look at the files, not at the process. Each phase is a new
  session, so the reviewers keep fresh context.
- A long session can drive the server to high memory use, and a supervisor may restart it. That ends
  the running phase: exit 20, resumable.
- Plain-HTTP basic auth sends the password unencrypted. Use loopback, or a TLS-terminating proxy, for
  anything beyond a trusted LAN. Recommended only for local, low-risk runs.

## Starting from an OpenCode client

An OpenCode client (the mobile app, a web client, a desktop client or the terminal interface) can talk
to a long-running OpenCode server on the machine that holds the clone, and start and follow a run from
there. A run takes tens of minutes, which must not hang an agent's bash tool call, so the commands go
through `scripts/factory-launch.sh`. It checks its arguments, then detaches `scripts/factory.sh` as a
systemd user unit `factory-<id>` (when `systemctl --user` answers) or with `setsid` and a log file
under `.factory/launch/`, and returns a short summary at once.

| Command           | What it does                                                                    |
| ----------------- | ------------------------------------------------------------------------------- |
| `/factory`        | Asks for the task, how far to go and where to run, then starts a detached run   |
| `/factory-resume` | Lists the resumable runs, asks which, asks the open owner decisions, resumes it |
| `/factory-status` | Summarises the configuration, the launches and the runs, and offers a next step |

The commands take no arguments: OpenCode may expand `!` shell substitution and `@` file references in
a command template after it has substituted the typed arguments (unverified), so the templates hold no
`$ARGUMENTS`, no `$1` and no such syntax, and everything the owner types comes back as the answer to a
`question`, which is a tool result and not template text. A static test pins this.

The commands run in the generated `factory-launcher` agent (`.opencode/agents/factory-launcher.md`).
Its rules: bash denied except `scripts/factory-launch.sh *`, every shared deny last; `edit` only under
`.factory/launch/`; `read` only under `.factory/runs/` and `.factory/launch/`; `question` allowed;
`task` denied, like every factory agent, so it cannot start a subagent. It runs the launcher in
exactly the form each command template names, with no option a template does not name: never the
driver, never the gate, never `cargo`, and it never waits for a run.
Everything is generated from `docs/factory/commands/`, `roles/launcher.md` and `meta/launcher*`. The
commands exist for OpenCode only: Claude Code has its own `/factory`.

### What you are asked

Every question comes from the OpenCode `question` tool: a header, the question, two to four options,
each with a one-sentence explanation of its consequence, and a free-text answer. The recommended option
comes first and says `(Recommended)`. The agent asks in the language you wrote in.

- `/factory`: one call with the task (the free-text answer), how far to go and, if a server is
  configured, where to run. A second call confirms the exact, secret-free command. The confirmation
  cannot share the first call, because the command depends on the first answers.
  - Plan only (recommended for a first run: cheap, no code is written): `--no-push --stop-after plan`.
  - Through code review, without pushing: `--no-push --stop-after review`.
  - Through a pull request: `--stop-after pr` (the driver pushes the factory branch and opens it).
  - Attached to the configured server (recommended, the run is visible and steerable there): no
    argument. A private server of its own: `--no-attach`.
- `/factory-resume`: the agent lists the runs stopped with exit 10 or 20 (`--status`, read-only) and
  asks which to resume, recommending the most recent. For exit 10 it reads the `## Owner decisions` section of `plan.md`
  and asks each decision with concrete options, what each means and its own recommendation, labelled
  `(My recommendation)` with the reason. Your answers are written to
  `.factory/launch/decisions-<run id>.md`, which the launcher copies to the run's `decisions.md`
  before the driver resumes. For exit 20 it explains the cause and offers resume, the log tail or
  nothing. Runs stopped with exits 11 to 16 are not resumable and are not offered.
- `/factory-status`: a summary of all launches and runs, then one question offering what fits: look
  at one run in detail (phase, step, rounds, exit code, phase durations from the logs), stop a running
  launch, resume (it points to `/factory-resume`), or nothing.

The task text and your answers are data: the prompts say so, and the agent runs nothing but the
launcher. If the `question` tool is not available (a headless run), the agent says so and stops:
`/factory` has no task without an answer, `/factory-resume` prints the resumable runs and the open
owner decisions instead of guessing, and `/factory-status` prints the summary.

### Configuring the server

The launcher passes the driver options only from a fixed list (`--backend`, `--opencode-attach`,
`--opencode-bin`, `--model-main`, `--model-helper`, `--variant-main`, `--variant-helper`,
`--stop-after`, `--plan-rounds`, `--code-rounds`, `--phase-timeout`, `--no-push`, and its own
`--no-attach`); `--allow-protected` and `--dry-run` are not on it. The task text never reaches a command
line. The defaults come from the environment of the server process, which the launcher forwards (after
the driver's own value checks) for exactly these names: `FACTORY_BACKEND`, `FACTORY_MODEL_MAIN`,
`FACTORY_MODEL_HELPER`, `FACTORY_VARIANT_MAIN`, `FACTORY_VARIANT_HELPER`, `FACTORY_OPENCODE_BIN`,
`FACTORY_OPENCODE_ATTACH` and `FACTORY_PASS_ENV`. Nothing else leaves the server's environment.

```sh
# in the environment of the process that serves the OpenCode client
FACTORY_BACKEND=opencode
FACTORY_MODEL_MAIN=provider/model
FACTORY_MODEL_HELPER=provider/model
FACTORY_OPENCODE_ATTACH=http://127.0.0.1:4096
FACTORY_LAUNCH_ENVFILE=/path/to/launch.env
```

Credentials for an attached server go in a file, named by `FACTORY_LAUNCH_ENVFILE` or `--env-file`,
with `OPENCODE_SERVER_USERNAME` and `OPENCODE_SERVER_PASSWORD` (and any provider key named in
`FACTORY_PASS_ENV`) as `NAME=value` lines. Keep it mode 600: the launcher warns on stderr when group
or others can read it and refuses a missing file. It never reads the file and never prints it:
systemd loads it for the unit (`EnvironmentFile`), or the detached shell sources it in the fallback.

### What you see

After the questions the agent reports the launcher's summary: the launch id, `journalctl --user -u
factory-<id> -f` (or the log path), `scripts/factory-launch.sh --status`, `scripts/factory-launch.sh
--stop <launch id>`, and where the run directory appears (`.factory/runs/`). With an attached server,
every phase is also a session in that server; a client that derives the title from the first prompt
line shows `Factory <slug>: <phase> <round>` (reasoned, not run). The driver prints one line per phase
with its duration and its exit code, and ends every run — finished, stopped or interrupted by a signal
— with a summary: the path, the number of phase runs and the time spent inside them, then one line per
phase. It also records every phase in
`phases.tsv` in the run directory. `--status` lists the five newest launches and runs and reads
`phases.tsv` when the driver wrote one; without it, the durations fall back to the last log header
(`== <phase> HH:MM:SS`, UTC) against the log's last write. `--stop` ends the systemd unit or
the fallback process group; an agent phase of the fallback may run on until its own timeout.

### Limits

- Anyone who can use the server's interface can start agents on that machine, with the credentials of
  the user the server runs as. The launcher agent is restricted, but the user's own agents on the
  same server are not.
- A command template is expanded by OpenCode before the agent sees it, and OpenCode may run `!`
  shell substitutions and attach `@` file references that appear in it after substituting typed
  arguments (unverified). That is why the commands take no arguments and the templates carry none of
  that syntax; the owner's text only ever arrives as a `question` answer, a tool result. Keep it that
  way when you edit the sources: the static test fails on `$ARGUMENTS`, `$` and a digit, `!` and a
  backtick, and `@` and a path character.
- Plain-HTTP basic auth sends the password unencrypted off loopback.
- The detached run uses the owner's credentials (`gh`, `ssh`, git helpers) like any driver run. Use a
  throwaway clone and a scoped, non-admin token for anything beyond local, low-risk runs.
- The bash rule `scripts/factory-launch.sh *` matches command text; it relies on OpenCode checking
  each part of a compound command. Unverified for both generations.
- The `read` rules also allow the absolute form of the two directories, because the path form
  `read` is matched against is not verified.
- Unverified until tried by hand, in both generations: that OpenCode finds commands in
  `.opencode/commands/` (the 1.x layout here uses `.opencode/agents/`; the current documentation names
  `commands/`, and `command/` as the older spelling), that the `description` and `agent` keys work as the
  documentation says in 1.x and in 2.x, that the `question` tool
  exists in the generation you run and under the `question` permission key, that a client shows it
  (the documentation says it needs one that supports the interactive form), and what it does in a
  headless `opencode run`.
- The launcher needs `setsid`, `git` and `od`; it exits 3 when the directory it runs in is not a
  repository root with `scripts/factory.sh`, or an env file is missing, and 2 on a usage error.

## Permissions

Both tools get guardrails, not security boundaries; the vendors say so too. The real layers are the
driver's snapshot verification, its own final gate, CI and the review of the protected-path diff.

**Interactive sessions are not restricted by the factory.** The committed project files
(`opencode.json`, `.claude/settings.json`) hold only what `AGENTS.md` states for every agent: no
`gh pr merge`, no auto-merge (`gh pr *--auto*`), no push to `main` or force push, no `--no-verify`
forms. Your own OpenCode `plan` and `build` agents and your own Claude Code sessions in this
repository keep their normal behaviour for everything else. Every other restriction exists only in
the factory layer:

| What                             | Where it lives                                                                                                          |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `AGENTS.md`-level denies         | `docs/factory/meta/deny-project.txt`, copied into `opencode.json`, `.claude/settings.json` and every factory agent      |
| Factory-only denies              | `docs/factory/meta/deny-factory.txt`: in the generated OpenCode agents, and passed by the driver to Claude per phase    |
| Allowed commands                 | `docs/factory/meta/claude-allow-*.txt`: OpenCode agents carry them as bash rules, the Claude driver as `--allowedTools` |
| Edit rules of the readonly roles | The generated OpenCode agents; for Claude the driver's `Edit(<artifact>)` grant                                         |
| The `task` tool (subagents)      | `task: "deny"` in every generated OpenCode agent; no agent spawns another                                               |

| Aspect                   | OpenCode (generated agents)                                          | Claude Code (driver flags)                                       |
| ------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Rule shape               | Ordered map per tool; the last matching rule wins                    | `allow`, `deny`; deny wins                                       |
| Baseline                 | `bash "*": "deny"`, allows of the access class next, every deny last | Nothing is allowed that is not listed; `dontAsk` denies the rest |
| Readonly roles           | Edit denied except the run directory; no mutating bash allowed       | Driver grants `Edit` on the one artifact file only               |
| Implementer              | Edit allowed; the common and code bash allows                        | Driver grants `Edit,Write` plus the common and code bash grants  |
| Push                     | Denied; only the driver pushes                                       | Denied through `--disallowedTools`; only the driver pushes       |
| Knows the current branch | No; the pre-push hook and the driver do                              | No; the pre-push hook and the driver do                          |

The OpenCode baseline is `deny`, not `ask`: a headless run cannot answer a prompt, and a deny fails
at once with a message the model can act on, while an `ask` would hang until the phase timeout. The
interactive `/factory` command of Claude Code has no per-command deny list: it pre-approves the
allow list, and the factory denies apply only to the driver's phases and to the OpenCode agents.

**Redirection is not covered.** Command-prefix rules match the command text and cannot stop shell
redirection: `cat x > y` matches `cat *`, and `sed`, `sort` or `uniq` can name an output file. The
read-only guarantee for the planner and the reviewers therefore does not rest on the allow list. It
rests on the driver's post-phase snapshot check (a changed file is exit 13) and on the artifact-only
`Edit` grant. Do not read the allow list as a sandbox.

## Troubleshooting

When a phase exits non-zero or ends without its report, the driver stays on exit 20 (resumable),
prints one `factory: cause: ...` line and adds a `## Cause` section to `handoff.md` with the first 12 non-blank
lines of `logs/<phase>.log` (ANSI codes removed, lines with personal data withheld). A phase that
exits **0** without its artifact is retried once before the run stops; a non-zero exit is not
retried. Fix the cause, then run `scripts/factory.sh --resume <run id>`.

| Cause in handoff.md       | What the log said                                 | Fix                                                                   |
| ------------------------- | ------------------------------------------------- | --------------------------------------------------------------------- |
| not logged in             | `Not logged in`, `run /login`                     | Log in once: run the tool interactively (Claude Code: `/login`).      |
| workspace not trusted     | `has not been trusted`, `trust dialog`            | Run `claude` in the clone once and accept the workspace trust dialog. |
| rate or usage limit       | `rate_limit`, `usage limit`, `spend limit`, `429` | Wait until the limit resets, or switch backend with `--backend`.      |
| ended without its report  | the phase exited 0 and wrote nothing              | Read the log; a turn cap or a refused tool call may have ended it.    |
| no known cause in the log | none of the above                                 | Read the log. On Claude Code the `Edit(...)` rule form may be wrong.  |

A phase that ends before writing its report usually did not keep its commands in the foreground. The
`## Discipline` section of the reviewer and implementer roles forbids background jobs and polling and
asks for the artifact first, so this should be rare: read the log for a command that was killed.

## Known limits

- The OpenCode backend has no documented switch to ignore the user's own configuration (`opencode run`
  has no such flag), so it still loads your MCP servers. If one of them creates files in the working
  tree, the driver's snapshot check can trip (exit 13). Use a throwaway clone and, if it happens,
  remove the server from your user-level OpenCode configuration for the run.
- Pattern rules match command text. Wrappers and other shells (`bash -c`, an absolute path) can get
  around them; the allow list is the control, the deny list adds clarity.
- `cargo` and `scripts/*` are allowed, so a build script or a test can run arbitrary code with the
  user's credentials. The hooks cannot stop that.
- The hooks under `.githooks/` are driver-only and local; a human never opts in, and an agent with a
  shell can edit them. The pre-commit stamp catches an agent committing something it did not check;
  it is not a gate. The per-commit check is `scripts/gate.sh --commit`. The deny lists block
  `--no-verify`, `-n` and `--no-v*` for `git commit`, but not every combined short form (`-an`,
  `-anm`): a glob cannot tell flag letters from a commit message.
- The gate selects its steps from the changed paths, so a change that looks unrelated to the step it
  would have needed can skip it locally. `.gitignore` keeps the generator check and the factory tests
  for that reason, and a path outside every class selects every step of the mode. The CI jobs always
  run the whole set on the pull request, so nothing skipped locally reaches `main` unchecked; `deny`
  skips only when `deny.toml` was never tracked, and deleting a tracked policy fails the gate.
- The snapshot ignores ignored paths on purpose (`target/`, `mutants.out*`, identity files): a new
  file in some other ignored location is invisible to it.
- The deny lists also block the `--output` option of `git diff`, `git log` and `git show`, which
  would write a file from a read-only grant.
- The check that no branch commit reached remote `main` fails closed: it can report a violation
  (exit 13) when the branch legitimately merged `origin/main`, when `main` was force-pushed during
  the run, or in a shallow clone that lacks the history. Check the remote by hand and start a new
  run.
- `opencode debug config` and `opencode debug agent` print the contributor's global configuration
  (providers, URLs, headers). The tests parse that output silently; never paste it into an issue.
- OpenCode and Claude Code evolve. The OpenCode rules here use the 1.x shape (`permission`, `bash`,
  `edit`); an installation that expects the newer `permissions` array rejects them. `scripts/test-factory.sh`
  probes the installed CLIs when they exist.

## `CLAUDE.md` on Windows

`CLAUDE.md` is a git symlink to `AGENTS.md`. A Windows checkout without symlink support yields a
one-line text file instead, and Claude Code then loses the project rules. Enable `core.symlinks`
(Developer Mode or an elevated shell) and check out again, or use WSL. OpenCode reads `AGENTS.md`
directly. Always edit `AGENTS.md`, never the link.

## Generated files

`scripts/factory-sync.sh` writes `.opencode/agents/`, `.opencode/commands/`, `.claude/agents/` and
`.claude/commands/factory.md` from `roles/`, `commands/`, `meta/` and `meta/claude-allow-*.txt` (the
launcher agent from `roles/launcher.md` and `meta/launcher-allow.txt`, the OpenCode commands from
`commands/`). `--check` (run by the
`lint` job) fails when a generated file differs from its source. Edit the source, run the script,
commit both.

## Verified with

Not yet verified against a live model. What runs in CI and locally is the hermetic suite
(`scripts/test-factory.sh`), which uses stub CLIs. Record here, after the first manual run, the
versions used and the result of each of these checks:

- a tiny task on each backend with `--no-push`;
- one real light run (`--no-push --stop-after review`) on a Markdown-only task: one planner call, no
  plan review, one implementer call, one light review, and a summary line;
- one run ended by a signal (or stopped through the launcher) prints the `factory: summary:` line;
- `opencode debug agent factory-planner` and `opencode debug agent factory-launcher` on an
  installation that has the client, to confirm both resolve with `task: "deny"` and that a session
  title comes out readable;
- `gh pr merge` and `git push origin main` refused inside both tools;
- a readonly OpenCode role cannot edit `src/` but can write its artifact (this confirms the `edit`
  path form and the rule order on OpenCode 1.x);
- the Claude Code `/factory` command waits for its foreground subagents;
- Claude Code follows the `CLAUDE.md` symlink (ask it to quote one rule from `AGENTS.md`);
- what OpenCode does headless when a rule says `ask`;
- the OpenCode commands: `.opencode/commands/` is found, `/factory` starts a detached run, the
  `question` tool is shown by the client and by `opencode run`, and the `factory-launcher` read and
  edit path forms match (1.x and 2.x).

## Manual cleanup

After an abandoned run: `git switch main`, `git branch -D factory/<name>-<id>` for the leftover
branch, and `rm -r .factory/runs/<run id>`. If a push happened, delete the remote branch and close
the pull request on GitHub.

## Not included

Deferred on purpose: rewriting history with `--force-with-lease`, a `--worktree` mode, a
`--verify-each` mode, an OpenCode `/factory` command that runs the phases inside the session (the
launcher commands only start the driver), a CI check that compares the permission files
with the CI jobs, and changes to the contributor guide or the pull request template beyond the
required-check count.
