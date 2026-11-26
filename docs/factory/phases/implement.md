Implement the approved plan in `{{PLAN}}` on the current branch `{{BRANCH}}`. The base commit is
`{{BASE_SHA}}`. Owner decisions, if any, are in `{{DECISIONS}}` and are binding.

Make one commit per commit of the plan's breakdown. Before every commit run `{{GATE_CMD}}` and fix
what it reports; never commit with a failing check. Do not push.

If you cannot continue, write `blocked.md` in `{{RUN_DIR}}` with the reason and stop.

{{RESUME_CONTEXT}}
