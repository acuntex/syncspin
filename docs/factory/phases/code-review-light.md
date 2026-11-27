Read the one commit on branch `{{BRANCH}}` against the plan in `{{PLAN}}`: `git diff {{BASE_SHA}}..HEAD`.
This is the short review of a small change, one round only.

Run `scripts/timed.sh 600 -- {{GATE_CMD}}` yourself and report what it printed. Write the review to
`{{ARTIFACT}}` with an `## Observed` section and end it with the verdict line `VERDICT: APPROVED` or
`VERDICT: CHANGES NEEDED`.

{{RESUME_CONTEXT}}
