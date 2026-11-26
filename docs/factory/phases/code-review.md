Review the commits on branch `{{BRANCH}}` against the plan in `{{PLAN}}`. Read the diff with
`git diff {{BASE_SHA}}..HEAD`. This is review round `{{ROUND}}` of at most `{{MAX_ROUNDS}}`.

Run `{{GATE_CMD}}` yourself and report what it printed. Write the review to `{{ARTIFACT}}` with an
`## Observed` section and end it with the verdict line `VERDICT: APPROVED` or
`VERDICT: CHANGES NEEDED`.

{{RESUME_CONTEXT}}
