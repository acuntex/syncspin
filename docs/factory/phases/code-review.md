Review the commits on branch `{{BRANCH}}` against the plan in `{{PLAN}}`. Read the diff with
`git diff {{BASE_SHA}}..HEAD`. This is review round `{{ROUND}}` of at most `{{MAX_ROUNDS}}`.

Run `scripts/timed.sh 1200 -- {{GATE_CMD}}` yourself in the foreground and report what it printed.
Write the review to `{{ARTIFACT}}` first, then amend it with the observed output; end it with the
verdict line `VERDICT: APPROVED` or `VERDICT: CHANGES NEEDED`.

{{RESUME_CONTEXT}}
