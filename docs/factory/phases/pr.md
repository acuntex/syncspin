Write the pull request text for branch `{{BRANCH}}` (base `{{BASE_SHA}}`) to `{{ARTIFACT}}`. Read the
commits with `git log {{BASE_SHA}}..HEAD` and the reviews in `{{RUN_DIR}}`. The plan is `{{PLAN}}`.

Format: first line the title, then a blank line, then the body with the grouped commit list, what
changed and why, the checklist from `.github/pull_request_template.md` ticked only for observed
items, and a `## Not verified` section.

{{RESUME_CONTEXT}}
