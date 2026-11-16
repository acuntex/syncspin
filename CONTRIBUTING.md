# Contributing

This is an early library: the client and the server work and are tested, and the API is allowed to
change until 1.0. Contributions that make the protocol handling more correct, the tests more honest
or the documentation more accurate are welcome — including the ones that tell us we got something
wrong.

## What is welcome

- **Protocol correctness** against the Sendspin specification, with a test that shows the behaviour.
- **Tests**, especially hermetic ones that do not need a server, a network or an audio device.
- **Documentation fixes**: a sentence that does not match the code is a bug.
- **ARMv7 and MSRV regressions.** The crates have to build where they are needed.

What does not fit:

- A second copy of the protocol inside one crate, or a shortcut around `syncspin-core`.
- An unencrypted path, a downgrade flag, or a "just for testing" bypass. There is none, and there
  will not be one.
- Drive-by reformatting, generated files or dependency churn.

## Before you start

Open an issue for anything larger than a typo. Say what you want to change and what you have tried;
it is cheaper to disagree about the shape of a change than about its diff. Typos and broken links
need no issue.

## Setup

The workspace builds with the toolchain in `rust-toolchain.toml`. `cargo test`, clippy and `fmt` are
CI gates, so a green local run is what a reviewer will see; prettier is a local hook, not a gate:

```sh
cargo test --workspace --locked
cargo test --workspace --features pairing-code,storage-file --locked
cargo test -p syncspin-core -p syncspin-client --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
npx --yes prettier@3.9.10 --check .
```

Feature unification decides what those three runs cover. `syncspin-client` has no default
features, but `player-pipe` enables `storage-file` by default, so the workspace run turns it on for
the client and runs the file backend's tests; `pairing-code` is off everywhere unless requested. The
second run adds the code flows, and the third tests `syncspin-core` and `syncspin-client` with their
own defaults — what a consumer that enables nothing gets. The workspace runs also cover
`syncspin-server`, which has no default features; its code-flow tests join the second run. All three
commands are the `test` gate. `--locked` is not optional: the workspace ships a `Cargo.lock`, and a
test run that silently resolves new versions tells you nothing about the code that will be released.

The MSRV is 1.85 and is checked separately:

```sh
rustup toolchain install 1.85.0
RUSTUP_TOOLCHAIN=1.85.0 cargo test --workspace --locked
```

The ARMv7 compile guard and the manual run against a real server are described in
[`docs/testing.md`](docs/testing.md). The local hooks — gitleaks, `cargo fmt`, clippy and prettier —
are configured in [`.pre-commit-config.yaml`](.pre-commit-config.yaml); install them with
`pre-commit install`.

## The gates

`main` is protected. A pull request merges only when all seven checks are green:

| Check     | What it proves                                                                                                                                                |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lint`    | `cargo fmt --check` and clippy without warnings.                                                                                                              |
| `test`    | The hermetic suite on x86_64: the workspace, the pairing features, and the library crates with their own defaults.                                            |
| `msrv`    | The suite still builds and passes on 1.85.                                                                                                                    |
| `arm`     | The crates still compile for ARMv7. The glibc 2.24 baseline itself needs the `zigbuild` run in [`docs/testing.md`](docs/testing.md); CI does not link it yet. |
| `deny`    | Licences, advisories and sources of every dependency.                                                                                                         |
| `docs`    | `cargo doc` without warnings, so a broken doc link cannot merge.                                                                                              |
| `secrets` | No credential in the history, scanned with gitleaks.                                                                                                          |

Two more jobs report without blocking: `coverage` (line coverage with every feature, floor 91.0) and
`package` (`cargo package -p syncspin-core`). The floor follows the workspace: core and the client
sit around 96.7, and the server crate that arrived in 0.2 sits near 85, which is what moved the
number down. Making them required would gate pull requests on numbers that move with a refactor,
not with a defect.

`mutants` is a third job that is not in the required set, and it is not a number either. It runs
weekly over `syncspin-core` and `cargo-mutants` exits non-zero as soon as one mutant survives, so a
red run is a test gap or an exemption to add - it stays red until one of the two happens. Read it as
a work list, not as a gate: the result arrives weekly, not on a pull request. A surviving mutant
that cannot be killed because the mutation does not change behaviour needs an explicit exemption -
a skip in the code or an exclusion in the cargo-mutants configuration - and the reason recorded
next to it.

## Hard rules

- **No unencrypted path.** A peer that does not complete the Noise handshake is refused. No flag, no
  fallback, no exception for tests.
- **Never log or paste key material.** No static keys, PSKs, pairing records or Noise handshake
  hashes — not in code, not in test fixtures, not in an issue, not in a commit message.
- **MSRV 1.85.** A dependency that demands more is pinned or replaced. Raising the MSRV is a
  deliberate, documented decision.
- **A spec deviation needs an entry and a test.** Add it to
  [`docs/spec-deviations.md`](docs/spec-deviations.md) with the reason and what closing it takes,
  and cover it.
- **Layering.** `syncspin-core` never depends on `syncspin-client` or `syncspin-server`, and it knows
  no transport. A dependency pointing the other way is a bug.
- **This repository is public.** No personal names, home-directory paths, device names, hostnames or
  private project details in code, tests, comments or commits.

## Commits and pull requests

- **Conventional Commits**: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, with an
  optional scope (`fix(client): ...`). The changelog is generated from these, so an unconventional
  subject is lost.
- **Squash merge**, one topic per pull request. A pull request that fixes a bug and reformats a file
  is two pull requests.
- The description says what changes and why, and names the issue it closes.
- Small, verified steps are easier to review than one large step that works.

## Tests

The suites are hermetic: no network, no audio device, no listener on a real port. A test that needs
one is wrong by construction. The client suites run against the fake server in
`crates/syncspin-client/tests/`, the server suites against a fake client in
`crates/syncspin-server/tests/`, and one round-trip test runs the real client crate against the real
server crate. Nothing runs against a live Music Assistant or opens a multicast socket.

## Release mechanics

Publishing is ordered by the registry: `syncspin-client` and `syncspin-server` both depend on
`syncspin-core` through a path dependency that `cargo package` rewrites to a registry dependency, so
neither can be packaged until `syncspin-core` exists on crates.io. The client is published next, then
the server, so the release order is core → client → server. All three crates publish from one tag; no
library crate is `publish = false`.

`CHANGELOG.md` is generated with [git-cliff](https://github.com/orhun/git-cliff) from the tags and
the conventional commits; do not edit it by hand.

One command prepares a release:

```sh
scripts/release.sh <version>            # bump, changelog, gates, commit
scripts/release.sh <version> --dry-run  # show what it would change
```

Before the tag, read the documents as a stranger would. The script enforces the version; nothing
enforces the prose, and that is where this project has been wrong three times: a feature that never
existed, a README pinned to a tag older than the features below it, and a server described as
"planned" after it shipped. Grep for `planned`, `stub`, `publish = false`, `not implemented` and the
previous version number, then check each hit against the code.

It bumps the workspace version, the internal path-dependency requirements and the three `version()`
tripwires, refreshes `Cargo.lock`, prepends the changelog section rendered from the commits since the
last tag, and refuses to continue
if the previous version is still named anywhere outside `CHANGELOG.md` and the lock file — that check
exists because a published README once advertised the release before it. Then it runs the format and
test gates and commits `chore(release): <version>`.

The script does not use `git cliff --tag` on its own: that renders every section from the tags, and a
tag created out of order is dropped, folding its commits into the previous release. `--unreleased`
renders exactly the new section, so the script prepends it and leaves the history alone.

Merge the resulting branch, then push the tag and let the pipeline do the rest:

```sh
git tag -a v<version> -m "syncspin <version>" && git push origin v<version>
```

[`release.yml`](.github/workflows/release.yml) verifies the commit under the tag, refuses a tag that
does not match the workspace version, publishes `syncspin-core`, waits for the index, publishes
`syncspin-client`, waits again, publishes `syncspin-server`, and writes the GitHub release from the
changelog section. It runs in the `release` environment, which holds the `CARGO_REGISTRY_TOKEN`
secret scoped to all three crates; add required reviewers there if a pushed tag should not be able to
publish on its own. A manual run packages without uploading unless `dry_run` is cleared, and every
step skips a version that is already on the registry, so a partial run can be repeated.

## Licence of contributions

Contributions are licensed under MIT OR Apache-2.0, the licence of the project. There is no CLA and
no sign-off requirement: opening a pull request is the whole agreement.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
