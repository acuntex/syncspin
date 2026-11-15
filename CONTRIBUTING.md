# Contributing

This is an early library: the client works and is tested, the server is a stub, and the API is
allowed to change until 1.0. Contributions that make the protocol handling more correct, the tests
more honest or the documentation more accurate are welcome — including the ones that tell us we got
something wrong.

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
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
npx --yes prettier@3.9.10 --check .
```

`--locked` is not optional: the workspace ships a `Cargo.lock`, and a test run that silently
resolves new versions tells you nothing about the code that will be released.

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
| `test`    | The hermetic suite on x86_64.                                                                                                                                 |
| `msrv`    | The suite still builds and passes on 1.85.                                                                                                                    |
| `arm`     | The crates still compile for ARMv7. The glibc 2.24 baseline itself needs the `zigbuild` run in [`docs/testing.md`](docs/testing.md); CI does not link it yet. |
| `deny`    | Licences, advisories and sources of every dependency.                                                                                                         |
| `docs`    | `cargo doc` without warnings, so a broken doc link cannot merge.                                                                                              |
| `secrets` | No credential in the history, scanned with gitleaks.                                                                                                          |

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
one is wrong by construction. Anything that needs a peer runs against the fake server in
`crates/syncspin-client/tests/`, not against a live Music Assistant.

## Release mechanics

`syncspin-core` has to be published before `syncspin-client`: the client's `syncspin-core`
dependency is a path dependency that `cargo package` rewrites to a registry dependency, so
`cargo package -p syncspin-client` fails until `syncspin-core` exists on crates.io.
`syncspin-server` is `publish = false` and stays out of the release.

`CHANGELOG.md` is generated with [git-cliff](https://github.com/orhun/git-cliff) from the tags and
the conventional commits; do not edit it by hand.

## Licence of contributions

Contributions are licensed under MIT OR Apache-2.0, the licence of the project. There is no CLA and
no sign-off requirement: opening a pull request is the whole agreement.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
