# syncspin

Sendspin protocol client and server library for Rust. It is **not** an official Sendspin
implementation and must never present itself as one; "Sendspin" is used only to describe the
protocol it speaks (see the spec's `TRADEMARKS.md`).

This file is for agents and contributors working in this repository.

## Layout

| Path                      | Contents                                                                        |
| ------------------------- | ------------------------------------------------------------------------------- |
| `crates/syncspin-core/`   | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `crates/syncspin-client/` | Client session loop, `Sink` trait, event stream.                                |
| `crates/syncspin-server/` | Listener, one group, roles, streams, pairing and discovery (`0.2`).             |
| `examples/player-pipe/`   | Runnable reference player: PCM on stdout, status lines on stderr.               |
| `examples/server-demo/`   | Runnable reference server: approves one client and streams a tone.              |
| `examples/mdns-pair/`     | One-command mDNS smoke test: advertises, discovers, approves, streams, exits.   |
| `docs/`                   | Design, spec deviations and the testing handbook.                               |

`player-pipe` is the reference `Sink`: it shows the event loop, the identity file and the reconnect
policy without device code. `server-demo` is the reference host: it shows the approval gate, the
event loop and the push data plane, and holds no files. `mdns-pair` is the smoke test: both roles in
one process, two mDNS daemons, and a format-and-byte gate that decides the exit code.

**Layering rule:** `syncspin-core` never imports `syncspin-client` or `syncspin-server`, and it
never knows a transport. A dependency pointing from core towards a crate is a bug, not a shortcut.

## Commands

```sh
cargo test --workspace --locked
cargo test --workspace --features pairing-code,storage-file --locked
cargo test -p mdns-pair --features mdns --locked        # the flow behind mdns-pair's own feature
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo package -p syncspin-core --locked                 # publishability, before a release
cargo package -p syncspin-server --locked               # once core and the client are on the registry
cargo check -p syncspin-core -p syncspin-client --all-features \
  --target armv7-unknown-linux-gnueabihf --locked       # the ARM guard, as CI runs it
cargo check -p syncspin-server --all-features \
  --target armv7-unknown-linux-gnueabihf --locked       # the same guard for the server, run it too
cargo check -p syncspin-client \
  --target armv7-unknown-linux-gnueabihf --locked       # the client with its default roles
cargo check -p syncspin-client --no-default-features \
  --target armv7-unknown-linux-gnueabihf --locked       # and with no role feature at all
scripts/check-roles.sh                                 # every role feature set: tests, docs, clippy
cargo zigbuild --target armv7-unknown-linux-gnueabihf  # once a dependency needs a C toolchain
cargo deny check                                       # licences, advisories, sources
scripts/coverage.sh                                    # coverage, all features, advisory
```

The ARMv7 build is the one that decides whether this library is usable where it is needed: it must
stay green. `zigbuild` needs `cargo-zigbuild` and a `zig` binary.

## Changes land through a pull request

`main` requires seven checks (`lint`, `test`, `msrv`, `arm`, `deny`, `docs`, `secrets`) and has
`enforce_admins` off. A push from the owner therefore bypasses them, and GitHub says so in the push
output: `Bypassed rule violations ... required status checks are expected`. The bypass works; it is
not to be used. No commit goes to `main` directly - not a one-line documentation fix, not a runner
label bump, not a commit whose checks you expect to pass.

```sh
git switch -c docs/<topic>
# commit on the branch, then
git push -u origin docs/<topic>
# open the pull request, let the seven checks run, merge squashed
```

Wait for the checks before merging: a green run after the merge proves nothing was gated. A push
straight to `main` is the one mistake that leaves the gates decorative, which is why it is a rule
here rather than a preference.

## Hard rules

- **No unencrypted path, ever.** A peer that does not complete the Noise handshake is refused.
  There is no plaintext fallback and no downgrade - not behind a flag, not in a test.
- **Never log key material or pairing records.** No static keys, no PSKs, no pairing blobs, no
  Noise handshake hashes - not at `trace`, not in `Debug` output, not in error strings.
- **The role feature defaults stay `player`, `controller`, `metadata`.**
  `artwork`, `visualizer`, `color` and `source` stay off unless a caller opts in, and only
  `syncspin-client` has role features: `player`, `controller` and `metadata` (on by default) and the
  tables `storage-file`, `pairing-code` (core/client/server), `discovery` and `mdns`
  (client/server). `artwork` is a role feature too (off by default: it holds images in memory and
  advertises nothing until the host configures a channel) and so is `color` (off by default); `visualizer`
  and `source` are not implemented. A set that turns a role off compiles other test files, so a change in the client
  runs `scripts/check-roles.sh` as well. `storage-file` is off in
  `syncspin-client` but on in `player-pipe`, so a workspace build enables it through feature
  unification; `pairing-code`, `discovery` and `mdns` are off unless requested. `mdns-pair` has its
  own `mdns` feature, which forwards to the client and server ones and is off by default: the flow
  is built only with `--features mdns`.
- **MSRV 1.85.** A dependency that demands more is pinned or replaced, not silently accepted; the
  `msrv` CI job is the gate.
- **Names and licence are fixed:** crates `syncspin-core`, `syncspin-client` and `syncspin-server`;
  licence `MIT OR Apache-2.0`. Renames break downstream consumers and the published crates.
- **Spec deviations are documented** in `docs/spec-deviations.md` and covered by a test. Where
  Music Assistant and the spec disagree, the spec wins.
- **A capability claim is checked against the tree, not against memory.** The documents have drifted
  three times: a `wss` feature that never existed, a README pinned to a tag older than the features
  it described, and a server called "planned" after it shipped. When a change adds a capability,
  removes one, or finishes a milestone, read `README.md`, `docs/spec-deviations.md`,
  `docs/testing.md`, `SECURITY.md` and the doc comments for the sentences it just made false. Words
  to grep first: `planned`, `stub`, `publish = false`, `not implemented`, and any release version.
- **This repository is public.** No personal names, home-directory paths, device names, hostnames,
  IP addresses, account names or details of downstream or private projects may appear in code,
  comments, tests, commit messages or docs. When porting code from elsewhere, rewrite the comments
  instead of copying them. The account in a repository URL is a location, not an account name; it is
  the one permitted occurrence.
- Everything in this repository is English: code, comments, commits, docs. Conventional Commits,
  small verified steps.

## Tests

Tests are hermetic: no network, no audio device, no listener on a real port unless the suite binds
`127.0.0.1` explicitly and owns it. A fake server is preferred over a live Music Assistant.

## Relationship to downstream consumers

The crate is consumed by applications that add device-specific behaviour: audio output, hardware
controls, a local HTTP API. Those consumers depend on `syncspin-client` by path during development
and by a pinned git tag afterwards.

Consequences for changes here:

- A consumer's ARMv7 build against glibc 2.24 counts as a regression here when it breaks, even if
  the workspace tests pass.
- Key material and pairing records belong to the consumer. This crate never rotates a keypair on its
  own and never writes into a file it does not own.
- A consumer's behaviour must stay identical across internal refactorings; its behaviour tests
  (volume clamp, mute, platform integration) are part of the acceptance criteria for changes in
  `syncspin-client`.
