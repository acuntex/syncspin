# syncspin

Sendspin protocol client and server library for Rust. It is **not** an official Sendspin
implementation and must never present itself as one; "Sendspin" is used only to describe the
protocol it speaks (see the spec's `TRADEMARKS.md`).

This file is for agents and contributors working in this repository.

## Layout

| Path | Contents |
| --- | --- |
| `crates/syncspin-core/` | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `crates/syncspin-client/` | Client session loop, `Sink` trait, event stream. |
| `crates/syncspin-server/` | Server listener, streams, roles, pairing (`0.2`, `publish = false`). |
| `docs/` | Design notes and `docs/spec-deviations.md` (planned). |

An `examples/` directory is planned (a pipe player and a fake server) but does not exist yet.

**Layering rule:** `syncspin-core` never imports `syncspin-client` or `syncspin-server`, and it
never knows a transport. A dependency pointing from core towards a crate is a bug, not a shortcut.

## Commands

```sh
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo zigbuild --target armv7-unknown-linux-gnueabihf   # the ARMv7 baseline, glibc 2.24
cargo deny check                                       # licences, advisories, sources
```

The ARMv7 build is the one that decides whether this library is usable where it is needed: it must
stay green. `zigbuild` needs `cargo-zigbuild` and a `zig` binary.

## Hard rules

- **No unencrypted path, ever.** A peer that does not complete the Noise handshake is refused.
  There is no plaintext fallback and no downgrade - not behind a flag, not in a test.
- **Never log key material or pairing records.** No static keys, no PSKs, no pairing blobs, no
  Noise handshake hashes - not at `trace`, not in `Debug` output, not in error strings.
- **Default features stay `player`, `controller`, `metadata`.** `artwork`, `visualizer`, `color`
  and `source` stay off unless a caller opts in.
- **MSRV 1.85.** A dependency that demands more is pinned or replaced, not silently accepted; the
  `msrv` CI job is the gate.
- **Spec deviations are documented** in `docs/spec-deviations.md` and covered by a test. Where
  Music Assistant and the spec disagree, the spec wins.
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
- A consumer's behaviour must stay identical across internal refactorings; its volume-clamp tests
  (at most +20 per command above 40, with the applied value reported back) are part of the
  acceptance criteria for changes in `syncspin-client`.
