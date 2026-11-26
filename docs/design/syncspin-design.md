# syncspin — Sendspin client and server library (Design)

Status: accepted design · Date: 2026-11-15 · Consumer: a downstream application

This is the public copy of the design document. Details of any specific downstream consumer are
deliberately generalised; nothing here describes a particular device, deployment or private project.

The repository is written entirely in English: code, comments, commit messages, README, AGENTS.md,
CHANGELOG and every file under `docs/`. This document is kept in English for that reason.

**This document describes the target, not the current tree.** It is the design the implementation is
measured against: the API sketch, the feature flags (`wss`, `flac`, `opus`, `artwork`, `visualizer`,
`color`, `source`), the pairing flows and the server half. What exists today is the README's "What
works today" and "What does not work yet", and
[`docs/spec-deviations.md`](../spec-deviations.md) for the departures from the specification.

**Status as of 0.2.** The client half and the server half both exist and are published: the Noise
handshake at either end, roles, the three pairing methods with their storage, the listener and its
approval gate, one group with one stream, and discovery in both directions. So the pairing flows,
the server half and bidirectional discovery below describe shipped code, not a plan. Still missing
are several groups per server, role versions beyond `@v1`, the `visualizer` and
`source` roles, the `flac`, `opus` and `wss` features, and a persisted last-playback server; those are
listed with their reasons in [`docs/spec-deviations.md`](../spec-deviations.md).

## Intent

A standalone, public Rust library for Music Assistant's Sendspin protocol: encrypted (Noise),
spec-faithful, with complete pairing, usable as a **client** (player, controller, metadata) and later
as a **server**. Today the only working Rust client is embedded in a downstream playback
application; `sendspin-rs` exists but is explicitly WIP and has **no encryption** (no `snow`, no
Noise module, no crypto dependency), which makes it unusable for an "encrypted only" client.

The library is extracted so the protocol code exists exactly once, can be reviewed and used by
others, and so the consumer focuses on device integration.

## Goals

- Client: connection, Noise `KKpsk2`, clock sync, roles, pairing (Sentinel guest, pairing PSK,
  code pairing with CPace), reconnect, volume reporting — as a reusable crate.
- Audio leaves the crate as **PCM through a `Sink` trait**; decoders (FLAC, optional Opus) are
  feature flags, output stays with the user (pipe, ALSA, cpal, GStreamer).
- 0.2, now shipped: a full server that accepts clients, manages streams, serves roles, pairs as
  server, and runs mDNS for both the client-initiated and the server-initiated mode.
- The downstream application becomes a consumer of the crate; its behaviour (volume guard, platform
  integration, pause on app leave) stays unchanged.
- Published on crates.io with docs.rs, MIT OR Apache-2.0, English README and API docs.

## Non-Goals (0.1)

- No unencrypted path, no legacy compatibility with pre-Noise clients.
- No server functionality in the 0.1 client (the server half shipped in 0.2).
- No multi-server arbitration (a client holds one server connection).
- No UI, no playlist/queue handling, no music sources — that is higher-level Sendspin server work
  and stays in Music Assistant.
- No `no_std`, no runtime-agnostic async abstraction: tokio.

## Anti-Goals

- **Failure even if it compiles:** a second protocol copy that nobody uses; a public API that still
  breaks after six months; hand-rolled crypto without test vectors.
- **Failure:** users have to read the spec before they can hear music.

## Constraints

- **Spec fidelity:** `github.com/Sendspin/spec` — `connection.md` (Noise, Sentinel fallback,
  re-handshake, mDNS), `pairing.md` (MUST: pairing PSK; SHOULD: code methods), `messaging.md`,
  `roles/*`. Deviations are allowed but must be documented and tested.
- **ARMv7 target:** 32-bit ARM, glibc 2.24, built with `cargo zigbuild`. No dependencies that break
  there (no `ring`/`openssl`, no forced `cpal`). Crypto stays with `snow` + `x25519-dalek`; CPace
  only with vetted primitives.
- **MSRV:** 1.85, with a dedicated CI job and a README line; if a dependency demands more, pin it or
  raise the MSRV deliberately and document it.
- **Trademark:** "Sendspin" is governed by spec/TRADEMARKS.md → project name `syncspin`, README
  describes it as a "Sendspin protocol client and server library", no logos, no claim of being
  official.
- **License:** MIT OR Apache-2.0 (same as `sendspin-rs`, Rust convention).

## Approaches

**Repo layout** — A: keep the protocol code inside the consuming application; B: own repository from
day one; C: workspace crate first, extract later. **Chosen: B** (own public GitHub repository from
day one; the consumer depends on the crate by path first, by git tag from the first release on).

**Crate split** — A: one crate with `client`/`server` features; B: three crates
`syncspin-core`/`-client`/`-server`. **Chosen: B** — the client can reach 0.1 independently of the
still-unstable server side, and Noise/pairing live in exactly one place.

**GitHub vs. Gitea** — **Chosen: GitHub primary**, CI with GitHub Actions, crates.io publishing from
the release workflow. No mirror, no second pipeline.

**Changelog** — `git-cliff` instead of semantic-release: Rust-native, reads Conventional Commits, no
Node toolchain in the repository, and produces both `CHANGELOG.md` and the GitHub release notes in
one run.

## Architecture

```
syncspin/
  crates/
    syncspin-core/      # ground truth: protocol and crypto
      noise.rs          # Noise KKpsk2 responder/initiator, Sentinel PSK, PSK ids, prologue
      messages.rs       # serde types for core/management/pairing/role messages
      framing.rs        # WS binary frame <-> Noise transport message, fragmentation
      clock.rs          # NTP burst + 2D Kalman (extracted from the consumer's clock module)
      pairing/          # PSK flow, CPace flow, record format, storage trait
      roles/            # shared role types (player, metadata, artwork, ...)
    syncspin-client/    # connection + session
      transport.rs      # ws://, optional wss:// (feature)
      session.rs        # handshake, role activation, event loop
      client.rs         # builder, handle, control methods
      sink.rs           # Sink trait, format changes, backpressure
      decode.rs         # feature "flac" (flac-codec), optional "opus"
      storage.rs        # identity + pairing records
    syncspin-server/    # server half, from 0.2
      listener.rs, streams.rs, pairing_server.rs, mdns.rs
  examples/
    player-pipe/        # PCM to stdout, title/status to stderr — works everywhere
    server-demo/        # fake server that serves one client (test and learning object)
  docs/                 # design, testing handbook, spec deviations
```

Rule: `syncspin-core` never imports `client`/`server`; every crypto decision lives in `core`.

## API sketch

```rust
// syncspin-client
pub enum AudioFrame<'a> {
    Pcm(&'a [u8]),                            // crate decoded (features "flac"/"opus")
    Encoded { codec: Codec, data: &'a [u8] }, // pass-through, e.g. a consumer's own decode stage
}

pub trait Sink: Send + 'static {
    fn open(&mut self, format: AudioFormat) -> Result<()>;
    /// `due` is the local instant the first sample should reach the audio port. The client calls
    /// this at the frame's pre-port write time; the sink writes now and does not schedule again.
    fn write(&mut self, frame: AudioFrame<'_>, due: Instant) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
    /// Drops the audio due at or after `due`; the default flushes everything. The client has
    /// already cut its own queued frames at the server timestamp.
    fn discard_from(&mut self, due: Instant) -> Result<()> { self.flush() }
    /// Delay between `write` and the audio port: decoder, pipeline and device buffers the client
    /// compensates by writing that much before `due`.
    fn pre_port_delay(&self) -> Duration { Duration::ZERO }
    /// The delay the output adds after the audio port (external speakers, amplifiers), reported
    /// to the server and subtracted from every deadline.
    fn output_delay(&self) -> Option<Duration> { None }
    fn underruns(&self) -> u64 { 0 }
}

pub enum Event {
    Connected { server_id: String, encrypted: bool },
    Disconnected { reason: String, retry_in: Duration },
    StreamStart { format: AudioFormat },
    StreamEnd { reason: StreamEndReason },     // End | RoleRemoved, before the sink flush
    StreamClear { from_timestamp: Option<i64> }, // seek, before the sink discards or flushes
    LateAudio { late_by: Duration, dropped: u64 }, // late or overrun drops, at most once a second
    Track { title: String, artist: String, album: Option<String>, duration: Option<Duration>,
            playback_speed: u32 },                            // per-mille, 1000 = normal
    State(PlaybackState),
    Volume { requested: u8, applied: u8, muted: Option<bool> },
    Artwork { mime: String, bytes: Bytes },                  // feature "artwork"
    Visualizer { .. },                                       // feature "visualizer"
    PairingCode { code: PairingCode, format: CodeFormat },   // feature "pairing-code"
}

pub struct Client;                               // handle: Clone + Send
impl Client {
    pub fn builder() -> ClientBuilder;           // name, server, roles, format, storage, sink
    pub async fn connect(&mut self) -> Result<ConnectInfo>;
    pub fn events(&self) -> impl Stream<Item = Event> + Send;
    pub fn control(&self) -> ControlHandle;      // play/pause/skip/seek/volume/mute
    pub fn state(&self) -> PlayerState;          // last known state, no await
}
```

Decisions: a client may run without a `Sink` (`connect_headless`): it then offers no `player@v1`,
reports no player state and takes part in the other roles only; events as an async stream (no
callback trait), reconnect/backoff and volume reporting
inside the crate, `Sink` receives audio frames (decoded or pass-through) when their write time
arrives and writes them on call, pushback via blocking `write` on its own task. The crate owns the
time filter, the playout queue and therefore the schedule: each frame's server timestamp becomes a
local deadline, the queue keeps the frames in deadline order, and the session calls `write` one
`pre_port_delay` before that deadline. A frame more than 10 ms past its write time is dropped, never
advanced, and `Event::LateAudio` reports the worst lateness and the count at most once per second,
together with capacity evictions. The queue holds at most the `buffer_capacity` the client
advertises (128 KiB), counted in write-time bytes - the 13-byte chunk header plus payload, released
when the frame is written - which is deliberately tighter than the spec's completion-time
accounting. The sink owns the real rendering latency: the part before the port is
`pre_port_delay()`, the part beyond the audio port reaches `output_delay_ms` through
`output_delay()`, while `underruns()` waits for a correction loop the session does not use yet.
`min_buffer_ms` belongs to the crate: a host may pin it in `ClientConfig`, and otherwise the session
derives it from the arrival delay of audio chunks and reports each sustained change in a
`client/state`.

## Pairing

- **Guest (today):** Sentinel PSK, `unpaired_access.enabled` — how an unpaired client runs.
- **Pairing PSK (spec MUST, 0.1):** negotiate the long-term PSK, persist a pairing record
  (`long_term_psk` + `server_id`), handle the re-handshake, detect and report Sentinel fallback.
  At least 5 records, LRU eviction.
- **Code pairing (0.1, feature):** CPACE-X25519-SHA512 per draft-irtf-cfrg-cpace-21, server = A,
  client = B, MCF; static and dynamic codes, `qr_code` optional. `wrapped_psk`/`wrapped_nonce_B`
  with AEAD and `K_wrap = SHA-256(label ‖ sid ‖ ISK)`.
- **Storage:** `trait Storage { identity, load_pairings, store_pairing, remove_pairing }` plus
  `FileStorage` (0600, atomic) as the default. **File ownership stays separated:** the crate never
  rewrites a file the host owns. The host loads its identity and passes the keypair in through the
  builder; the crate persists pairing records in its own file next to it (default
  `<storage-dir>/syncspin-pairings.json`). A consumer that owns its identity file keeps its fields
  and keypair untouched and gets the pairing records beside it — otherwise the consumer's next
  configuration save would silently drop them.

**CPace risk:** before implementing, verify whether `pake-cpace`/`pakery-cpace` match draft-21 with
MCF and the spec's generator/`sid` layout. If not, the CPace wrapper is built around
`x25519-dalek` + SHA-512, with draft test vectors and a review step.

## Connection model

- **0.1: client-initiated** (`ws://<server>:8927/sendspin`, optional server list in the builder).
  In 0.1 clients did not advertise over mDNS, which deviated from `connection.md`; 0.2 closed that
  deviation.
- **0.2: both directions, shipped.** The server advertises `_sendspin-server._tcp` and discovers
  clients via `_sendspin._tcp`; the client advertises itself and accepts server-initiated
  connections. Spec rule to respect: a client that advertises MUST NOT additionally connect
  manually, so `ClientConfig::inbound` selects the advertising mode and a configuration that sets it
  refuses to dial; the manual path stays the fallback for setups where mDNS is filtered (as in some
  consumer builds today).
- `wss://` only as a feature for remote access, never the default. Not implemented yet: the client
  rejects a `wss://` address when it is configured.

## Repository layout (target)

```
syncspin/
  .github/workflows/{ci.yml,release.yml}
  .pre-commit-config.yaml          # fmt, clippy, prettier (md), shellcheck
  AGENTS.md  CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md
  README.md  CHANGELOG.md  LICENSE-MIT  LICENSE-APACHE
  rust-toolchain.toml  deny.toml  cliff.toml  renovate.json5  .gitignore
  Cargo.toml (workspace)
  crates/…  examples/…  docs/…
```

`AGENTS.md` in the new repository (short, ~60 lines): purpose; layout and the rule "core knows no
transport"; commands (`cargo test --workspace`, clippy, `cargo zigbuild --target
armv7-unknown-linux-gnueabihf`, `cargo deny check`); hard rules (no plaintext path, never log
pairing records, Sentinel only as guest, MSRV, spec deviations only with an entry in
`docs/spec-deviations.md`); relationship to downstream consumers (the ARM build must stay green).

## CI/CD (GitHub Actions)

| Job     | Content                                                                                                                        | Trigger          |
| ------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| lint    | `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`                                                   | push, PR         |
| test    | `cargo test --workspace` (x86_64, all features), hermetic fake-server test                                                     | push, PR         |
| msrv    | build + test with the MSRV toolchain                                                                                           | PR               |
| arm     | `cargo zigbuild --target armv7-unknown-linux-gnueabihf` (the job that guards the ARM target)                                   | push, PR         |
| deny    | `cargo deny check` (licenses, advisories, duplicates)                                                                          | push, PR, weekly |
| semver  | `cargo semver-checks` against the last published version (from 0.1)                                                            | PR               |
| docs    | `cargo doc --no-deps` with `-D warnings`                                                                                       | push             |
| release | tag `vX.Y.Z`: verify, `git-cliff` → `CHANGELOG.md` + release notes, `cargo publish` for `core` before `client`, GitHub release | tag              |

- Actions pinned by SHA, minimal `permissions:`, `CARGO_REGISTRY_TOKEN` as a repository secret.
- Conventional Commits, single `main` branch, PR required.
- No nightly run and no coverage gate in 0.1 (optional later).
- **Feature matrix:** `wss` pulls `rustls` (whose only usable backends are `ring` and `aws-lc-rs`).
  It is therefore an opt-in feature that is **excluded from the ARM job and from
  `--all-features`**; the ARM job and the `--all-features` clippy run use the encryption-only default
  set. If a `ring`-free TLS backend appears, the exclusion is revisited.

### Dependency updates: Renovate (not Dependabot)

Renovate with the **dependency dashboard** is required on GitHub.

- **Install:** the official **Renovate GitHub App** — free for public repositories, which this one is
  from day one. It creates and maintains the "Dependency Dashboard" issue, needs no token in the
  repository and no workflow of its own. Fallback only if the App is ever unavailable to us: the
  self-hosted `renovatebot/github-action` workflow with a `RENOVATE_TOKEN` secret, same dashboard.
- **Config:** `renovate.json5` with `config:recommended`, `:semanticCommits`, `:dependencyDashboard`.
  Managers: `cargo` (crates.io), `github-actions`, `rust-toolchain`.
- **Grouping:** one PR per ecosystem per week — `cargo` non-major together, `github-actions` with
  `helpers:pinGitHubActionDigests` (SHA pinning stays intact), MSRV/toolchain separately.
- **Automerge:** only `dev-dependencies` patch/minor, and only once the full CI including the ARM
  cross job is green. Crypto and transport crates (`snow`, `x25519-dalek`, `tokio`,
  `tokio-tungstenite`, `flate2`/`flac-codec`) never automerge — those PRs are reviewed by hand,
  because a silent protocol/crypto change would pass the tests we have.
- **Schedule:** weekly, Monday morning; no rebase storms (`rebaseWhen: "conflicted"`).
- **Labels:** `dependencies` plus `security` for advisory-driven PRs, so the dashboard is readable
  without opening it.

### Optional: Copilot code review (not part of the baseline)

GitHub Copilot code review is **not** included in Copilot Free, so the CI baseline must not depend on
it. When the maintainer has Copilot Pro or better, Copilot is added as a PR reviewer by hand — no
workflow, no gate. Two consequences worth knowing:

- Each review consumes AI credits (Lite ≈ $0.25, Balanced ≈ $1.50, Max ≈ $10 per review) plus
  Actions minutes, which are free for this public repository on standard runners.
- Copilot code review reads the repository's `AGENTS.md` automatically, so the hard rules written
  there (no plaintext path, never log pairing records, ARM build must stay green) apply to it as
  well. No separate `.github/copilot-instructions.md` is needed.

Free paths worth checking later: verified student/teacher accounts and the Copilot Pro grant for
maintainers of popular open-source projects.

## Tests

- `core`: message round trips, Noise handshake against test vectors (including the Sentinel PSK id),
  framing limits (65 535 bytes, fragmentation), clock filter.
- `client`: session state machine against a **hermetic fake server** (no network, no MA), reconnect
  and backoff, volume clamp reporting, sink backpressure.
- Pairing: PSK and CPace flows against a fake peer, including negative cases (wrong code, replay,
  wrong `psk_id`).
- The consumer's protocol tests move into the matching crates; the consumer keeps behaviour tests
  (volume, mute, platform integration).
- A manual run against a real Music Assistant is documented in [`docs/testing.md`](../testing.md),
  not run in CI.

## Integration into a downstream consumer

1. Stage 1: the consumer's protocol module consumes `syncspin-client` via a path dependency; the
   protocol code it contained is removed. Behaviour unchanged, `cargo test` green, deployed only
   after a green device test.
2. After the first release: switch to a git tag; the consumer's packaging build still runs on the
   host (network available), `Cargo.lock` stays pinned.
3. The consumer keeps: sink implementation (its audio pipeline), volume guard, platform
   integration, HTTP API/SSE, UI.

## Staged plan

| Stage | Content                                                                                                                                                                                                                       | Done when                                                                                                                                |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Repo skeleton, CI, design imported, spike "connects and plays 30 s"                                                                                                                                                           | CI green, spike findings folded in                                                                                                       |
| 1     | Extract `core`+`client` (player/controller/metadata, guest), consumer switched over, **spec backlog closed in stage 1b** (`group/update` as state source, `client/goodbye`, `server/error`, `activities`, fragmentation id 1) | consumer tests green, playback works through the crate, spec checklist for those five items green                                        |
| 2     | Pairing PSK + storage + records/re-handshake                                                                                                                                                                                  | pairing against a real MA succeeds, negative cases tested                                                                                |
| 3     | Roles `artwork`, `visualizer`, `color`, `source` behind feature flags                                                                                                                                                         | role coverage per the spec checklist                                                                                                     |
| 4     | CPace + static/dynamic code pairing                                                                                                                                                                                           | spec MUST/SHOULD met, draft test vectors green                                                                                           |
| 5     | **0.1 release** (client complete)                                                                                                                                                                                             | crates.io publish, docs.rs, example player runs for a stranger                                                                           |
| 6     | Server: listener, streams, roles, pairing server, **mDNS discovery both ways** (`_sendspin-server` and `_sendspin`), server-initiated connections                                                                             | **0.2**, a foreign client plays against our server and our client is discovered; the deviation is removed from `docs/spec-deviations.md` |

Versioning: `0.1` client, `0.2` client and server with full discovery, `1.0` once the API survives
two releases without a breaking change.

## Risks

| Risk                                          | Impact                                    | Mitigation                                                                    |
| --------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------- |
| CPace crates do not match draft-21            | stage 4 blocked                           | conformance check first, otherwise build on `x25519-dalek` with draft vectors |
| New dependencies break ARMv7/glibc 2.24       | the ARM target cannot use the crate       | ARM cross job in CI from stage 0                                              |
| Scope (client + all roles + pairing + server) | 0.1 arrives late, API ages untested       | staged releases; 0.1 = client complete                                        |
| Public API without users                      | permanent maintenance load without effect | success criterion: a stranger plays music with it (example + docs)            |
| Spec changes (technical preview)              | breaking points                           | spec pages pinned in `docs/spec/`, deviations documented                      |

## Spec backlog found during the builder check

The current consumer implementation never implemented these, and 0.1 is the point to decide them,
not stage 3:

- `group/update` — in the spec it is the authoritative source of `PlaybackState`, and the consumer
  derives state from stream events instead.
- `client/goodbye`, `server/error`, `activities` admissibility and rejection.
- Binary fragmentation (message id 1) — previously every Noise transport message was one WS frame.
- Pairing: version-0 pairing token export (`SP:` + `client_key ‖ pairing_psk`), the static-code
  operator gesture (pairing window) and the 20-round hold-back release (`client/pair-pending`).

## Open points

- CPace crate conformance, to be settled at the start of stage 4 (early check recommended). If the
  crates miss draft-21, the wrapper is built on `x25519-dalek` + SHA-512 with draft test vectors.
- **MA pairing support:** verified against the running 2.10.x; if MA lacks the flow, stage 2 is
  validated against the hermetic fake server and the MA gap is documented, not treated as a blocker.

## Decisions taken after the builder check

- **Playout timing:** the crate owns the time filter and the playout queue; it schedules each frame
  from its server timestamp and calls `Sink::write` at the frame's pre-port write time, so the sink
  writes on call instead of scheduling again. A sink whose output buffers before the port reports
  that delay through `pre_port_delay()`, and the client moves the write time back by it; the part
  beyond the audio port goes back to the server through `output_delay()`, which is also subtracted
  from every deadline. A frame more than 10 ms past its write time is dropped, never advanced, and
  `Event::LateAudio` reports the worst lateness and the count at most once per second. Audio that
  arrives before the filter has an estimate - it is ready after three accepted samples - is written
  with `Instant::now()`. `underruns()` still waits for a correction loop the session does not use,
  and with no drift correction the client does not claim the spec's ±1 ms steady-state window
  (`docs/spec-deviations.md` #20). `min_buffer_ms` is derived from arrival delay unless the host pins
  it, and `required_lead_time_ms` is at least the sink's pre-port delay: the client reports both.
  The server derives its start and seek lead from the largest reported `min_buffer_ms` +
  `output_delay_ms` among the ready members, anchored on the trigger's transmit time; what remains
  of `docs/spec-deviations.md` #17 is the live queue, the `required_lead_time_ms` hint and the
  15 ms lower bound.
- **0.1 measures against the spec, not MA:** the five spec mandates found in the check are part of
  stage 1, not a later stage. Where MA disagrees with the spec, the spec wins and MA compatibility is
  verified by test.
- **Pairing UX:** 0.1 ships the library API only (`pairing_token()`, `open_pairing_window()`,
  `release_holdback()`); code display and the remote-control gesture belong to the consumer's UI.
- **Repository:** the project's own public GitHub repository, name `syncspin`. The workspace ships
  three crates — `syncspin-core`, `syncspin-client`, `syncspin-server`; a facade crate named
  `syncspin` was considered and dropped, so no crate carries the bare project name. The repository is **public from
  day one**, which is what makes the Renovate App free and the Actions minutes unlimited.
- **MSRV:** 1.85, checked by a CI job.
- **Feature defaults:** `player`, `controller`, `metadata` are on; `artwork`, `visualizer`, `color`,
  `source` are off unless requested.
- **CPace fallback decided up front:** if the existing crates miss draft-21, we build the MCF/sid
  wrapper ourselves on `x25519-dalek` + SHA-512 with draft test vectors — stage 4 does not block on
  a third-party merge.
- **Reference peer in tests:** the hermetic fake server, not the live Music Assistant. MA runs stay
  a manual, documented check.
