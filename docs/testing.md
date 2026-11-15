# Testing

Two layers, deliberately unequal: the automated suites are hermetic and run in CI on every push,
and the end-to-end run against a real Music Assistant server is manual and documented here so it
stays repeatable.

## The hermetic suite

```sh
cargo test --workspace --locked
```

`--locked` is not optional: the workspace ships a `Cargo.lock`, and a test run that silently
resolves new versions tells you nothing about the code that will be released.

What the suite must never do:

- open a socket, or connect to anything outside the machine;
- start an audio process or touch an audio device;
- read a real identity, pairing record or configuration file;
- depend on a live Music Assistant server.

Nothing in the workspace listens on a port today: the tests drive the protocol in memory against an
independent `snow` peer built inside the test. When the session loop lands, its fake server may bind
`127.0.0.1:0` — an ephemeral loopback port that the suite owns and closes — and nothing else. A test
that needs a fixed port, a hostname or a device is wrong by construction.

### What each suite covers

| Suite                                           | Covers                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crates/syncspin-core/tests/noise_handshake.rs` | The Noise `KKpsk2` wire behaviour against a `snow` peer that is built independently of the code under test: initiator/responder roles, PSK location, the init exchange as prologue, the message-2 payload, the published Sentinel PSK id, a tampered prologue failing the handshake, transport-mode replay and size limits, and finishing the handshake too early. |
| `crates/syncspin-core/tests/messages.rs`        | Exact JSON keys of every message this revision implements, envelope round trips for the cleartext and encrypted phases, unknown types being ignorable while a malformed known type is an error, and binary framing: message ids, the exact fragmentation boundary, reassembly rejecting missing, misplaced and oversized fragments.                                |
| `crates/syncspin-core/tests/clock.rs`           | Clock-filter convergence under jitter, the readiness threshold, an outlier not moving the estimate, the local/server timestamp round trip and the reset.                                                                                                                                                                                                           |
| In-module unit tests (`crates/*/src`)           | Small invariants next to the code they guard, such as the workspace version and the message length helpers.                                                                                                                                                                                                                                                        |

A fake server, not a live Music Assistant, is the reference peer for anything that needs a peer.

## MSRV

The workspace declares `rust-version = "1.85"`, and `rust-toolchain.toml` pins the `stable` channel,
which wins over any toolchain chosen for the shell. The MSRV run therefore has to override the file:

```sh
RUSTUP_TOOLCHAIN=1.85.0 cargo test --workspace --locked
```

Without `RUSTUP_TOOLCHAIN` this would silently test the current stable and pass while 1.85 is
broken. The `msrv` CI job does the same thing, and prints `rustc --version` first so the log shows
which compiler ran. A dependency that demands a newer compiler is pinned or replaced; raising the
MSRV is a deliberate, documented decision, not a side effect of an update.

## ARMv7 compile guard

The library has to build for 32-bit ARM with the old glibc that the oldest supported consumer
target ships. That is cheap to check and expensive to discover late:

```sh
rustup target add armv7-unknown-linux-gnueabihf
cargo check -p syncspin-core -p syncspin-client \
  --target armv7-unknown-linux-gnueabihf --locked
```

This is a compile guard, not a release build: it catches a dependency that does not compile for the
target, which is the failure that actually happens. Once the crates link real dependencies, use the
full cross build so the glibc baseline is exercised:

```sh
cargo zigbuild --target armv7-unknown-linux-gnueabihf --no-default-features --features player,controller
```

`zigbuild` needs `cargo-zigbuild` and a `zig` binary. The `wss` feature pulls a TLS backend that
does not build for this target; it is an opt-in feature and stays out of the ARM job and out of
`--all-features`.

## Manual end-to-end run against a real Music Assistant server

Not part of CI: it needs a server, a shared audio output and ears. Run it before a release and after
any change to the handshake, the session loop or the sink contract.

The workspace has no runnable client binary yet — the example player is still planned. Until it
exists, run these steps with any build that embeds `syncspin-client`; the sequence is the same.

### What to start

1. A Music Assistant server with its Sendspin endpoint enabled. Note the address and path it
   listens on (`ws://<server>:8927/sendspin` is the convention) and, if the server only grants
   playback to paired clients, whatever setting admits an unpaired client for the run. A 0.1 client
   has no pairing yet, so a server that insists on a paired client will refuse or park the session —
   that is a configuration result, not a library failure.
2. The client, pointed at that URL, with a storage directory of its own. The first run generates a
   keypair there; keep it for the whole session, because a new keypair is a new player identity on
   the server.
3. Keep the server's log and the client's output visible side by side; the interesting failures are
   visible in both.

### What to observe

- **Connection.** One TCP connection to the endpoint, a cleartext `client/init` / `server/init`
  exchange, then the Noise handshake with no AEAD failure. The socket stays up; a handshake that
  keeps reconnecting points at a prologue or PSK mismatch, not at the network.
- **Session.** `server/hello`, `client/hello` with the offered roles, and a `server/activate` whose
  `activities` include `playback` and whose `active_roles` include `player@v1`.
- **`stream/start`.** The announced format (codec, sample rate, channels, bit depth) matches what
  the sink is opened with. A format change mid-stream closes and reopens the sink instead of
  writing mismatched audio.
- **Audio at the sink.** Audio actually reaches the output, at the right rate and without gaps: the
  sink's underrun counter stays at zero after the first buffer, and the first frames are not
  swallowed. Silence with a healthy connection usually means a playout deadline in the past.
- **State.** Title, artist and playback state in the client match what the server is playing, and a
  pause/resume or track skip from the server is reflected without reconnecting.
- **Volume.** A volume change from the server reaches the sink and the applied value is reported
  back — the reported value, not the requested one.
- **Sync.** With two clients in the same group, both stay audibly aligned; drift over several
  minutes points at the clock filter or at a sink that does not report latency.
- **Recovery.** Stop the server: the client reports a disconnect and retries with backoff. Start it
  again: the client reconnects and plays without a restart.

### Cleaning up

- Stop playback in the server first, then stop the client, so the server sees an ordinary
  disconnect rather than a timeout.
- If the run created a player the server should not keep, remove it from the server's player list;
  a deleted identity leaves a stale entry behind, and a kept one is a player nobody uses.
- Restore anything shared that the run changed: output volume, mute, the active group. Leave
  hardware and other people's sessions as you found them.
- Delete a throwaway storage directory only after the stale player entry is gone.
- Confirm nothing is left connected: `ss -tn | grep 8927` should be empty.
- Never paste a pairing token, a keypair or a pairing record into a log excerpt, an issue or a
  commit. Redact before sharing.
