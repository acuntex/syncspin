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

- open a socket other than an ephemeral loopback listener the test owns, or connect to anything
  outside the machine;
- start an audio process or touch an audio device;
- read a real identity, pairing record or configuration file;
- depend on a live Music Assistant server.

Ports: the client session suite binds one ephemeral loopback port per test (`127.0.0.1:0`, owned and
closed by the test, never a fixed one); the core suites open no socket at all. A test that needs a
fixed port, a hostname or a device is wrong by construction.

### What each suite covers

| Suite                                           | Covers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/syncspin-core/tests/noise_handshake.rs` | The Noise `KKpsk2` wire behaviour against a `snow` peer that is built independently of the code under test: initiator/responder roles, PSK location, the init exchange as prologue, the message-2 payload, the published Sentinel PSK id, a tampered prologue failing the handshake, the transport nonce advancing per message (equal plaintexts differ on the wire), the oversize-plaintext limit, and finishing the handshake too early.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-core/tests/messages.rs`        | Exact JSON keys of every message this revision implements, envelope round trips for the cleartext and encrypted phases, unknown types being ignorable while a malformed known type is an error, and binary framing: message ids, the exact fragmentation boundary, reassembly rejecting missing, misplaced and oversized fragments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `crates/syncspin-core/tests/clock.rs`           | Clock-filter convergence under jitter, the readiness threshold, an outlier not moving the estimate, the local/server timestamp round trip and the reset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-client/tests/session_guest.rs` | The guest session end to end: connect and report an encrypted connection, `stream/start` opening the sink with the announced format, the stream lifecycle reaching the host as events before the sink flush (`stream/end`, a seek with its timestamp and a removed player role), audio chunks reaching the sink with their length and a playout deadline once the clock is ready, a volume command and controller state, fragmented audio reassembly, a wrong `psk_id` falling back to the Sentinel key, malformed PSK metadata closing without a second handshake message, the device description reaching `client/hello`, the playback speed in the track event, unknown types and malformed control messages ignored while a malformed audio header stays a protocol error, a server that never starts the handshake being refused, transient failures leaving the connection reconnecting, and a sink failure ending the connection without a retry delay. |
| `crates/syncspin-client/tests/fake_server.rs`   | The harness the session suite runs against: a loopback WebSocket listener that plays the Noise initiator with `snow`, serves the configured number of connections and reports what it observed on each of them - Noise message 2 and whether it authenticated, the `client/hello`, every `client/state` report, every `client/command`, the `client/time` requests it answered and each close. It records no audio: the suites judge audio through their own recording sinks. It carries no tests of its own.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crates/syncspin-client/tests/volume.rs`        | Playback controls and the volume limit end to end: `play`, `pause`, `next` and `previous` reaching the server as `client/command`, the initial `client/state` advertising `volume` and `mute`, a request above 40 raised by at most 20 and reported as applied, requests at or below 40 and lower requests applied unchanged, a level above the protocol range capped at 100, a mute that keeps the level, a reported level that bypasses the limit while a report above 100 is refused, the limit as a pure function, a configurable threshold-floor policy, the requested and applied level in one event, a command for an inactive role or an unadvertised command being refused, and the configured level and mute reaching the first report.                                                                                                                                                                                                              |
| `crates/syncspin-client/tests/reconnect.rs`     | The reconnect policy: the exponential sequence of `next_backoff` (1 s, 2 s, 4 s, and so on up to the cap) and its reset after a session that connected, the delay `Event::Disconnected` reports, a dropped session reconnecting on its own with the sink flushed before the next connection and no stale format reopened, the retry delay actually awaited, the level and mute state carried across the drop, the roles of the previous connection seeding an activation that omits them, and dropping the handle ending the event stream.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `examples/player-pipe` (in-module tests)        | The example's command line: the default name and identity file, `--flag=value` parsing, `--help` without a server, and rejection of incomplete, unknown, empty, dashed and over-long values as well as a TLS or non-`ws` server address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| In-module unit tests (`crates/*/src`)           | The per-crate `version()` test, the prologue parsing and identity-redaction tests beside `noise.rs`, and the PSK-selection, endpoint and codec-name tests beside the client code.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

A fake server, not a live Music Assistant, is the reference peer for anything that needs a peer.

## MSRV

The workspace declares `rust-version = "1.85"`, and `rust-toolchain.toml` pins the `stable` channel,
which wins over any toolchain chosen for the shell. A machine with only `stable` installed needs the
toolchain first:

```sh
rustup toolchain install 1.85.0

RUSTUP_TOOLCHAIN=1.85.0 cargo test --workspace --locked
```

Without the install the second line fails to resolve the toolchain; without `RUSTUP_TOOLCHAIN` it
would silently test the current stable and pass while 1.85 is broken. The `msrv` CI job does the same
thing, and prints `rustc --version` first so the log shows which compiler ran. A dependency that
demands a newer compiler is pinned or replaced; raising the MSRV is a deliberate, documented
decision, not a side effect of an update.

## ARMv7 compile guard

The library has to build for 32-bit ARM with the old glibc that the oldest supported consumer
target ships. That is cheap to check and expensive to discover late:

```sh
rustup target add armv7-unknown-linux-gnueabihf
cargo check -p syncspin-core -p syncspin-client \
  --target armv7-unknown-linux-gnueabihf --locked
```

This is a compile guard, not a release build: it catches a dependency that does not compile for the
target, which is the failure that actually happens. Once the `player`/`controller` features exist,
use the full cross build so the glibc baseline is exercised:

```sh
cargo zigbuild --target armv7-unknown-linux-gnueabihf --no-default-features --features player,controller
```

`zigbuild` needs `cargo-zigbuild` and a `zig` binary. There is no TLS feature in this revision: a
`wss://` address is rejected when the client is configured, so no TLS backend can reach this target.

## Manual end-to-end run against a real Music Assistant server

Not part of CI: it needs a server, a shared audio output and ears. Run it before a release and after
any change to the handshake, the session loop or the sink contract.

`examples/player-pipe` is a runnable client: it implements `Sink`, writes PCM to stdout and keeps
its identity in a file. This section is the acceptance checklist for that player; a consumer build
that replaces the sink is checked the same way. Read each item as an acceptance criterion and tick
it against the running server.

### What to start

1. A Music Assistant server with the **Sendspin provider** enabled — the server side of the protocol.
   Note the address and path it listens on (`ws://<server>:8927/sendspin` is the convention) and turn
   on **unpaired access** (`unpaired_access`) in that provider's settings for the run: a 0.1 client
   has no pairing yet, and the guest session announces `unpaired_access` with `enabled: true`. Without
   the server-side setting the session is kept out of playback, which is a configuration result, not
   a library failure.
2. The example player, pointed at that address:

   ```sh
   cargo run -p player-pipe -- --server <server>:8927 | aplay -f S16_LE -r 48000 -c 2
   ```

   Replace `aplay` with any consumer of the announced raw format.

3. The first run writes `./identity.key` in 0600 mode and prints the public key the server sees.
   Later runs reuse that file, because a fresh keypair makes the server treat the player as a new
   device. The library itself never writes it; the example does. `--identity <path>` stores it
   elsewhere.
4. Keep the server's log and the client's output visible side by side; the interesting failures are
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
- **Audio at the sink.** Audio actually reaches the output, at the right rate and without audible
  gaps, and the first frames are not swallowed. The example's sink does not count underruns
  (`Sink::underruns` keeps its default of zero), so a zero reading proves nothing there; judge gaps
  by ear. Silence with a healthy connection usually means a playout deadline in the past.
- **State.** Title and artist arrive from `server/state.metadata`, and volume, mute and the supported
  commands from `server/state.controller`. The group's `playback_state` and `group_id` travel in
  `group/update`, which the library does not handle yet, so playing/stopped is not observable — see
  [`spec-deviations.md`](spec-deviations.md).
- **Volume.** A volume command from the server arrives as `Event::Volume`, which the player prints to
  stderr, and the session has already applied it: the request runs through
  `ClientConfig::volume_policy`, and the level that came out of it is what the next `client/state`
  reports, so the server sees the applied level and not the one it asked for. The event carries both
  numbers when they differ, and a mute leaves the level untouched. The host only moves its own output
  device: `player-pipe` writes PCM to stdout and has nothing to move, and a build that does move one
  calls `ControlHandle::report_volume` with the level the device actually reached, so the reported
  state matches what is audible.
- **Sync.** With two clients in the same group, both stay audibly aligned; drift over several minutes
  points at the clock filter or at a sink that does not report latency. `PipeSink::latency` returns
  `None`, so with the example only the audible check applies; a build that reports latency can also
  compare it with the playout deadlines.
- **Recovery.** Stop the server: the attempt ends with `Event::Disconnected`, whose `retry_in` is the
  delay the crate waits before it dials again — two seconds after an attempt that never connected,
  doubling with every further failed attempt up to `ClientConfig::max_backoff`, and one second after
  a session that connected. The crate owns that loop and reconnects with the same sink, identity,
  level and mute state, so there is nothing for the host to schedule. Start the server again and
  playback resumes without a restart; only a failed sink, a dropped event stream or a dropped handle
  ends the loop.

### Cleaning up

- Stop playback in the server first, then stop the client, so the server sees an ordinary
  disconnect rather than a timeout.
- If the run created a player the server should not keep, remove it from the server's player list;
  a deleted identity leaves a stale entry behind, and a kept one is a player nobody uses.
- Restore anything shared that the run changed: output volume, mute, the active group. Leave
  hardware and other people's sessions as you found them.
- Delete a throwaway keypair only after the stale player entry is gone.
- Confirm nothing is left connected: `ss -tn | grep 8927` should be empty.
- Never paste a pairing token, a keypair or a pairing record into a log excerpt, an issue or a
  commit. Redact before sharing.
