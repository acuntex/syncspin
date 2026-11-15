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

| Suite                                                  | Covers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/syncspin-core/tests/noise_handshake.rs`        | The Noise `KKpsk2` wire behaviour against a `snow` peer that is built independently of the code under test: initiator/responder roles, PSK location, the init exchange as prologue, the message-2 payload, the published Sentinel PSK id, a tampered prologue failing the handshake, the transport nonce advancing per message (equal plaintexts differ on the wire), the oversize-plaintext limit, and finishing the handshake too early.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-core/tests/messages.rs`               | Exact JSON keys of every message this revision implements, envelope round trips for the cleartext and encrypted phases, unknown types being ignorable while a malformed known type is an error, and binary framing: message ids, the exact fragmentation boundary, reassembly rejecting missing, misplaced and oversized fragments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `crates/syncspin-core/tests/clock.rs`                  | Clock-filter convergence under jitter, the readiness threshold, an outlier not moving the estimate, the local/server timestamp round trip and the reset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-core/tests/pairing_token.rs`          | The pairing token against both reference vectors of the specification: version 0 from a key and a PSK, version 1 from the 24-byte code, the `2`→`9` transliteration, the lenient decode (whitespace, case, missing `SP:`), the rejections (unknown version, short payload, body outside the alphabet, a length base32 cannot encode), extension bytes ignored, and a round trip over arbitrary payloads.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-core/tests/pake_vectors.rs`           | The CPace layer against the draft's own vectors: `prepend_len` and `lv_cat` (§A.1.4, §A.3.5), the message strings (§A.3.7), the generator, the public shares, both transcript hashes, the 64-byte ISK and the MCF tags (§B.1.2–§B.1.7), the low-order and non-canonical rejections (§B.1.10), and the Elligator 2 adapter against RFC 9380 vectors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `crates/syncspin-core/tests/pairing_wrap.rs`           | The wrapping under the CPace output: `K_wrap` for both labels, the sealed bytes for a fixed input, `sid` entering raw at its real length, a wrong label, `sid` or key deriving a different key, and a tampered ciphertext or tag failing to open.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `crates/syncspin-core/tests/pairing_code.rs`           | The dynamic pairing code: the derivation from fixed `h` and nonces, the six digits including a leading-zero case, the version-1 token, and the commitment.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-core/tests/properties.rs`             | Property tests for the parts with an input space rather than a handful of cases: fragmentation and reassembly of arbitrary bytes, reassembly rejecting missing, misplaced and oversized fragments, the PSK id derivation, and envelope parsing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `crates/syncspin-client/tests/session_guest.rs`        | The guest session end to end: connect and report an encrypted connection, `stream/start` opening the sink with the announced format, the stream lifecycle reaching the host as events before the sink flush (`stream/end`, a seek with its timestamp and a removed player role), audio chunks reaching the sink with their length and a playout deadline once the clock is ready, a volume command and controller state, fragmented audio reassembly, a wrong `psk_id` falling back to the Sentinel key, malformed PSK metadata closing without a second handshake message, the device description reaching `client/hello`, the playback speed in the track event, unknown types and malformed control messages ignored while a malformed audio header stays a protocol error, a server that never starts the handshake being refused, transient failures leaving the connection reconnecting, and a sink failure ending the connection without a retry delay. |
| `crates/syncspin-client/tests/handshake.rs`            | The handshake refusals: a cleartext message that is not `server/init` or Noise message 1, an unsupported version, a close before or after the handshake, a first encrypted message that is not `server/hello`, a second that is not `server/activate`, cleartext text after message 2, an empty plaintext during the handshake, and binary frames or messages skipped at their point. No test here plays audio.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `crates/syncspin-client/tests/fake_server.rs`          | The harness the session suite runs against: a loopback WebSocket listener that plays the Noise initiator with `snow`, serves the configured number of connections and reports what it observed on each of them - Noise message 2 and whether it authenticated, the `client/hello`, every `client/state` report, every `client/command`, the `client/time` requests it answered and each close. It records no audio: the suites judge audio through their own recording sinks. It carries no tests of its own.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crates/syncspin-client/tests/volume.rs`               | Playback controls and the volume limit end to end: `play`, `pause`, `next` and `previous` reaching the server as `client/command`, the initial `client/state` advertising `volume` and `mute`, a request above 40 raised by at most 20 and reported as applied, requests at or below 40 and lower requests applied unchanged, a level above the protocol range capped at 100, a mute that keeps the level, a reported level that bypasses the limit while a report above 100 is refused, the limit as a pure function, a configurable threshold-floor policy, the requested and applied level in one event, a command for an inactive role or an unadvertised command being refused, and the configured level and mute reaching the first report.                                                                                                                                                                                                              |
| `crates/syncspin-client/tests/reconnect.rs`            | The reconnect policy: the exponential sequence of `next_backoff` (1 s, 2 s, 4 s, and so on up to the cap) and its reset after a session that connected, the delay `Event::Disconnected` reports, a dropped session reconnecting on its own with the sink flushed before the next connection and no stale format reopened, the retry delay actually awaited, the level and mute state carried across the drop, the roles of the previous connection seeding an activation that omits them, and dropping the handle ending the event stream.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-client/tests/storage.rs`              | The `Storage` trait is object-safe, and the crate's record rule: five records with oldest-first eviction, the live record never evicted (even when it is the oldest or the only one), a pairing never fails for lack of space, the record being stored is never the victim, a re-stored record moves to the end, a record without a server is refused, and removal keeps the order. With `storage-file`: the JSON backend round-trips five records in order, applies the crate rule, is created `0600`, refuses a shape it does not know and leaves it alone, echoes no key in an error, formats without its contents, reads a larger host store without trimming it, and leaves no temporary file.                                                                                                                                                                                                                                                            |
| `crates/syncspin-client/tests/unpair.rs`               | The record lifecycle from the server's side: `server/unpair` removes the record, reports `Event::Unpaired` and ends the connection; an unpaired session ignores the message; a `psk_id` the client does not hold is reported once per connection as a credential mismatch; a plain Sentinel handshake reports nothing; and an evicted record is a mismatch on the next connection.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `crates/syncspin-client/tests/pairing_psk.rs`          | The Pairing PSK flow end to end: no store means no advertised method, a store draws exactly one key, the method is advertised in `client/hello`, the flow stores one `LongTerm` record and pairs the next connection, a Sentinel-keyed connection is aborted as unsupported, a silent server times out, a cancelling activation persists nothing, a server abort carries its reason, a refused record and an unreadable store end the session, `server/activate` with `pairing` but no parameters is a protocol error, a malformed pair message closes, audio survives the in-band re-handshake, a pairing after it uses index one, a re-handshake to an unknown key closes, and a message under the previous keys is discarded.                                                                                                                                                                                                                               |
| `crates/syncspin-client/tests/pairing_code_static.rs`  | The static code flow: a gesture without a connection is an error, a window runs one CPace round and persists the key the fake server unwraps, `client/pair-pending` carries the host's text while no window is open, a wrong server code aborts as a mismatch, the fifth failed confirmation closes the window, `server/pair-auth` without an attempt is a sequence violation, and an activation without a configured code is aborted as unsupported.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `crates/syncspin-client/tests/pairing_code_dynamic.rs` | The dynamic code flow: the derivation matches a pinned vector, digits and the version-1 QR token reach the host, the commitment opens to the revealed nonce (the fake server checks it), a failed `server_kc` retries with the same code and the same deadline, the twentieth round aborts as a mismatch, the round limit holds the next attempt back until `release_holdback`, abandoned rounds count toward the limit and attempts that never reach a round do not.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `examples/player-pipe` (in-module tests)               | The example's command line: the default name, identity file and pairing store, `--flag=value` parsing, `--help` without a server, the token mode without a server and its refusal of one, the static-code and window pair (both flags required, eight digits), a bad code never echoed, the usage text naming the flags this build has, and rejection of incomplete, unknown, empty, dashed and over-long values as well as a TLS or non-`ws` server address.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| In-module unit tests (`crates/*/src`)                  | The per-crate `version()` test, the prologue parsing and identity-redaction tests beside `noise.rs`, and the PSK-selection, endpoint and codec-name tests beside the client code.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

A fake server, not a live Music Assistant, is the reference peer for anything that needs a peer.

### Pairing

The pairing suites are split by flow. Feature unification decides what a run covers: `storage-file`
is off in `syncspin-client` but on in `player-pipe`, so a workspace run enables it for the client and
runs the file backend's tests; `pairing-code` is off everywhere unless requested.

```sh
cargo test --workspace --locked
cargo test --workspace --features pairing-code,storage-file --locked
cargo test -p syncspin-core -p syncspin-client --locked
```

The first runs the PSK, storage and unpair suites, the second adds the code flows, and the third runs
the library crates with their own defaults - the set a consumer that enables nothing gets.

- `pairing_psk.rs` is the mandatory flow: advertisement, one drawn key, the record, the abort and
  timeout paths, and the re-handshake that carries the stream across a key change.
- `storage.rs` is the record rule on top of an arbitrary `Storage` and the JSON backend behind
  `storage-file`. The rule is the crate's, so the trait-level tests run without the feature.
- `unpair.rs` is the server dropping its side: `server/unpair`, the credential-mismatch signal and
  the eviction case that looks the same from the handshake.
- `pairing_code_static.rs` and `pairing_code_dynamic.rs` run the two code flows against the fake
  server, which plays the CPace initiator and unwraps the key. The dynamic derivation is pinned to a
  vector computed from the spec's formula; the specification publishes none.

What the suites do not cover:

- the operator order "open the window first, let the server activate pairing afterwards" - for a
  _first_ activation neither the tests nor `player-pipe --open-window` reach it: the connection
  reports `Connected` and handles the activation before the host's gesture arrives, so both send
  `client/pair-pending` first. The library supports a window opened before a _later_ activation, and
  that path is untested.
- a live server. Everything above runs against the fake server; see the manual pairing run below.
- external review. The CPace layer has draft vectors and hermetic tests, not a review
  ([`spec-deviations.md`](spec-deviations.md), entry 5).

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
cargo check -p syncspin-core -p syncspin-client --all-features \
  --target armv7-unknown-linux-gnueabihf --locked
```

`--all-features` is what makes the guard cover the pairing stack: `elligator2`, `hmac` and the
ChaCha20-Poly1305 wrapping are optional dependencies behind `pairing-code`, and without the flag they
are not cross-compiled at all. The `arm` job runs exactly this command.

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
   on **unpaired access** (`unpaired_access`) in that provider's settings for the run. The guest
   session announces `unpaired_access` with `enabled: true`; without the server-side setting an
   unpaired session is kept out of playback, which is a configuration result, not a library failure.
   Whether the provider implements the pairing activity is not assumed here: if it does not, the
   pairing checklist below cannot run.
2. The example player, pointed at that address:

   ```sh
   cargo run -p player-pipe -- --server <server>:8927 | aplay -f S16_LE -r 48000 -c 2
   ```

   Replace `aplay` with any consumer of the announced raw format.

3. The first run writes `./identity.key` and `./pairing.json` in 0600 mode and prints the public key
   the server sees. Later runs reuse both, because a fresh keypair makes the server treat the player
   as a new device. The library itself never writes the identity; the example does. `--identity
<path>` and `--pairing-store <path>` store them elsewhere.
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

### Pairing (performed 2026-11-16)

**Run against a real Music Assistant server with the Sendspin provider enabled.** Observed:

1. The client connected as an unpaired guest, completed the Noise handshake and received
   `server/activate` with the controller state.
2. The operator entered the token from `player-pipe --pairing-token` in the provider after starting
   the client. The client printed `paired: record stored for server <id>`, which means the server's
   `server/pair-finalize` arrived — the server had persisted its half.
3. `./pairing.json` then held one long-term record (`category: lt`) beside the pairing PSK.
4. A second start, same identity and store, connected without a second pairing and without a
   credential-mismatch event, so the stored record was the one the handshake used.

Not covered by that run: the server-side UI state after pairing, unpairing through the server, and
both code flows — the example offers only the static one and neither has met a real server.

Steps, for the next run:

1. Print the token and enter it in the server:

   ```sh
   cargo run -p player-pipe -- --pairing-token
   ```

   One `SP:` line goes to stdout; the first run draws the pairing PSK and stores it in
   `./pairing.json`. The token is a credential: do not paste it into a log, an issue or this
   document.

2. Start the player against the server and let it play. Expected: `client/hello` advertises
   `pairing_psk`; the server starts the pairing activity; the client prints
   `paired: record stored for server <id>`. The server normally re-handshakes the live connection to
   the new long-term key, and playback must neither stop nor reopen the stream across that
   handshake.

3. Restart the player. Expected: the handshake is keyed by the stored record, no second pairing is
   requested, and playback starts without the token being entered again.

4. Unpair the client in the server. Expected: `unpaired: ...`, the record disappears from
   `./pairing.json`, and the connection ends. The next start is a guest; a server that still holds
   its half reports `pairing required by ...: CredentialMismatch`.

5. The example offers only the static code flow. It has no display and no speaker, so it advertises
   neither an emission format nor an out-channel, and a server that activates
   `dynamic_pairing_code` is answered with `pair/abort`. For a server that implements the static
   flow, rebuild with `--features pairing-code`:

   ```sh
   cargo run -p player-pipe --features pairing-code -- --server <server>:8927 \
     --static-code <8 digits> --open-window
   ```

   The operator configures the same eight-digit code on both sides. This flow has not run against a
   real server either.

If a step fails, the client's stderr names the event or the abort reason and the server log shows
what it sent. Record both before filing an issue, with the token and all key material removed.

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
