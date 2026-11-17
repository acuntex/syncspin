# Testing

Two layers, deliberately unequal: the automated suites are hermetic and run in CI on every push,
and the end-to-end runs against a real Music Assistant server and between two machines are manual
and documented here so they stay repeatable.

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

Ports: the client and server suites bind one ephemeral loopback port per test (`127.0.0.1:0`, owned
and closed by the test, never a fixed one); the core suites open no socket at all. The server's
discovery suite uses a fake backend, so no multicast socket is opened and no mDNS packet leaves the
process. Identities are generated per test and pairing records live in an in-memory store: a suite
never reads an identity or a record from disk. A test that needs a fixed port, a hostname or a device
is wrong by construction.

### What each suite covers

| Suite                                                   | Covers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/syncspin-core/tests/noise_handshake.rs`         | The Noise `KKpsk2` wire behaviour against a `snow` peer that is built independently of the code under test: initiator/responder roles, PSK location, the init exchange as prologue, the message-2 payload, the published Sentinel PSK id, a tampered prologue failing the handshake, the transport nonce advancing per message (equal plaintexts differ on the wire), the oversize-plaintext limit, and finishing the handshake too early.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `crates/syncspin-core/tests/messages.rs`                | Exact JSON keys of every message this revision implements, envelope round trips for the cleartext and encrypted phases, unknown types being ignorable while a malformed known type is an error, and binary framing: message ids, the exact fragmentation boundary, reassembly rejecting missing, misplaced and oversized fragments.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-core/tests/clock.rs`                   | Clock-filter convergence under jitter, the readiness threshold, an outlier not moving the estimate, the local/server timestamp round trip and the reset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crates/syncspin-core/tests/pairing_token.rs`           | The pairing token against both reference vectors of the specification: version 0 from a key and a PSK, version 1 from the 24-byte code, the `2`→`9` transliteration, the lenient decode (whitespace, case, missing `SP:`), the rejections (unknown version, short payload, body outside the alphabet, a length base32 cannot encode), extension bytes ignored, and a round trip over arbitrary payloads.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crates/syncspin-core/tests/pake_vectors.rs`            | The CPace layer against the draft's own vectors: `prepend_len` and `lv_cat` (§A.1.4, §A.3.5), the message strings (§A.3.7), the generator, the public shares, both transcript hashes, the 64-byte ISK and the MCF tags (§B.1.2–§B.1.7), the low-order and non-canonical rejections (§B.1.10), and the Elligator 2 adapter against the five RFC 9380 §J.4.2 vectors, `map(u) == map(p − u)` and the reduction of `p … 2^255−1`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `crates/syncspin-core/tests/pairing_wrap.rs`            | The wrapping under the CPace output: `K_wrap` for both labels, the sealed bytes for a fixed input, `sid` entering raw at its real length, a wrong label, `sid` or key deriving a different key, and a tampered ciphertext or tag failing to open.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `crates/syncspin-core/tests/pairing_code.rs`            | The dynamic pairing code: the derivation from fixed `h` and nonces, the six digits including a leading-zero case, the version-1 token, and the commitment.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `crates/syncspin-core/tests/properties.rs`              | Property tests for the parts with an input space rather than a handful of cases: fragmentation and reassembly of arbitrary bytes, reassembly rejecting missing, misplaced and oversized fragments, the PSK id derivation, and envelope parsing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `crates/syncspin-client/tests/session_guest.rs`         | The guest session end to end: connect and report an encrypted connection, `stream/start` opening the sink with the announced format, the stream lifecycle reaching the host as events before the sink discards or flushes (`stream/end`, a seek with its timestamp and a removed player role), audio chunks reaching the sink with their length and a playout deadline once the clock is ready, a volume command and controller state, a controller `seek` and `seek_relative` reaching the server with their position or offset and refused when the server does not advertise them, fragmented audio reassembly, a wrong `psk_id` falling back to the Sentinel key, malformed PSK metadata closing without a second handshake message, the device description reaching `client/hello`, the playback speed in the track event, unknown types and malformed control messages ignored while a malformed audio header stays a protocol error, a server that never starts the handshake being refused, transient failures leaving the connection reconnecting, the unpaired-access switch advertised in `client/hello` and the refusal reason it picks for each refused activation (`pairing_required` for a guest refused playback, `unauthorized` for an unoffered role, an unknown or repeated activity or an unadmitted pairing method), and a sink failure ending the connection without a retry delay. |
| `crates/syncspin-client/tests/handshake.rs`             | The handshake refusals: a cleartext message that is not `server/init` or Noise message 1, an unsupported version, a close before or after the handshake, a first encrypted message that is not `server/hello`, a second that is not `server/activate`, cleartext text after message 2, an empty plaintext during the handshake, and binary frames or messages skipped at their point. No test here plays audio.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `crates/syncspin-client/tests/fake_server.rs`           | The harness the session suite runs against: a loopback WebSocket listener that plays the Noise initiator with `snow`, serves the configured number of connections and reports what it observed on each of them - Noise message 2 and whether it authenticated, the `client/hello`, every `client/state` report, every `client/command`, the `client/time` requests it answered, every WebSocket ping and pong, every `client/goodbye` with its reason, and each close; `answer_pings` chooses between answering a ping and letting the link go silent with the socket still open. It records no audio: the suites judge audio through their own recording sinks. It carries no tests of its own.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `crates/syncspin-client/tests/volume.rs`                | Playback controls and the volume limit end to end: `play`, `pause`, `next` and `previous` reaching the server as `client/command`, the initial `client/state` advertising `volume` and `mute`, a request above 40 raised by at most 20 and reported as applied, requests at or below 40 and lower requests applied unchanged, a level above the protocol range capped at 100, a mute that keeps the level, a reported level that bypasses the limit while a report above 100 is refused, the limit as a pure function, a configurable threshold-floor policy, the requested and applied level in one event, a command for an inactive role or an unadvertised command being refused, and the configured level and mute reaching the first report.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `crates/syncspin-client/tests/reconnect.rs`             | The reconnect policy: the exponential sequence of `next_backoff` (1 s, 2 s, 4 s, and so on up to the cap) and its reset after a session that connected, the delay `Event::Disconnected` reports, a dropped session reconnecting on its own with the sink flushed before the next connection and no stale format reopened, the retry delay actually awaited, the level and mute state carried across the drop, the roles of the previous connection seeding an activation that omits them, and dropping the handle ending the event stream.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `crates/syncspin-client/tests/keepalive.rs`             | The WebSocket keepalive with the shipped 15 s and 10 s windows, measured on a paused clock: an idle session that activates no role sends exactly one ping and stays connected when the harness pongs, a ping the harness leaves unanswered ends the session as a `Disconnected` with the initial retry delay and the next connection re-registers, frames arriving every 10 s never produce a ping, and a server-initiated ping is still answered with its payload.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-client/tests/storage.rs`               | The `Storage` trait is object-safe, and the crate's record rule: five records with oldest-first eviction, the live record never evicted (even when it is the oldest or the only one), a pairing never fails for lack of space, the record being stored is never the victim, a re-stored record moves to the end, a record without a server is refused, and removal keeps the order. With `storage-file`: the JSON backend round-trips five records in order, applies the crate rule, is created `0600`, refuses a shape it does not know and leaves it alone, echoes no key in an error, formats without its contents, reads a larger host store without trimming it, and leaves no temporary file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-client/tests/unpair.rs`                | The record lifecycle from the server's side: `server/unpair` removes the record, reports `Event::Unpaired` and ends the connection; an unpaired session ignores the message; a `psk_id` the client does not hold is reported once per connection as a credential mismatch; a plain Sentinel handshake reports nothing; and an evicted record is a mismatch on the next connection.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `crates/syncspin-client/tests/goodbye.rs`               | `client/goodbye` on the closes that have a reason: `server/unpair` sends `unpaired` before the close, a dropped handle sends `shutdown`, `ClientHandle::close` sends the reason the host chose, and a protocol error ends the connection without one.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-client/tests/pairing_token_control.rs` | `ControlHandle::pairing_token()`: the version-0 token decodes to the identity's public key and the stored pairing PSK, a client without a store has none, the value survives a second call and a reconnect, and `Debug` never prints it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crates/syncspin-client/tests/pairing_psk.rs`           | The Pairing PSK flow end to end: no store means no advertised method, a store draws exactly one key, the method is advertised in `client/hello`, the flow stores one `LongTerm` record and pairs the next connection, a Sentinel-keyed connection is aborted as unsupported, a silent server times out, a cancelling activation persists nothing, a server abort carries its reason, a refused record and an unreadable store end the session, `server/activate` with `pairing` but no parameters is a protocol error, a malformed pair message closes, audio survives the in-band re-handshake, a re-handshake to the pairing PSK clearing the carried player role when the new keys cannot carry playback, a pairing after it uses index one, a re-handshake to an unknown key closes, and a message under the previous keys is discarded.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `crates/syncspin-client/tests/pairing_code_static.rs`   | The static code flow: a gesture without a connection is an error, a window runs one CPace round and persists the key the fake server unwraps, `client/pair-pending` carries the host's text while no window is open, a wrong server code aborts as a mismatch, the fifth failed confirmation closes the window, `server/pair-auth` without an attempt is a sequence violation, and an activation without a configured code is aborted as unsupported.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-client/tests/pairing_code_dynamic.rs`  | The dynamic code flow: the derivation matches a pinned vector, digits and the version-1 QR token reach the host, the commitment opens to the revealed nonce (the fake server checks it), a failed `server_kc` retries with the same code and the same deadline, the twentieth round aborts as a mismatch, the round limit holds the next attempt back until `release_holdback`, abandoned rounds count toward the limit and attempts that never reach a round do not.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-server/tests/common/mod.rs`            | The fake client the server suites drive: it walks `client/init`, `server/init`, both Noise messages, `server/hello`, `client/hello` and `server/activate` in the order `connection.md` and `messaging.md` define, and reports what the server sent. It shares the core responder rather than the server's internals and carries no tests of its own. For the keepalive suite it also sends and observes pings and pongs (`send_ping`, `send_pong`), observes the server's pings (`wait_for_ping` re-wraps the socket so tungstenite's automatic pong is never flushed) and can leave one unanswered while keeping the socket open (`hold_unanswered_ping`), which is the half-open peer the server must drop.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `crates/syncspin-server/tests/connection.rs`            | The listener and one group end to end: both cipher suites, `server/error` for a refused `client/init`, a silent close for an unauthenticated handshake, `server/hello` and `server/activate`, only the configured path served, the three roles activated, `player@v1` withheld when the client lacks the stream format, audio frames with playout timestamps, `server/state` carrying the group and the track, volume and controller commands, pause ending the stream and play announcing it again, two players receiving identical frames, a stalled member not holding up the other, a clock reply per member, a `client/state` report that is not a command, no audio before the player state, an unavailable member receiving none, and `client/goodbye` reported verbatim.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `crates/syncspin-server/tests/pairing.rs`               | The server's pairing: a token pairs a real client and its next connection authenticates, another client's token is refused, an unapproved client gets no roles and no audio, revoking an approval takes both away, `unpair` removes the record and disconnects, a client that seals its handshake with the Sentinel key while the server holds its record is admitted unpaired with no roles and a `CredentialMismatch` event while the record stays, its next connection repeats the event, an approval and an unpair are refused on that session until the record is removed or the client re-pairs, a real client that lost its record re-pairs over the live session, a re-handshake miss never falls back to the Sentinel key, a malformed pairing message is a protocol error, and the static and dynamic code flows complete through CPace with the commitment and code binding; a wrong static code ends without a record.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `crates/syncspin-server/tests/discovery.rs`             | A fake `Discovery` and a real advertising client: the server publishes its record, dials the advertised endpoint with no `Origin` header, and refuses an endpoint that is not `ws://`; the client's record carries the service, port, path and name. No multicast socket is opened.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/syncspin-server/tests/roundtrip.rs`             | The two halves in one process: the real `syncspin-client` against the real server, with an encrypted connection, a `stream/start` the sink is opened for, the server's bytes arriving unchanged, and a playout deadline ahead of the frame's arrival.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/syncspin-server/tests/keepalive.rs`             | The server's WebSocket keepalive with the shipped 15 s and 10 s windows on a paused clock: a silent connection is pinged only after the idle window and stays served when the fake client pongs, an unanswered ping ends the connection as `ClientLeft` naming the keepalive while the server keeps serving other clients, a normal frame inside the pong window keeps the connection alive, a frame waiting at the pong deadline is read before the window is judged, and a client ping is answered with a pong carrying its payload. Two more are the cross-crate proof a fake client cannot give: a real client and a real server keep a silent link alive across three idle rounds - bidirectional liveness, neither side may go silent and survive - and a fake client that withholds its pong is dropped and a healthy second connection served.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `examples/player-pipe` (in-module tests)                | The example's command line: the default name, identity file and pairing store, `--flag=value` parsing, `--help` without a server, the token mode without a server and its refusal of one, the static-code and window pair (both flags required, eight digits), a bad code never echoed, the usage text naming the flags this build has, and rejection of incomplete, unknown, empty, dashed and over-long values as well as a TLS or non-`ws` server address. With `discovery`: `--advertise` and `--discover` as modes of their own, their mutual exclusion and the exclusion with `--server`, the token mode's refusal of them, the feature named when the build lacks it, and the advertise/discover wiring against a fake `Discovery` without a socket.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `examples/server-demo` (in-module tests)                | The example's command line: the default bind address and name, `--flag=value` parsing, `--help` without an address, `--mdns` accepted when the build has it and rejected with the feature named when it does not, the usage text naming the flags this build has, rejection of a missing, unknown, empty or dashed value, an over-long name and a bind that is not an `IP:port`, and the `--mdns` wiring installing a fake `Discovery` in the configuration without binding a socket.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| In-module unit tests (`crates/*/src`)                   | The per-crate `version()` test, the prologue parsing and identity-redaction tests beside `noise.rs`, the PSK-selection, endpoint and codec-name tests beside the client code, the server's defaults and configuration validation, the audio format's duration and format gate, and the discovery record constructors (the mDNS record tests run only with `mdns`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

A fake server, not a live Music Assistant, is the reference peer for anything that needs a peer.

### Pairing

The pairing suites are split by flow. Feature unification decides what a run covers: `storage-file`
is off in `syncspin-client` but on in `player-pipe`, so a workspace run enables it for the client and
runs the file backend's tests; `pairing-code` is off everywhere unless requested. The server's
`pairing.rs` runs without features for the token flow and the approval gate, and the code flows are
compiled in only with `pairing-code`; its `PairingStore` is an in-memory map, so no suite writes a
record to disk.

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
- the `mdns` backend. Its record constructors are unit-tested, but publishing and browsing need a
  multicast socket, so CI drives both crates through a fake `Discovery` and never runs the backend.
- a second machine. The server suites use loopback; the two-device LAN check below has not been
  performed.
- external review. The CPace layer has draft vectors and hermetic tests, not a review
  ([`spec-deviations.md`](spec-deviations.md), "Code pairing is a feature and the CPace layer is unaudited").

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
cargo check -p syncspin-core -p syncspin-client -p syncspin-server --all-features \
  --target armv7-unknown-linux-gnueabihf --locked
```

`--all-features` is what makes the guard cover the pairing stack: `elligator2` and `hmac` sit behind
`pairing-code`, and without the flag they are not cross-compiled at all; the AEADs come from `snow`,
which resolves both cipher suites. The `arm` job runs this command over all three crates, so an ARM
regression in the server turns CI red just as one in the core or the client does.

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

**Performed 2026-11-16** against a Music Assistant 2.10 server with the Sendspin provider, and the
chain held end to end: connection over Noise, `server/activate` with `player@v1`, `stream/start` with
`pcm 48000 Hz, 2 channels, 16-bit`, track metadata, and audio frames reaching the sink. Two things the
run taught that the checklist below did not know:

- **That provider has no unpaired-access switch and no approval control.** Its only pairing input is a
  token field, so a client must pair before the server will play to it. An unpaired client is listed
  and receives state, but never a stream.
- **It sends a `group_id` that is not 43 base64url characters** (a UUID), which the specification calls
  a protocol error. The client accepts it as an opaque string and says so once — see
  [`spec-deviations.md`](spec-deviations.md). Before that tolerance existed, every session against this
  server closed and retried.

### What to start

1. A Music Assistant server with the **Sendspin provider** enabled — the server side of the protocol.
   Note the address and path it listens on (`ws://<server>:8927/sendspin` is the convention). Where the
   provider offers an **unpaired access** (`unpaired_access`) setting, a guest session reaches playback
   without it; when it offers none, as Music Assistant 2.10 does, pair the client first — the server
   lists an unpaired client but never streams to it. Whether the provider implements the pairing
   activity is not assumed here: if it does not, the pairing checklist below cannot run.
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
  commands from `server/state.controller`. The group's `playback_state`, `group_id` and `group_name`
  arrive in `group/update`, which the client handles as the authoritative group state; the controller
  fields still come from `server/state.controller`.
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

### Keepalive (performed 2026-11-16)

The client pings after 15 s of silence and drops the session after 10 s more without any frame. The
ping is the only traffic an idle session sends, and it exists for the half-open link: a peer whose
process is gone but whose sockets stay open answers nothing, so without the ping neither side would
ever notice the loss.

To make a half-open link deterministically without touching either peer's code, freeze the peer's
processes while their sockets stay open — `docker pause <container>` for a containerised Music
Assistant, or a local TCP proxy between the two that is stopped with `SIGSTOP` (which is how this run
did it). A frozen process sends no close and answers no ping, so the link falls silent with both
sockets still open.

**Performed 2026-11-16** against a Music Assistant 2.10 server through a frozen proxy:

- The client reported
  `disconnected: no WebSocket frame arrived within 10s of a keepalive ping, so the connection is dead; retrying in 1s`
  about 25 s after the freeze, kept retrying with backoff, and re-registered within seconds of the
  thaw.
- A 70 s silent session with an answering server produced no disconnect at all, so the ping is not a
  false positive on an idle but healthy link.

### Unpaired-access refusal (how to check)

`--pairing-required` turns off the client's `unpaired_access` switch, so a session the server
activates without a pairing record is refused: the client sends `client/goodbye` with reason
`pairing_required`, reports `pairing required for server <id>: UnpairedAccessDisabled`, and the
session ends. Pairing itself is unaffected — a `['pairing']` activation stays admissible under the
Sentinel key — so the client can still pair with the server and then play.

Two limits on checking it:

- Music Assistant 2.10 never activates playback on an unpaired client, so there is no unpaired
  activation for the client to refuse.
- The crate's own `server-demo` honours `unpaired_access: false` and grants an unpaired client no
  roles, so it leaves the player connected but silent rather than triggering the refusal.

To check it, point `player-pipe --pairing-required` at a server that activates roles on an unpaired
connection regardless of the client's hello. Expected: the client sends `client/goodbye` reason
`pairing_required`, reports the `PairingRequired` event, and ends the session, while a `['pairing']`
activation stays admissible so pairing still works. This paragraph records how to check it, not a
performed run.

The setting also changes on a live connection: `ControlHandle::set_unpaired_access` stores the value
the next `client/hello` advertises and acts on the running session at once. Turning it off on an
unpaired session that holds roles or declared `playback` sends `client/goodbye` reason
`pairing_required` and reports `Event::Disconnected` with "the client stopped admitting unpaired
access"; the client reconnects and the new hello advertises `false`. Turning it on restarts an
unpaired session with `client/goodbye` reason `restart`, so the reconnected hello advertises `true`.
A paired session is neither closed nor restarted, because the setting never applied to it.

`player-pipe` calls the control handle only for `open_pairing_window`, so this check needs a host
around the library that exposes the call, as with the Sentinel fallback below. **This run has not been
performed.**

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
   its half reports `pairing required for server <id>: CredentialMismatch`.

5. The example offers only the static code flow. It has no display and no speaker, so it advertises
   neither an emission format nor an out-channel, and a server that activates
   `dynamic_pairing_code` is answered with `pair/abort`. For a server that implements the static
   flow, rebuild with `--features pairing-code`:

   ```sh
   cargo run -p player-pipe --features pairing-code -- --server <server>:8927 \
     --static-code <8 digits> --open-window
   ```

   The operator configures the same eight-digit code on both sides.

   **Not exerciseable against Music Assistant 2.10.** Its Sendspin provider exposes three settings —
   log level, manual discovery addresses and "allow legacy clients" — and no pairing method or code
   entry; the provider's only pairing command in the API pairs Music Assistant's own web player. A
   client that connects with `--static-code` and an open window is never sent a code activation: it
   stays a guest, with the window open and nothing to answer. The flows remain verified against the
   fake server only, and this is a server-side gap, not an untested client.

If a step fails, the client's stderr names the event or the abort reason and the server log shows
what it sent. Record both before filing an issue, with the token and all key material removed.

### Sentinel fallback (how to check)

A client whose handshake is sealed by the Sentinel key while the server still holds a record for its
`client_id` is admitted unpaired: the server activates it with no roles, reports
`Event::CredentialMismatch`, and leaves the record alone, and `ServerHandle::approve` is refused
until the record is gone. The client reports `pairing required for server <id>: CredentialMismatch`
from its own event and stays connected; it sends no `pairing_required` goodbye, because that refusal
belongs to an activation its own unpaired-access switch rejects. Pairing again with the token
replaces the record and promotes the live connection without a reconnect.

To run it on real devices, a host needs a `PairingStore` on the server side and a `Storage` on the
client side: pair once, then start the client with the same identity and no record. Neither example
keeps server-side records, so the check needs a host around the library. **This run has not been
performed.**

### Controller seek (performed 2026-11-17)

Run with a real host on an LG webOS device against Music Assistant `2.11.0.dev2026111303`.
`ControlHandle::seek(30_000)` and `seek_relative(-10_000)` both reached the server and moved
playback: the server reported the new position and the host kept playing. The gate
(`controller.supported_commands` plus `seek_max_ms`) behaved as designed.

**The seek did not produce a timestamped `stream/clear`.** Music Assistant repositioned by
restarting the item: `stream/end` followed by `stream/start`, twice, with no `stream/clear` at all.
That matches its provider, which calls the queue's seek and restarts the playing item
(`providers/sendspin/player.py`, "a seek restarts the item that is already playing"). Aiosendspin
does expose a timestamped clear (`PushStream.clear_from`, which calls `on_stream_clear_from`), but
Music Assistant's server does not call it: a code search of that repository finds no `clear_from`,
and its only `stream_clear` uses are the bridge and synchronizer roles, not the player.

Consequence for `Sink::discard_from`: against this server a seek is a full stream restart, so the
sink's timestamped discard is not exercised; it remains the path for a server that sends
`stream/clear` with `from_timestamp`. A host that relies on gapless seeking must expect the restart
from this server, not a partial discard.

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

## Manual two-device LAN check (not yet performed)

Not part of CI: it needs two machines on one LAN, a player and ears. **This check has not been
performed for 0.2.** It is the only run that puts these two crates on separate machines; the suites
bind loopback and use fake discovery.

1. On the first device, start the demo server:

   ```sh
   cargo run -p server-demo
   ```

   It prints the address it listens on and generates a new identity. It has no pairing store, so the
   first client is unpaired and the demo approves it on arrival.

2. On the second device, point the player at that address and play the tone:

   ```sh
   cargo run -p player-pipe -- --server <server>:8927 | aplay -f S16_LE -r 48000 -c 2
   ```

   `<server>` is the address the server printed, not a name or address kept in this document.

3. Expected: the server reports `ClientConnected`, then `ClientActivated` with `player@v1` and
   `streaming a 440 Hz tone`; the player hears the quiet tone without a handshake retry loop. Stop
   the server: the player reports `Disconnected` and retries; start the server again and it plays.

4. Stop both with Ctrl-C. Restarting `server-demo` gives it a new identity, so a client that paired
   with the previous run must pair again; this is the example's in-memory identity, not a library
   rule. The server leaves nothing behind; the player writes its identity and pairing store in its
   working directory as usual, so delete those if the run was throwaway.

What this does not exercise: mDNS in either direction. `server-demo` runs without its `mdns`
feature and `player-pipe` without `discovery` in the commands above, so that run covers only the
client-initiated connection with a known address. The mDNS paths need the examples' features and are
described in the section below; the suites drive them with a fake backend
(`crates/syncspin-server/tests/discovery.rs` and the `mdns` unit tests), not with multicast.

## Manual two-device discovery check (not yet performed)

Not part of CI, and **not performed for 0.2**. It needs two machines on one LAN and a network that
carries multicast between them. Run the server first: `--discover` takes one browse and fails if
nothing answers.

1. On the first device, start the demo server with its backend:

   ```sh
   cargo run -p server-demo --features mdns -- --mdns
   ```

   It prints the address it listens on, then one line:
   `advertising _sendspin-server._tcp as syncspin-demo`.

2. On the second device, let the player find it:

   ```sh
   cargo run -p player-pipe --features discovery -- --discover | aplay -f S16_LE -r 48000 -c 2
   ```

   The player prints one `discovered a server at ws://<address>/sendspin` line, then connects and
   plays the tone. Stop the server: the player reports `Disconnected` and retries the address it
   found, because a discovered address is a dialled one from then on.

3. To test the other direction, start the player first:

   ```sh
   cargo run -p player-pipe --features discovery -- --advertise | aplay -f S16_LE -r 48000 -c 2
   ```

   It prints `advertising _sendspin._tcp as syncspin-pipe` and accepts a server. Then start the
   server with `--features mdns -- --mdns`; it browses `_sendspin._tcp` and dials the advertised
   endpoint. The server's log shows the approval and the tone, as in the address-based run.

4. Limits of this check: both examples generate a fresh identity per run, so a restart is a new peer
   and a paired client must pair again. `server-demo --mdns` dials every advertising client it
   finds, so a LAN with several players exercises the first one only. Neither example keeps state,
   and the player's working directory still gets an identity and pairing store.
