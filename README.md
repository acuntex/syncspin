# syncspin

A Rust library for [the Sendspin protocol](https://github.com/Sendspin/spec): a client and a server.
The server owns the clock and the stream, clients render the audio and report their state back. A
host supplies the server's frames; it does not turn into a music server.

[![CI](https://github.com/acuntex/syncspin/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/acuntex/syncspin/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/syncspin-client.svg)](https://crates.io/crates/syncspin-client)
[![docs.rs](https://docs.rs/syncspin-client/badge.svg)](https://docs.rs/syncspin-client)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://github.com/acuntex/syncspin/blob/main/Cargo.toml)

## Status

**0.4.0, both halves.** The client is covered by a hermetic test suite, including pairing: the Pairing
PSK flow, the records it writes, the in-band re-handshake and `server/unpair`, plus the static and
dynamic code flows behind the `pairing-code` feature. The server accepts clients, owns one group and
its stream, serves the three roles, pairs with all three methods and discovers peers in both
directions. Its suites use a fake client that walks the specification, and one test runs the real
client against the real server so the two halves cannot agree on a bug unnoticed. A session that
carries no traffic keeps itself alive with a WebSocket keepalive on both sides, and a group id that
is not the specification's 43 base64url characters is tolerated instead of ending the session. Every
release publishes `syncspin-server` beside `syncspin-core` and `syncspin-client` from the same tag. The API
may change before 1.0. The CPace layer behind the code flows has not been reviewed externally, so it
is unaudited code until it has been; what a reviewer would look at is written down in
[the review package](docs/cpace-review.md).

`syncspin` is not an official Sendspin implementation and is not affiliated with the Sendspin
project; the name describes only the protocol the code speaks.

## Crates

| Path                      | Version                                                                                                       | Contents                                                                        |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `crates/syncspin-core/`   | [![crates.io](https://img.shields.io/crates/v/syncspin-core.svg)](https://crates.io/crates/syncspin-core)     | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `crates/syncspin-client/` | [![crates.io](https://img.shields.io/crates/v/syncspin-client.svg)](https://crates.io/crates/syncspin-client) | Session loop, `Sink` trait, event stream, pairing and its `Storage` trait.      |
| `crates/syncspin-server/` | [![crates.io](https://img.shields.io/crates/v/syncspin-server.svg)](https://crates.io/crates/syncspin-server) | Listener, one group, roles, host-fed streams, pairing and discovery.            |
| `examples/player-pipe/`   | —                                                                                                             | Runnable reference player: PCM on stdout, status lines on stderr, pairing.      |
| `examples/server-demo/`   | —                                                                                                             | Runnable reference server: approves the first client and streams a tone.        |

`syncspin-core` never depends on `syncspin-client` or `syncspin-server`; every protocol and crypto
decision lives in one place.

## Getting started

```toml
[dependencies]
syncspin-client = "0.4.0"
syncspin-server = "0.4.0"
```

Every release is tagged, and the tag carries the source it was published from. `syncspin-core` is
published first; the other two depend on it through the registry.

The two examples can talk to each other, with no music server in between. Start the demo server and
note the address it prints:

```sh
cargo run -p server-demo
```

Then point the player at that address:

```sh
cargo run -p player-pipe -- --server <server>:8927 | aplay -f S16_LE -r 48000 -c 2
```

`server-demo` approves its first client, activates the roles it offered and streams a quiet 440 Hz
tone until Ctrl-C. It holds no files and decodes nothing; its identity is new on every run. The same
player talks to Music Assistant's Sendspin provider when `--server` names that endpoint instead.

Run `cargo run -p player-pipe -- --help` for the player name, the identity file and the pairing
store. The first run writes `./identity.key` and `./pairing.json` with owner-only permissions; later
runs reuse both. To pair the player, print its version-0 pairing token and enter it in the server:

```sh
cargo run -p player-pipe -- --pairing-token
```

The token is a credential: whoever holds it can pair a server with this client, so hand it over
directly and keep it out of logs and issues. A server that admits unpaired clients still accepts the
player as a guest. `--features pairing-code` adds `--static-code` and `--open-window` for the static
code flow.

Both examples are meant to be read. `player-pipe/src/main.rs` holds the event loop, the identity
handling and the pairing token, and `player-pipe/src/pipe_sink.rs` the `Sink` implementation.
`server-demo/src/main.rs` holds the approval gate, the event loop and the push data plane.

## What works today

A connection reconnects on its own: when an attempt ends, the crate flushes the sink, reports
`Event::Disconnected` with the delay it applies (2 s at first, doubling up to
`ClientConfig::max_backoff`, and 1 s again after a session that connected) and tries again with the
same sink, identity, volume and mute state. It stops only when the audio sink fails or when the
handle or event stream is dropped.

A silent link is detected instead of staying "connected" forever: after 15 s without receiving any
WebSocket frame the client sends a ping, and when nothing arrives in the 10 s after it the attempt
ends as a disconnect so the reconnect above runs. The ping appears only when nothing has arrived for
15 s, so a link that keeps carrying audio, metadata or clock replies sees none, and a ping from the
server is answered as before. The ping is a transport control frame with an 8-byte nonce, not a
protocol message and not application data; the client depends on the peer answering pings or sending
something else within that window.

`ClientConfig::volume` and `ClientConfig::muted` are the level and mute state the first `client/state`
carries. A host passes the values it restored, so the server never sees an invented baseline; a host
without stored values passes `100` and `false`. `ControlHandle::set_volume` returns the level that
was applied, and `ControlHandle::volume` reports the level in force without a call.

`ClientConfig::volume_policy` limits a request from the server or from the host. The default policy
is the rule `clamp_volume` implements: a request to 40 or below is applied as asked, and above 40 one
request may raise the level by at most 20. `clamp_volume_with` takes a policy, for a device that needs
a different guard. `Event::Volume` carries both the requested and the applied level, and the
`client/state` report carries the applied one.

`ControlHandle::report_volume` is the other direction: a host that reads the level its output is
actually at - because the device applied one at its own control, or because another process changed
it - reports it, and the next `client/state` carries it unchanged. The policy limits requests, not
the level the device is at, so a device the user raised to 70 while the threshold is 40 reports 70.
A level above the protocol maximum of 100 is refused and nothing is recorded or sent.

`ClientConfig::device_info` describes the machine the client runs on - product name, manufacturer,
software version and MAC address - and is announced in `client/hello`, so the server can show the
hardware rather than only the player name. A host that describes no device passes `None`.

`ClientConfig::required_lead_time_ms` is the host's own start-up cost - launching the output,
warming the decoder - and reaches the server in `client/state`; it defaults to 250 ms and has no
upper bound beyond its type. `ClientConfig::min_buffer_ms` pins the buffer the server should keep
filled; with the default `None` the client derives it from the arrival delay of audio chunks, starts
from 250 ms, and reports an applied change in a `client/state`. A pin above the protocol's 5000 ms
is refused before a connection is attempted.

The stream lifecycle is visible on the event stream: `Event::StreamStart` announces a new format,
`Event::StreamEnd` reports a pause or a removed player role, and `Event::StreamClear` reports a seek
with its timestamp. The end and clear events arrive before the client discards or flushes buffered
audio, so a host can mute, stop or restart its output first; a reconnect flush produces no stream
event. `Event::Track` carries the now-playing metadata with the position, the duration and the
playback speed in per-mille, where `1000` is normal speed.

### The server

`syncspin-server` listens on a configurable address and path, answers `client/init` with `server/init`
and runs the Noise handshake as its initiator over either cipher suite. A `client/init` it cannot
accept is answered with `server/error` and a close; a handshake that does not authenticate ends
without a further message. Each connection is reported to the host as it connects, is activated and
leaves.

One group holds every client. All members receive the same frames with the same playout timestamps,
the server answers each client's `client/time` burst, and a member that stops reading does not hold
up the others. The host pushes audio into a `StreamWriter` from `ServerHandle::open_stream`; the server
stamps every chunk from the configured format and fans it out without decoding. A client is given
`player@v1` only when its `player@v1_support` lists that exact format, so nobody is sent a stream it
cannot play. Volume, mute and play/pause/stop belong to the group. The active roles are the three v1
roles a player needs: `player@v1`, `controller@v1` and `metadata@v1`.

The server pings a silent link just as the client does: after 15 s without receiving any WebSocket
frame it sends a ping, and a peer that sends nothing in the 10 s after it - not even a pong - is
dropped and reported as `Event::ClientLeft` naming the keepalive. Any received frame counts as the
answer, so a link that keeps carrying clock requests, state reports or commands sees no ping, and a
client's own ping is answered as before. The ping is a transport control frame with an 8-byte nonce,
not application data; a client that vanished without closing its socket is noticed within 25 s
instead of only when the server next writes and TCP fails.

The server has its own pairing: `PairingStore` holds one record per `client_id`, an unpaired client
is held at empty activities until the operator approves it, and `pair`, `start_pairing`,
`submit_code` and `unpair` drive the token, static-code and dynamic-code flows. Discovery runs in both directions:
with a `Discovery` backend the server advertises `_sendspin-server._tcp` and dials the clients that
advertise `_sendspin._tcp`; the `mdns` feature carries the `mdns-sd` implementation.

## Pairing

Pairing belongs to the host: it supplies a [`Storage`](crates/syncspin-client/src/storage.rs) with the
pairing PSK, the records of servers it has paired with, and the calls that read and write them. The
crate draws and persists the PSK on the first run, offers the Pairing PSK method on every connection,
and writes a record after `server/pair-finalize`; `Event::Paired` reports it. A record authenticates
the next connection, and the session survives the server's in-band re-handshake without dropping the
stream. `server/unpair` removes the record and arrives as `Event::Unpaired`; a server that names a
`psk_id` the client does not hold produces `Event::PairingRequired` once per connection. Without a
store the client offers no pairing method and runs as a guest — unless the host passes records
through `connect_with_psks`, which needs no store and still authenticates against them.

`FileStorage` is the optional JSON backend behind the `storage-file` feature, and the example uses
it. The crate writes at most five records into a store it manages, evicting the oldest first and
never the record backing the live connection; a store that already holds more is read as it is. That
order is insertion order, not use order, so a record kept since long ago can be evicted before one
used recently. `Storage::store_pairing` is the primitive, not the whole rule: calling it directly
skips the live-record pin, and `FileStorage` trims to five there only as a safety net while a host
backend may not trim at all. A host that writes a record itself calls the exported `persist_pairing`,
which applies both rules to any store, instead of reimplementing them.

With the `pairing-code` feature the client also runs the static and dynamic code flows, gated by a
pairing window the host opens or by the process-wide round limit. The dynamic flow shows the operator
a six-digit code or a version-1 token; both flows deliver the long-term key sealed under the CPace
output. The CPace layer is unaudited — see [Status](#status).

Unpaired access is a client setting: `ClientConfig::unpaired_access` is the value each `connect`
starts from and what `client/hello` advertises, and `ControlHandle::set_unpaired_access` changes it on
a running client. Turning it off closes a session that relied on it — an unpaired session with active
roles, or with `playback` among the activities of its accepted activation — after a `client/goodbye`
with reason `pairing_required`; an idle unpaired session stays open and the activation guard refuses
the next activation that would need the setting. Turning it on restarts an unpaired session with
`client/goodbye` reason `restart`, because `client/hello` is the only carrier of the advertisement and
only a new connection can send a new one. A paired session is untouched in both directions: the
setting never applied to it, so it is neither closed nor restarted. The value the host set is what
every later `client/hello` in that `connect` advertises.

The server's side is symmetric. `ServerConfig::storage` is the host's `PairingStore`, keyed by
`client_id`; the listener seals a client's first handshake with the record it holds. A client with no
record is reported with `approved: false`, gets no roles and no audio, and stays that way until
`ServerHandle::approve` or a completed pairing. A client that seals its handshake with the Sentinel
key while the server holds its record is admitted unpaired, reported with
`Event::CredentialMismatch`, and re-pairs. `Event::PairingRequested` asks the operator for a code,
`Event::Paired` reports the record, and `ServerHandle::unpair` removes it and disconnects — except on
a live connection that fell back to the Sentinel key over its record, where the call is refused
until the record is gone.
Approval lasts as long as the server process; it is not written to a store and a restart asks again.

## Discovery

`connection.md` gives a server two ways to reach a client and a client two ways to reach a server.
Both halves implement both. A server with a `Discovery` backend publishes
`_sendspin-server._tcp` with its bound port, `path` and `name` and browses `_sendspin._tcp` for the
clients it dials. The `mdns` feature carries an `mdns-sd` implementation for each crate; without a
backend the `Discovery` trait is the seam, so a test drives advertising with a fake and no multicast
socket is opened.

With the `discovery` feature the client can take the server-initiated half: instead of dialling a
server it advertises `_sendspin._tcp` through a host-supplied `Discovery` and accepts the server that
connects. `Inbound` carries the backend, the listen address (every interface on 8928 by default) and
the path (`/sendspin` by default); `advertise` publishes the record with the bound port and the
`path` and `name` TXT records, then serves the inbound WebSocket. An upgrade that carries an `Origin`
header is refused with a 403, as the spec requires, and the Noise handshake is unchanged: the server
is its initiator in both directions.

One server is served at a time. While `ClientConfig::inbound` is set the client does not dial, and
`connect` refuses: the spec lets a client use one of the two methods at a time, never both. A second
server that connects while one is admitted is rejected with `client/goodbye` reason
`concurrent_attempt` and closed, as the admission rule requires; it is not left waiting in the
listener's backlog. Nothing browses automatically on the client: the host chooses among the servers
it found and passes one URL to `connect`, which the spec leaves implementation-defined.

## What does not work yet

- **Server scope.** No queue, library, playlist, decoding, resampling, HTTP API or UI. The host owns
  the content and writes the frames; the crate owns the connection, clock, group and wire.
- **Several groups.** One group per server. An unavailable member stays in it and simply receives no
  audio; there is no solo group and no `switch` command cycle.
- **Roles.** Only `player@v1`, `controller@v1` and `metadata@v1`. There are no other role versions
  and no `artwork`, `visualizer`, `color` or `source` role.
- **Discovery persistence.** Both crates browse and advertise, but the client does not persist the
  server it last admitted with `playback`, and the server keeps operator approval for its lifetime
  only. A restart asks the operator again.
- **Playout lead.** Every member shares one timeline whose first sample is 200 ms after the stream
  opens. The reported `required_lead_time_ms` and `min_buffer_ms` are received but do not move it.
- **TLS.** No TLS stack: a `wss://` address is rejected when the client is configured, and nothing
  is downgraded to `ws://`. A TLS backend is out of scope.

Pairing, discovery and the other departures from the specification are tracked with their reasons
and the work that closes them in [docs/spec-deviations.md](docs/spec-deviations.md).

## Integrating a client

A host supplies a [`Sink`](crates/syncspin-client/src/sink.rs): `open` for a new format, `write` for
every chunk with the playout deadline the client computed, `discard_from` for a seek with a
timestamp, `flush` at each boundary the crate announces, and optionally `output_delay` for the delay
the output adds beyond the audio port, which the client reports to the server, and `underruns` for
diagnostics. The buffer the session asks for comes from its configuration or from arriving audio,
so it needs no sink hook. The crate owns the connection, the clock and the reconnect loop; the host
owns the output device, the identity file and everything below the pipe.
Pairing needs a [`Storage`](crates/syncspin-client/src/storage.rs) as well; without one the client
offers no pairing method, and a host that already holds records can pass them to `connect_with_psks`
instead.

```rust
let (handle, mut events) = Client::connect(config, Box::new(my_sink)).await?;
while let Some(event) = events.next().await {
    // StreamStart, StreamEnd, StreamClear, Track, Volume, Disconnected, ...
}
```

`handle.control()` returns the play/pause/skip, seek, volume and mute controls; dropping the handle
or the event stream ends the connection.

## Integrating a server

A host supplies the server's identity, an optional
[`PairingStore`](crates/syncspin-server/src/pairing.rs) and an optional
[`Discovery`](crates/syncspin-server/src/discovery.rs). `Server::start` binds the listener and hands
back a handle and an event stream. The host writes frames into the `StreamWriter` that
`open_stream` returns and follows the connections through the events:

```rust
let mut server = Server::start(config).await?;
let mut events = server.events();
let mut stream = server.open_stream(track);
stream.write(&pcm);
while let Some(event) = events.next().await {
    // ClientConnected, ClientActivated, PairingRequested, Paired, ClientLeft, ...
}
```

An unapproved client reaches `ClientConnected { approved: false }` and gets no roles until
`server.approve(&client_id).await?`; a paired client arrives already approved.
`server.set_volume`, `play`, `pause` and `stop` change the group, and `pair`, `start_pairing`,
`submit_code` and `unpair` drive the pairing flows. `examples/server-demo` is the smallest complete
host, including the approval call; its source is short enough to read next to this section.

## Related projects

Nothing to list yet. A sibling open-source client built on `syncspin-client` will be linked here
once it is public.

## Documentation

[`docs/`](docs/README.md) indexes the protocol design, every known spec deviation and the testing
handbook.

## Requirements

- **MSRV 1.85**, edition 2021.
- On the ARMv7 / glibc 2.24 target build with
  `cargo zigbuild --target armv7-unknown-linux-gnueabihf`. `openssl` and `ring` are out: the crypto
  stack is `snow` — which resolves both cipher suites — `x25519-dalek`, `elligator2`, `subtle` and
  the RustCrypto primitives (`sha2`, `hmac`, `zeroize`) the pairing code flows need.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
