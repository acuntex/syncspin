# syncspin

A Rust library for [the Sendspin protocol](https://github.com/Sendspin/spec): a client today, a
server planned. A server owns the queue and the clock, clients render the audio and report their
state back.

[![CI](https://github.com/acuntex/syncspin/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/acuntex/syncspin/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://github.com/acuntex/syncspin/blob/main/Cargo.toml)

## Status

**0.1, client first.** The client is implemented and covered by a hermetic test suite;
`syncspin-server` is a stub with `publish = false`. No crate is published on crates.io — `v0.1.0` is
a pre-release tag that marks the first pinnable state. The API may change before 1.0.

`syncspin` is not an official Sendspin implementation and is not affiliated with the Sendspin
project; the name describes only the protocol the code speaks.

## Crates

| Path                      | Contents                                                                        |
| ------------------------- | ------------------------------------------------------------------------------- |
| `crates/syncspin-core/`   | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `crates/syncspin-client/` | Session loop, `Sink` trait, event stream.                                       |
| `crates/syncspin-server/` | Planned for 0.2: listener, streams, roles, pairing.                             |
| `examples/player-pipe/`   | Runnable reference player: PCM on stdout, status lines on stderr.               |

`syncspin-core` never depends on `syncspin-client` or `syncspin-server`; every protocol and crypto
decision lives in one place.

## Getting started

The crates are not on crates.io yet, so depend on the tag:

```toml
[dependencies]
syncspin-client = { git = "https://github.com/acuntex/syncspin", tag = "v0.1.0" }
```

The example player needs a Sendspin server to talk to:

```sh
cargo run -p player-pipe -- --server music-assistant.local:8927 | aplay -f S16_LE -r 48000 -c 2
```

Run `cargo run -p player-pipe -- --help` for the player name and identity file. The first run writes
`./identity.key` with owner-only permissions and prints the public key the server sees; later runs
reuse it. The server must allow unpaired access, because this revision has no pairing yet.

The example's source is meant to be read: `src/main.rs` holds the event loop and the identity
handling, `src/pipe_sink.rs` the `Sink` implementation.

## What works today

A connection reconnects on its own: when an attempt ends, the crate flushes the sink, reports
`Event::Disconnected` with the delay it applies (2 s at first, doubling up to
`ClientConfig::max_backoff`, and 1 s again after a session that connected) and tries again with the
same sink, identity, volume and mute state. It stops only when the audio sink fails or when the
handle or event stream is dropped.

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

The stream lifecycle is visible on the event stream: `Event::StreamStart` announces a new format,
`Event::StreamEnd` reports a pause or a removed player role, and `Event::StreamClear` reports a seek
with its timestamp. The end and clear events arrive before the client flushes the sink, so a host can
mute, stop or restart its output first; a reconnect flush produces no stream event. `Event::Track`
carries the now-playing metadata with the position, the duration and the playback speed in per-mille,
where `1000` is normal speed.

## What does not work yet

- **Pairing.** No pairing flow: no PSK negotiation, no code pairing, no pairing window. A client
  connects as an unpaired guest, which the server must allow. A host that already holds a pairing
  record can hand it in through `connect_with_psks`.
- **Server.** `syncspin-server` is a stub; the listener, streams, roles and pairing server arrive in
  0.2.
- **Discovery.** Clients do not advertise over mDNS and do not accept server-initiated connections.
- **Group state.** `group/update`, the spec's authoritative source of the playback state, is not
  handled.
- **TLS.** No TLS stack: a `wss://` address is rejected when the client is configured, and nothing
  is downgraded to `ws://`. A TLS backend is out of scope for 0.1.

Pairing, discovery, `group/update` and the other departures from the specification are tracked with
their reasons and the work that closes them in [docs/spec-deviations.md](docs/spec-deviations.md).
The server half is not a deviation — it is staged work for 0.2.

## Integrating a client

A host supplies a [`Sink`](crates/syncspin-client/src/sink.rs): `open` for a new format, `write` for
every chunk with the playout deadline the client computed, `flush` at each boundary the crate
announces, and optionally `latency` and `underruns` so the client can hold its buffer and report
timing. The crate owns the connection, the clock and the reconnect loop; the host owns the output
device, the identity file and everything below the pipe.

```rust
let (handle, mut events) = Client::connect(config, Box::new(my_sink)).await?;
while let Some(event) = events.next().await {
    // StreamStart, StreamEnd, StreamClear, Track, Volume, Disconnected, ...
}
```

`handle.control()` returns the play/pause/skip, volume and mute controls; dropping the handle or the
event stream ends the connection.

## Integrating a server

`syncspin-server` is a stub and is not published. It is where the listener, the stream handling, the
roles and the server side of pairing will live for 0.2, and its shape is described in
[docs/design/syncspin-design.md](docs/design/syncspin-design.md). Until then, build the client side
and use a Sendspin server you already have.

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
  stack is `snow` plus `x25519-dalek`.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
