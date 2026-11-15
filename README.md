# syncspin

A Sendspin protocol client and server library for Rust.

`syncspin` speaks [Sendspin](https://github.com/Sendspin/spec), a protocol for synchronised,
multi-room audio: a server owns the queue and the clock, clients render the audio and report their
state back. The crate is not an official Sendspin implementation and is not affiliated with the
Sendspin project; "Sendspin" is used only to describe what the code speaks.

**Status: 0.1 work in progress.** The workspace exists and compiles, the client is being extracted
from a working player, the server is a stub. Nothing here is stable yet.

## Client behaviour

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

## Layout

| Path                      | Contents                                                                        |
| ------------------------- | ------------------------------------------------------------------------------- |
| `crates/syncspin-core/`   | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `crates/syncspin-client/` | Session loop, `Sink` trait, event stream.                                       |
| `crates/syncspin-server/` | Listener, streams, roles, pairing (planned for 0.2).                            |
| `examples/player-pipe/`   | Runnable reference player: PCM on stdout, status lines on stderr.               |

`syncspin-core` never depends on `syncspin-client` or `syncspin-server`; every protocol and crypto
decision lives in one place.

## Documentation

- [Design](docs/design/syncspin-design.md) - crate split, API sketch, pairing plan and the staged
  plan towards 0.1.
- [Spec deviations](docs/spec-deviations.md) - every known departure from the Sendspin
  specification, why it exists and what closing it takes.
- [Testing](docs/testing.md) - the hermetic suites, the MSRV and ARMv7 checks, and the manual run
  against a real Music Assistant server.

## Example

[`examples/player-pipe`](examples/player-pipe) is a runnable player: it connects to a server,
implements the `Sink` trait and writes the raw samples to stdout, with one status line per event on
stderr.

```sh
cargo run -p player-pipe -- --server music-assistant.local:8927 | aplay -f S16_LE -r 48000 -c 2
```

Run `cargo run -p player-pipe -- --help` for the player name and identity file. The first run writes
`./identity.key` with owner-only permissions and prints the public key the server sees; later runs
reuse it. The server must allow unpaired access, because this revision has no pairing yet.

The source is small and meant to be read: `src/main.rs` holds the event loop and the identity
handling, `src/pipe_sink.rs` the `Sink` implementation.

## Requirements

- **MSRV 1.85**, edition 2021.
- On the ARMv7 / glibc 2.24 target build with
  `cargo zigbuild --target armv7-unknown-linux-gnueabihf`. `openssl` and `ring` are out: the crypto
  stack is `snow` plus `x25519-dalek`.

## Publishing

`syncspin-core` has to be published before `syncspin-client`: the client's `syncspin-core`
dependency is a path dependency that `cargo package` rewrites to a registry dependency, so
`cargo package -p syncspin-client` fails until `syncspin-core` 0.1.0 exists on crates.io.
`syncspin-server` is `publish = false` and stays out of the release.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
