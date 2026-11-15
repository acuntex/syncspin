# syncspin

A Sendspin protocol client and server library for Rust.

`syncspin` speaks [Sendspin](https://github.com/Sendspin/spec), a protocol for synchronised,
multi-room audio: a server owns the queue and the clock, clients render the audio and report their
state back. The crate is not an official Sendspin implementation and is not affiliated with the
Sendspin project; "Sendspin" is used only to describe what the code speaks.

**Status: 0.1 work in progress.** The workspace exists and compiles, the client is being extracted
from a working player, the server is a stub. Nothing here is stable yet.

## Layout

| Crate             | Contents                                                                        |
| ----------------- | ------------------------------------------------------------------------------- |
| `syncspin-core`   | Noise handshake, framing, messages, clock filter. No transport, no device code. |
| `syncspin-client` | Session loop, `Sink` trait, event stream.                                       |
| `syncspin-server` | Listener, streams, roles, pairing (planned for 0.2).                            |

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

The API is still being shaped, so this sketch is what the client is meant to look like - it does
not compile against `0.1` yet:

```rust,ignore
use syncspin_client::{Client, ClientConfig, Event};

let config = ClientConfig::new("wss://music-assistant.local:8927/sendspin");
let mut client = Client::connect(config, PipeSink::new()).await?; // any `Sink`

while let Some(event) = client.next_event().await? {
    match event {
        Event::NowPlaying { title, artist, .. } => println!("{artist} - {title}"),
        Event::Volume { percent } => println!("volume: {percent}"),
        _ => {}
    }
}
```

## Requirements

- **MSRV 1.85**, edition 2021.
- On the ARMv7 / glibc 2.24 target build with
  `cargo zigbuild --target armv7-unknown-linux-gnueabihf`. `openssl` and `ring` are out: the crypto
  stack is `snow` plus `x25519-dalek`.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
