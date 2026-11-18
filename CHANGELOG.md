# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Sections are generated from Conventional Commits with [git-cliff](cliff.toml).

## [Unreleased]

### Added

- **client:** `ClientConfig::output_delay_control` advertises `set_output_delay`; an accepted command is reported as `Event::OutputDelay`, and `ControlHandle::output_delay_applied` makes the session read the sink and send a `client/state`. A value outside 0-5000 ms ends the connection.

### Changed

- `ClientConfig` gains `output_delay_control`, one 0.x break for full struct literals; `ClientConfig::new` and `with_output_delay_control` keep working.

## [0.4.0] - 2026-11-18

### Added

- **core:** `PskOutcome` and `Initiator::read_message_with_sentinel`, so an initiator can retry a failed Noise message 2 under the Sentinel key.
- **server:** a client whose pairing record did not seal the handshake is admitted as an unpaired session, reported once per connection as `Event::CredentialMismatch`, and held at no roles until it re-pairs; `approve` and `unpair` are refused on that session while the record exists.
- **client:** `ControlHandle::seek` and `seek_relative`, and `PlaybackState::seek_max_ms`, for controller scrubbing bounded by the server's advertised range.
- **client:** `ControlHandle::set_unpaired_access` changes the setting on a live connection: turning it off closes a relying unpaired session with `client/goodbye` `pairing_required`, turning it on closes an unpaired session with `restart` so the next `client/hello` advertises the value.
- **client:** `Sink::discard_from`, a provided method defaulting to `flush`, so a `stream/clear` carrying `from_timestamp` can keep the audio before the cut.
- **client:** `Sink::output_delay` (the former `latency`), which reports only delay after the audio port, and `ClientConfig::required_lead_time_ms` / `min_buffer_ms` for the host's start-up lead and an optional buffer pin.
- **client:** when `min_buffer_ms` is not pinned, the client derives it from the arrival-delay distribution of `send_ahead`, reports changes in `client/state`, and starts from 250 ms.
- **examples:** `player-pipe --pairing-required`, which refuses an unpaired activation at the client.

### Changed

- `Event` is now `#[non_exhaustive]` and gains `CredentialMismatch`; a downstream exhaustive `match` needs a wildcard arm.
- `ControllerState` gains `seek_max_ms`, one 0.x break for struct literals; `PlaybackState` gains the same field additively because it is `#[non_exhaustive]`.
- `ServerHandle::approve` and `unpair` write the registry only after the session confirms, so a failed call leaves the approval and the record as they were.
- Sessions register before `ClientConnected`, so a host reacting to an event can reach the live connection.
- `snow` is pinned `=0.10.0`: the Sentinel retry relies on its error-path checkpoint, and a bump waits for the core test that re-verifies it.
- `Sink::latency` is removed in favour of `Sink::output_delay`; every in-tree sink and example is renamed, and downstream sinks need the same one-line edit.
- `ClientConfig` gains `required_lead_time_ms` and `min_buffer_ms`; `..Default` constructors keep working, full struct literals need both fields.
- Mutation testing runs on every pull request in four core shards, in addition to the weekly schedule; it reports but is not a required check.

### Notes

- Against Music Assistant 2.11 a seek restarts the item with `stream/end` + `stream/start`, so `Sink::discard_from` stays unused there; it applies to a server that sends `stream/clear` with `from_timestamp`.
- The Sentinel fallback's manual device check has not been performed; it needs a host that keeps server-side pairing records.

## [0.3.1] - 2026-11-16

### Fixed

- The README published on crates.io still named 0.2 and told readers to depend on `syncspin-client = "0.2"`,
  which resolves to the release that cannot talk to Music Assistant. The page now names 0.3.1, and
  `scripts/release.sh` refuses to prepare a release whose README does not carry the full version

## [0.3.0] - 2026-11-16

### Added

- **client:** Refuse an activation the matched PSK does not allow (#33)

- Keep a silent session alive with a WebSocket keepalive on both sides (#38)

### Fixed

- Interoperate with a foreign group id and fall back across addresses (#26)

- **core:** Harden the CPace layer after review (#32)

- **server:** Wait for the clock estimate instead of the writer's luck (#35)

- **client:** Use a clock reply that arrives after the per-message timeout (#39)

## [0.2.0] - 2026-11-16

### Added

- **core:** Both cipher suites — `25519_ChaChaPoly_SHA256` and `25519_AESGCM_SHA256`, chosen by the
  suite the peer announces, with no downgrade
- **core:** The Noise initiator, so the server no longer copies the test harness
- **core:** `group/update` and `server/error`
- **server:** Listener, handshake and activation over both suites
- **server:** Roles and a stream: `StreamWriter`, player/controller/metadata, format gate
- **server:** One group with several clients, per-client clock, group volume
- **server:** Pairing as the server — token, static and dynamic codes — and the approval gate
- **client:** Advertising and inbound connections behind `discovery`
- **examples:** `server-demo`, a host that streams a tone to a connected player

### Changed

- **client:** `group/update` is the authoritative playback state; `server/error` reaches the host as an event
- **client:** A second inbound server is refused with `client/goodbye` reason `concurrent_attempt`

### Fixed

- **server:** Published on crates.io together with core and the client

## [0.1.2] - 2026-11-16

### Fixed

- **docs:** Stop naming a release version in the README, so a published package cannot advertise the previous one

## [0.1.1] - 2026-11-15

### Added

- **client:** Expose the pairing token and say goodbye

### Fixed

- **client:** Bound the goodbye and observe shutdown while connecting

## [0.1.0] - 2026-11-15

### Added

- **core:** Port the Noise KKpsk2 layer

- **core:** Add protocol messages and binary framing

- **core:** Port the clock filter

- **client:** Add the guest session with a sink trait

- **examples:** Add the pipe player

- **client:** Add controls, the volume clamp and reconnect

- **client:** Let a host observe stream lifecycle and own the volume policy

- **client:** Let the host report its own level and identity

- Pairing for the client (#8)

### Fixed

- Make the crates packageable and tighten the gate config

- **ci:** Correct the Renovate rule and tighten the gates

- **ci:** Install gitleaks from the release tarball

- **core:** Pin the Noise security properties in tests

- **core:** Name the clock thresholds and pin the estimate quality

- **core:** Separate unknown types from malformed ones

- **examples:** Make the pipe player honest about its identity and limits

- **client:** Honour stream lifecycle and complete the player state

- **client:** Send the clock burst sequentially

- **client:** Bound the volume and own the reconnect loop

- **client:** Treat the bare player role in stream/end as ours
