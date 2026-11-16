# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Sections are generated from Conventional Commits with [git-cliff](cliff.toml).

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
