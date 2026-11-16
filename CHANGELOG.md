# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Sections are generated from Conventional Commits with [git-cliff](cliff.toml).

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
