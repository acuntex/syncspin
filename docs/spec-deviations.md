# Spec deviations

`syncspin` targets the published [Sendspin specification](https://github.com/Sendspin/spec). Every
place where this library knowingly departs from it is listed here, with the spec section it
concerns, the reason for the departure and what closing the gap requires.

A deviation is only acceptable when it is in this file and, where the behaviour is observable,
pinned by a test. "Not implemented yet" entries are staged work, not a claim that the deviation is
harmless.

## Summary

| #   | Area                                                            | Spec section                                                                                                                                                                      | Status                             |
| --- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 1   | Client-initiated connections only, no client mDNS advertisement | [`connection.md` — Establishing a Connection](https://github.com/Sendspin/spec/blob/main/connection.md#establishing-a-connection)                                                 | Closes in 0.2                      |
| 2   | No `activities` admissibility handling                          | [`messaging.md` — `server/activate`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serveractivate)                                                       | Stage 1b                           |
| 3   | No `pairing_token()` export                                     | [`pairing.md` — Pairing Token](https://github.com/Sendspin/spec/blob/main/pairing.md#pairing-token)                                                                               | Open, accessor only                |
| 4   | `psk_id` validation deferred to the session layer               | [`connection.md` — Pre-Shared Key](https://github.com/Sendspin/spec/blob/main/connection.md#pre-shared-key)                                                                       | Accepted, `select_psk`             |
| 5   | Code pairing behind a feature; CPace layer unaudited            | [`pairing.md` — PAKE](https://github.com/Sendspin/spec/blob/main/pairing.md#pake)                                                                                                 | Accepted, `pairing-code`           |
| 6   | `group/update` is not the state source                          | [`messaging.md` — `group/update`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-groupupdate)                                                             | Stage 1b                           |
| 7   | No failure diagnostics from `server/error`                      | [`messaging.md` — `server/error`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-servererror)                                                             | Stage 1b                           |
| 8   | No `_sendspin-server._tcp` discovery, explicit URL only         | [`connection.md` — Client Initiated Connections](https://github.com/Sendspin/spec/blob/main/connection.md#client-initiated-connections)                                           | Closes in 0.2                      |
| 9   | No `client/goodbye` writer                                      | [`messaging.md` — `client/goodbye`](https://github.com/Sendspin/spec/blob/main/messaging.md#client--server-clientgoodbye)                                                         | Stage 1b                           |
| 10  | No unpaired-access switch; unpair closes without a goodbye      | [`pairing.md` — Unpaired Access](https://github.com/Sendspin/spec/blob/main/pairing.md#unpaired-access)                                                                           | Accepted, `handle_unpair`          |
| 11  | Scheduled metadata applied immediately                          | [`messaging.md` — `server/state`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serverstate)                                                             | Stage 1b                           |
| 12  | In-place format change flushes buffered audio                   | [`messaging.md` — `stream/start`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamstart)                                                             | Stage 1b                           |
| 13  | `Sink::underruns()` reported but never used                     | — (library contract, no wire field)                                                                                                                                               | Stage 1b                           |
| 14  | `stream/clear` with `from_timestamp` flushes everything         | [`messaging.md` — `stream/clear`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamclear)                                                             | Stage 1b                           |
| 15  | Playout deadlines begin after three clock bursts                | [`messaging.md` — Clock Synchronization](https://github.com/Sendspin/spec/blob/main/messaging.md#clock-synchronization)                                                           | Documented                         |
| 16  | A player volume above 100 is capped, not rejected               | [`roles/player/v1.md` — `server/command` player object](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server--client-servercommand-player-object)                 | Accepted, `clamp_volume_with`      |
| 17  | A transport command before the controller state is not checked  | [`roles/controller/v1.md` — `client/command` controller object](https://github.com/Sendspin/spec/blob/main/roles/controller/v1.md#client--server-clientcommand-controller-object) | Accepted, `check_control`          |
| 18  | A reconnect keeps the last known `active_roles`                 | [`messaging.md` — `server/activate`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serveractivate)                                                       | Accepted, `handshake`              |
| 19  | A malformed control message is ignored, not fatal               | [`messaging.md` — Communication](https://github.com/Sendspin/spec/blob/main/messaging.md#communication)                                                                           | Accepted, `handle_control_message` |

## 1. Client-initiated connections only

**Spec:** `connection.md`, _Establishing a Connection_ and _Client Initiated Connections_. The spec
RECOMMENDS server-initiated connections, requires servers to support both methods and requires a
client to use exactly one of them. A client using client-initiated connections MUST NOT advertise
`_sendspin._tcp`.

**What we do:** `ClientConfig` takes a WebSocket URL (`ws://<server>:8927/sendspin`; a bare address
gets the default endpoint) and `connect` opens one connection to it. There is no advertisement, no
listening socket and no discovery: the client never owns a `_sendspin._tcp` service, so it also never
arbitrates competing servers.

**Why:** 0.1 is a client only. An advertisement obliges the advertiser to accept inbound upgrades,
reject requests carrying `Origin`, arbitrate `playback`/`pairing` activities across connections and
persist a last-playback server — all of which belong to the multi-server work in 0.2. Adding a
listening socket and an mDNS dependency for a mode nobody consumes yet would enlarge the surface
without a test that can hold it.

**Removing it:** implement the server-initiated half — advertise with the `path` (and optional
`name`) TXT records, accept the upgrade on that path, reject any request with an `Origin` header,
apply the admission rules, send `client/goodbye` with `another_server` / `concurrent_attempt` when
displacing or rejecting, and expose a switch so a caller never advertises and connects manually at
the same time. Then delete this entry.

## 2. No `activities` admissibility handling

**Spec:** `messaging.md`, `server/activate`. An activation declares `activities` and `active_roles`
and is _admissible_ only when those form an allowed set for the matched PSK and only a
playback-capable connection carries `active_roles`. An inadmissible activation must be rejected with
`client/goodbye` (`pairing_required`, `unauthorized`) or `pair/abort` (`method_not_supported`).

**What we do:** the session starts the first sync burst once the connection is ready
(`session::attempt`). `apply_activate` records `active_roles`, starts a burst only when a re-added
`player@v1` has no sample yet, and flushes the player stream when the role disappears. It checks
only the pairing half of the table: a pairing activity whose method does not match the matched PSK,
or which this build does not offer, is answered with `pair/abort` reason `method_not_supported`.
The activity set itself is never validated and there is no `client/goodbye` writer, so every other
inadmissible activation is accepted and the session carries on.

**Why:** the allowed set depends on the matched PSK and its category. The Sentinel row alone already
allows four sets — `[]`, `['pairing']`, `['playback']` and `['playback','pairing']` — so this is not
a single case that a bare parser could settle: the playback-capable rule, the re-evaluation of
`active_roles` on later activations and the two rejection paths all have to exist first. The
candidate set can hold this client's pairing PSK (`pr`), the records in `Storage` (`lt`) and records a
host passes through `connect_with_psks` (entry 4), so both announcements are reachable and the
allowed set has to be keyed by the matched record's category instead of assuming the Sentinel row.

**Removing it:** add the allowed-set table per PSK category, the playback-capable rule with the
`active_roles` re-evaluation on later activations, and the two rejection paths (stage 1b). Test each
rejection reason against the fake server.

## 3. No `pairing_token()` export

**Spec:** `pairing.md`, _Pairing Token_ and _Pairing PSK Flow_. The pairing PSK MUST be exposed to
the operator as a version-0 token, `SP:0` plus the base32 body of
`client_key (32 bytes) || pairing_psk (32 bytes)`, transliterating `2` to `9`. The bare PSK is not
an acceptable interface.

**What we do:** the client draws the pairing PSK from the CSPRNG, persists it through `Storage` and
offers the Pairing PSK method, but no accessor hands the operator a token: `ControlHandle` carries a
command channel and the level in force, not the identity or the store, so there is no
`pairing_token()`. The encoder (`syncspin_core::pairing::token::encode_v0`) exists and is pinned to
both spec vectors. A host can assemble the token itself from the identity's public key and
`Storage::pairing_psk()`, and `player-pipe --pairing-token` does exactly that.

**Why:** a token is a credential: whoever holds it can pair any server with the client. The accessor
belongs with the rest of the pairing control surface - it has to be documented as a credential, and
its lifetime is the host's UI, not a protocol message. The rest of that surface
(`open_pairing_window`, `release_holdback`) shipped; this getter did not, because it needs the
identity and the store carried into the handle, which the handle does not hold.

**Removing it:** add `pairing_token()` to the control handle, returning the version-0 token built
from the identity's public key and the stored pairing PSK, and test it against the spec's reference
vector plus a decoder round trip that exercises the `2`/`9` transliteration.

## 4. `psk_id` validation deferred to the session layer

**Spec:** `connection.md`, _Encryption_ → _Pre-Shared Key_ and _Sentinel Fallback_. The client
decrypts the first handshake message, compares the announced `psk_id` against the hash of every
candidate PSK of the announced `psk_category`, mixes in the match, fails on a stored-pubkey
mismatch and falls back to the Sentinel PSK on a plain lookup miss.

**What we do:** `syncspin_core::noise` is a byte-level responder. It starts every handshake with the
Sentinel PSK and hands the decrypted message-1 payload back verbatim; the caller may replace the PSK
with `Responder::set_psk` between reading message 1 and writing message 2. The selecting and
validating is the session layer's job: `PskMetadata::parse` rejects an unknown category and a
non-canonical id, and `select_psk` applies the matching key and falls back to the Sentinel key only
on the initial handshake. The candidates come from `pairing::Candidates::load`: the records
`ClientConfig::storage` holds, the records `connect_with_psks` passes (the store wins for a
`server_id` it already knows), and the client's own pairing PSK. That pairing PSK is drawn once,
persisted through `Storage::store_pairing_psk` and offered on every connection; it is a client-wide
credential, so `select_psk` matches it for the announced `pr` id without a `server_id` check, which
is what lets one token pair any number of servers. A stored record still has to match category and
id and then name the `server_id` from `server/init`. A pairing that completes is persisted on
`server/pair-finalize` as a `LongTerm` record, so the next handshake reads it as a stored record.
`connect` passes no explicit records; a store on the config still supplies records and the pairing
PSK, and a host that has neither reaches the guest path. `core` itself enforces none of that.

**Why:** the Noise module owns no storage and no policy, so it cannot enumerate candidate PSKs or
decide what a category mismatch means. Splitting it this way keeps `core` free of file I/O and lets
a host with its own identity store drive selection.

**Consequence while it stands:** a caller that drives `Responder` directly and ignores the payload
completes a handshake against any announced `psk_id`/`psk_category` pair, with no fallback decision
made for it. The client path is covered: the session validates the metadata, checks the category,
id and server id of a stored record, checks the pairing PSK against the announced id alone, and
falls back to the Sentinel key on the initial handshake only.

**Removing it:** give `core` a PSK resolver (a trait the session implements over its storage, passed
into the responder) so the handshake cannot finish without a matched category and id, and enforce
the record's `server_id` check and the fallback-on-miss rule there. Then narrow `set_psk` or delete
it.

## 5. Code pairing is a feature and the CPace layer is unaudited

**Spec:** `pairing.md`, _PAKE_, _Dynamic Pairing Code Flow_ and _Static Pairing Code Flow_ — a
SHOULD, not a MUST. `CPACE-X25519-SHA512` per `draft-irtf-cfrg-cpace-21`, with the server as `A`,
the client as `B` and the `MCF` generator, plus the wrapped-PSK exchange.

**What we do:** both flows are implemented in `syncspin-client` behind the `pairing-code` feature
and offered only when a `Storage` can persist the record they produce - and, for the dynamic flow,
when the host advertises an emission format and an out-channel. The static flow is gated by the
pairing window `ControlHandle::open_pairing_window` opens; the dynamic flow is gated by its
20-round limit and `ControlHandle::release_holdback`. The CPace layer is built here - `x25519-dalek`,
`elligator2` for the `MCF` map, SHA-512 - because no crate was found that matched draft-21 with the
spec's `MCF` and `sid` layout. It is pinned to the draft's vectors and the spec's `sid` construction.
The wrapping uses ChaCha20-Poly1305, fixed in `syncspin-core::pairing::wrap`, which is correct for
`25519_ChaChaPoly_SHA256`, the only suite this build negotiates; offering
`25519_AESGCM_SHA256` would need the AEAD selected per connection instead. The specification
publishes no test vectors for the dynamic code derivation: the tests pin a vector computed from the
spec's formula and run the flow end to end against the fake server only.

**The CPace and wrapping layer has not had an external review.** That is the reason this entry still
exists after both flows shipped.

**Why:** a default build must not advertise a method whose PAKE it does not carry, and unaudited
crypto stays out of the default surface. A host that does not enable the feature gets the mandatory
Pairing PSK flow only; one that enables it accepts that the layer is new code with draft vectors but
no review.

**Removing it:** get the layer reviewed externally. Then decide whether the feature becomes default:
while it is not, a default build departs from the SHOULD by offering only the mandatory method. Select
the AEAD from the negotiated suite when a second suite is offered, and add spec vectors for the
dynamic derivation when they are published.

## 6. `group/update` is not the state source

**Spec:** `messaging.md`, `group/update`. The server MUST send it after the first activation and on
every change, carrying all fields each time; a `group_id` that is not 43 base64url characters is a
protocol error and the client MUST close the connection.

**What we do:** `Incoming` has no `group/update` variant, so the session treats it as an unknown
type and ignores it. The fields it carries are therefore never seen: the `PlaybackState` event is
filled from `server/state.controller` (volume, mute, supported commands) and the track from
`server/state.metadata`. `server/state` is no substitute — it carries only the `metadata` and
`controller` role state — so neither `playback_state` nor `group_id` is known at all, and a malformed
`group_id` cannot be rejected.

**Why:** the field was absent from the protocol code this library was extracted from, and the
message set was frozen before the session loop existed. Leaving it out was preferred over
half-handling the authoritative state source.

**Removing it:** add the type, treat it as the authoritative `PlaybackState` and `group_id` source,
validate the `group_id` length and charset, and close on a violation. Delete this entry when that
lands.

## 7. No failure diagnostics from `server/error`

**Spec:** `messaging.md`, `server/error` and `connection.md`, _Failure Handling_. The server sends it
in place of `server/init` when it rejects `client/init`, then closes; the reason is
`unsupported_version`, `unsupported_suite` or `malformed`.

**What we do:** `server/error` has no variant in `Incoming`, so `Incoming::parse` reports it as an
unknown type and the handshake — which expects `server/init` next — fails with `expected a cleartext
server/init`. The reason (`unsupported_version`, `unsupported_suite`, `malformed`) never reaches the
caller, who sees only that generic connect error.

**Why:** the message set was frozen at the types the extracted code used, which never included
`server/error`; a server that rejects `client/init` is rare enough that the guest session was built
without it. A dedicated error type is worth adding together with the disconnect reasons, not before.

**Removing it:** add the type and a typed connect error carrying the reason so a caller can act on
`unsupported_version` rather than guessing. The server half arrives with `syncspin-server`.

## 8. No `_sendspin-server._tcp` discovery

**Spec:** `connection.md`, _Client Initiated Connections_. A client that initiates the connection
SHOULD discover the server over mDNS (`_sendspin-server._tcp`, `path` TXT record REQUIRED, `name`
OPTIONAL) and connect to the advertised address and path, ignoring loopback and unspecified
addresses.

**What we do:** the caller passes the URL. There is no mDNS client, no service browser and no
dependency that could provide one; the only discovery today is whatever the consumer does outside
the library.

**Why:** discovery is one half of the 0.2 work and would drag an mDNS stack into a build that must
stay small for the ARM target, while giving the caller a fallback URL anyway. A wrong or filtered
mDNS answer is also indistinguishable from a wrong URL at this stage, so a library-side browser would
add a failure mode without a test that could hold it.

**Removing it:** browse `_sendspin-server._tcp`, apply the loopback/unspecified filter and the
`path` rule, and offer the result to the builder as a candidate list the caller can still override.
The manual URL stays the fallback, as the spec allows an implementation-defined choice between
discovered servers.

## 9. No `client/goodbye` writer

**Spec:** `messaging.md`, `client/goodbye`. A client sends it before a graceful close to say why it
is disconnecting (`another_server`, `shutdown`, `restart`, `user_request`, `unauthorized`,
`pairing_required`, `concurrent_attempt`, `unpaired`). The spec permits a deliberate close without
it, except that a client leaving one server for another MUST send `another_server`.

**What we do:** the library has no writer for the message and no typed reason. A connection that is
dropped looks the same to the server whatever the caller intended, so the server cannot tell a
shutdown from a restart, and the one MUST that can arise — a client leaving one server for another —
cannot be expressed. The one place the protocol asks this client for a goodbye today is
`server/unpair`, where the reason would be `unpaired`: `session::handle_unpair` removes the record,
reports `Event::Unpaired` and closes the socket without one, so the server learns nothing beyond the
close (entry 10). `concurrent_attempt` is unreachable as a goodbye reason for a second reason: the
process holds one connection, so no other pairing attempt can arrive to be turned away, and the
reason waits for multi-server support or a second process.

**Why:** the reasons are only actionable once a close path exists and multiple servers or
displacement exist. The guest session ends by dropping the socket, and a writer without the call
sites would be an API nobody can reach.

**Removing it:** add the typed writer and send it on the paths that have a reason (user request,
shutdown, restart, another server), then test on the fake server that the server sees the reason
before the close.

## 10. No unpaired-access switch and no goodbye after `server/unpair`

**Spec:** `pairing.md`, _Unpaired Access_ and _Pairing Records_, and `messaging.md`, `server/unpair`
and `client/goodbye`. Whether a client admits unpaired access is a local setting, advertised in
`client/hello` as `unpaired_access.enabled`; a client that stops admitting it closes an unpaired
connection with `client/goodbye` reason `pairing_required`. On `server/unpair` the client removes the
matched pairing record, sends `client/goodbye` reason `unpaired` and closes. A server that announces
a `psk_id` the client does not hold receives the Sentinel Fallback's authenticated
credential-mismatch signal, and the client is expected to surface the mismatch to its operator.

**What we do:** the signal and the record handling are implemented. `session::select_psk` sets its
`credential_mismatch` flag when the initial handshake falls back to the Sentinel key although the
server named another credential, and `session::attempt` reports
`Event::PairingRequired { server_id, reason: CredentialMismatch }` once per connection, after
`Event::Connected` and before the first activation; a plain Sentinel announcement, a matched record
and the pairing PSK all report nothing, and `Event::PairingRequired` is never sent twice.
`Incoming::ServerUnpair` is decoded as `server/unpair`, and `Session::handle_unpair` removes the
record through `Storage::remove_pairing`, emits `Event::Unpaired { server_id }` and ends the
connection with the disconnect reason `Ending::Unpaired`. A session that is unpaired - Sentinel-keyed
or pairing-PSK-keyed - ignores the message, as the spec requires. A record the host passed through
`connect_with_psks` is not in a store the crate may write, so the event reports it and the host has
to drop it. `server_unpair_drops_the_record_and_ends_the_connection`,
`an_unpair_on_an_unpaired_session_is_ignored`,
`an_unheld_psk_id_is_reported_once_as_a_credential_mismatch` and
`a_plain_guest_handshake_does_not_ask_for_pairing` pin the observable behaviour, and
`a_credential_mismatch_is_reported_once_per_connection` pins the once-per-connection rule.

Two parts are still missing. Unpaired access is always admitted: `client/hello` carries
`unpaired_access: { enabled: true }` unconditionally, there is no setting that turns it off, and so
no `pairing_required` close exists. And the close after `server/unpair` carries no `client/goodbye`
reason `unpaired`, because the crate has no writer for that message (entry 9): the server sees the
socket close and learns nothing more.

**Why:** the goodbye reasons are only actionable once a close path with a typed reason exists, and
the unpaired-access switch is a manufacturer decision the host exposes in its own UI; both belong to
the pairing control surface rather than to the record handling. Removing the record and reporting the
mismatch do not depend on either, so they ship first.

**Removing it:** add the `client/goodbye` writer with a typed reason and send `unpaired` in
`Session::handle_unpair` before the close; expose the unpaired-access setting on `ClientConfig`,
advertise it in `client/hello`, and close an unpaired connection with `pairing_required` when it is
turned off. Test both on the fake server by asserting the goodbye reason arrives before the close.

## 11. Scheduled metadata applied immediately

**Spec:** `messaging.md`, `server/state` → `metadata.timestamp`. The field is the server time at
which the metadata becomes valid; a client that buffers audio ahead of playout should schedule the
change rather than apply it on arrival.

**What we do:** `handle_state` emits `Event::Track` as soon as the message is decoded, so the
timestamp is ignored. A title or artwork overlay can be ahead of the audible position by the buffer
depth (at least the 250 ms the client asks for, more when the sink buffers).

**Why:** scheduling needs a per-role event queue with a timer tied to the clock filter, which the
session does not have yet; the extracted consumer treated metadata as immediate. Applying it late
also needs a rule for a change that is superseded before it becomes valid, which belongs with that
queue.

**Removing it:** give metadata its own scheduled queue, compare `timestamp` with `clock.now_us`,
and emit at the mapped deadline. Test a future timestamp, a past one, and a change superseded before
it becomes valid.

## 12. In-place format change flushes buffered audio

**Spec:** `messaging.md`, `stream/start`. The server may send it again with a new format to
reconfigure a running stream.

**What we do:** `handle_stream_start` flushes the sink and opens the new format, so every frame
buffered for the old format is dropped. That is safe - no mixed-format audio is played - but not
gapless: audio already handed to the sink is discarded at the switch.

**Why:** `Sink::open` is the only format-change hook and its contract starts a new stream. A
gapless switch would need a drain-and-swap step or a second output, neither of which the trait
offers, and the current consumer's format does not change mid-stream.

**Removing it:** extend the sink contract with a drain-and-switch path (or a second output), wait
for the old buffer to drain at the switch timestamp, and test a mid-stream change against a sink
that records the boundary.

## 13. `Sink::underruns()` is not used

**Spec:** none; this is the design's sink contract (`docs/design/syncspin-design.md`, _Playout
timing_), which expects underrun counts to feed buffer corrections.

**What we do:** `Sink::underruns` has a default of zero and the session never calls it. "The sink
reports latency and underruns back" is therefore half true: `latency()` fills `output_delay_ms`,
while `underruns()` is inert. A host can implement it for its own diagnostics, but the crate makes
no decision from it.

**Why:** adapting `min_buffer_ms` needs the re-sync and state-reporting loop plus a sink whose
buffers the crate understands; the guest session only reports its initial state. Wiring an unused
number into playback would be an unverified control loop.

**Removing it:** read `underruns()` at each `client/state` report and after a clock burst, grow
`min_buffer_ms` (bounded) when the count rises, and test the reported value against a fake sink that
returns a fixed count.

## 14. `stream/clear` with `from_timestamp` flushes everything

**Spec:** `messaging.md`, `stream/clear`. A `from_timestamp` asks the client to discard the buffered
audio from that server time onward and keep what is earlier; an absent timestamp clears everything.

**What we do:** `handle_stream_clear` flushes the sink regardless of `from_timestamp`, so audio
before the timestamp is dropped too. The announced format stays open for the chunks that follow,
because a clear does not end the stream. The client keeps no timestamped queue of its own; the sink
does, and `Sink::flush` has no "drop from a timestamp" mode. `Event::StreamClear` carries the
timestamp to the host before the flush, so a host that owns a timestamped queue can discard the
suffix itself; the client's own flush still drops everything.

**Why:** a partial drop needs the sink to map server timestamps to its own buffer and discard a
suffix of it; the current trait can only drop everything. The full flush is audible as a short gap
at a seek, but leaving stale audio buffered would be worse.

**Removing it:** add a `Sink::discard_from(&mut self, due: Instant)` (or move the timestamped queue
into the session) and discard only frames whose deadline is at or after the mapped timestamp; test a
clear in the middle of a burst of buffered frames.

## 15. Playout deadlines begin after three clock bursts

**Spec:** `messaging.md`, _Clock Synchronization_. The client estimates the server clock from bursts
of `client/time`/`server/time`, one request at a time, and schedules each frame's playout from that
estimate.

**What we do:** each burst contributes one measurement, the one with the lowest positive
`max_error`. `ClockFilter` has an estimate only after three accepted samples
(`READY_AFTER_SAMPLES`), and the player state goes out when the first burst completes with at least
one measurement, so the report never precedes the filter's first sample. Audio that arrives before
the third burst is handed to the sink with `Instant::now()` instead of a scheduled deadline. With a
responsive server the three bursts follow each other immediately; with lost replies each burst costs
its per-message timeouts first.

**Why:** one measurement per burst is the spec's rule, and a readiness threshold below three would
schedule from a single offset sample with no drift or error estimate. Delivering the audio without a
deadline is the only honest option while no estimate exists; `Sink::write` documents "now" as "play
as soon as possible".

**Removing it:** keep bursting until the filter is ready (already done) and, if a deadline is
required earlier, seed the filter from the first three bursts before reporting the state or relax
readiness with an explicit accuracy bound; test deadlines with one, two and three answered
requests.

## 16. A player volume above 100 is capped, not rejected

**Spec:** `roles/player/v1.md`, `server/command` player object. `volume` is an integer in the range
0-100, and `messaging.md` says a field value outside the fixed range its definition gives is a
protocol error: the receiver MUST close the connection.

**What we do:** a `server/command` carrying a volume of 101-255 - the wire field is a `u8`, so such
a value decodes - is applied as 100 and reported as 100. The policy in
`ClientConfig::volume_policy` (`clamp_volume_with`, with the fixed rule as `clamp_volume` and the
default) limits both the level in force and the requested one before it applies the step rule, so the
client's own `client/state` stays inside the range a conformant server accepts, and the connection
stays open. `a_server_volume_above_the_protocol_range_is_capped` pins the behaviour.

**Why:** closing the connection would silence playback over a value the server got wrong, and the
right audible outcome - full volume, no mute change - is unambiguous. The alternative, closing,
belongs with the failure handling that `server/error` and typed protocol errors would introduce
(entry 7); until then a cap is the failure mode that keeps the player usable.

**Removing it:** give `clamp_volume_with` and `handle_command` a typed rejection path and close the
connection with a protocol-error reason once that path exists, or reject the value at the parser
with the same effect. Test the closed connection instead of the capped level.

## 17. A transport command before the controller state is not checked

**Spec:** `roles/controller/v1.md`, `client/command` controller object. `command` MUST be one of
the values listed in `supported_commands` from the latest controller state the client received in
`server/state`.

**What we do:** the session records `controller.supported_commands` whenever a controller state
arrives and refuses a transport command outside that set (`check_control`,
`a_transport_command_must_be_advertised_by_the_server`). Before the first controller state the set
is unknown, so a command is sent instead of refused; the server ignores a command it does not
accept, so the observable outcome is the same, but the client has broken the MUST in that window.

**Why:** a host may offer a play button before the first `server/state` arrives - it has no other
source of truth - and refusing there would make the button dead for an unbounded time. The window
closes with the first controller state, which the server sends promptly after activation.

**Removing it:** expose the known commands on the connection (an `Event::State` snapshot or a
`ControlHandle` query) and let the host disable its buttons until the first state arrives, then
refuse every command while the set is unknown.

## 18. A reconnect keeps the last known `active_roles`

**Spec:** `messaging.md`, `server/activate`. `active_roles` is required on the first activation of a
connection and persists across later activations that omit it; a client treats a first
`server/activate` that omits it as carrying an empty `active_roles`.

**What we do:** the connection carries the roles of the session that ended into the next attempt
(`Carried::active_roles`), and the handshake uses them when the first activation omits
`active_roles` (`handshake`, `activate.active_roles.unwrap_or_else(|| previous_roles.to_vec())`).
The `player@v1` role therefore stays active across a reconnect even when the server omits the field:
the new session reports its `client/state` and starts its clock burst as if the roles had been
announced. Roles the client has no `client/state` object for - `metadata@v1` and `controller@v1` -
are kept in the set but produce no state of their own.
`an_activation_without_roles_keeps_the_roles_of_the_previous_connection` pins the player case: the
second connection's first activation carries no roles, and the client still reports its player
state.

**Why:** the previous connection had those roles, so treating them as empty would silence a player
whose server merely repeats a non-conformant activation. Closing the connection or dropping the
roles would punish the audible output for a field the server is required to send, and a reconnect
is exactly when a silent player is hardest to notice.

**Removing it:** treat an omitted first `active_roles` as empty, as the spec says, and wait for the
server to send a conformant activation; test that no `client/state` and no audio follow until it
does.

## 19. A malformed control message is ignored, not fatal

**Spec:** `messaging.md`, _Communication_ and _Binary Message ID Structure_. A field value in a
recognized message that is outside the fixed range or length limit its definition gives is a
protocol error: the receiver MUST close the connection. A binary message with id `0` whose body is
not a valid UTF-8 JSON object with a `type` string and a `payload` object is a protocol error too.

**What we do:** `Session::receive` classifies a completed transport message by its binary id and
hands the control kind - id `0` - to `Session::handle_control_message`, which parses it with
`Incoming::parse`. A body that does not decode is written to stderr and dropped: a truncated
envelope, JSON that is not an object, and a known `type` whose payload does not deserialize, such as
`server/command` with `volume: 300`. The session, its clock and its audio continue. One class is
exempt: `session::names_pairing_message` reads the envelope's `type` before the payload, and a decode
failure for one of the five pairing types - `server/pair-init`, `server/pair-auth`,
`server/pair-confirm`, `server/pair-finalize` and `pair/abort` - closes the connection instead,
because a half-open pairing attempt must not continue; every other type keeps the lenient path.
`a_malformed_pairing_message_is_a_protocol_error` pins that exception. Every framing rule stays
strict: a body that is not valid UTF-8, an empty plaintext, a malformed audio chunk header, a bad
fragment sequence and an oversize reassembly all end the connection.
`a_malformed_control_message_is_ignored` pins the lenient path; `a_malformed_audio_header_is_a_protocol_error`
and the fragmentation tests pin the strict ones.

The leniency covers decode failures only: a message that decodes but is unusable is still a protocol
error. `session::admits_pairing` returns an error for a `server/activate` that declares the
`pairing` activity without its `pairing` parameters, which closes the connection instead of
guessing - the alternative would leave the server waiting for a `client/pair-init` the client never
sends - and `a_pairing_activity_without_parameters_ends_the_attempt_with_an_error` pins it.

**Why:** the extracted consumer depended on the leniency: one bad field from the server should not
silence playback, and closing turns a single message into a gap plus a reconnect. A message the
client cannot decode carries nothing it could act on, so dropping it loses no information the
client could have used. The stderr line is the only trace, and it names the parse error, never key
material.

**Removing it:** decode every control message against a typed error and close the connection with a
protocol-error reason once the close path carries one (`server/error`, entry 7); turn the lenient
branch into a typed protocol error and flip both tests.

## How to update this file

- Every PR that adds, narrows or closes a deviation updates the summary table and the matching
  section in the same commit.
- Quote the spec section by file and heading, and link the anchor; if the spec revision moves the
  heading, fix the link rather than dropping it.
- State the current behaviour as the code does it, not as the design intends it. Name the function,
  type or test that shows it.
- Add or update a test that pins observable behaviour before claiming a deviation is harmless. If
  nothing can be tested yet, say so in the entry.
- Closing a deviation means deleting its section and its table row, and recording the closure in the
  changelog entry of the commit that closes it — a `feat` or other `change` commit, because
  `cliff.toml` skips `docs:` commits.
