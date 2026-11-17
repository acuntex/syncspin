# Spec deviations

`syncspin` targets the published [Sendspin specification](https://github.com/Sendspin/spec). Every
place where this library knowingly departs from it is listed here, with the spec section it
concerns, the reason for the departure and what closing the gap requires.

A deviation is only acceptable when it is in this file and, where the behaviour is observable,
pinned by a test. "Not implemented yet" entries are staged work, not a claim that the deviation is
harmless.

## Summary

| #   | Area                                                                             | Spec section                                                                                                                                                                      | Status                                      |
| --- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| 1   | Server-initiated connections: last-playback server not persisted                 | [`connection.md` — Establishing a Connection](https://github.com/Sendspin/spec/blob/main/connection.md#establishing-a-connection)                                                 | Open, no last-playback record               |
| 3   | `psk_id` validation deferred to the session layer                                | [`connection.md` — Pre-Shared Key](https://github.com/Sendspin/spec/blob/main/connection.md#pre-shared-key)                                                                       | Accepted, `select_psk`                      |
| 4   | Code pairing behind a feature; CPace layer unaudited                             | [`pairing.md` — PAKE](https://github.com/Sendspin/spec/blob/main/pairing.md#pake)                                                                                                 | Accepted, `pairing-code`                    |
| 6   | Approval is not persisted across restarts                                        | [`pairing.md` — Unpaired Access](https://github.com/Sendspin/spec/blob/main/pairing.md#unpaired-access)                                                                           | Open, server lifetime                       |
| 7   | Scheduled metadata applied immediately                                           | [`messaging.md` — `server/state`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serverstate)                                                             | Stage 1b                                    |
| 8   | In-place format change flushes buffered audio                                    | [`messaging.md` — `stream/start`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamstart)                                                             | Stage 1b                                    |
| 9   | `Sink::underruns()` reported but never used                                      | — (library contract, no wire field)                                                                                                                                               | Stage 1b                                    |
| 10  | A stream-clear timestamp is honoured only by sinks that implement `discard_from` | [`messaging.md` — `stream/clear`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamclear)                                                             | Accepted, `Sink::discard_from`              |
| 11  | Playout deadlines begin after three clock bursts                                 | [`messaging.md` — Clock Synchronization](https://github.com/Sendspin/spec/blob/main/messaging.md#clock-synchronization)                                                           | Documented                                  |
| 12  | A player volume above 100 is capped, not rejected                                | [`roles/player/v1.md` — `server/command` player object](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server--client-servercommand-player-object)                 | Accepted, `clamp_volume_with`               |
| 13  | A controller command before the controller state is not checked                  | [`roles/controller/v1.md` — `client/command` controller object](https://github.com/Sendspin/spec/blob/main/roles/controller/v1.md#client--server-clientcommand-controller-object) | Accepted, `check_control`                   |
| 14  | A reconnect keeps the last known `active_roles` while playback-capable           | [`messaging.md` — `server/activate`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serveractivate)                                                       | Accepted, `handshake`                       |
| 15  | A malformed control message is ignored, not fatal                                | [`messaging.md` — Communication](https://github.com/Sendspin/spec/blob/main/messaging.md#communication)                                                                           | Accepted, `handle_control_message`          |
| 16  | A server keeps an unavailable client in the group                                | [`messaging.md` — `client/state`](https://github.com/Sendspin/spec/blob/main/messaging.md#server-behavior-when-a-client-becomes-unavailable-available-false)                      | Open, one group                             |
| 17  | The server's stream start lead is one fixed value                                | [`messaging.md` — `stream/start`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamstart)                                                             | Open, shared timeline                       |
| 19  | A foreign `group_id` is accepted unless strict mode is set                       | [`messaging.md` — `group/update`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-groupupdate)                                                             | Accepted, `strict_group_id`                 |
| 20  | Live unpaired-access changes are not applied to a running connection             | [`pairing.md` — Unpaired Access](https://github.com/Sendspin/spec/blob/main/pairing.md#unpaired-access)                                                                           | Open, `pairing_required`/`restart` goodbyes |

## 1. Server-initiated connections: the last-playback server is not persisted

**Spec:** `connection.md`, _Establishing a Connection_ and _Server Initiated Connections_. The spec
RECOMMENDS server-initiated connections, requires servers to support both methods and requires a
client to use exactly one of them. A client that advertises `_sendspin._tcp` MUST advertise the port
and the `path` TXT record, reject an upgrade carrying an `Origin` header and MUST NOT also connect
manually. The _Multiple servers_ section then arbitrates several connections: at most one with
`playback` and one with `pairing`, a provisional connection that never activates is dropped after 30
seconds, and a displaced or rejected connection gets `client/goodbye`.

**What we do:** with the `discovery` feature the client implements the server-initiated half:
`advertise` publishes `_sendspin._tcp` with the bound port and the `path` and `name` TXT records
through a host-supplied `Discovery`, accepts the inbound upgrade, answers any request carrying an
`Origin` header with a 403, and runs the same session as a dialled connection. A configuration that
advertises refuses to dial, so the two methods never run side by side. The client admits one
connection at a time, which the spec permits. A second server that connects while the first session
is live is no longer queued: the client completes its handshake in a task of its own, then sends
`client/goodbye` reason `concurrent_attempt` - or `pair/abort` with the same reason when the
activation declares the `pairing` activity - and closes, as the rejection rule requires. A
provisional connection that does not reach its first `server/activate` within 30 seconds is dropped.
`a_second_server_is_rejected_with_concurrent_attempt` pins the rejection.

The server's side is implemented too. With a `Discovery` backend it publishes
`_sendspin-server._tcp` with the bound port, the `path` and `name` TXT records, browses
`_sendspin._tcp` and dials the clients it finds without an `Origin` header.
`a_server_record_has_the_service_the_port_the_path_and_the_name` and
`a_discovered_client_is_connected_without_an_origin_header` pin the record and the dialled direction.
Exclusivity is the client's rule; the server does not merge a dialled connection with an inbound
one.

What remains is persistence of the last-playback server. The specification says a client MUST store
the `server_id` of the server most recently admitted with `playback` in its activities; this crate
has no `Storage` method for it, and the cap of one admitted connection means the both-empty tie-break
that value decides is not reachable. The MUST is still unimplemented even though it currently has no
observable effect.

**Why:** capping the client at one connection is what `connection.md` allows ("A client MAY cap how
many connections it admits at once"), and one group per server makes several simultaneous sessions
useless for playback. With the cap there is no equal-ranked conflict for a last-playback server to
decide, so the ranking and displacement rules reduce to always rejecting the second connection.

**Removing it:** add a `Storage` method for the last-playback `server_id`, record it whenever an
admitted connection whose `activities` include `playback` is activated, and consult it in the
both-empty tie-break once the cap rises above one. Then delete this entry.

## 3. `psk_id` validation deferred to the session layer

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

## 4. Code pairing is a feature and the CPace layer is unaudited

**Spec:** `pairing.md`, _PAKE_, _Dynamic Pairing Code Flow_ and _Static Pairing Code Flow_ — a
SHOULD, not a MUST. `CPACE-X25519-SHA512` per `draft-irtf-cfrg-cpace-21`, with the server as `A`,
the client as `B` and the `MCF` generator, plus the wrapped-PSK exchange.

**What we do:** both flows are implemented in `syncspin-client` behind the `pairing-code` feature
and offered only when a `Storage` can persist the record they produce - and, for the dynamic flow,
when the host advertises an emission format and an out-channel. The static flow is gated by the
pairing window `ControlHandle::open_pairing_window` opens; the dynamic flow is gated by its
20-round limit and `ControlHandle::release_holdback`. `syncspin-server` carries the same feature
and runs the server half of both flows: `ServerHandle::start_pairing` refuses a code method without
it, and with it the server is CPace role `A`. The CPace layer is built here - `x25519-dalek`,
`elligator2` for the `MCF` map, SHA-512 - because no crate was found that matched draft-21 with the
spec's `MCF` and `sid` layout. It is pinned to the draft's vectors and the spec's `sid` construction.
The wrapping takes the connection's cipher suite, so `25519_ChaChaPoly_SHA256` seals with
ChaCha20-Poly1305 and `25519_AESGCM_SHA256` with AES-256-GCM, both through the resolver `snow`
already brings. `syncspin-core` has both suites and refuses a name it does not have; the client in
this workspace still announces `25519_ChaChaPoly_SHA256` in `client/init`, so AES-GCM is reachable
from `syncspin-core` only until a client opts into it. The specification publishes no test vectors
for the dynamic code derivation: the tests pin a vector computed from the spec's formula and run the
flow end to end against the fake server only.

**The CPace and wrapping layer has not had an external review.** That is the reason this entry still
exists after both flows shipped.

**Why:** a default build must not advertise a method whose PAKE it does not carry, and unaudited
crypto stays out of the default surface. A host that does not enable the feature gets the mandatory
Pairing PSK flow only; one that enables it accepts that the layer is new code with draft vectors but
no review.

**Removing it:** get the layer reviewed externally. Then decide whether the feature becomes default:
while it is not, a default build departs from the SHOULD by offering only the mandatory method. Add
spec vectors for the dynamic derivation when they are published.

## 6. Approval is not persisted across restarts

**Spec:** `pairing.md`, _Unpaired Access_. Operator approval is granted per `client_id`; it SHOULD
persist, MUST be revocable, and MUST be discarded on a successful pairing.

**What we do:** `Registry::approved` is an in-memory set owned by the running server. It survives a
reconnect and is dropped by `ServerHandle::revoke_approval`, by `ServerHandle::unpair` and by a
successful pairing, but it is never written anywhere, so stopping the server forgets every approval.
`an_unapproved_client_gets_no_roles_and_no_audio` and
`revoking_an_approval_takes_the_roles_and_the_audio_away` pin the gate and the revocation; no test
covers persistence because there is no store to read.

**Why:** approval is an operator decision about one client, and the crate has no storage for it:
`PairingStore` is keyed by `client_id` but holds only the long-term PSKs of paired clients, and a
host that wanted approvals to survive a restart would need a second trait or a wider record.
Remembering it for the process keeps the MUSTs that are testable - gating, revocation and the pairing
reset - while the SHOULD waits for a store the host owns.

**Removing it:** add an approval store the host supplies (or a flag on `PairingStore`) keyed by
`client_id`, write on `approve`, remove on `revoke_approval`, `unpair` and a completed pairing, and
test that a fresh server reads the approval back.

## 7. Scheduled metadata applied immediately

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

## 8. In-place format change flushes buffered audio

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

## 9. `Sink::underruns()` is not used

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

## 10. A stream-clear timestamp is honoured only by sinks that implement `discard_from`

**Spec:** `messaging.md`, `stream/clear`. A `from_timestamp` asks the client to discard the buffered
audio from that server time onward and keep what is earlier; an absent timestamp clears everything.

**What we do:** `handle_stream_clear` emits `Event::StreamClear` and then calls
`Sink::discard_from` with the timestamp mapped through the clock estimate, so a sink that implements
it drops only the audio due at or after that deadline. While no estimate is ready, for a timestamp
already in the past, and when the mapping would overflow, the deadline is `Instant::now()`, which
drops everything buffered; a clear without a timestamp still flushes. The
provided default calls `Sink::flush`, so a sink without its own timestamped queue keeps dropping
everything. The announced format stays open for the chunks that follow, because a clear does not end
the stream. `a_clear_with_a_timestamp_maps_the_deadline_once_the_clock_is_ready`,
`a_clear_before_the_clock_is_ready_discards_from_now` and
`a_sink_without_its_own_discard_flushes_everything` pin the mapped deadline, the no-estimate
fallback and the default.

**Why:** a partial drop needs the sink to map server timestamps to its own buffer and discard a
suffix of it. The crate holds no timestamped queue - the sink owns the buffered audio and its
deadlines - so it cannot discard that suffix itself; the hook is the one operation only the sink can
perform. A sink that does not override it still drops everything, which is audible as a short gap at
a seek.

**Conforming sink:** implement `discard_from` by comparing `due` with the playout deadline of each
buffered frame, dropping the frames at or after it and keeping the earlier ones. It must succeed when
no stream is open or no queue exists — a clear can arrive before `stream/start` or after `stream/end`
— and an empty queue discards nothing. The default already matches `flush`, so a sink that leaves it
out is the documented everything-drop, not a silent failure.

## 11. Playout deadlines begin after three clock bursts

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

## 12. A player volume above 100 is capped, not rejected

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
belongs with the failure handling that typed protocol errors would introduce; until then a cap is
the failure mode that keeps the player usable.

**Removing it:** give `clamp_volume_with` and `handle_command` a typed rejection path and close the
connection with a protocol-error reason once that path exists, or reject the value at the parser
with the same effect. Test the closed connection instead of the capped level.

## 13. A controller command before the controller state is not checked

**Spec:** `roles/controller/v1.md`, `client/command` controller object. `command` MUST be one of
the values listed in `supported_commands` from the latest controller state the client received in
`server/state`.

**What we do:** the session records `controller.supported_commands` whenever a controller state
arrives and refuses a controller command outside that set (`check_control`,
`a_transport_command_must_be_advertised_by_the_server`). Before the first controller state the set
is unknown, so a command is sent instead of refused; the server ignores a command it does not
accept, so the observable outcome is the same, but the client has broken the MUST in that window.
`seek_relative` shares that window: an offset needs no range, so nothing has to be known first.
Absolute `seek` is the deliberate exception - it additionally requires the seekable range from the
same controller state, and with no range known yet it is refused before the first controller state
rather than sent unvalidated.

**Why:** a host may offer a play button before the first `server/state` arrives - it has no other
source of truth - and refusing there would make the button dead for an unbounded time. The window
closes with the first controller state, which the server sends promptly after activation.

**Removing it:** expose the known commands on the connection (an `Event::State` snapshot or a
`ControlHandle` query) and let the host disable its buttons until the first state arrives, then
refuse every command while the set is unknown.

## 14. A reconnect keeps the last known `active_roles` while playback-capable

**Spec:** `messaging.md`, `server/activate`. `active_roles` is required on the first activation of a
connection and persists across later activations that omit it; a client treats a first
`server/activate` that omits it as carrying an empty `active_roles`.

**What we do:** the connection carries the roles of the session that ended into the next attempt
(`Carried::active_roles`), and the handshake uses them when the first activation omits
`active_roles` (`handshake`, `activate.active_roles.unwrap_or_else(|| previous_roles.to_vec())`).
Whether the seeded set survives depends on `apply_activate`, the handler every activation passes
through: its guard calls `admit_activation`, which returns only the verdict, and a separate block
then clears the carried roles when an activation that omits `active_roles` leaves the connection not
playback-capable. On a
paired connection - or a guest whose setting admits unpaired access - the `player@v1` role therefore
stays active across a reconnect even when the server omits the field: the new session reports its
`client/state` and starts its clock burst as if the roles had been announced. A guest with
`unpaired_access` off that reconnects into an activation whose activity set has no `playback` is not
playback-capable, so the carried roles are cleared and no state or burst follows. Roles the client
has no `client/state` object for - `metadata@v1` and `controller@v1` - are kept in the set but
produce no state of their own.
`an_activation_without_roles_keeps_the_roles_of_the_previous_connection` pins the player case, and
covers only the setting-on case: the second connection's first activation carries no roles while
`unpaired_access` is on, and the client still reports its player state.

**Why:** the previous connection had those roles, so treating them as empty would silence a player
whose server merely repeats a non-conformant activation. Closing the connection or dropping the
roles would punish the audible output for a field the server is required to send, and a reconnect
is exactly when a silent player is hardest to notice.

**Removing it:** treat an omitted first `active_roles` as empty, as the spec says, and wait for the
server to send a conformant activation; test that no `client/state` and no audio follow until it
does.

## 15. A malformed control message is ignored, not fatal

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
protocol-error reason once the close path carries one (`server/error` exists; the client still keeps
the lenient path); turn the lenient branch into a typed protocol error and flip both tests.

## 16. A server keeps an unavailable client in the group

**Spec:** `messaging.md`, _`client/state`_ and _Server behavior when a client becomes unavailable
(`available: false`)_. A client that reports `available: false` is moved to a new solo group with
`group/update`, and `stream/end` is sent for every active stream; it rejoins its previous group only
through an explicit `switch`, never automatically.

**What we do:** the server has one group. A member that reports `available: false` stays in it; the
group stops sending it audio, and `Group::report_client_state` records the report without touching
group volume, mute or playback. No `group/update` and no `stream/end` follow, and a member that
reports `available: true` again receives the running stream without an announcement, because its
stream was never ended. `a_member_that_reports_itself_unavailable_receives_no_audio` pins the
withheld audio, and `group_state_applies_to_every_member_and_a_report_is_not_a_command` pins that a
report never becomes a command.

**Why:** a solo group and the `switch` command cycle need several groups per server, which this
milestone does not have; the one thing that must not happen - audio to a client that says it will
not play it - is kept, and the rest of the rule cannot be followed without the groups it names.

**Removing it:** add solo groups, move an unavailable member into one, send the `group/update` and
`stream/end` the spec requires in that order, and serve the controller's `switch` command; then flip
the first test so an unavailable member ends in a stopped solo group.

## 17. The server's stream start lead is one fixed value

**Spec:** `messaging.md`, _`stream/start`_. After a role that defines a `client/state` object is
added to `active_roles`, the server MUST wait for that update before starting the role's stream, and
each role's stream configuration is derived from what the client reports - for the player, its
`required_lead_time_ms` and `min_buffer_ms`.

**What we do:** the stream waits for the update (the group announces nothing to a member without its
`player` object) but schedules the first sample at `START_LEAD`, 200 ms after the stream opens, for
every member. The reported lead and buffer are read but not used. The group fans one timeline out to
every member, so all of them share the timestamps; the tests
`two_players_receive_the_same_frames` and `a_player_hears_nothing_before_it_reports_its_state` pin
that.

**Why:** a stream is one timeline: starting it at each member's own reported lead would give the
members different timestamps for the same audio, which the server fan-out and the group design do
not allow. The honest fixes are a lead derived from the slowest ready player, or a per-member
announcement ahead of the shared first sample.

**Removing it:** schedule a new stream at the largest `required_lead_time_ms` among the players that
are ready when it opens, wait for a late member's report before announcing to it, and test a stream
with two members whose reported leads differ.

## 19. A foreign `group_id` is accepted unless strict mode is set

**Spec:** `messaging.md`, `group/update`. `group_id` is 32 server-chosen bytes encoded as 43
unpadded base64url characters. A field value outside the fixed range or length its definition
gives is a protocol error, and the receiver MUST close the connection.

**What we do:** the default configuration treats a non-canonical `group_id` as an opaque string
and keeps the connection open, provided it is non-empty, at most 128 bytes and free of control
characters. A value that is empty, longer than 128 bytes or carries a control character is still a
protocol error. The first tolerated value on a connection is reported as
`Event::GroupIdNotCanonical { len }`; later non-canonical updates on the same connection are
accepted silently, and a canonical identifier reports nothing.
`a_foreign_group_id_is_accepted_and_reported_once` pins the acceptance, the event and the
once-per-connection rule, and `an_absurd_group_id_is_a_protocol_error` pins the remaining bound.
`ClientConfig::strict_group_id` restores the spec's behaviour: with it set, any value that is not
43 base64url characters closes the connection and ends the attempt. That path is pinned by
`a_group_update_with_a_malformed_group_id_is_a_protocol_error_in_strict_mode`.

**Why:** Music Assistant 2.10, the real server this library is tested against, sends a standard
UUID in `group_id` rather than the 43-character encoding. Closing the connection on it makes the
client unusable against that server: it connects, receives `group/update`, closes and retries
forever. Accepting the value keeps playback working while the server is not conformant; the
identifier is public, not key material.

**What it costs:** a host and any consumer cannot assume the identifier is 32 random bytes. Code
that decodes it as base64url, compares it with a locally derived group, or uses its length as a key
must handle the tolerated form. The crate itself only stores and reports it as a string, and the
server side still generates the canonical 43-character form.

**Removing it:** once Music Assistant sends a canonical `group_id`, delete the tolerance, the
event, the `strict_group_id` field and this entry. Until then a deployment that needs the spec's
strictness sets `strict_group_id: true`; a client compiled against a conformant server keeps the
default and never sees the event.

## 20. Live unpaired-access changes are not applied to a running connection

**Spec:** `pairing.md`, _Unpaired Access_. A client that stops admitting unpaired access closes the
relying connections that depended on it with `client/goodbye` reason `pairing_required`. The
`restart` goodbye is the enabled direction: a client that admits unpaired access MAY close and
re-establish a connection with `client/goodbye` reason `restart`, and the new session runs under the
new setting.

**What we do:** the setting is read from the configuration the connection was built with
(`ClientConfig::unpaired_access`), at the guard's call site in `apply_activate`, which passes it to
`admit_activation`; `admit_activation` only returns the verdict. A change the host makes to its own
configuration does not reach a session that is already running: a host that wants a live connection
to stop admitting unpaired access closes the session through `ClientHandle::close` and
starts a new connection with a configuration that sets `unpaired_access: false`, whose activation
guard then applies the new setting. Neither goodbye is sent automatically: no control request flips
the setting on a running session, so the `pairing_required` close for a connection that becomes
unadmitted and the `restart` re-establishment for one that becomes admitted are both left to the
host.

**Why:** the configuration is owned by the connection, not by the session: it is captured when the
host calls `connect`, and every activation check borrows it from there. There is
no channel that could carry a setting change into a live session, and adding one would mean deciding
what to do with the connections a change makes admissible or not - the two directions the spec
answers with `pairing_required` and `restart`, neither of which is implemented.

**Removing it:** add a control request that flips the setting on a live session, closes the relying
connections with `client/goodbye` reason `pairing_required` when the setting turns off, and sends
reason `restart` on an unpaired session when it turns on so the server re-establishes the connection
under the new setting; then delete this entry.

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
