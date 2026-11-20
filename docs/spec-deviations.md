# Spec deviations

`syncspin` targets the published [Sendspin specification](https://github.com/Sendspin/spec). Every
place where this library knowingly departs from it is listed here, with the spec section it
concerns, the reason for the departure and what closing the gap requires.

A deviation is only acceptable when it is in this file and, where the behaviour is observable,
pinned by a test. "Not implemented yet" entries are staged work, not a claim that the deviation is
harmless.

## Summary

| #   | Area                                                                   | Spec section                                                                                                                                                                                                                                                           | Status                             |
| --- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| 1   | Server-initiated connections: last-playback server not persisted       | [`connection.md` — Establishing a Connection](https://github.com/Sendspin/spec/blob/main/connection.md#establishing-a-connection)                                                                                                                                      | Open, no last-playback record      |
| 4   | Code pairing is behind a feature (server MUST)                         | [`pairing.md` — PAKE](https://github.com/Sendspin/spec/blob/main/pairing.md#pake)                                                                                                                                                                                      | Accepted, `pairing-code`           |
| 6   | Approval is not persisted across restarts                              | [`pairing.md` — Unpaired Access](https://github.com/Sendspin/spec/blob/main/pairing.md#unpaired-access)                                                                                                                                                                | Open, server lifetime              |
| 7   | Scheduled metadata applied immediately                                 | [`messaging.md` — `server/state`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serverstate)                                                                                                                                                  | Stage 1b                           |
| 8   | In-place format change flushes queued audio                            | [`messaging.md` — `stream/start`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamstart); [`roles/player/v1.md` — `stream/start`](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server--client-streamstart-player-object) | Stage 1b                           |
| 10  | A stream-clear reaches the sink buffer only through `discard_from`     | [`messaging.md` — `stream/clear`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamclear)                                                                                                                                                  | Accepted, `Sink::discard_from`     |
| 11  | Playout deadlines begin after three clock bursts                       | [`messaging.md` — Clock Synchronization](https://github.com/Sendspin/spec/blob/main/messaging.md#clock-synchronization)                                                                                                                                                | Documented                         |
| 12  | A player volume above 100 is capped, not rejected                      | [`roles/player/v1.md` — `server/command` player object](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server--client-servercommand-player-object)                                                                                                      | Accepted, `clamp_volume_with`      |
| 13  | A controller command before the controller state is not checked        | [`roles/controller/v1.md` — `client/command` controller object](https://github.com/Sendspin/spec/blob/main/roles/controller/v1.md#client--server-clientcommand-controller-object)                                                                                      | Accepted, `check_control`          |
| 14  | A reconnect keeps the last known `active_roles` while playback-capable | [`messaging.md` — `server/activate`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serveractivate)                                                                                                                                            | Accepted, `handshake`              |
| 15  | A malformed control message is ignored, not fatal                      | [`messaging.md` — Communication](https://github.com/Sendspin/spec/blob/main/messaging.md#communication)                                                                                                                                                                | Accepted, `handle_control_message` |
| 16  | A server keeps an unavailable client in the group                      | [`messaging.md` — `client/state`](https://github.com/Sendspin/spec/blob/main/messaging.md#server-behavior-when-a-client-becomes-unavailable-available-false)                                                                                                           | Open, one group                    |
| 17  | The live queue, the lead hint and the 15 ms lower bound                | [`roles/player/v1.md` — Server Audio Send Constraints](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server-audio-send-constraints)                                                                                                                    | Open, live queue, hint, 15 ms      |
| 19  | A foreign `group_id` is accepted unless strict mode is set             | [`messaging.md` — `group/update`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-groupupdate)                                                                                                                                                  | Accepted, `strict_group_id`        |
| 20  | No drift correction: the ±1 ms steady-state window is not guaranteed   | [`roles/player/v1.md` — Sync Accuracy](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#sync-accuracy)                                                                                                                                                    | Open, no correction loop           |
| 21  | A `set_output_delay` above 5000 ms is capped, not rejected             | [`roles/player/v1.md` — `server/command` player object](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server--client-servercommand-player-object)                                                                                                      | Accepted, `output_delay_control`   |
| 22  | A natural track transition is sent as `stream/end` then `stream/start` | [`messaging.md` — `stream/end`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamend)                                                                                                                                                     | Open, host API                     |

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

## 4. Code pairing is behind a feature (server MUST)

**Spec:** `pairing.md`, _PAKE_, _Dynamic Pairing Code Flow_ and _Static Pairing Code Flow_. Servers
MUST implement all three methods - Pairing PSK, the static code flow and the dynamic code flow.
Clients MUST implement Pairing PSK and MAY implement additional methods; a client with an
out-channel SHOULD prefer the dynamic flow over the static one. The code flows are
`CPACE-X25519-SHA512` per `draft-irtf-cfrg-cpace-21`, with the server as `A`, the client as `B` and
the `MCF` generator, plus the wrapped-PSK exchange.

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

**Why:** the server's default build departs from the MUST by offering only the Pairing PSK flow: a
default `syncspin-server` refuses the two code methods (`ServerHandle::start_pairing`). A feature
gate keeps a build that does not carry the PAKE from advertising the method. The client is free to
gate the optional code methods, which is within the MAY, and the feature restores the server's MUST
when enabled.

**Removing it:** enable the code flows in the server by default (and then the client's optional
methods) once the external review in `SECURITY.md` is done; add spec vectors for the dynamic
derivation when they are published.

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
depth: the `min_buffer_ms` the client asks for - 250 ms until it has enough arrival-delay samples to
derive one, then the upper tail of the measured distribution - plus whatever the sink buffers.

**Why:** scheduling needs a per-role event queue with a timer tied to the clock filter, which the
session does not have yet; the extracted consumer treated metadata as immediate. Applying it late
also needs a rule for a change that is superseded before it becomes valid, which belongs with that
queue.

**Removing it:** give metadata its own scheduled queue, compare `timestamp` with `clock.now_us`,
and emit at the mapped deadline. Test a future timestamp, a past one, and a change superseded before
it becomes valid.

## 8. In-place format change flushes queued audio

**Spec:** `messaging.md`, `stream/start`, and `roles/player/v1.md`, the `stream/start` player object.
The server may send it again with a new format to reconfigure a running stream; clients MUST keep
buffered chunks and decode each in the format that was in effect when it arrived, and SHOULD switch
their output between formats without adding a gap.

**What we do:** `handle_stream_start` flushes the sink, drops every frame in the client's playout
queue and opens the new format, so both the frames the client scheduled and the audio already handed
to the sink are discarded at the switch. That is safe - no mixed-format audio is played - but not
gapless: a frame queued for the previous announcement never reaches the output, and audio already
handed to the sink is discarded too.

**Why:** `Sink::open` is the only format-change hook and its contract starts a new stream, so the
queue cannot hand the old frames to an output that has already reopened for the new format. A
gapless switch would need a drain-and-swap step or a second output, neither of which the trait
offers, and the current consumer's format does not change mid-stream.

**Removing it:** extend the sink contract with a drain-and-switch path (or a second output), keep the
queue across an in-place start with each frame tagged by the format in effect when it arrived, drain
the old format at the switch timestamp, and test a mid-stream change against a sink that records the
boundary.

## 10. A stream-clear reaches the sink buffer only through `discard_from`

**Spec:** `messaging.md`, `stream/clear`. A `from_timestamp` asks the client to discard the buffered
audio from that server time onward and keep what is earlier; an absent timestamp clears everything.
`roles/player/v1.md` adds that a client which cannot discard audio already in its backend must drop
the chunks that follow until the old audio ends.

**What we do:** `handle_stream_clear` emits `Event::StreamClear`, cuts the client's playout queue by
the raw server timestamp - dropping every queued frame stamped at or after it and keeping the
earlier prefix - and then calls `Sink::discard_from` for the audio already released to the sink,
with the timestamp mapped through the clock estimate and `output_delay` subtracted. While no
estimate is ready, for a timestamp already in the past, and when the mapping would overflow, the
sink deadline is `Instant::now()`, which drops everything the sink buffered; a clear without a
timestamp flushes both queues. The provided default calls `Sink::flush`, so a sink without its own
timestamped queue still drops everything. The announced format stays open for the chunks that
follow, because a clear does not end the stream. The client relies on `Sink::discard_from` here:
the default flushes and an error is fatal, so the specification's fallback - dropping chunks until
the old audio ends, for a backend that cannot discard - is unreachable in this design, and the
client does not implement it.
`flush_and_a_timestamped_clear_keep_the_prefix`,
`a_clear_with_a_timestamp_maps_the_deadline_once_the_clock_is_ready`,
`a_clear_before_the_clock_is_ready_discards_from_now` and
`a_sink_without_its_own_discard_flushes_everything` pin the queued prefix, the mapped deadline, the
no-estimate fallback and the default.

**Why:** the client now holds the timestamped queue and discards its own suffix itself. What remains
with the sink is the audio already released to it: a frame is written `pre_port_delay` before its
port deadline, and once written the client queue cannot recall it, so `discard_from` is the only
hook that reaches a sink's internal buffer. The client's queue is also a defensive bound in
write-time bytes: it holds at most the 128 KiB `buffer_capacity` the client advertises, counts the
13-byte chunk header plus payload, and evicts the oldest frames on overrun. It releases those bytes
when the frame is written, earlier than the specification's completion-time accounting, so the bound
is only ever tighter than the server's own cap. A sink that does not override `discard_from` still
drops everything, which is audible as a short gap at a seek.

**Conforming sink:** implement `discard_from` by comparing `due` with the playout deadline of each
buffered frame, dropping the frames at or after it and keeping the earlier ones; the client has
already cut its own queue at the same server stamp. It must succeed when no stream is open or no
queue exists — a clear can arrive before `stream/start` or after `stream/end` — and an empty queue
discards nothing. The default already matches `flush`, so a sink that leaves it out is the
documented everything-drop, not a silent failure.

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
reports `available: true` again rejoins the running stream on its existing announcement, because its
stream was never ended. A track jump forgets every announcement: the clear reaches an announced
unavailable member so it discards its buffers, but the new stream's `stream/start` does not, so a
member that returns after one gets that start rather than a second start for the old track. A
member that stays unavailable across a later pause keeps the cleared stream open and misses that
pause's `stream/end`, because the group ends only the streams it has announced; the next `play`
announces a new stream to it, or, if it stays unavailable through that too, it is announced when it
returns.
`a_member_that_reports_itself_unavailable_receives_no_audio` pins the withheld audio,
`a_returning_member_keeps_its_larger_old_start_at_and_gets_no_second_start` pins the returning
member, and `group_state_applies_to_every_member_and_a_report_is_not_a_command` pins that a report
never becomes a command.

**Why:** a solo group and the `switch` command cycle need several groups per server, which this
milestone does not have; the one thing that must not happen - audio to a client that says it will
not play it - is kept, and the rest of the rule cannot be followed without the groups it names.

**Removing it:** add solo groups, move an unavailable member into one, send the `group/update` and
`stream/end` the spec requires in that order, and serve the controller's `switch` command; then flip
the first test so an unavailable member ends in a stopped solo group.

## 17. The live queue, the lead hint and the 15 ms lower bound

**Spec:** `roles/player/v1.md`, _Server Audio Send Constraints_. After a `stream/start` that begins
buffering from empty, the server MUST schedule the first audio timestamp at least `min_buffer_ms` +
`output_delay_ms` ahead for each player, and for grouped playback uses a common send-ahead equal to
the maximum per-player send-ahead across the group, recomputed when players join, leave or update
their timing. A `stream/clear` without `from_timestamp` restarts the same way. During live playback
the server MUST schedule timestamps so each player's queued duration stays at or above its
`min_buffer_ms`. The `required_lead_time_ms` is a hint: the server SHOULD extend the lead toward it
only when that adds no latency (buffered sources, not live streams). A server MUST NOT send a chunk
longer than 150 ms and SHOULD NOT send one shorter than 15 ms. Separately, `messaging.md`
(`stream/start`) has the server wait for a role's `client/state` object before starting that role's
stream.

**What we do:** the lead rules are kept. `Group::group_lead_us` takes the largest `min_buffer_ms` +
`output_delay_ms` over the members that `plays()`, and every restart from empty - a new stream, a
`play` restart and a seek's `stream/clear` - anchors the shared timeline on the transmit time of its
trigger plus that lead; a report that arrives after the instant re-leads from `now` instead of using
a past timestamp. A late joiner gets a future timestamp only: it joins the group timeline when the
common lead covers it and gets its own lead, with a hole, when it does not. Each member's
outstanding audio is capped at the `buffer_capacity` its `client/hello` announced: a chunk that
would overrun it is not started, and a queued or sent chunk counts until its transmission is
finished and `timestamp + duration - output_delay_ms` has passed. The `client/state` wait is kept
too: the group announces no stream to a member without its `player` object.

What remains is the live queue: the group does not keep a player's queued duration at
`min_buffer_ms` during playback, and does not restore it after a join or an increase of the reported
timing. `required_lead_time_ms` is received and ignored; the group cannot tell a buffered source
from a live stream, and extending toward the hint is a SHOULD only in the buffered case. The 15 ms
lower bound is the host's chunk size: the server forwards what `StreamWriter` is given and refuses a
chunk above 150 ms.

The `stream/clear` `from_timestamp` rule is not triggered: the server always sends
`from_timestamp: None`, so a clear drops every buffer. The first change that sends a timestamp has
to derive it from the reported timing - at least the larger of `min_buffer_ms` and
`required_lead_time_ms`, plus `output_delay_ms`, after `server_transmitted`.

The closed parts are pinned by `the_group_lead_is_the_maximum_of_the_ready_members`,
`the_anchor_waits_for_every_report_and_starts_at_the_maximum`,
`a_member_pending_at_the_deadline_stays_gated_and_re_leads_late`,
`a_seek_clears_as_the_anchor_and_resets_the_count`,
`the_start_lead_follows_the_reported_timing`,
`a_late_joiner_is_gated_on_its_own_start_and_keeps_the_timeline`,
`a_member_with_capacity_one_is_skipped_for_every_chunk`,
`a_member_with_no_room_is_skipped_until_its_buffer_drains`,
`a_chunk_longer_than_150_ms_is_refused` and
`a_player_hears_nothing_before_it_reports_its_state`. `two_players_receive_the_same_frames` still
pins that the timestamps are identical across the group, as the group maximum requires.

**Why:** one timeline serves the whole group, and the spec's own answer is a common send-ahead equal
to the group maximum, which a restart now applies. The live queue is the host's feed: the group can
place and pace the chunks it receives, but it has no audio of its own to refill a player that runs
low, and after a join or a timing increase the only ways to raise the queued duration are to move
the shared timeline or resend audio, which break group sync or duplicate what was played. The hint
needs the host to say that a source is buffered, which the API does not carry. The lower bound is a
property of the host's chunking, which the server cannot change.

**Removing it:** track each member's queued duration against its `min_buffer_ms` and refill after a
join or a timing increase; add a buffered-source signal the host sets so the lead may extend toward
`required_lead_time_ms`; and state the 15 ms floor as the host's contract, or split a shorter chunk
at the API boundary. Then delete this entry.

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

## 20. No drift correction: the ±1 ms steady-state window is not guaranteed

**Spec:** `roles/player/v1.md`, _Playback Synchronization_ and _Sync Accuracy_. In steady state a
player MUST keep the error at the audio output within ±1 ms of what the time filter predicts, and
SHOULD soft-correct an error that leaves ±1 ms when the ±0.5% speed cap allows bringing it back
within 10 seconds. Corrections in steady state MUST NOT be audible.

**What we do:** the client maps each chunk's server timestamp through the time filter, subtracts
`output_delay_ms`, queues it and writes it at its pre-port deadline. A frame more than 10 ms past
that write time is dropped and reported through `Event::LateAudio`, never advanced; nothing inserts
or deletes samples, resamples, or adjusts the output rate. Scheduling accuracy is therefore bounded
by the clock estimate, the sink's own jitter and the 10 ms late tolerance, not by a correction loop.
The 10 ms is this crate's own choice: the spec only says a player SHOULD drop chunks whose
timestamp is already in the past and names no tolerance.
The client makes no ±1 ms steady-state claim and does not implement soft correction or the ±0.5%
speed limit, because it never changes playback speed.

**Why:** correction needs a feedback path from the output - how far the renderer actually is from
the position a frame was scheduled for - and `Sink` reports only `underruns()`, with no such
position. The sink owns the device buffer, so the client cannot observe or correct the error after
`write` returns. Writing each frame at its timestamp, or dropping it when that is no longer
possible, is the half the queue can do on its own.

**Removing it:** have the sink report its render position (or an underrun/overrun count tied to a
frame) and let the queue apply the spec's sample deletion and insertion, or an asynchronous sample
rate converter, before the write; then pin the ±1 ms window and the ±0.5% speed cap with tests. The
queue in `syncspin-client` is where the correction lands.

## 21. A `set_output_delay` above 5000 ms is capped, not rejected

**Spec:** `roles/player/v1.md`, `server/command` player object. `output_delay_ms` is an integer in
the range 0-5000, required for `set_output_delay`, and `messaging.md` says a field value outside
the fixed range its definition gives is a protocol error: the receiver MUST close the connection.
This client does not close: that is a conscious deviation.

**What we do:** a `server/command` carrying `set_output_delay` with an `output_delay_ms` of 5001 or
more - the wire field is a `u32`, so such a value decodes - is reported as
`Event::OutputDelay { requested, applied }` with `applied` capped to 5000. The host applies
`applied`, so the client's own `client/state` stays inside the range a conformant server accepts,
and the connection stays open. A negative or non-integer value fails to decode and is ignored with
the whole message, as deviation 15 records. A missing `output_delay_ms` is ignored silently, like
the missing field of `volume` and `mute`. `the_output_delay_command_reports_the_clamped_value`
pins 0, 200, 5000 and 5001.

**Why:** closing the connection would silence playback over a value the server got wrong, and the
nearest legal delay is unambiguous. This is the same tolerance deviation 12 records for volume.

**Removing it:** give `handle_command` a typed rejection path and close the connection with a
protocol-error reason once that path exists, together with the volume case in deviation 12. Test the
closed connection instead of the capped value.

## 22. A natural track transition is sent as `stream/end` then `stream/start`

**Spec:** `messaging.md`,
[`stream/end`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-streamend).
For a track that ends and is followed naturally by the next one, the stream continues uninterrupted
for gapless playback: servers SHOULD send no stream command except a `stream/start` that updates the
configuration, and MUST NOT send `stream/end` for a track transition, a seek or a track jump. A jump
is a `stream/clear` instead.

**What we do:** the host API has no transition call. A host that ends one track and opens the next
through `StreamWriter::end()` followed by `ServerHandle::open_stream()` makes the server send
`stream/end` and then the new `stream/start`; the group has no queue, so it cannot tell a natural
transition from a track that really ended. A host that opens the next track while the old one still
runs gets the jump instead - a `stream/clear` and an in-place `stream/start` - which the spec
prescribes. `opening_a_second_track_is_a_jump_not_an_in_place_change` pins the jump, and
`ending_a_track_sends_an_end_and_the_next_start_opens_a_new_stream` pins the end-then-start
sequence.

**Why:** a server without a queue cannot know whether the host has more audio for the same stream or
has stopped playback. `end()` is the host saying the stream is over, and the API must not guess
otherwise. The transition cannot be promised as gapless either: the next track's first sample is
scheduled a fresh lead after its start, not at the old stream's next timestamp, so treating
`end()` as a transition would claim a continuity the server does not provide.

**Removing it:** give the writer a transition call that clears and restarts in place without ending
the stream - the start is the spec's in-place configuration update - or let a queue in the server
drive the transition; then test that a natural transition sends `stream/clear` and `stream/start`
without a `stream/end`, and that `end()` still means playback termination.

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
