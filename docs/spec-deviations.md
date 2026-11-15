# Spec deviations

`syncspin` targets the published [Sendspin specification](https://github.com/Sendspin/spec). Every
place where this library knowingly departs from it is listed here, with the spec section it
concerns, the reason for the departure and what closing the gap requires.

A deviation is only acceptable when it is in this file and, where the behaviour is observable,
pinned by a test. "Not implemented yet" entries are staged work, not a claim that the deviation is
harmless.

## Summary

| #   | Area                                                            | Spec section                                                                                                                      | Status                        |
| --- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| 1   | Client-initiated connections only, no client mDNS advertisement | [`connection.md` — Establishing a Connection](https://github.com/Sendspin/spec/blob/main/connection.md#establishing-a-connection) | Closes in 0.2                 |
| 2   | No `activities` admissibility handling                          | [`messaging.md` — `server/activate`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-serveractivate)       | Closes with pairing (stage 2) |
| 3   | No version-0 pairing-token export                               | [`pairing.md` — Pairing Token](https://github.com/Sendspin/spec/blob/main/pairing.md#pairing-token)                               | Closes with pairing (stage 2) |
| 4   | `psk_id` validation deferred to the session layer               | [`connection.md` — Pre-Shared Key](https://github.com/Sendspin/spec/blob/main/connection.md#pre-shared-key)                       | Closes with pairing (stage 2) |
| 5   | No code pairing (PAKE)                                          | [`pairing.md` — PAKE](https://github.com/Sendspin/spec/blob/main/pairing.md#pake)                                                 | Stage 4                       |
| 6   | `group/update` is not the state source                          | [`messaging.md` — `group/update`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-groupupdate)             | Stage 1b                      |
| 7   | No failure diagnostics from `server/error`                      | [`messaging.md` — `server/error`](https://github.com/Sendspin/spec/blob/main/messaging.md#server--client-servererror)             | Stage 1b                      |

## 1. Client-initiated connections only

**Spec:** `connection.md`, _Establishing a Connection_ and _Client Initiated Connections_. The spec
RECOMMENDS server-initiated connections, requires servers to support both methods and requires a
client to use exactly one of them. A client using client-initiated connections MUST NOT advertise
`_sendspin._tcp`.

**What we do:** the client takes a WebSocket URL (`ws://<server>:8927/sendspin`, optional server
list) and connects. It never advertises `_sendspin._tcp`, never listens for an incoming upgrade and
therefore never arbitrates competing servers.

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

**What we do:** [`ServerActivate`](../crates/syncspin-core/src/messages.rs) parses `activities`,
`active_roles` and `pairing`, but nothing arbitrates them. There is no allowed-set table, no
`client/goodbye` writer and no `pair/abort` writer, so an activation is accepted as received.

**Why:** the allowed set depends on the matched PSK and its category, and 0.1 has only the Sentinel
PSK. Without pairing there is exactly one case to enforce (Sentinel admits `playback`), and the
rejection reasons that exist for the other cases cannot be produced at all.

**Removing it:** add the allowed-set table per PSK category, the playback-capable rule with the
`active_roles` re-evaluation on later activations, and the two rejection paths, once the session
loop and the PSK lookup exist. Test each rejection reason against the fake server.

## 3. No version-0 pairing-token export

**Spec:** `pairing.md`, _Pairing Token_ and _Pairing PSK Flow_. The pairing PSK MUST be exposed to
the operator as a version-0 token, `SP:0` plus the base32 body of
`client_key (32 bytes) || pairing_psk (32 bytes)`, transliterating `2` to `9`. The bare PSK is not
an acceptable interface.

**What we do:** the library has no `pairing_token()` and no pairing PSK at all. The only key the
client uses today is the published Sentinel PSK, which is not a pairing credential.

**Why:** a token is a credential: whoever holds it can pair any server with the client. Emitting one
before the pairing PSK is generated, persisted and covered by the record lifecycle would ship a
secret with no rotation and no test for its lifecycle. The spec's reference vector makes the
encoder testable only once the pairing PSK exists.

**Removing it:** in stage 2, generate and persist the pairing PSK, add `pairing_token()` returning
the encoded string (never the raw PSK), and pin it with the spec's reference vector plus a decoder
round trip that exercises the `2`/`9` transliteration. Record handling for `server/unpair` arrives
in the same stage.

## 4. `psk_id` validation deferred to the session layer

**Spec:** `connection.md`, _Encryption_ → _Pre-Shared Key_ and _Sentinel Fallback_. The client
decrypts the first handshake message, compares the announced `psk_id` against the hash of every
candidate PSK of the announced `psk_category`, mixes in the match, fails on a stored-pubkey
mismatch and falls back to the Sentinel PSK on a plain lookup miss.

**What we do:** `syncspin_core::noise` is a byte-level responder. It starts every handshake with the
Sentinel PSK and hands the decrypted message-1 payload back verbatim; the caller may replace the PSK
with `Responder::set_psk` between reading message 1 and writing message 2. Selecting, validating and
falling back is the session layer's job, as the module documentation states.

**Why:** the Noise module owns no storage and no policy, so it cannot enumerate candidate PSKs or
decide what a category mismatch means. Splitting it this way keeps `core` free of file I/O and lets
a host with its own identity store drive selection.

**Consequence while it stands:** a caller that drives `Responder` directly and ignores the payload
completes a handshake against any announced `psk_id`/`psk_category` pair, and no Sentinel fallback
decision is made for it. The published Sentinel PSK id is pinned by
`sentinel_psk_id_matches_the_published_value`, so the metadata is at least observable.

**Removing it:** give `core` a PSK resolver (a trait the session implements over its storage, passed
into the responder) so the handshake cannot finish without a matched category and id, and enforce
the record's `server_id` check and the fallback-on-miss rule there. Then narrow `set_psk` or delete
it.

## 5. No code pairing (PAKE)

**Spec:** `pairing.md`, _PAKE_, _Dynamic Pairing Code Flow_ and _Static Pairing Code Flow_ — a
SHOULD, not a MUST. `CPACE-X25519-SHA512` per `draft-irtf-cfrg-cpace-21`, with the server as `A`,
the client as `B` and the `MCF` generator, plus the wrapped-PSK exchange.

**What we do:** nothing. No `client/pair-init`, `client/pair-auth`, `client/pair-confirm`,
`server/pair-*` parsing and no CPace implementation.

**Why:** no vetted crate is known to match draft-21 with the spec's `MCF` and `sid` layout. Writing
the PAKE by hand before that is settled would put unaudited crypto in the handshake path.

**Removing it:** check the candidate crates against draft-21 first; if they do not match, build the
wrapper on `x25519-dalek` and SHA-512 with the draft test vectors and an external review, then add
the message flow and negative cases (wrong code, replay, `method_not_supported`).

## 6. `group/update` is not the state source

**Spec:** `messaging.md`, `group/update`. The server MUST send it after the first activation and on
every change, carrying all fields each time; a `group_id` that is not 43 base64url characters is a
protocol error and the client MUST close the connection.

**What we do:** `Incoming` has no `group/update` variant, so the message is classified as an unknown
type and ignored, as the spec requires for types this revision does not implement. Playback state
comes from `stream/start`, `stream/end` and `server/state` instead, and a malformed `group_id` is
never seen, so it cannot be rejected.

**Why:** the field was absent from the protocol code this library was extracted from, and 0.1 had to
freeze the message set before the session loop existed. Leaving it out was preferred over
half-handling the authoritative state source.

**Removing it:** add the type, treat it as the authoritative `PlaybackState` and `group_id` source,
validate the `group_id` length and charset, and close on a violation. Delete this entry and the
`stream`-derived state path at the same time.

## 7. No failure diagnostics from `server/error`

**Spec:** `messaging.md`, `server/error` and `connection.md`, _Failure Handling_. The server sends it
in place of `server/init` when it rejects `client/init`, then closes; the reason is
`unsupported_version`, `unsupported_suite` or `malformed`.

**What we do:** `server/error` has no variant in `Incoming`, so a client that received one would
ignore it and only notice the close, reporting a generic disconnect.

**Why:** 0.1 has no session loop yet; the message set was frozen at the types the extracted code
used. A dedicated error type is worth adding together with the disconnect reasons, not before.

**Removing it:** add the type and a typed connect error carrying the reason so a caller can act on
`unsupported_version` rather than guessing. The server half arrives with `syncspin-server`.

## How to update this file

- Every PR that adds, narrows or closes a deviation updates the summary table and the matching
  section in the same commit.
- Quote the spec section by file and heading, and link the anchor; if the spec revision moves the
  heading, fix the link rather than dropping it.
- State the current behaviour as the code does it, not as the design intends it. Name the function,
  type or test that shows it.
- Add or update a test that pins observable behaviour before claiming a deviation is harmless. If
  nothing can be tested yet, say so in the entry.
- Closing a deviation means deleting its section and its table row, and mentioning the closure in
  `CHANGELOG.md` under _Spec deviations_.
