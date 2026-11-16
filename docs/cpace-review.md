# CPace review package

Status: prepared 2026-11-16, awaiting a reviewer · Not a design document

## What is being asked

`syncspin` implements CPACE-X25519-SHA512 (draft-irtf-cfrg-cpace-21, MCF) for Sendspin's code-based
pairing. No crate implements that suite: `pakery-cpace` offers Ristretto255 and P-256 only, and
`pake-cpace` is Ristretto255 under an older draft. The layer is therefore written here, on
`x25519-dalek`, `sha2` and `elligator2`, and pinned to the draft's test vectors.

**The question is not "rewrite this".** It is: is the construction what the draft describes, is the
transcript byte-exact, and are there places where the code is correct for the wrong reason — passing
the vectors while being fragile for another input? An opinion with reasons is the deliverable; a patch
is welcome but not required.

## Scope

| File                                        | Contents                                                                         |
| ------------------------------------------- | -------------------------------------------------------------------------------- |
| `crates/syncspin-core/src/pairing/pake.rs`  | Generator, shares, `lv_cat`, transcripts, ISK, MCF tags, the Elligator 2 adapter |
| `crates/syncspin-core/src/pairing/wrap.rs`  | `K_wrap` and the AEAD sealing of the new PSK and of `nonce_B`                    |
| `crates/syncspin-core/src/pairing/code.rs`  | Dynamic code derivation and the commitment                                       |
| `crates/syncspin-core/src/pairing/token.rs` | Versioned tokens (base32, `2`↔`9`) — adjacent, not PAKE                          |
| `crates/syncspin-client/src/pairing.rs`     | Role B: the attempt state machine, rounds, holdback                              |
| `crates/syncspin-server/src/pairing.rs`     | Role A: the server side of the same flows                                        |

Out of scope: framing, Noise (`noise.rs`), the clock filter and the host's pairing UI. They are
reviewed elsewhere or are not cryptography.

## The construction as implemented

- **Group**: `G_X25519` — the generator is `map_to_curve_elligator2(decodeUCoordinate(H(gen_str)))`,
  as §8.2 requires. `elligator2` (0.1, fiat-crypto field arithmetic) supplies the map; the code
  adapts the input by reducing mod p and negating when bit 254 is set.
- **`sid`**: `"sendspin-pair-pake-v1"` ‖ `h` ‖ `pairing_index`(u32 BE) ‖ `round`(u32 BE), 61 bytes,
  `h` being the Noise handshake hash.
- **`PRS`**: the six ASCII digits, or the 24 raw bytes for the QR format.
- **Roles**: server = `A` (initiator), client = `B` (responder); `ADa` = `"server"`, `ADb` =
  `"client"`, `CI` empty.
- **MCF**: `Ta`/`Tb` = HMAC-SHA-512 keyed by `SHA-512("CPaceMac" ‖ sid ‖ ISK)` over
  `lv_cat(share, ad)`; the client verifies `Ta` in constant time before revealing anything.
- **Wrapping**: `K_wrap = SHA-256(label ‖ sid ‖ ISK)`, the connection's AEAD, 12 zero bytes of nonce,
  empty AAD, 32-byte value in, 48 out.

## What pins it

| Property                                            | Pinned by                                                                                                                        |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `prepend_len`, `lv_cat`, `generator_string`         | draft §A.1.4, §A.3.5, §A.3.7 vectors                                                                                             |
| Generator, shares, both transcripts, ISK, `Ta`/`Tb` | draft §B.1.2–§B.1.7 vectors                                                                                                      |
| Low-order and non-canonical rejections              | draft §B.1.10, all twelve cases                                                                                                  |
| The Elligator 2 adapter                             | five RFC 9380 §J.4.2 vectors (two with bit 254 set, three clear), plus `map(u) == map(p − u)` and the reduction of `p … 2^255−1` |
| Token encoding                                      | both specification reference vectors, v0 and v1                                                                                  |
| `K_wrap` and sealing                                | known-answer tests computed outside this code                                                                                    |

## What is **not** pinned, and why that matters

- **The dynamic code flow has no vectors in the specification.** `code.rs` is derived from the text
  (label, `SHA-256`, `uint256_be mod 10^6`, first 24 bytes for the QR form) and tested against fixed
  inputs this project chose. A reviewer's second opinion is worth more here than anywhere else.
- **The server side (role A) is newer than the client side.** It was written against the client's
  transcripts, so a shared misreading would pass both.
- **The Bit-254 adapter** is the one place where the code does something the draft does not spell out.
  It is derived — Elligator 2 depends on `r²`, so `r` and `−r` share an image, and the representative
  domain requires the high bits clear — and it is checked against RFC 9380 vectors rather than the
  draft's single generator vector. It is still the first thing to attack.
- **The draft's own coverage of the map is one vector deep.** §B.1.1 is the only generator vector the
  specification publishes, so in the draft's terms the Elligator 2 adapter rests on a single input.
  RFC 9380 §J.4.2 supplies the breadth (both bit-254 branches, values either side of the
  representative domain), but it pins the map, not the draft's use of it. The representative
  convention is a property of `elligator2` 0.1.0, which is why that dependency is pinned exactly
  (`=0.1.0`): a `0.1.x` that moved the convention would map a negated input to the other point, and
  every vector would still pass, because that point is a valid group element too.

## Questions, ranked

1. **Is the adapter a legitimate way to evaluate `map_to_curve_elligator2` through a crate that wants
   a representative?** Does it cover every `decodeUCoordinate` output, including the twist cases?
2. **Is the transcript byte-exact** for a dialer that is not this code — an independent
   implementation of the draft, given the same `PRS` and `sid`?
3. **What breaks if `elligator2` changes?** The crate is pinned to `=0.1.0`, because a change to the
   representative convention would silently change the generator without failing a vector. Is the
   pin the right response, or is vendoring the map the only defensible one?
4. **Is the constant-time posture adequate** for the values that depend on `PRS`: the conditional
   negation, the `select` helper, the tag comparison, and `x25519-dalek`'s clamping?
5. **Does the re-handshake change `h` in a way that lets two attempts share a `sid`?** `pairing_index`
   counts activations since the last handshake; is the pair (h, index, round) collision-free in
   practice?
6. **Is the dynamic code derivation faithful** — the label, the modulus, the zero padding, the QR
   slice — and does `uint256_be mod 10^6` introduce a bias worth naming?

## How to review it

```sh
cargo test -p syncspin-core --features pairing-code
cargo test -p syncspin-client --features pairing-code,storage-file
cargo test -p syncspin-server --features pairing-code
```

The vector tests are in `crates/syncspin-core/tests/{pake_vectors,pairing_wrap,pairing_code}.rs`; each
assertion names the draft section it comes from. [`spec-deviations.md`](spec-deviations.md) lists what the implementation knowingly does differently
from the specification.

Roughly: an hour to read the four files, an hour to re-derive one vector by hand. The vectors were
transcribed from the draft and cross-checked twice; the risk is in what they do not cover, not in
what they assert.

## What an internal pass found (2026-11-16)

Three reviewers read this layer against the draft, each with a different part, and were told to
recompute rather than trust the vectors. The construction held:

- The generator adapter is equivalent to `map_to_curve_elligator2` for every input class — checked
  over 519 inputs including `u ≥ p`, `u ∈ {0, 1}` and the twist cases, against a transcription of
  RFC 9380 §6.7.1 and five §J.4.2 vectors.
- The transcript is byte-exact against §B.1.5 and Appendix A.2, the `sid` is identical on both sides,
  and a re-handshake replaces `h` and resets the index on both ends, so two attempts cannot share one.
- The MCF tags were recomputed independently from the draft's ISK and shares and match.

Seven things were wrong or fragile, and are fixed: `wrap` did not check how much the AEAD wrote; key
material was not zeroized; the tag comparison was a hand-rolled fold; `elligator2` was caret-ranged;
the generator had a single vector, all of it in one branch; a zero round was silently coerced to one;
and the pairing index saturated on one side only. The generator now also carries the RFC 9380 vectors
with bit 254 clear, a `map(u) = map(p−u)` property, and the boundary inputs.

**This is not the external review.** The reviewers were asked by the project and share its reading of
the draft. What it cannot rule out is a misreading both sides made — that is what the request above is
for, and the sentence in the README stands until someone outside answers.

## What this repository claims today

[The README](../README.md) says the CPace layer has not been reviewed externally and is unaudited. That
sentence comes out when a reviewer has looked at it — not before.
