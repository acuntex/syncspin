//! Pairing primitives shared by clients and servers.
//!
//! The pairing token is the operator-facing half: one string that carries a client's identity
//! and pairing secret, or a dynamic pairing code, from the client into the server. It is text, so
//! it lives here unconditionally.
//!
//! Code-based pairing additionally authenticates with CPace, a PAKE that turns a short pairing
//! code into a shared key. The PAKE is a pure function of bytes, so it lives in this crate rather
//! than in `syncspin-client`, which owns the pairing attempt state machine. It is behind the
//! `pairing-code` feature: the default build has no PAKE, no Elligator 2 and no dependency on the
//! map.

pub mod token;

#[cfg(feature = "pairing-code")]
pub mod pake;
