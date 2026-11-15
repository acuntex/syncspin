//! Pairing primitives shared by clients and servers.
//!
//! Code-based pairing authenticates with CPace, a PAKE that turns a short pairing code into a
//! shared key. The PAKE is a pure function of bytes, so it lives in this crate rather than in
//! `syncspin-client`, which owns the pairing attempt state machine.
//!
//! Everything here is behind the `pairing-code` feature. The default build has no PAKE, no
//! Elligator 2 and no dependency on the map.

pub mod pake;
