//! Sendspin's Noise layer: `Noise_KKpsk2_25519_<cipher>_SHA256`.
//!
//! Every Sendspin connection is wrapped in Noise. The handshake follows the cleartext init
//! exchange and precedes all application traffic:
//!
//! ```text
//! client -> server  client/init      cleartext JSON, carries the client_id and the suite
//! server -> client  server/init      cleartext JSON, carries the server_id
//! server -> client  noise/handshake  Noise message 1, payload {"psk_id": .., "psk_category": ..}
//! client -> server  noise/handshake  Noise message 2, payload {}
//! ```
//!
//! The server is always the Noise initiator and the client the responder, whichever side opened
//! the WebSocket. Both static public keys are known before the handshake (`KK`), and the
//! pre-shared key is mixed in at the end of the second message (`psk2`). The Noise prologue is
//! the exact concatenation of the `client/init` and `server/init` bytes as sent on the wire, so
//! tampering with the cleartext exchange fails the handshake.
//!
//! This module carries both halves of the handshake - [`Responder`] for the client, [`Initiator`]
//! for the server - plus the transport that follows it. It does not interpret handshake payloads;
//! the session layer validates the `psk_id`/`psk_category` metadata. A handshake starts with the
//! published Sentinel PSK, which is what an unpaired client uses and which provides no
//! authentication on its own; the session layer reads the PSK metadata from message 1 and selects
//! the matching key through [`Responder::set_psk`] or [`Initiator::set_psk`] before it answers.
//!
//! # Cipher suites
//!
//! The specification defines two suites and requires a server to support both. [`Suite`] is the
//! set this build has; a name outside it is refused. The client picks the suite and announces it
//! in `client/init`, so there is no negotiation to fall back from: a responder built for another
//! suite than the one announced is an error, not a downgrade.

use std::fmt;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// A Sendspin cipher suite: the `<DH>_<cipher>_<hash>` tail of a Noise protocol name.
///
/// The specification lists both of these and requires a server to have both; a client announces
/// the one it uses in `client/init`. [`Suite::ChaChaPoly`] is the default because it is the suite
/// this library has always spoken and the one its pairing wrapping was pinned against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Suite {
    /// `25519_ChaChaPoly_SHA256`, the software-friendly suite and the default.
    #[default]
    ChaChaPoly,
    /// `25519_AESGCM_SHA256`, the hardware-accelerated suite.
    AesGcm,
}

impl Suite {
    /// Every suite this implementation has, in the order the specification lists them.
    pub const ALL: [Suite; 2] = [Suite::ChaChaPoly, Suite::AesGcm];

    /// The name `client/init` carries in `suite`, which is also the `<DH>_<cipher>_<hash>`
    /// tail of the Noise protocol name.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Suite::ChaChaPoly => "25519_ChaChaPoly_SHA256",
            Suite::AesGcm => "25519_AESGCM_SHA256",
        }
    }

    /// The full Noise protocol name: `Noise_KKpsk2_` followed by [`Suite::wire_name`].
    pub const fn params(self) -> &'static str {
        match self {
            Suite::ChaChaPoly => "Noise_KKpsk2_25519_ChaChaPoly_SHA256",
            Suite::AesGcm => "Noise_KKpsk2_25519_AESGCM_SHA256",
        }
    }

    /// Parses the suite name a `client/init` announces.
    ///
    /// `None` means this build does not have the suite. There is deliberately no fallback to
    /// [`Suite::default`]: a caller that cannot honour the announced suite must refuse it.
    pub fn from_wire_name(name: &str) -> Option<Suite> {
        Suite::ALL
            .into_iter()
            .find(|suite| suite.wire_name() == name)
    }
}

impl fmt::Display for Suite {
    /// Writes the wire name, so an error names the suite the peer announced.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// Noise protocol parameters of the default suite, [`Suite::ChaChaPoly`].
pub const NOISE_PARAMS: &str = Suite::ChaChaPoly.params();

/// The published Sentinel PSK, used whenever no paired PSK applies.
///
/// Its value is public, so it authenticates nothing. It exists so an unpaired client can
/// connect before pairing establishes a private PSK.
pub const SENTINEL_PSK: [u8; 32] = [
    0x1b, 0x5e, 0x24, 0xdb, 0xc1, 0xae, 0xd9, 0x5f, 0xc2, 0xa5, 0xa3, 0x38, 0xa9, 0x0c, 0x05, 0xdf,
    0x44, 0xbd, 0x10, 0xf5, 0xec, 0x1f, 0x4c, 0xd6, 0x6c, 0xbf, 0x86, 0x27, 0x27, 0x67, 0xb9, 0xd3,
];

/// The Sentinel PSK's published id, `psk_id_for(SENTINEL_PSK)`.
pub const SENTINEL_PSK_ID: &str = "GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zoo";

/// Maximum size of one Noise message, handshake or transport, including the authentication tag.
///
/// This is the Noise specification's limit; `snow` does not re-export the constant, so it is
/// repeated here.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Length of the authentication tag appended to every Noise transport ciphertext.
pub const TAG_LEN: usize = 16;

/// Largest plaintext that fits into one Noise transport message, including the leading binary
/// message id byte.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// Label that Sendspin hashes together with a PSK to derive its id.
const PSK_ID_LABEL: &[u8] = b"sendspin-psk-id-v1";

/// Payload of Noise handshake message 2: the literal empty JSON object, not zero bytes.
const HANDSHAKE_MESSAGE_2: &[u8] = b"{}";

/// Unpadded base64url length of a 32-byte key.
const KEY_CHARS: usize = 43;

/// Derives a PSK id: `base64url(SHA-256("sendspin-psk-id-v1" || psk))`, without padding.
///
/// The id is what a server announces in `noise/handshake` message 1 so the client can select
/// the matching PSK; it is a hash of the key and reveals nothing about its value.
pub fn psk_id_for(psk: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PSK_ID_LABEL);
    hasher.update(psk);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// A long-lived X25519 keypair that identifies one side of a connection.
///
/// Sendspin uses the public key as the `client_id` or `server_id` and the secret key as the
/// static key of the Noise handshake. Both halves must match: [`Identity::generate`] and
/// [`Identity::from_secret_base64`] derive the public key from the secret, so an identity built
/// through them always does.
#[derive(Clone, Copy)]
pub struct Identity {
    /// Public X25519 key as 32 raw bytes; 43 base64url characters once encoded.
    pub public: [u8; 32],
    /// Secret X25519 key as 32 raw bytes. Never log this value.
    pub secret: [u8; 32],
}

impl Identity {
    /// Generates a fresh keypair from the operating system's CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's CSPRNG is unavailable. That is not a recoverable
    /// condition: a silent fallback would be a weak key.
    pub fn generate() -> Identity {
        let params = NOISE_PARAMS
            .parse()
            .expect("NOISE_PARAMS is a valid Noise protocol name");
        let keypair = snow::Builder::new(params)
            .generate_keypair()
            .expect("the operating system CSPRNG is available");
        let secret: [u8; 32] = keypair
            .private
            .as_slice()
            .try_into()
            .expect("an X25519 secret key is 32 bytes");
        Identity::from_secret(secret)
    }

    /// Decodes an identity from its 43-character unpadded base64url secret key.
    ///
    /// The public key is derived from the secret. The input must be the canonical encoding of
    /// exactly 32 bytes; a truncated, padded or non-base64url string is an error. Every 32-byte
    /// value is a valid secret, so this cannot tell a secret key from a public key: passing a
    /// public key such as [`Identity::public_base64`] succeeds and silently yields a different
    /// identity.
    pub fn from_secret_base64(s: &str) -> Result<Identity> {
        let secret = decode_key(s).ok_or_else(|| {
            anyhow!("identity secret is not a canonical 43-character unpadded base64url X25519 key")
        })?;
        Ok(Identity::from_secret(secret))
    }

    /// Returns the public key as 43-character unpadded base64url text.
    ///
    /// This is the value to send as `client_id` or `server_id`.
    pub fn public_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }

    /// Returns the secret key as 43-character unpadded base64url text.
    ///
    /// The value is key material: hand it to [`Identity::from_secret_base64`] to restore an
    /// identity and treat the text like a password.
    pub fn secret_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret)
    }

    /// Builds an identity whose public key is derived from `secret`.
    fn from_secret(secret: [u8; 32]) -> Identity {
        Identity {
            public: public_key_for(&secret),
            secret,
        }
    }

    /// Rejects a hand-built identity whose two halves do not belong together.
    fn validate(&self) -> Result<()> {
        if public_key_for(&self.secret) != self.public {
            bail!("identity public key does not match its secret key");
        }
        Ok(())
    }
}

impl fmt::Debug for Identity {
    /// Formats the public key and redacts the secret, so `Debug` output is safe to log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public_base64())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Noise responder state for one connection.
pub struct Responder {
    handshake: snow::HandshakeState,
    /// The suite this handshake runs, kept for the transport and for callers that report it.
    suite: Suite,
}

impl Responder {
    /// Builds the responder for the client side of a Sendspin handshake, using the suite the
    /// prologue's `client/init` announces.
    ///
    /// `prologue` must be the exact concatenation of the `client/init` and `server/init` bytes
    /// as transmitted, in that order. It is mixed into the handshake verbatim, the initiator's
    /// static public key is read from the `server_id` field of the `server/init` document it
    /// contains, and the cipher suite from the `suite` field of `client/init`. A prologue that
    /// is not a sequence of JSON documents, that carries no `server/init`, that carries two of
    /// them, that announces no suite or that announces one this build does not have is
    /// rejected; use [`Responder::with_peer`] when the key is already known, as during a
    /// re-handshake where the prologue is the previous handshake hash.
    pub fn new(identity: &Identity, prologue: &[u8]) -> Result<Responder> {
        let peer_public = initiator_key_from_prologue(prologue)?;
        let suite = suite_from_prologue(prologue)?;
        Responder::with_peer_suite(identity, &peer_public, suite, prologue)
    }

    /// Builds the responder for the suite the prologue announces, refusing any other.
    ///
    /// This is [`Responder::new`] with an explicit choice, for a caller that must pin the suite.
    /// A prologue whose `client/init` announces a different suite is an error: honouring the
    /// caller's suite would hand the peer a handshake it cannot follow, and switching to the
    /// announced one would be a silent downgrade of what the caller asked for.
    pub fn with_suite(identity: &Identity, suite: Suite, prologue: &[u8]) -> Result<Responder> {
        let peer_public = initiator_key_from_prologue(prologue)?;
        let announced = suite_from_prologue(prologue)?;
        if announced != suite {
            bail!(
                "the `client/init` in the prologue announces the cipher suite `{announced}`, so \
                 this handshake cannot run `{suite}`; a suite the peer did not announce is \
                 refused, never substituted"
            );
        }
        Responder::with_peer_suite(identity, &peer_public, suite, prologue)
    }

    /// Builds the responder with the initiator's static public key supplied explicitly, for the
    /// default suite [`Suite::ChaChaPoly`].
    ///
    /// Use this when the prologue is not the init exchange, for example on a re-handshake whose
    /// prologue is the previous handshake hash. `prologue` still reaches Noise unchanged; both
    /// sides must mix in the same bytes. A re-handshake must keep the suite of the connection it
    /// replaces, so a caller that can offer more than one suite must use
    /// [`Responder::with_peer_suite`] and pass the suite the connection already runs.
    pub fn with_peer(
        identity: &Identity,
        peer_public: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Responder> {
        Responder::with_peer_suite(identity, peer_public, Suite::default(), prologue)
    }

    /// Builds the responder for an explicit peer key and suite.
    ///
    /// This is the constructor every other one ends in. It does not read the prologue, so it is
    /// the one to use on a re-handshake, where the prologue is the previous handshake hash and
    /// carries no announcement.
    pub fn with_peer_suite(
        identity: &Identity,
        peer_public: &[u8; 32],
        suite: Suite,
        prologue: &[u8],
    ) -> Result<Responder> {
        identity.validate()?;

        // Keep the published constant honest even if someone edits it.
        debug_assert_eq!(psk_id_for(&SENTINEL_PSK), SENTINEL_PSK_ID);

        let params = suite
            .params()
            .parse()
            .context("failed to parse the Noise protocol parameters")?;
        let handshake = snow::Builder::new(params)
            .local_private_key(&identity.secret)
            .context("failed to set the local static key")?
            .remote_public_key(peer_public)
            .context("failed to set the peer static key")?
            .psk(2, &SENTINEL_PSK)
            .context("failed to set the handshake PSK")?
            .prologue(prologue)
            .context("failed to set the Noise prologue")?
            .build_responder()
            .context("failed to build the Noise responder")?;
        Ok(Responder { handshake, suite })
    }

    /// Returns the cipher suite this handshake runs.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Replaces the pre-shared key used by the rest of the handshake.
    ///
    /// The responder starts with the published Sentinel PSK because the key is selected from the
    /// metadata that message 1 carries. Call this after [`Responder::read_message`] and before
    /// [`Responder::write_message`]: Noise mixes the key into message 2, so both sides must use
    /// the same value and the initiator rejects a message sealed with another one.
    ///
    /// # Errors
    /// The call is forwarded to `snow`, which refuses only a key of the wrong length or an
    /// out-of-range location; both are fixed here, so this does not fail in practice. `snow` does
    /// not refuse a late call either: the key must be set before [`Responder::write_message`]
    /// seals message 2, and a later call has no effect on the handshake or on the message already
    /// sealed.
    pub fn set_psk(&mut self, psk: &[u8; 32]) -> Result<()> {
        self.handshake
            .set_psk(2, psk)
            .context("failed to set the Noise handshake PSK")
    }

    /// Reads one Noise handshake message and returns its decrypted payload.
    ///
    /// The payload is returned verbatim. Message 1 carries the PSK metadata
    /// (`psk_id`, `psk_category`) for the session layer to validate; the handshake itself starts
    /// with the Sentinel PSK, which [`Responder::set_psk`] can replace.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        read_handshake_payload(&mut self.handshake, msg)
    }

    /// Writes Noise handshake message 2 and returns it.
    ///
    /// The payload is the empty JSON object that Sendspin requires; it is not configurable.
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        write_handshake_payload(&mut self.handshake, HANDSHAKE_MESSAGE_2)
    }

    /// Returns whether both handshake messages have been processed.
    pub fn handshake_finished(&self) -> bool {
        self.handshake.is_handshake_finished()
    }

    /// Finishes the handshake and switches to transport mode.
    ///
    /// Fails if a handshake message is still outstanding, which
    /// [`Responder::handshake_finished`] reports ahead of time.
    pub fn into_transport(self) -> Result<TransportState> {
        transport_from(self.handshake, self.suite)
    }
}

/// Which key sealed the handshake message 2 the initiator just read.
///
/// [`Initiator::read_message_with_sentinel`] reports this so the session layer can tell a peer
/// that holds the selected key from one that sealed with the published Sentinel key. It is a fact
/// about the wire, not a verdict: what an unpaired peer may do is the caller's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskOutcome {
    /// The key selected with [`Initiator::set_psk`], which for a server is the pairing record's
    /// key.
    SelectedKey,
    /// The published [`SENTINEL_PSK`]: the selected key did not seal this handshake, so the peer
    /// does not hold it.
    SentinelFallback,
}

/// Noise initiator state for one connection: the server half.
///
/// The server always sends the first handshake message, so this type produces message 1 and
/// consumes message 2. It starts with the published Sentinel PSK; [`Initiator::set_psk`] selects
/// the key the session will actually use, which message 1 must announce.
///
/// The suite is the one the client announced in `client/init`: a server must run exactly that one,
/// because the client builds its responder for it. There is no fallback - [`Initiator::new`]
/// refuses a prologue that announces another suite, and [`Initiator::with_announced_suite`] takes
/// the suite from the announcement so the two cannot disagree.
pub struct Initiator {
    handshake: snow::HandshakeState,
    /// The suite this handshake runs, kept for the transport and for callers that report it.
    suite: Suite,
    /// Whether the key [`Initiator::set_psk`] currently installed is a key other than
    /// [`SENTINEL_PSK`].
    ///
    /// [`Initiator::read_message_with_sentinel`] has nothing to retry under when the selected key
    /// is the Sentinel key itself.
    selected_non_sentinel: bool,
}

impl Initiator {
    /// Builds the initiator for an explicit peer key and suite.
    ///
    /// `prologue` reaches Noise unchanged, so both sides must mix in the same bytes: the exact
    /// `client/init` and `server/init` of a first handshake, or the previous handshake hash on a
    /// re-handshake. When the prologue carries a `client/init`, the suite it announces must be
    /// `suite`; a prologue that carries no announcement - a re-handshake hash, which is not
    /// JSON - leaves `suite` as the only source, and a suite this build does not have is always
    /// refused.
    pub fn new(
        identity: &Identity,
        peer_public: &[u8; 32],
        suite: Suite,
        prologue: &[u8],
    ) -> Result<Initiator> {
        if let Some(announced) = announced_suite_from_prologue(prologue)? {
            if announced != suite {
                bail!(
                    "the `client/init` in the prologue announces the cipher suite `{announced}`, \
                     so this handshake cannot run `{suite}`; the suite a peer announced is \
                     refused when it differs, never substituted"
                );
            }
        }
        Initiator::build(identity, peer_public, suite, prologue)
    }

    /// Builds the initiator for the suite the prologue's `client/init` announces.
    ///
    /// This is the constructor for a first handshake: the announcement decides the suite, so the
    /// two cannot disagree. A prologue that is not the init exchange, that carries no
    /// `client/init`, that carries two of them, that announces no suite or that announces one
    /// this build does not have is rejected; use [`Initiator::new`] on a re-handshake, where the
    /// prologue is the previous handshake hash.
    pub fn with_announced_suite(
        identity: &Identity,
        peer_public: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Initiator> {
        let suite = suite_from_prologue(prologue)?;
        Initiator::build(identity, peer_public, suite, prologue)
    }

    /// Builds the handshake state every constructor ends in.
    fn build(
        identity: &Identity,
        peer_public: &[u8; 32],
        suite: Suite,
        prologue: &[u8],
    ) -> Result<Initiator> {
        identity.validate()?;

        // Keep the published constant honest even if someone edits it.
        debug_assert_eq!(psk_id_for(&SENTINEL_PSK), SENTINEL_PSK_ID);

        let params = suite
            .params()
            .parse()
            .context("failed to parse the Noise protocol parameters")?;
        let handshake = snow::Builder::new(params)
            .local_private_key(&identity.secret)
            .context("failed to set the local static key")?
            .remote_public_key(peer_public)
            .context("failed to set the peer static key")?
            .psk(2, &SENTINEL_PSK)
            .context("failed to set the handshake PSK")?
            .prologue(prologue)
            .context("failed to set the Noise prologue")?
            .build_initiator()
            .context("failed to build the Noise initiator")?;
        Ok(Initiator {
            handshake,
            suite,
            selected_non_sentinel: false,
        })
    }

    /// Returns the cipher suite this handshake runs.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Replaces the pre-shared key used by the rest of the handshake.
    ///
    /// The initiator starts with the published Sentinel PSK. Call this before writing message 1
    /// when the handshake announces a private key, because message 1's payload names the key this
    /// call selects; noise mixes the key into message 2 either way, so both sides must use the
    /// same value or the peer's message 2 does not authenticate.
    ///
    /// That is the contract: before message 1, or once on the same state after a failed read, which
    /// is what [`Initiator::read_message_with_sentinel`] does. Those are the only two call sites
    /// this crate has; any other call replaces a key the handshake has already used.
    pub fn set_psk(&mut self, psk: &[u8; 32]) -> Result<()> {
        self.handshake
            .set_psk(2, psk)
            .context("failed to set the Noise handshake PSK")?;
        self.selected_non_sentinel = psk != &SENTINEL_PSK;
        Ok(())
    }

    /// Writes Noise handshake message 1 with `payload` and returns the message.
    ///
    /// The payload is the PSK metadata (`psk_id`, `psk_category`) the session layer builds; this
    /// module does not interpret it. It travels encrypted, so it must fit into a Noise message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        write_handshake_payload(&mut self.handshake, payload)
    }

    /// Reads Noise handshake message 2 and returns its decrypted payload.
    ///
    /// The payload is returned verbatim; Sendspin requires it to be the empty JSON object, which
    /// the session layer checks. Fails when the message does not authenticate, which covers a
    /// message sealed with another PSK, a changed byte and a truncation.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        read_handshake_payload(&mut self.handshake, msg)
    }

    /// Reads Noise handshake message 2, retrying the same bytes under [`SENTINEL_PSK`] when they
    /// do not authenticate.
    ///
    /// This is [`Initiator::read_message`] with the recovery a server needs after announcing a key
    /// its peer does not hold: a message 2 sealed with the Sentinel key fails under the selected
    /// key, and the same bytes then authenticate under the published one. `snow` restores its
    /// symmetric state when a read fails, so the retry sees the handshake position the first
    /// attempt left; the payload buffer is reused and returned verbatim, as
    /// [`Initiator::read_message`] returns it.
    ///
    /// The outcome reports which key sealed the message. A message that authenticates is never
    /// retried, whatever payload it carries, and a failure that is not an authentication failure is
    /// returned as it comes. This is for the first handshake of a server that selected a key; a
    /// re-handshake has no fallback and its caller keeps [`Initiator::read_message`].
    ///
    /// # Errors
    /// Fails when the selected key is [`SENTINEL_PSK`] itself, because there is no second key to
    /// retry under; when the message is shorter than the authentication tag; when it does not
    /// authenticate under either key; and on everything else [`Initiator::read_message`] reports.
    pub fn read_message_with_sentinel(&mut self, msg: &[u8]) -> Result<(PskOutcome, Vec<u8>)> {
        if !self.selected_non_sentinel {
            bail!(
                "the selected PSK is the Sentinel key, so a failed read cannot be retried under \
                 the Sentinel key"
            );
        }
        ensure_message_len(msg.len(), "handshake message")?;
        let mut payload = vec![0u8; plaintext_capacity(msg.len(), "handshake message")?];
        match self.handshake.read_message(msg, &mut payload) {
            Ok(len) => return Ok((PskOutcome::SelectedKey, payload[..len].to_vec())),
            // The failed read restored the symmetric state, so the same bytes can be read again
            // under the key the peer sealed with.
            Err(error) if should_retry_under_sentinel(&error) => {}
            Err(error) => return Err(error).context("failed to read the Noise handshake message"),
        }
        self.handshake
            .set_psk(2, &SENTINEL_PSK)
            .context("failed to set the Noise handshake PSK")?;
        let len = self
            .handshake
            .read_message(msg, &mut payload)
            .context("failed to read the Noise handshake message under the Sentinel key")?;
        Ok((PskOutcome::SentinelFallback, payload[..len].to_vec()))
    }

    /// Returns whether both handshake messages have been processed.
    pub fn handshake_finished(&self) -> bool {
        self.handshake.is_handshake_finished()
    }

    /// Finishes the handshake and switches to transport mode.
    ///
    /// Returns what [`Responder::into_transport`] returns: the handshake hash a re-handshake
    /// mixes in and the suite these keys were derived under. Fails if message 2 is still
    /// outstanding, which [`Initiator::handshake_finished`] reports ahead of time.
    pub fn into_transport(self) -> Result<TransportState> {
        transport_from(self.handshake, self.suite)
    }
}

/// Reads a handshake message and returns the payload it carries.
fn read_handshake_payload(handshake: &mut snow::HandshakeState, msg: &[u8]) -> Result<Vec<u8>> {
    ensure_message_len(msg.len(), "handshake message")?;
    let mut payload = vec![0u8; plaintext_capacity(msg.len(), "handshake message")?];
    let len = handshake
        .read_message(msg, &mut payload)
        .context("failed to read the Noise handshake message")?;
    payload.truncate(len);
    Ok(payload)
}

/// Returns whether a failed handshake read is worth retrying under [`SENTINEL_PSK`].
///
/// Only an authentication failure means "the peer sealed this with another key". Everything else -
/// a malformed length, a wrong handshake position, a failed DH - would fail the same way under the
/// Sentinel key, so a retry could only hide the real fault. `snow::Error` is `#[non_exhaustive]`,
/// and a variant added later is not a decryption failure: every one of them means "no retry".
fn should_retry_under_sentinel(error: &snow::Error) -> bool {
    matches!(error, snow::Error::Decrypt)
}

/// Writes one handshake message carrying `payload`.
fn write_handshake_payload(
    handshake: &mut snow::HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut message = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .write_message(payload, &mut message)
        .context("failed to write the Noise handshake message")?;
    message.truncate(len);
    Ok(message)
}

/// Finishes a handshake and switches to transport mode.
///
/// `h` is final once the second message has been processed, and `into_transport_mode` consumes the
/// handshake state that holds it.
fn transport_from(handshake: snow::HandshakeState, suite: Suite) -> Result<TransportState> {
    let handshake_hash: [u8; 32] = handshake
        .get_handshake_hash()
        .try_into()
        .context("the Noise handshake hash is not 32 bytes")?;
    let state = handshake
        .into_transport_mode()
        .context("failed to finish the Noise handshake")?;
    Ok(TransportState {
        state,
        handshake_hash,
        suite,
    })
}

/// A Noise transport session: one ciphertext per message.
///
/// The nonce advances with every message in each direction; a repeated or reordered ciphertext
/// fails authentication. Payloads are not fragmented at this layer, so a caller that needs to
/// send more than a single Noise message can carry has to split the data itself.
pub struct TransportState {
    state: snow::TransportState,
    /// The handshake hash `h` of the handshake that produced these keys.
    handshake_hash: [u8; 32],
    /// The cipher suite of the handshake that produced these keys.
    suite: Suite,
}

impl TransportState {
    /// Returns the cipher suite these keys were derived under.
    ///
    /// A re-handshake must use it again, and so must anything the specification seals with the
    /// suite's AEAD, such as a pairing payload.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Returns the handshake hash `h` of the handshake these keys came from.
    ///
    /// Noise finalises `h` when the second handshake message is processed, and nothing after that
    /// changes it. Sendspin uses it once: a [re-handshake](https://github.com/Sendspin/spec/blob/main/connection.md#re-handshake)
    /// mixes the previous handshake's `h` in as its prologue, so a second handshake that reuses
    /// these keys must be built with this value. It is a transcript hash, not key material, but it
    /// must still never be logged.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Encrypts one plaintext into a Noise transport message.
    ///
    /// Fails if the plaintext does not fit into a single Noise message, that is if it is larger
    /// than [`MAX_MESSAGE_LEN`] minus the 16-byte authentication tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure_plaintext_len(plaintext.len())?;
        let mut message = vec![0u8; plaintext.len() + TAG_LEN];
        let len = self
            .state
            .write_message(plaintext, &mut message)
            .context("failed to encrypt the Noise transport message")?;
        message.truncate(len);
        Ok(message)
    }

    /// Decrypts one Noise transport message.
    ///
    /// Fails if the ciphertext is longer than a Noise message, shorter than the authentication
    /// tag, or does not authenticate under the current key and nonce.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure_message_len(ciphertext.len(), "transport message")?;
        let mut plaintext = vec![0u8; plaintext_capacity(ciphertext.len(), "transport message")?];
        let len = self
            .state
            .read_message(ciphertext, &mut plaintext)
            .context("failed to decrypt the Noise transport message")?;
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

/// Reads the initiator's static public key from a prologue of concatenated init messages.
///
/// The prologue is the exact `client/init` followed by `server/init` exchange, so it is parsed
/// as a stream of top-level JSON documents and the caller passes the two documents without
/// splitting them. Malformed JSON, a missing `server/init`, a non-canonical `server_id` and a
/// second `server/init` are all errors: guessing a key here would mean handshaking with a static
/// key the initiator may not hold.
fn initiator_key_from_prologue(prologue: &[u8]) -> Result<[u8; 32]> {
    let mut server_id = None;
    for document in serde_json::Deserializer::from_slice(prologue).into_iter::<serde_json::Value>()
    {
        let document = document.context("the prologue is not a sequence of JSON documents")?;
        if document.get("type").and_then(serde_json::Value::as_str) != Some("server/init") {
            continue;
        }
        if server_id.is_some() {
            bail!("the prologue contains more than one `server/init` document");
        }
        let id = document
            .pointer("/payload/server_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                anyhow!("the `server/init` document carries no string `payload.server_id`")
            })?;
        server_id = Some(decode_key(id).ok_or_else(|| {
            anyhow!("`server_id` is not a canonical 43-character unpadded base64url X25519 key")
        })?);
    }

    server_id.ok_or_else(|| {
        anyhow!(
            "the prologue contains no `server/init` document with a `server_id`, so the \
             initiator's static public key is unknown; pass it with `Responder::with_peer`"
        )
    })
}

/// Derives the X25519 public key that belongs to `secret`.
fn public_key_for(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Reads the cipher suite the prologue's `client/init` announces.
///
/// The suite a handshake runs is the suite the client announced: it is not negotiated, and a
/// name this build does not have is an error rather than a reason to use [`Suite::default`]. A
/// prologue with no `client/init`, a missing or non-string `suite` and two `client/init`
/// documents are errors too, for the same reason a missing `server_id` is: the handshake would
/// otherwise guess what the peer meant.
fn suite_from_prologue(prologue: &[u8]) -> Result<Suite> {
    let mut announced = None;
    for document in serde_json::Deserializer::from_slice(prologue).into_iter::<serde_json::Value>()
    {
        let document = document.context("the prologue is not a sequence of JSON documents")?;
        if let Some(suite) = client_init_suite(&document)? {
            if announced.is_some() {
                bail!("the prologue contains more than one `client/init` document");
            }
            announced = Some(suite);
        }
    }

    announced.ok_or_else(|| {
        anyhow!(
            "the prologue contains no `client/init` document with a `suite`, so the cipher suite \
             is unknown; a first handshake needs the init exchange, pass the suite with \
             `Responder::with_peer_suite` on a re-handshake"
        )
    })
}

/// Reads the suite a prologue announces, if the prologue is the init exchange at all.
///
/// `None` means there is no `client/init` document to read: a re-handshake prologue is the
/// previous handshake hash, which is not JSON, and carries no announcement. A `client/init` that
/// carries no usable suite is still an error, so an announcement is never half-read.
fn announced_suite_from_prologue(prologue: &[u8]) -> Result<Option<Suite>> {
    let mut announced = None;
    for document in serde_json::Deserializer::from_slice(prologue).into_iter::<serde_json::Value>()
    {
        let Ok(document) = document else {
            // Not a sequence of JSON documents: no announcement to check against.
            return Ok(None);
        };
        if let Some(suite) = client_init_suite(&document)? {
            if announced.is_some() {
                bail!("the prologue contains more than one `client/init` document");
            }
            announced = Some(suite);
        }
    }
    Ok(announced)
}

/// Returns the suite one init document announces, or `None` when it is not a `client/init`.
fn client_init_suite(document: &serde_json::Value) -> Result<Option<Suite>> {
    if document.get("type").and_then(serde_json::Value::as_str) != Some("client/init") {
        return Ok(None);
    }
    let name = document
        .pointer("/payload/suite")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow!(
                "the `client/init` document carries no string `payload.suite`; the cipher suite \
                 is required and is not assumed to be `{}`",
                Suite::default()
            )
        })?;
    Ok(Some(Suite::from_wire_name(name).ok_or_else(|| {
        anyhow!(
            "the `client/init` document announces the cipher suite `{name}`, which this build \
             does not have; it supports {}",
            Suite::ALL
                .map(Suite::wire_name)
                .map(|name| format!("`{name}`"))
                .join(", ")
        )
    })?))
}

/// Rejects a Noise message that exceeds the protocol maximum.
fn ensure_message_len(len: usize, what: &str) -> Result<()> {
    if len > MAX_MESSAGE_LEN {
        bail!(
            "Noise {what} is {len} bytes, exceeding the maximum Noise message size of \
             {MAX_MESSAGE_LEN} bytes"
        );
    }
    Ok(())
}

/// Rejects plaintext that cannot fit into one Noise message.
fn ensure_plaintext_len(len: usize) -> Result<()> {
    if len > MAX_PLAINTEXT_LEN {
        bail!(
            "plaintext is {len} bytes, exceeding the maximum Noise plaintext size of \
             {MAX_PLAINTEXT_LEN} bytes (a {MAX_MESSAGE_LEN}-byte message including the \
             {TAG_LEN}-byte tag); payloads are not fragmented at this layer"
        );
    }
    Ok(())
}

/// Returns how much plaintext a message of `len` bytes can carry.
fn plaintext_capacity(len: usize, what: &str) -> Result<usize> {
    len.checked_sub(TAG_LEN).ok_or_else(|| {
        anyhow!("Noise {what} is {len} bytes, shorter than the {TAG_LEN}-byte authentication tag")
    })
}

/// Decodes a canonical 32-byte unpadded base64url key.
fn decode_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != KEY_CHARS {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return None;
    }
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_INIT: &[u8] =
        br#"{"type":"client/init","payload":{"client_id":"test-client","version":1}}"#;

    fn server_init(server_id: &str) -> Vec<u8> {
        format!(r#"{{"type":"server/init","payload":{{"server_id":"{server_id}","version":1}}}}"#)
            .into_bytes()
    }

    fn prologue(server_id: &str) -> Vec<u8> {
        let mut bytes = CLIENT_INIT.to_vec();
        bytes.extend_from_slice(&server_init(server_id));
        bytes
    }

    /// The prologue the Sentinel tests mix in. It is not JSON, so `Initiator::new` sees no suite
    /// announcement and takes the one it is passed - the same rule a re-handshake relies on.
    const TEST_PROLOGUE: &[u8] = b"client/init{}server/init{}";

    /// A pairing record's PSK, distinct from [`SENTINEL_PSK`] so the two outcomes cannot be
    /// confused.
    const RECORD_PSK: [u8; 32] = [0x11; 32];

    /// The metadata message 1 carries. This layer never interprets it, so its content is arbitrary.
    const MESSAGE_1_PAYLOAD: &[u8] = br#"{"psk_id":"test","psk_category":"sn"}"#;

    /// Builds the client half of the handshake on `snow` directly, as `tests/noise_handshake.rs`
    /// does, with `psk` in the message-2 slot.
    fn peer_responder(
        client: &Identity,
        server: &Identity,
        psk: &[u8; 32],
    ) -> snow::HandshakeState {
        snow::Builder::new(
            Suite::ChaChaPoly
                .params()
                .parse()
                .expect("valid Noise parameters"),
        )
        .local_private_key(&client.secret)
        .expect("set the local static key")
        .remote_public_key(&server.public)
        .expect("set the peer static key")
        .psk(2, psk)
        .expect("set the handshake PSK")
        .prologue(TEST_PROLOGUE)
        .expect("set the Noise prologue")
        .build_responder()
        .expect("build the Noise responder")
    }

    fn peer_write(peer: &mut snow::HandshakeState, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; MAX_MESSAGE_LEN];
        let len = peer
            .write_message(payload, &mut message)
            .expect("write a Noise handshake message");
        message.truncate(len);
        message
    }

    fn peer_read(peer: &mut snow::HandshakeState, message: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; MAX_MESSAGE_LEN];
        let len = peer
            .read_message(message, &mut payload)
            .expect("read a Noise handshake message");
        payload.truncate(len);
        payload
    }

    /// Builds both halves with their own PSK and exchanges message 1, which no PSK seals.
    fn handshake_after_message_1(
        initiator_psk: &[u8; 32],
        peer_psk: &[u8; 32],
    ) -> (Initiator, snow::HandshakeState) {
        let server = Identity::generate();
        let client = Identity::generate();
        let mut initiator =
            Initiator::new(&server, &client.public, Suite::ChaChaPoly, TEST_PROLOGUE)
                .expect("build the initiator");
        initiator
            .set_psk(initiator_psk)
            .expect("select the initiator PSK");
        let mut peer = peer_responder(&client, &server, peer_psk);

        let message_1 = initiator
            .write_message(MESSAGE_1_PAYLOAD)
            .expect("write message 1");
        assert_eq!(
            peer_read(&mut peer, &message_1),
            MESSAGE_1_PAYLOAD,
            "message 1 must reach the peer whichever key each side selected"
        );
        (initiator, peer)
    }

    #[test]
    fn the_prologue_carries_the_initiator_static_key() {
        let identity = Identity::generate();
        let key = initiator_key_from_prologue(&prologue(&identity.public_base64()))
            .expect("server/init carries server_id");
        assert_eq!(key, identity.public);
    }

    #[test]
    fn a_prologue_without_a_server_init_is_rejected() {
        let identity = Identity::generate();

        for prologue in [&b""[..], CLIENT_INIT] {
            let result = Responder::new(&identity, prologue);
            assert!(
                result.is_err(),
                "a prologue without server/init must be rejected"
            );
            let err = result.err().expect("the rejection was asserted");
            let message = format!("{err:#}");
            assert!(
                message.contains("server_id") && message.contains("with_peer"),
                "error should name the missing key and the way out, got: {message}"
            );
        }

        // Malformed JSON is a parse error, not a silently skipped document.
        let result = Responder::new(&identity, b"not json at all");
        assert!(
            result.is_err(),
            "a prologue that is not JSON must be rejected"
        );
        let err = result.err().expect("the rejection was asserted");
        assert!(
            format!("{err:#}").contains("prologue is not a sequence of JSON documents"),
            "error should name the malformed prologue, got: {err:#}"
        );
    }

    #[test]
    fn prologue_with_duplicate_server_id_is_rejected() {
        let identity = Identity::generate();
        let first = Identity::generate().public_base64();
        let second = Identity::generate().public_base64();
        let mut prologue = prologue(&first);
        prologue.extend_from_slice(&server_init(&second));

        let result = Responder::new(&identity, &prologue);
        assert!(result.is_err(), "two server/init documents are ambiguous");
        let err = result.err().expect("the rejection was asserted");
        assert!(
            format!("{err:#}").contains("more than one `server/init`"),
            "error should name the duplicate, got: {err:#}"
        );
    }

    #[test]
    fn an_identity_mismatch_is_rejected_before_the_handshake() {
        let mut identity = Identity::generate();
        identity.public = Identity::generate().public;
        let prologue = prologue(&Identity::generate().public_base64());
        let result = Responder::with_peer(&identity, &[0u8; 32], &prologue);
        assert!(result.is_err(), "a mismatched identity must be rejected");
        let err = result.err().expect("the rejection was asserted");
        assert!(
            format!("{err:#}").contains("does not match"),
            "error should name the mismatch, got: {err:#}"
        );
    }

    #[test]
    fn a_server_init_without_a_usable_server_id_is_rejected() {
        let identity = Identity::generate();

        let mut missing = CLIENT_INIT.to_vec();
        missing.extend_from_slice(br#"{"type":"server/init","payload":{"version":1}}"#);
        let result = Responder::new(&identity, &missing);
        assert!(result.is_err(), "a server/init without server_id must fail");
        assert!(
            format!("{:#}", result.err().expect("the rejection was asserted"))
                .contains("payload.server_id"),
            "the error must name the missing field"
        );

        let mut wrong_type = CLIENT_INIT.to_vec();
        wrong_type.extend_from_slice(br#"{"type":"server/init","payload":{"server_id":42}}"#);
        let result = Responder::new(&identity, &wrong_type);
        assert!(result.is_err(), "a non-string server_id must fail");
        assert!(
            format!("{:#}", result.err().expect("the rejection was asserted"))
                .contains("payload.server_id")
        );
    }

    #[test]
    fn a_server_id_that_is_not_a_canonical_key_is_rejected() {
        let identity = Identity::generate();

        // Wrong length, an invalid base64url character, and 43 characters whose unused trailing
        // bits are not zero: only the canonical encoding of exactly 32 bytes may be accepted.
        for server_id in ["short", &"!".repeat(43), &"a".repeat(43)] {
            let result = Responder::new(&identity, &prologue(server_id));
            assert!(
                result.is_err(),
                "{server_id:?} must not be accepted as a key"
            );
            let message = format!("{:#}", result.err().expect("the rejection was asserted"));
            assert!(
                message.contains("canonical 43-character"),
                "the error must name the encoding, got: {message}"
            );
        }

        // The canonical form of the same 32-byte secret is accepted and yields that key.
        let id = "A".repeat(43);
        assert_eq!(
            initiator_key_from_prologue(&prologue(&id)).expect("a canonical key is accepted"),
            {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine as _;
                let bytes = URL_SAFE_NO_PAD.decode(&id).expect("the id is base64url");
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                key
            }
        );
    }

    #[test]
    fn identity_debug_redacts_the_secret() {
        let identity = Identity::generate();
        let text = format!("{identity:?}");
        assert!(text.contains(&identity.public_base64()));
        assert!(!text.contains(&identity.secret_base64()));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn a_failed_read_can_be_retried_with_another_psk() {
        // The initiator announced the record's key, but the peer sealed message 2 with the
        // Sentinel key: the read fails under the record's key and succeeds on the same bytes under
        // the Sentinel key.
        let (mut initiator, mut peer) = handshake_after_message_1(&RECORD_PSK, &SENTINEL_PSK);
        let message_2 = peer_write(&mut peer, b"{}");

        let error = initiator
            .read_message(&message_2)
            .expect_err("a message 2 sealed with the Sentinel key must not authenticate");
        assert_eq!(
            error.downcast_ref::<snow::Error>(),
            Some(&snow::Error::Decrypt),
            "a wrong PSK is an authentication failure, not a length or state failure"
        );

        let (outcome, payload) = initiator
            .read_message_with_sentinel(&message_2)
            .expect("the same bytes authenticate under the Sentinel key");
        assert_eq!(outcome, PskOutcome::SentinelFallback);
        assert_eq!(payload, b"{}");
        assert!(initiator.handshake_finished());

        // The retry must leave both sides on the same keys. The peer's `h` is captured before
        // `into_transport_mode` consumes the state that holds it.
        let peer_hash = peer.get_handshake_hash().to_vec();
        let mut ours = initiator.into_transport().expect("initiator transport");
        assert_eq!(
            ours.handshake_hash().to_vec(),
            peer_hash,
            "the retried handshake derived a hash the peer does not share"
        );
        let mut theirs = peer.into_transport_mode().expect("the peer's transport");

        let ciphertext = ours.encrypt(b"from the initiator").expect("encrypt");
        let mut plaintext = vec![0u8; MAX_MESSAGE_LEN];
        let len = theirs
            .read_message(&ciphertext, &mut plaintext)
            .expect("the peer decrypts");
        assert_eq!(&plaintext[..len], b"from the initiator");

        let mut ciphertext = vec![0u8; MAX_MESSAGE_LEN];
        let len = theirs
            .write_message(b"from the responder", &mut ciphertext)
            .expect("the peer encrypts");
        assert_eq!(
            ours.decrypt(&ciphertext[..len]).expect("decrypt"),
            b"from the responder"
        );
    }

    #[test]
    fn a_successful_read_is_not_retried() {
        let (mut initiator, mut peer) = handshake_after_message_1(&RECORD_PSK, &RECORD_PSK);
        let message_2 = peer_write(&mut peer, b"{}");

        let (outcome, payload) = initiator
            .read_message_with_sentinel(&message_2)
            .expect("message 2 authenticates under the selected key");
        assert_eq!(outcome, PskOutcome::SelectedKey);
        assert_eq!(payload, b"{}");
        assert!(initiator.handshake_finished());
    }

    #[test]
    fn a_successful_read_returns_a_foreign_payload() {
        // A message that authenticates is never a reason to retry, whatever it carries: this layer
        // returns the payload verbatim and the session layer rejects a non-`{}` one.
        let (mut initiator, mut peer) = handshake_after_message_1(&RECORD_PSK, &RECORD_PSK);
        let message_2 = peer_write(&mut peer, b"not-empty");

        let (outcome, payload) = initiator
            .read_message_with_sentinel(&message_2)
            .expect("message 2 authenticates under the selected key");
        assert_eq!(outcome, PskOutcome::SelectedKey);
        assert_eq!(payload, b"not-empty");
    }

    #[test]
    fn the_sentinel_key_cannot_be_the_selected_key() {
        let server = Identity::generate();
        let client = Identity::generate();
        let mut initiator =
            Initiator::new(&server, &client.public, Suite::ChaChaPoly, TEST_PROLOGUE)
                .expect("build the initiator");
        initiator
            .set_psk(&SENTINEL_PSK)
            .expect("the Sentinel key is a valid PSK");

        // Four bytes are too short even for a tag: the refusal must come from the key, which means
        // the guard runs before anything is read.
        let error = initiator
            .read_message_with_sentinel(&[0u8; 4])
            .expect_err("there is no second key to retry under");
        let text = format!("{error:#}");
        assert!(
            text.contains("Sentinel"),
            "the error must name the Sentinel key, got: {text}"
        );
        assert!(!initiator.handshake_finished());
    }

    #[test]
    fn the_last_psk_write_wins() {
        let server = Identity::generate();
        let client = Identity::generate();
        let mut initiator =
            Initiator::new(&server, &client.public, Suite::ChaChaPoly, TEST_PROLOGUE)
                .expect("build the initiator");
        initiator
            .set_psk(&RECORD_PSK)
            .expect("select the record's key");
        initiator
            .set_psk(&SENTINEL_PSK)
            .expect("select the Sentinel key again");

        let error = initiator
            .read_message_with_sentinel(&[0u8; 4])
            .expect_err("the Sentinel key was the last write, so there is nothing to retry under");
        assert!(
            format!("{error:#}").contains("Sentinel"),
            "the error must name the Sentinel key, got: {error:#}"
        );
    }

    #[test]
    fn only_a_decrypt_failure_is_retried() {
        assert!(should_retry_under_sentinel(&snow::Error::Decrypt));

        for error in [
            snow::Error::Input,
            snow::Error::Dh,
            snow::Error::Rng,
            snow::Error::State(snow::error::StateProblem::NotTurnToRead),
        ] {
            assert!(
                !should_retry_under_sentinel(&error),
                "{error:?} is not an authentication failure and must not be retried"
            );
        }
    }

    #[test]
    fn a_frame_shorter_than_the_tag_is_not_retried() {
        let (mut initiator, _peer) = handshake_after_message_1(&RECORD_PSK, &RECORD_PSK);

        let error = initiator
            .read_message_with_sentinel(&[0u8; 12])
            .expect_err("12 bytes cannot carry an authentication tag");
        assert!(
            error.downcast_ref::<snow::Error>().is_none(),
            "the capacity guard, not snow, must reject a frame below the tag length"
        );
        assert!(
            format!("{error:#}").contains("16-byte"),
            "the error must name the tag length, got: {error:#}"
        );
    }

    #[test]
    fn a_frame_in_the_input_band_is_not_retried() {
        let (mut initiator, _peer) = handshake_after_message_1(&RECORD_PSK, &RECORD_PSK);

        // 20 bytes leave no room for the 32-byte `e` token, so `snow` rejects the shape without
        // authenticating anything; retrying that under another key could only hide a malformed
        // frame.
        let error = initiator
            .read_message_with_sentinel(&[0u8; 20])
            .expect_err("20 bytes cannot carry a message-2 ephemeral key");
        assert_eq!(
            error.downcast_ref::<snow::Error>(),
            Some(&snow::Error::Input)
        );
    }

    #[test]
    fn a_truncated_tag_is_retried_and_still_fails() {
        let (mut initiator, _peer) = handshake_after_message_1(&RECORD_PSK, &RECORD_PSK);

        // 40 bytes carry the 32-byte `e` token but only 8 bytes where a 16-byte tag belongs, so
        // both keys fail as `Decrypt`; the caller sees the retry's failure.
        let error = initiator
            .read_message_with_sentinel(&[0u8; 40])
            .expect_err("a truncated tag must not authenticate");
        assert_eq!(
            error.downcast_ref::<snow::Error>(),
            Some(&snow::Error::Decrypt)
        );
    }
}
