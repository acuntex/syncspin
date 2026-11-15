//! Sendspin's Noise layer: `Noise_KKpsk2_25519_ChaChaPoly_SHA256`.
//!
//! Every Sendspin connection is wrapped in Noise. The handshake follows the cleartext init
//! exchange and precedes all application traffic:
//!
//! ```text
//! client -> server  client/init      cleartext JSON, carries the client_id
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
//! This module is the responder half plus the transport that follows the handshake. It does not
//! interpret handshake payloads; the session layer validates the `psk_id`/`psk_category`
//! metadata. This milestone uses the published Sentinel PSK, which is what an unpaired client
//! uses and which provides no authentication on its own; selecting a different PSK from message 1
//! arrives with the session layer.

use std::fmt;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Noise protocol parameters used by Sendspin.
pub const NOISE_PARAMS: &str = "Noise_KKpsk2_25519_ChaChaPoly_SHA256";

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
}

impl Responder {
    /// Builds the responder for the client side of a Sendspin handshake.
    ///
    /// `prologue` must be the exact concatenation of the `client/init` and `server/init` bytes
    /// as transmitted, in that order. It is mixed into the handshake verbatim, and the
    /// initiator's static public key is read from the `server_id` field of the `server/init`
    /// document it contains. A prologue that is not a sequence of JSON documents, that carries
    /// no `server/init`, or that carries two of them is rejected; use [`Responder::with_peer`]
    /// when the key is already known, as during a re-handshake where the prologue is the
    /// previous handshake hash.
    pub fn new(identity: &Identity, prologue: &[u8]) -> Result<Responder> {
        let peer_public = initiator_key_from_prologue(prologue)?;
        Responder::with_peer(identity, &peer_public, prologue)
    }

    /// Builds the responder with the initiator's static public key supplied explicitly.
    ///
    /// Use this when the prologue is not the init exchange, for example on a re-handshake whose
    /// prologue is the previous handshake hash. `prologue` still reaches Noise unchanged; both
    /// sides must mix in the same bytes.
    pub fn with_peer(
        identity: &Identity,
        peer_public: &[u8; 32],
        prologue: &[u8],
    ) -> Result<Responder> {
        identity.validate()?;

        // Keep the published constant honest even if someone edits it.
        debug_assert_eq!(psk_id_for(&SENTINEL_PSK), SENTINEL_PSK_ID);

        let params = NOISE_PARAMS
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
        Ok(Responder { handshake })
    }

    /// Replaces the pre-shared key used by the rest of the handshake.
    ///
    /// The responder starts with the published Sentinel PSK because the key is selected from the
    /// metadata that message 1 carries. Call this after [`Responder::read_message`] and before
    /// [`Responder::write_message`]: Noise mixes the key into message 2, so both sides must use
    /// the same value and the initiator rejects a message sealed with another one.
    ///
    /// # Errors
    /// Fails when the handshake has already mixed in the key, which makes a late change
    /// impossible.
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
        ensure_message_len(msg.len(), "handshake message")?;
        let mut payload = vec![0u8; plaintext_capacity(msg.len(), "handshake message")?];
        let len = self
            .handshake
            .read_message(msg, &mut payload)
            .context("failed to read the Noise handshake message")?;
        payload.truncate(len);
        Ok(payload)
    }

    /// Writes Noise handshake message 2 and returns it.
    ///
    /// The payload is the empty JSON object that Sendspin requires; it is not configurable.
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        let mut message = vec![0u8; MAX_MESSAGE_LEN];
        let len = self
            .handshake
            .write_message(HANDSHAKE_MESSAGE_2, &mut message)
            .context("failed to write the Noise handshake message")?;
        message.truncate(len);
        Ok(message)
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
        // `h` is final once the second message has been processed, and `into_transport_mode`
        // consumes the handshake state that holds it.
        let handshake_hash: [u8; 32] = self
            .handshake
            .get_handshake_hash()
            .try_into()
            .context("the Noise handshake hash is not 32 bytes")?;
        let state = self
            .handshake
            .into_transport_mode()
            .context("failed to finish the Noise handshake")?;
        Ok(TransportState {
            state,
            handshake_hash,
        })
    }
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
}

impl TransportState {
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
}
