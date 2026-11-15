//! Binary framing: message ids, fragmentation and reassembly.
//!
//! After the Noise handshake every application message is one Noise transport message. Its
//! plaintext starts with a one-byte binary message id: `0` carries a UTF-8 JSON body, `1` is the
//! fragmentation channel, and each role owns its own ids (for example `4` for player audio).
//! [`MAX_PLAINTEXT_LEN`] bounds one plaintext, so a larger payload has to be split.
//!
//! Fragmentation keeps the byte layout of the published protocol:
//!
//! ```text
//! first fragment   [1][flags with the first bit][original message id][data]
//! later fragments  [1][flags][data]
//! ```
//!
//! Bit 0 of the flags byte marks the last fragment, bit 1 the first one, and bits 2-7 must be
//! zero. Only one fragmented message may be in flight per direction, so the receiver appends every
//! fragment to one buffer and dispatches the result when the last flag arrives. [`Reassembler`]
//! does that for a session reading frame by frame; [`reassemble_binary`] does it for a sequence
//! already in hand. This module does no I/O.

use anyhow::{bail, Context, Result};

pub use crate::noise::MAX_PLAINTEXT_LEN;

/// Binary message id of a JSON message body.
pub const BINARY_MESSAGE_ID_JSON: u8 = 0;

/// Binary message id of a fragment.
///
/// A sender must never use it as the id of a fragmented message.
pub const BINARY_MESSAGE_ID_FRAGMENT: u8 = 1;

/// Fragment flag marking the last fragment of a message.
pub const FRAGMENT_FLAG_LAST: u8 = 0x01;

/// Fragment flag marking the first fragment of a message.
pub const FRAGMENT_FLAG_FIRST: u8 = 0x02;

/// Fragment flag bits that are reserved and must be zero.
pub const FRAGMENT_FLAGS_RESERVED: u8 = 0xfc;

/// Largest reassembled message, bounding the buffer a peer can make the receiver allocate.
///
/// The protocol lets a receiver choose its own limit; a message beyond it is a protocol error.
pub const MAX_REASSEMBLED_LEN: usize = 64 * 1024 * 1024;

/// Header of a first fragment: message id, flags byte and original message id.
const FIRST_FRAGMENT_HEADER_LEN: usize = 3;

/// Header of a continuation fragment: message id and flags byte.
const FRAGMENT_HEADER_LEN: usize = 2;

/// One plaintext frame, classified by its leading message id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A JSON message body (message id [`BINARY_MESSAGE_ID_JSON`]).
    Json(&'a str),
    /// A binary message of the given id; `payload` is everything after the id byte.
    Binary {
        /// Binary message id.
        id: u8,
        /// Message body, without the id byte.
        payload: &'a [u8],
    },
}

/// Decodes one Noise transport plaintext into a [`Frame`].
///
/// The first byte of a plaintext is its binary message id: id [`BINARY_MESSAGE_ID_JSON`]
/// introduces a UTF-8 JSON body and every other id introduces a binary body. Cleartext handshake
/// messages do not travel through Noise, carry no id byte and are JSON text the caller parses
/// directly; this function never sees them.
///
/// Fragment frames (id [`BINARY_MESSAGE_ID_FRAGMENT`]) are classified like any other binary
/// message, with the payload starting at the flags byte. A session hands the plaintexts themselves
/// to a [`Reassembler`], which needs the id byte of each fragment, and decodes only the message the
/// reassembler completes.
///
/// # Errors
/// Returns an error for an empty plaintext, which is always a protocol error, and for a JSON body
/// that is not valid UTF-8.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>> {
    let Some((&id, payload)) = bytes.split_first() else {
        bail!("empty plaintext: every transport message carries a message id byte");
    };
    if id == BINARY_MESSAGE_ID_JSON {
        let text = std::str::from_utf8(payload).context("JSON message body is not valid UTF-8")?;
        return Ok(Frame::Json(text));
    }
    Ok(Frame::Binary { id, payload })
}

/// Encodes one binary message: the id byte followed by the payload.
pub fn encode_binary(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(id);
    frame.extend_from_slice(payload);
    frame
}

/// Splits a binary message into plaintext frames that each fit `max_plaintext`.
///
/// A message that fits returns exactly one frame, `[id][payload]`; a larger one returns the
/// fragments of message id [`BINARY_MESSAGE_ID_FRAGMENT`], the first carrying the original id.
/// Every fragment is at most `max_plaintext` bytes.
///
/// The payload is cut into equally sized chunks of `max_plaintext - 3` bytes, the capacity of a
/// first fragment, so a continuation frame stays one byte below the limit.
///
/// # Panics
/// Panics when `id` is [`BINARY_MESSAGE_ID_FRAGMENT`], or when `max_plaintext` is smaller than a
/// first-fragment header plus one payload byte.
pub fn split_binary(id: u8, payload: &[u8], max_plaintext: usize) -> Vec<Vec<u8>> {
    assert!(
        id != BINARY_MESSAGE_ID_FRAGMENT,
        "message id 1 is reserved for fragmentation"
    );
    assert!(
        max_plaintext > FIRST_FRAGMENT_HEADER_LEN,
        "max_plaintext must leave room for a fragment header and at least one payload byte"
    );

    if payload.len() < max_plaintext {
        return vec![encode_binary(id, payload)];
    }

    let chunk_len = max_plaintext - FIRST_FRAGMENT_HEADER_LEN;
    let count = payload.len().div_ceil(chunk_len);
    let mut frames = Vec::with_capacity(count);
    for (index, data) in payload.chunks(chunk_len).enumerate() {
        let first = index == 0;
        let last = index + 1 == count;
        let header_len = if first {
            FIRST_FRAGMENT_HEADER_LEN
        } else {
            FRAGMENT_HEADER_LEN
        };
        let mut frame = Vec::with_capacity(header_len + data.len());
        frame.push(BINARY_MESSAGE_ID_FRAGMENT);
        frame.push(fragment_flags(first, last));
        if first {
            frame.push(id);
        }
        frame.extend_from_slice(data);
        frames.push(frame);
    }
    frames
}

/// Incremental reassembler for one direction of a connection.
///
/// A session reads one frame at a time and owns a `Reassembler`; [`reassemble_binary`] is the same
/// validation for a sequence that is already in hand. Both allow only one fragmented message in
/// flight, as the protocol requires.
#[derive(Debug)]
pub struct Reassembler {
    max_message_len: usize,
    message: Option<InFlight>,
}

/// A fragmented message that is still being assembled.
#[derive(Debug)]
struct InFlight {
    /// Original message id, carried by the first fragment.
    message_id: u8,
    /// Payload bytes collected so far.
    body: Vec<u8>,
}

impl Reassembler {
    /// Creates a reassembler that rejects a reassembled message longer than `max_message_len`.
    ///
    /// A session usually passes [`MAX_REASSEMBLED_LEN`], the bound a receiver may choose for
    /// itself.
    pub fn new(max_message_len: usize) -> Self {
        Self {
            max_message_len,
            message: None,
        }
    }

    /// Feeds one Noise transport plaintext.
    ///
    /// Returns `Some((id, payload))` when the frame completes a message: immediately for a plain
    /// frame, and on the fragment that carries the last flag for a sequence. Every other fragment
    /// returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns an error, and drops any message in flight, for the malformed sequences the protocol
    /// defines: an empty frame, a plain frame while a fragmented message is in flight, a fragment
    /// without its flags byte, reserved flag bits, a continuation fragment without a first
    /// fragment, a second first fragment while one is in flight, a first fragment without its
    /// original message id, an original id of [`BINARY_MESSAGE_ID_FRAGMENT`], and a message larger
    /// than `max_message_len`.
    ///
    /// The framing carries no byte count and no sequence number, so a fragment lost from the middle
    /// of a message cannot be detected here.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<(u8, Vec<u8>)>> {
        let outcome = self.push_frame(frame);
        if outcome.is_err() {
            self.message = None;
        }
        outcome
    }

    /// Validates one frame and advances the reassembly state.
    fn push_frame(&mut self, frame: &[u8]) -> Result<Option<(u8, Vec<u8>)>> {
        let Some((&id, body)) = frame.split_first() else {
            bail!("empty frame");
        };
        if id != BINARY_MESSAGE_ID_FRAGMENT {
            if self.message.is_some() {
                bail!("non-fragment frame while a fragmented message is in flight");
            }
            return Ok(Some((id, body.to_vec())));
        }

        let Some((&flags, body)) = body.split_first() else {
            bail!("fragment frame missing its flags byte");
        };
        if flags & FRAGMENT_FLAGS_RESERVED != 0 {
            bail!("fragment flags 0x{flags:02x} set reserved bits");
        }
        let first = flags & FRAGMENT_FLAG_FIRST != 0;
        let last = flags & FRAGMENT_FLAG_LAST != 0;

        if first {
            if self.message.is_some() {
                bail!("first fragment while a fragmented message is in flight");
            }
            let Some((&message_id, data)) = body.split_first() else {
                bail!("first fragment missing its original message id");
            };
            if message_id == BINARY_MESSAGE_ID_FRAGMENT {
                bail!("first fragment carries the fragmentation id as its original message id");
            }
            if data.len() > self.max_message_len {
                bail!("fragmented message exceeds {} bytes", self.max_message_len);
            }
            let mut message = InFlight {
                message_id,
                body: Vec::with_capacity(data.len()),
            };
            message.body.extend_from_slice(data);
            if !last {
                self.message = Some(message);
                return Ok(None);
            }
            return Ok(Some((message_id, message.body)));
        }

        let Some(message) = self.message.as_mut() else {
            bail!("continuation fragment without a first fragment");
        };
        if message.body.len() + body.len() > self.max_message_len {
            bail!("fragmented message exceeds {} bytes", self.max_message_len);
        }
        message.body.extend_from_slice(body);
        if !last {
            return Ok(None);
        }
        let Some(InFlight { message_id, body }) = self.message.take() else {
            bail!("continuation fragment without a first fragment");
        };
        Ok(Some((message_id, body)))
    }
}

/// Reassembles a complete sequence of frames into the original message.
///
/// Accepts a single unfragmented frame, returning its id and body unchanged, as well as the
/// fragment sequence [`split_binary`] produces. A session that reads frame by frame keeps a
/// [`Reassembler`] instead; this is the batch form for a sequence that is already in hand.
///
/// The framing carries no byte count and no sequence number, so a fragment lost from the middle of
/// a message cannot be detected here. What is detectable is rejected: a continuation before the
/// first fragment, a first flag on a later fragment, data after the last fragment, a missing last
/// fragment, reserved flag bits, an original id of [`BINARY_MESSAGE_ID_FRAGMENT`], and a message
/// larger than [`MAX_REASSEMBLED_LEN`].
///
/// # Errors
/// Returns an error when the frames are empty, cannot form exactly one well-formed message, or
/// exceed [`MAX_REASSEMBLED_LEN`].
pub fn reassemble_binary(frames: &[Vec<u8>]) -> Result<(u8, Vec<u8>)> {
    if frames.is_empty() {
        bail!("no frame to reassemble");
    }
    let mut reassembler = Reassembler::new(MAX_REASSEMBLED_LEN);
    let mut message = None;
    for (index, frame) in frames.iter().enumerate() {
        let completed = reassembler
            .push(frame)
            .with_context(|| format!("frame {index}"))?;
        if let Some(completed) = completed {
            if message.is_some() {
                bail!("frame {index}: more than one message in one sequence");
            }
            message = Some(completed);
        }
    }
    let Some(message) = message else {
        bail!("the last fragment is missing: no fragment carried the last flag");
    };
    Ok(message)
}

/// Largest encoded-audio payload that fits one frame without fragmentation.
///
/// An audio chunk spends one byte on its message id, eight on the timestamp and four on
/// `send_ahead`, so the payload gets whatever `max_plaintext` has left. A value below that fixed
/// header, which makes any chunk impossible, yields 0.
pub fn max_audio_payload(max_plaintext: usize) -> usize {
    max_plaintext.saturating_sub(crate::messages::AudioChunkHeader::LEN)
}

/// Builds the flags byte of one fragment.
fn fragment_flags(first: bool, last: bool) -> u8 {
    let mut flags = 0;
    if first {
        flags |= FRAGMENT_FLAG_FIRST;
    }
    if last {
        flags |= FRAGMENT_FLAG_LAST;
    }
    flags
}
