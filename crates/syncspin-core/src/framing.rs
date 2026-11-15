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
//! fragment to one buffer and dispatches the result when the last flag arrives. This module does
//! no I/O: [`split_binary`] and [`reassemble_binary`] are pure conversions.

use anyhow::{bail, Context, Result};

use crate::noise::MAX_MESSAGE_LEN;

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

/// Largest plaintext that fits in one Noise transport message, including the message id byte.
///
/// The Noise specification caps a transport message at [`MAX_MESSAGE_LEN`]; the cipher suites
/// used by the protocol authenticate the message with a 16-byte tag, which leaves 65 519 bytes of
/// plaintext.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - AEAD_TAG_LEN;

/// Largest reassembled message, bounding the buffer a peer can make the receiver allocate.
///
/// The protocol lets a receiver choose its own limit; a message beyond it is a protocol error.
pub const MAX_REASSEMBLED_LEN: usize = 64 * 1024 * 1024;

/// Length of the authentication tag every Noise transport message carries.
const AEAD_TAG_LEN: usize = 16;

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
/// The first byte carries the binary message id: id [`BINARY_MESSAGE_ID_JSON`] introduces a
/// UTF-8 JSON body and every other id introduces a binary body. Cleartext text frames of the
/// handshake have no id byte and are parsed as JSON directly.
///
/// Fragment frames (id [`BINARY_MESSAGE_ID_FRAGMENT`]) are classified like any other binary
/// message, with the payload starting at the flags byte. To reassemble, pass the plaintexts
/// themselves to [`reassemble_binary`], because it needs the id byte of each fragment.
///
/// # Errors
/// Returns an error for an empty plaintext, which is always a protocol error, and for a JSON body
/// that is not valid UTF-8.
pub fn decode_text(bytes: &[u8]) -> Result<Frame<'_>> {
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

/// Reassembles frames into the original message.
///
/// Accepts a single unfragmented frame, returning its id and body unchanged, as well as the
/// fragment sequence [`split_binary`] produces. The sequence is validated before the body is
/// returned.
///
/// The framing carries no byte count and no sequence number, so a fragment lost from the middle of
/// a message cannot be detected here. What is detectable is rejected: a continuation before the
/// first fragment, a first flag on a later fragment, data after the last fragment, a missing last
/// fragment, reserved flag bits, an original id of [`BINARY_MESSAGE_ID_FRAGMENT`], and a message
/// larger than [`MAX_REASSEMBLED_LEN`].
///
/// # Errors
/// Returns an error when the frames are empty or cannot be a complete, well-formed message.
pub fn reassemble_binary(frames: &[Vec<u8>]) -> Result<(u8, Vec<u8>)> {
    if frames.is_empty() {
        bail!("no frame to reassemble");
    }
    if let [frame] = frames {
        if let Some((&id, payload)) = frame.split_first() {
            if id != BINARY_MESSAGE_ID_FRAGMENT {
                return Ok((id, payload.to_vec()));
            }
        }
    }

    let mut message_id = None;
    let mut body = Vec::new();
    let mut complete = false;
    for (index, frame) in frames.iter().enumerate() {
        let Some((&id, rest)) = frame.split_first() else {
            bail!("frame {index}: empty");
        };
        if id != BINARY_MESSAGE_ID_FRAGMENT {
            bail!("frame {index}: message id {id} is not the fragmentation id");
        }
        if complete {
            bail!("frame {index}: follows the last fragment");
        }
        let Some((&flags, rest)) = rest.split_first() else {
            bail!("frame {index}: missing flags byte");
        };
        if flags & FRAGMENT_FLAGS_RESERVED != 0 {
            bail!("frame {index}: reserved flag bits set in 0x{flags:02x}");
        }
        let first = flags & FRAGMENT_FLAG_FIRST != 0;
        let last = flags & FRAGMENT_FLAG_LAST != 0;
        if first && index != 0 {
            bail!("frame {index}: first flag set on a continuation fragment");
        }
        if !first && index == 0 {
            bail!("frame 0: continuation fragment without a first fragment");
        }
        if first {
            let Some((&original_id, data)) = rest.split_first() else {
                bail!("frame 0: first fragment misses the original message id");
            };
            if original_id == BINARY_MESSAGE_ID_FRAGMENT {
                bail!("frame 0: original message id is the fragmentation id");
            }
            message_id = Some(original_id);
            body.extend_from_slice(data);
        } else {
            body.extend_from_slice(rest);
        }
        if body.len() > MAX_REASSEMBLED_LEN {
            bail!("fragmented message exceeds {MAX_REASSEMBLED_LEN} bytes");
        }
        complete = last;
    }
    if !complete {
        bail!("the last fragment is missing: no fragment carried the last flag");
    }
    let id = message_id.expect("a complete sequence starts with a first fragment");
    Ok((id, body))
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
