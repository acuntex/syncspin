//! `server-demo` - a minimal Sendspin server: one group, a tone, no files.
//!
//! Start it, then point `player-pipe` at the address it prints:
//!
//! ```sh
//! cargo run -p server-demo
//! cargo run -p player-pipe -- --server <host>:8927 | aplay -f S16_LE -r 48000 -c 2
//! ```
//!
//! The first client is unpaired, so the demo approves it on arrival; approval is the operator
//! action `pairing.md` requires before a server may activate roles. Once the client has the
//! `player@v1` role, the demo opens a stream and writes a quiet 440 Hz tone, one 10 ms chunk every
//! 10 ms, until Ctrl-C. The identity is generated per run: this example holds no key material on
//! disk, so every start is a new server to a client that paired with the previous one.
//!
//! Nothing here decodes, queues or reads a file. A real host replaces the tone with its own frames
//! and keeps its identity in storage it owns.

use std::time::Duration;

use anyhow::Result;
use syncspin_server::{Event, Identity, Server, ServerConfig, StreamWriter, TrackInfo};
use tokio::time::{interval, MissedTickBehavior};

/// Sample rate of the demo stream, the rate every player must support.
const SAMPLE_RATE: u32 = 48_000;

/// Channel count of the demo stream.
const CHANNELS: u8 = 2;

/// Frames in one 10 ms chunk at [`SAMPLE_RATE`].
const FRAMES_PER_CHUNK: usize = 480;

/// Width of one sample in bytes.
const SAMPLE_BYTES: usize = 2;

/// Bytes in one interleaved frame.
const BYTES_PER_FRAME: usize = CHANNELS as usize * SAMPLE_BYTES;

/// Bytes in one chunk, the unit the writer is paced at.
const CHUNK_BYTES: usize = FRAMES_PER_CHUNK * BYTES_PER_FRAME;

/// Frequency of the demo tone.
const TONE_HZ: f64 = 440.0;

/// Peak amplitude as a fraction of the full scale, quiet enough to leave the speakers alone.
const AMPLITUDE: f64 = 0.1;

/// Builds one second of a stereo 16-bit little-endian tone.
fn tone() -> Vec<u8> {
    let frames = SAMPLE_RATE as usize;
    let mut bytes = Vec::with_capacity(frames * BYTES_PER_FRAME);
    for frame in 0..frames {
        let seconds = frame as f64 / f64::from(SAMPLE_RATE);
        let sample = (std::f64::consts::TAU * TONE_HZ * seconds).sin() * AMPLITUDE;
        let value = (sample * f64::from(i16::MAX)) as i16;
        for _ in 0..CHANNELS {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::new("syncspin-demo", Identity::generate());
    let mut server = Server::start(config).await?;
    eprintln!(
        "listening on {}; point player-pipe at this address",
        server.local_addr()
    );

    let tone = tone();
    let mut events = server.events();
    let mut stream: Option<(StreamWriter, usize)> = None;
    let mut pace = interval(Duration::from_millis(10));
    pace.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            event = events.next() => match event {
                Some(Event::ClientConnected {
                    client_id,
                    name,
                    approved,
                }) => {
                    eprintln!("{name} connected as {client_id} (approved: {approved})");
                    if !approved {
                        if let Err(error) = server.approve(&client_id).await {
                            eprintln!("could not approve {client_id}: {error}");
                        }
                    }
                }
                Some(Event::ClientActivated { roles, .. }) => {
                    eprintln!("activated with roles: {}", roles.join(", "));
                    if stream.is_none() && roles.iter().any(|role| role == "player@v1") {
                        let writer = server.open_stream(TrackInfo {
                            title: Some("syncspin demo tone".to_owned()),
                            ..TrackInfo::default()
                        });
                        stream = Some((writer, 0));
                        eprintln!("streaming a {TONE_HZ} Hz tone");
                    }
                }
                Some(Event::ClientLeft { reason }) => eprintln!("client left: {reason}"),
                Some(other) => eprintln!("{other:?}"),
                None => break,
            },
            _ = pace.tick(), if stream.is_some() => {
                if let Some((writer, offset)) = stream.as_mut() {
                    writer.write(&tone[*offset..*offset + CHUNK_BYTES]);
                    *offset = (*offset + CHUNK_BYTES) % tone.len();
                }
            }
        }
    }

    server.shutdown().await
}
