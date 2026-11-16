//! The two halves of this repository in one process: a real `syncspin-client` on a real
//! `syncspin-server`.
//!
//! Every other test of this crate speaks the specification with a fake client, so the two halves
//! could agree on a mistake and both tests would pass. This one connects the published client
//! crate - its Noise responder, its `client/time` bursts, its clock filter and its playout
//! scheduling - to the server's listener, clock and stream, and checks what reaches the client's
//! sink: the server's bytes, and a playout deadline in the near future rather than in the past.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use syncspin_client::{AudioFrame, Client, ClientConfig, Event, GoodbyeReason, Identity, Sink};
use syncspin_server::{AudioFormat, Server, ServerConfig, TrackInfo};
use tokio::sync::mpsc;

/// How long the test waits for anything at all.
const TIMEOUT: Duration = Duration::from_secs(20);

/// The lead the server schedules the first frame with, plus room for a busy machine.
const MAX_LEAD: Duration = Duration::from_millis(400);

/// How far behind its arrival a deadline may be before it counts as stale.
///
/// A deadline the client cannot place in the future is reported as the instant it computed it,
/// which is microseconds before the sink sees it. Anything further behind would mean the frame was
/// scheduled from a clock that no longer holds.
const DEADLINE_SLACK: Duration = Duration::from_millis(50);

/// The playtime of one test chunk: 480 stereo frames of 16-bit PCM at 48 kHz.
const CHUNK: Duration = Duration::from_millis(10);

/// A sink that reports every frame to the test and plays nothing.
///
/// The client's clock estimate is ready before the server announces the stream, so a frame that
/// arrives after that carries the deadline the scheduling is about.
struct ReportingSink {
    frames: mpsc::UnboundedSender<(Instant, Instant, usize)>,
}

impl Sink for ReportingSink {
    fn open(&mut self, _format: syncspin_client::AudioFormat) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, frame: AudioFrame<'_>, due: Instant) -> Result<()> {
        let length = match &frame {
            AudioFrame::Pcm(bytes) => bytes.len(),
            AudioFrame::Encoded { data, .. } => data.len(),
        };
        let _ = self.frames.send((Instant::now(), due, length));
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_real_client_plays_our_stream_on_schedule() -> Result<()> {
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        format: AudioFormat::pcm(48_000, 2, 16),
        ..ServerConfig::new("A test server", syncspin_server::Identity::generate())
    };
    let server = Server::start(config).await?;
    let port = server.local_addr().port();

    let (frames, mut received) = mpsc::unbounded_channel();
    // `ClientConfig::new` asks for PCM by default, which is the format this server streams.
    let client_config = ClientConfig::new(
        format!("127.0.0.1:{port}"),
        "A test player",
        Identity::generate(),
    );
    let (mut handle, mut events) =
        Client::connect(client_config, Box::new(ReportingSink { frames })).await?;

    let event = tokio::time::timeout(TIMEOUT, events.next())
        .await
        .context("the client did not reach the server")?
        .context("the client's event stream ended")?;
    match event {
        Event::Connected { encrypted, .. } => assert!(encrypted, "the connection is encrypted"),
        other => bail!("expected Connected, got {other:?}"),
    }

    // The server announces a stream; the client receives it only after the `client/state` its first
    // clock bursts allow, because the server waits for that report before announcing anything.
    let mut writer = server.open_stream(TrackInfo {
        title: Some("A title".to_owned()),
        duration: Some(Duration::from_secs(200)),
        ..TrackInfo::default()
    });
    loop {
        let event = tokio::time::timeout(TIMEOUT, events.next())
            .await
            .context("the client did not report a stream")?
            .context("the client's event stream ended")?;
        match event {
            Event::StreamStart { format } => {
                assert_eq!(format.sample_rate, 48_000);
                assert_eq!(format.channels, 2);
                assert_eq!(format.bit_depth, 16);
                break;
            }
            Event::Disconnected { reason, .. } => bail!("the client disconnected: {reason}"),
            _ => continue,
        }
    }

    // 480 stereo frames of 16-bit PCM are 10 ms at 48 kHz. Frames that arrive while the clock
    // estimate is still forming carry `now`, so the test keeps writing until the server's lead
    // shows: that is the deadline the scheduling promise is about. Each write is paced at the
    // playtime of the chunk, because a writer that ran ahead of the timeline would push the
    // deadlines into the past and prove nothing.
    let chunk = [9u8; 480 * 4];
    let give_up = Instant::now() + TIMEOUT;
    let (arrival, due) = 'frames: loop {
        if Instant::now() >= give_up {
            bail!("no frame arrived with a playout deadline ahead of its arrival");
        }
        writer.write(&chunk);
        tokio::time::sleep(CHUNK).await;
        while let Ok((arrival, due, length)) = received.try_recv() {
            assert_eq!(
                length,
                chunk.len(),
                "the server's bytes reach the sink unchanged"
            );
            let behind = arrival.saturating_duration_since(due);
            assert!(
                behind <= DEADLINE_SLACK,
                "a deadline {behind:?} behind its arrival is scheduled from a stale clock"
            );
            if due > arrival {
                break 'frames (arrival, due);
            }
        }
    };
    let lead = due.duration_since(arrival);
    assert!(
        lead <= MAX_LEAD,
        "the frame is due {lead:?} ahead, beyond the {MAX_LEAD:?} the server schedules with"
    );

    writer.end();
    handle.close(GoodbyeReason::Shutdown);
    drop(events);
    drop(handle);
    server.shutdown().await?;
    Ok(())
}
