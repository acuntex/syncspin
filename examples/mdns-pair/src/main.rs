//! `mdns-pair` - one process that discovers its own server over mDNS.
//!
//! The example runs both halves of the protocol in one binary: it publishes
//! `_sendspin-server._tcp` under a name it derives for this run, discovers that same name from a
//! separate mDNS query, approves only the client that carries the name, and streams silent frames
//! into a counting sink until the stream arrives.
//!
//! Both dependencies are built with their `mdns` backend unconditionally: there is no feature
//! table, because an example without discovery has nothing to demonstrate.
//!
//! ```sh
//! cargo run -p mdns-pair
//! ```
//!
//! The run name is `mdns-pair-<pid>` unless `--name` names it explicitly. The PID keeps two runs on
//! one host apart, and it is also why an explicit name must fit the mDNS label with room to spare:
//! a derived name grows by the suffix, an explicit one is published as given.

mod advertise_only;
mod client_role;
mod find;
mod server_role;
mod sink;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use syncspin_client::{AudioFormat, ClientHandle, EventStream, GoodbyeReason, Identity};
// Both crates export an `MdnsDiscovery`; each role runs its own daemon, so each import names the
// role. The client's alias lives in `client_role`.
use syncspin_server::MdnsDiscovery as ServerMdns;
use syncspin_server::ServerConfig;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::advertise_only::AdvertiseOnly;
use crate::find::{timeout_message, Stage};
use crate::sink::{Counters, CountingSink};

/// Base name the run announces unless `--name` says otherwise.
const DEFAULT_NAME: &str = "mdns-pair";

/// Seconds of discovery and stream budget unless `--timeout` says otherwise.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Shortest accepted budget; below a second, no mDNS query completes.
const MIN_TIMEOUT_SECS: u64 = 1;

/// Longest accepted budget; a smoke test that waits longer has hung, not failed slowly.
const MAX_TIMEOUT_SECS: u64 = 120;

/// Longest mDNS label, in bytes. The service name is one DNS label, so this is its ceiling.
const MAX_MDNS_LABEL_LEN: usize = 63;

/// Sample rate of the run's stream: the PCM format the spec requires every server to support,
/// and the format this run's client advertises.
const SAMPLE_RATE: u32 = 48_000;

/// Channel count of the run's stream.
const CHANNELS: u8 = 2;

/// Bits per sample of the run's stream.
const BIT_DEPTH: u8 = 16;

/// Bytes in one interleaved frame: both channels of one sample.
const BYTES_PER_FRAME: usize = CHANNELS as usize * BIT_DEPTH as usize / 8;

/// Duration of one streamed chunk, in milliseconds.
///
/// The specification forbids a chunk shorter than 15 ms and longer than 150 ms, so 20 ms sits in
/// the middle of the range, and it is also the pace the server writes at.
const CHUNK_MS: u64 = 20;

/// Frames in one chunk at [`SAMPLE_RATE`].
const CHUNK_FRAMES: usize = SAMPLE_RATE as usize / 1000 * CHUNK_MS as usize;

/// Payload bytes in one chunk.
const CHUNK_BYTES: usize = CHUNK_FRAMES * BYTES_PER_FRAME;

/// Chunks the server streams: 600 ms, enough for the gate and still a short run.
const CHUNK_COUNT: usize = 30;

/// Frames the sink must receive before the run counts as a success.
const GATE_FRAMES: usize = 20;

/// Payload bytes those frames carry: 76,800, the number the gate asserts rather than prints.
const GATE_BYTES: usize = GATE_FRAMES * CHUNK_BYTES;

/// Upper bound on each of the three teardown waits — the client's goodbye, the server seeing it,
/// and the server task — so a stuck peer cannot hold the command open.
const TEARDOWN: Duration = Duration::from_secs(2);

/// What the command line asked for.
struct Options {
    /// Base name announced and discovered, without the PID suffix.
    name: String,
    /// Whether `--name` supplied the name; only a derived name grows by the PID.
    explicit_name: bool,
    /// Budget for discovery and for the first frames to arrive.
    timeout: Duration,
}

/// Result of parsing the command line.
enum Parse {
    /// Print the usage text and exit.
    Help,
    /// Run the example with these options.
    Run(Options),
}

/// Parses `--flag value`, `--flag=value`, `--help` and `-h`.
fn parse_args<I>(args: I) -> Result<Parse>
where
    I: IntoIterator<Item = String>,
{
    let mut name = DEFAULT_NAME.to_owned();
    let mut explicit_name = false;
    let mut timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let (flag, inline) = split_flag(&argument);
        match flag {
            "-h" | "--help" => return Ok(Parse::Help),
            "--name" => {
                name = take_value(flag, inline, &mut args)?;
                explicit_name = true;
            }
            "--timeout" => {
                let value = take_value(flag, inline, &mut args)?;
                let secs: u64 = value.parse().map_err(|_| {
                    anyhow!("--timeout needs a whole number of seconds, got {value:?}")
                })?;
                if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) {
                    bail!(
                        "--timeout is {secs} s, but the accepted range is \
                         {MIN_TIMEOUT_SECS}..={MAX_TIMEOUT_SECS}"
                    );
                }
                timeout = Duration::from_secs(secs);
            }
            other => bail!("unknown argument {other:?}; try --help"),
        }
    }

    // The run name is a single mDNS label; checking it here reports a bad name before an identity
    // is generated and a socket is opened. `run_name` checks the derived name again, because the
    // PID suffix can push a valid base over the limit.
    if name.len() > MAX_MDNS_LABEL_LEN {
        bail!(
            "--name is {} bytes, but an mDNS label allows at most {MAX_MDNS_LABEL_LEN}",
            name.len()
        );
    }

    Ok(Parse::Run(Options {
        name,
        explicit_name,
        timeout,
    }))
}

/// The name this run publishes and looks for.
///
/// A derived name carries the PID so two runs on one host do not answer for each other; an
/// explicit name is used as given and never grown. Either way the result must fit one mDNS label.
fn run_name(options: &Options, pid: u32) -> Result<String> {
    let name = if options.explicit_name {
        options.name.clone()
    } else {
        format!("{}-{pid}", options.name)
    };
    if name.len() > MAX_MDNS_LABEL_LEN {
        bail!(
            "the run name {name:?} is {} bytes, but an mDNS label allows at most \
             {MAX_MDNS_LABEL_LEN}",
            name.len()
        );
    }
    Ok(name)
}

/// Splits `--flag=value` into its two halves; leaves every other argument unchanged.
fn split_flag(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
        _ => (argument, None),
    }
}

/// Reads a flag's value from `--flag=value` or from the next argument.
fn take_value(
    flag: &str,
    inline: Option<&str>,
    args: &mut impl Iterator<Item = String>,
) -> Result<String> {
    let value = match inline {
        Some(value) => value.to_owned(),
        None => args.next().ok_or_else(|| anyhow!("{flag} needs a value"))?,
    };
    if value.trim().is_empty() {
        bail!("{flag} needs a value that is not empty");
    }
    if value.starts_with('-') {
        bail!("{flag} needs a value, but {value:?} is another flag");
    }
    Ok(value)
}

/// The help text; the defaults come from the same constants the parser uses.
fn usage() -> String {
    format!(
        "\
mdns-pair - discover this run's own server over mDNS and stream to a counting sink

Usage: mdns-pair [options]

Options:
      --name <run name>       Base name to publish and discover [default: {DEFAULT_NAME}]
      --timeout <seconds>     Discovery and stream budget in seconds
                              [default: {DEFAULT_TIMEOUT_SECS}, range {MIN_TIMEOUT_SECS}..={MAX_TIMEOUT_SECS}]
  -h, --help                  Print this help and exit

The run appends its PID to the name unless --name is given, publishes
_sendspin-server._tcp under it, discovers that same name and approves only the
client that carries it. Silent frames go to a counting sink, which exits once
the stream has delivered enough of them. Status lines go to standard output.
"
    )
}

/// Runs the command line and turns the run's outcome into the process's exit code.
///
/// The runtime has two worker threads on purpose: a browse blocks its worker for one second per
/// attempt, and the server has to keep serving on the other one even on a host with one vCPU.
#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(Parse::Help) => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Ok(Parse::Run(options)) => options,
        Err(error) => {
            eprint!("error: {error}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    match run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The cause chain stays on one line: a captured smoke-test log shows which stage
            // failed and why without a stack of separate lines.
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs one discovery, approval and stream pass, then tears both roles down.
async fn run(options: Options) -> Result<()> {
    let run_name = run_name(&options, std::process::id())?;
    // The record is published through the real backend and the server's browsing half is the
    // wrapper: the server must not dial unrelated clients that advertise on the network.
    let (sink, counters) = CountingSink::new(GATE_FRAMES);
    let mut config = ServerConfig::new(run_name.clone(), Identity::generate());
    // Port 0: the operating system picks the port, so two runs on one host do not fight over a
    // fixed one, and the record names the port that was actually bound.
    config.bind = SocketAddr::from(([0, 0, 0, 0], 0));
    config.discovery = Some(Arc::new(AdvertiseOnly::new(Arc::new(ServerMdns::new()?))));

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(server_role::serve(
        config,
        ready_tx,
        stop_rx,
        run_name.clone(),
    ));
    ready_rx
        .await
        .context("the server role ended before it published its record")?;

    // One deadline covers the browse, the connection and the frames; the stage the flow reached is
    // shared through an atomic so the timeout can name where it stopped.
    let stage = Arc::new(AtomicU8::new(0));
    let report = counters.clone();
    let flow = {
        let stage = Arc::clone(&stage);
        let run_name = run_name.clone();
        async move {
            let endpoint = client_role::discover(&run_name, options.timeout).await?;
            stage.store(1, Ordering::SeqCst);
            let (handle, events) =
                client_role::await_connected(&run_name, &endpoint, Box::new(sink)).await?;
            stage.store(2, Ordering::SeqCst);
            counters.wait().await;
            Ok::<_, anyhow::Error>((handle, events))
        }
    };
    let outcome: Result<Option<(ClientHandle, EventStream)>> = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("interrupted");
            Ok(None)
        }
        result = timeout(options.timeout, flow) => match result {
            Ok(result) => result.map(Some),
            Err(_) => Err(anyhow!(timeout_message(
                stage_of(&stage),
                &run_name,
                options.timeout
            ))),
        },
    };

    // The client side of the teardown: the goodbye first, while the close signal still reaches a
    // session that can send it, then the task, then the event stream. Dropping the stream first
    // makes the session loop return on `events.is_closed()` without a `client/goodbye`, so this
    // order is what deterministically takes the shutdown arm. A `finished()` that outlives
    // `TEARDOWN` is dropped, and a dropped handle detaches the task instead of aborting it;
    // process exit is the real bound the design accepts.
    let mut said_goodbye = false;
    let verdict = match outcome {
        Ok(Some((mut handle, events))) => {
            let verdict = verify_gate(&report);
            handle.close(GoodbyeReason::Shutdown);
            said_goodbye = true;
            let _ = timeout(TEARDOWN, handle.finished()).await;
            drop(events);
            verdict
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };

    // The server ends its loop on the `ClientLeft` the goodbye produces, so a clean close waits
    // for the server task — the departure, or the server ending on its own — before the stop
    // signal, which would otherwise win the race and hide the reason. A goodbye the server never
    // reports falls through to the stop after `TEARDOWN`.
    let departed = said_goodbye && timeout(TEARDOWN, &mut server_task).await.is_ok();
    if !departed {
        // The record goes even when the flow failed: the run is a smoke test, not a service, and a
        // withdrawn advertisement is what keeps the next run from finding this one.
        let _ = stop_tx.send(());
        let _ = timeout(TEARDOWN, server_task).await;
    }
    verdict
}

/// Reads back the stage the flow had reached, for the timeout's diagnostic.
///
/// The flow stores 0, 1 and 2 in order before each awaited stage, so the mapping from the counter
/// to [`Stage`] is fixed here and nowhere else.
fn stage_of(stage: &AtomicU8) -> Stage {
    match stage.load(Ordering::SeqCst) {
        0 => Stage::Discovery,
        1 => Stage::Connection,
        _ => Stage::Stream,
    }
}

/// Checks the two properties that make this run a success: the format and the byte count.
///
/// This is an assertion, not a log line. A run that only printed the numbers would pass on a
/// stream that delivered one chunk or announced another format, and the approval it demonstrates
/// would be unproven.
fn verify_gate(report: &Counters) -> Result<()> {
    let expected = AudioFormat::pcm(SAMPLE_RATE, CHANNELS, BIT_DEPTH);
    match report.format() {
        Some(format) if format == expected => {}
        Some(format) => bail!(
            "the stream announced {} Hz, {} channels, {}-bit `{}`, but this run expects \
             {SAMPLE_RATE} Hz, {CHANNELS} channels, {BIT_DEPTH}-bit `pcm`",
            format.sample_rate,
            format.channels,
            format.bit_depth,
            format.codec
        ),
        None => bail!("the stream never announced a format"),
    }
    if report.bytes() < GATE_BYTES {
        bail!(
            "the stream delivered {} bytes, fewer than the {GATE_BYTES} the gate requires",
            report.bytes()
        );
    }
    println!(
        "received {} frames / {} bytes",
        report.frames(),
        report.bytes()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> anyhow::Result<Parse> {
        parse_args(args.iter().map(|argument| (*argument).to_owned()))
    }

    fn options(args: &[&str]) -> Options {
        match parse(args).expect("the command line parses") {
            Parse::Run(options) => options,
            Parse::Help => panic!("expected options, got the usage text"),
        }
    }

    #[test]
    fn the_defaults_apply_without_arguments() {
        let options = options(&[]);
        assert_eq!(options.name, "mdns-pair");
        assert!(!options.explicit_name);
        assert_eq!(options.timeout, Duration::from_secs(10));
    }

    #[test]
    fn flags_accept_inline_and_separate_values() {
        let inline = options(&["--name=Kitchen", "--timeout=3"]);
        assert_eq!(inline.name, "Kitchen");
        assert!(inline.explicit_name);
        assert_eq!(inline.timeout, Duration::from_secs(3));

        let separate = options(&["--name", "Hall", "--timeout", "7"]);
        assert_eq!(separate.name, "Hall");
        assert_eq!(separate.timeout, Duration::from_secs(7));
    }

    #[test]
    fn the_timeout_is_bounded() {
        for value in ["0", "121", "not-a-number"] {
            assert!(
                parse(&["--timeout", value]).is_err(),
                "{value:?} must be rejected"
            );
        }
        assert!(parse(&["--timeout", "1"]).is_ok());
        assert!(parse(&["--timeout", "120"]).is_ok());
    }

    #[test]
    fn help_is_reported_without_running() {
        assert!(matches!(parse(&["--help"]), Ok(Parse::Help)));
        assert!(matches!(parse(&["-h"]), Ok(Parse::Help)));
    }

    #[test]
    fn a_bad_command_line_is_rejected() {
        for args in [
            &["--name"][..],
            &["--name", ""][..],
            &["--name", "--timeout"][..],
            &["--bogus"][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} must be rejected");
        }
    }

    #[test]
    fn the_run_name_is_bounded_by_the_mdns_label() {
        let name = "a".repeat(63);
        assert!(parse(&["--name", &name]).is_ok());
        let too_long = "a".repeat(64);
        assert!(parse(&["--name", &too_long]).is_err());

        let options = options(&["--name", &name]);
        assert!(
            run_name(&options, 42).is_ok(),
            "an explicit name is not grown"
        );
    }

    #[test]
    fn the_derived_name_carries_the_pid_and_is_validated() {
        let defaults = options(&[]);
        let name = run_name(&defaults, 4242).expect("the derived name fits");
        assert_eq!(name, "mdns-pair-4242");

        let base = "a".repeat(60);
        // Reaching the derived path through `--name` is impossible by design: the flag marks the
        // name explicit, and an explicit name is never grown. The 60-byte base is built directly so
        // the row still exercises what it names, a base the PID suffix pushes over the limit.
        let named = Options {
            name: base,
            explicit_name: false,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        };
        assert!(
            run_name(&named, 4242).is_err(),
            "the PID suffix pushes 60 bytes over the label limit"
        );
    }

    #[test]
    fn the_usage_names_the_flags_and_defaults() {
        let text = usage();
        for expected in ["--name", "--timeout", "--help", "mdns-pair", "10"] {
            assert!(
                text.contains(expected),
                "the usage must name {expected:?}: {text}"
            );
        }
    }

    #[test]
    fn the_chunk_and_gate_geometry_is_the_designed_one() {
        // The numbers are pinned here, not derived from each other: 20 ms of stereo 16-bit PCM at
        // 48 kHz is 3,840 bytes, and the gate is 20 of those chunks.
        assert_eq!(BYTES_PER_FRAME, 4);
        assert_eq!((CHUNK_BYTES, GATE_BYTES), (3_840, 76_800));
        assert_eq!(GATE_BYTES, GATE_FRAMES * CHUNK_BYTES);
    }

    #[test]
    fn the_stage_counter_maps_onto_the_three_stages() {
        let stage = AtomicU8::new(0);
        assert_eq!(stage_of(&stage), Stage::Discovery);
        stage.store(1, Ordering::SeqCst);
        assert_eq!(stage_of(&stage), Stage::Connection);
        stage.store(2, Ordering::SeqCst);
        assert_eq!(stage_of(&stage), Stage::Stream);
    }

    #[test]
    fn the_gate_requires_the_format_and_the_byte_count() {
        use std::time::Instant;

        use syncspin_client::{AudioFrame, Sink};

        fn feed(sink: &mut CountingSink, frames: usize) {
            let chunk = vec![0u8; CHUNK_BYTES];
            for _ in 0..frames {
                sink.write(AudioFrame::Pcm(&chunk), Instant::now())
                    .expect("the chunk is accepted");
            }
        }

        let (mut sink, counters) = CountingSink::new(GATE_FRAMES);
        sink.open(AudioFormat::pcm(SAMPLE_RATE, CHANNELS, BIT_DEPTH))
            .expect("the stream format opens");
        feed(&mut sink, GATE_FRAMES);
        assert!(
            verify_gate(&counters).is_ok(),
            "the full gate passes and prints its count"
        );

        let (mut sink, counters) = CountingSink::new(GATE_FRAMES);
        sink.open(AudioFormat::pcm(SAMPLE_RATE, CHANNELS, BIT_DEPTH))
            .expect("the stream format opens");
        feed(&mut sink, GATE_FRAMES - 1);
        assert!(
            verify_gate(&counters).is_err(),
            "one chunk short fails the byte count"
        );

        let (_sink, counters) = CountingSink::new(GATE_FRAMES);
        assert!(
            verify_gate(&counters).is_err(),
            "a sink that never opened a stream fails the format check"
        );
    }
}
