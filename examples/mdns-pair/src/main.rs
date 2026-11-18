//! `mdns-pair` - one process that discovers its own server over mDNS.
//!
//! The example runs both halves of the protocol in one binary: it publishes
//! `_sendspin-server._tcp` under a name it derives for this run, discovers that same name from a
//! separate mDNS query, approves only the client whose static public key it generated, and streams
//! silent frames into a counting sink until the stream arrives.
//!
//! Both dependencies need their `mdns` backend, so the flow is behind this example's `mdns`
//! feature. A build without it still parses the command line and exits 2 with the feature named.
//!
//! ```sh
//! cargo run -p mdns-pair --features mdns
//! ```
//!
//! The run name is `mdns-pair-<pid>` unless `--name` names it explicitly. The PID keeps two runs on
//! one host apart, and it is also why an explicit name must fit the mDNS label with room to spare:
//! a derived name grows by the suffix, an explicit one is published as given.

// Without the mDNS feature the flow is not built, so its helpers are reachable only from the test
// module, while the feature-less build still parses the command line and exits 2. The allow is
// scoped to that build: with `mdns` on, dead code is still reported.
#![cfg_attr(not(feature = "mdns"), allow(dead_code))]

mod advertise_only;
mod client_role;
mod find;
mod server_role;
mod sink;

#[cfg(feature = "mdns")]
use std::net::SocketAddr;
use std::process::ExitCode;
#[cfg(feature = "mdns")]
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use syncspin_client::{AudioFormat, MAX_PLAYER_NAME_LEN};
#[cfg(feature = "mdns")]
use syncspin_client::{GoodbyeReason, Identity};
// Both crates export an `MdnsDiscovery`; each role runs its own daemon, so each import names the
// role. The client's alias lives in `client_role`.
#[cfg(feature = "mdns")]
use syncspin_server::MdnsDiscovery as ServerMdns;
#[cfg(feature = "mdns")]
use syncspin_server::ServerConfig;
#[cfg(feature = "mdns")]
use tokio::sync::oneshot;
#[cfg(feature = "mdns")]
use tokio::time::timeout;

#[cfg(feature = "mdns")]
use crate::advertise_only::AdvertiseOnly;
#[cfg(feature = "mdns")]
use crate::find::Stage;
#[cfg(feature = "mdns")]
use crate::find::{no_service_message, timeout_message};
use crate::sink::Counters;
#[cfg(any(feature = "mdns", test))]
use crate::sink::CountingSink;

/// Base name the run announces unless `--name` says otherwise.
const DEFAULT_NAME: &str = "mdns-pair";

/// Seconds of discovery and stream budget unless `--timeout` says otherwise.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Shortest accepted budget: a browse alone blocks for about a second, so a smaller budget cannot
/// cover discovery, the connection and the frame gate.
const MIN_TIMEOUT_SECS: u64 = 5;

/// Longest accepted budget; a smoke test that waits longer has hung, not failed slowly.
const MAX_TIMEOUT_SECS: u64 = 120;

/// Suffix the player appends to the run name, so the server's log lines tell the roles apart.
pub(crate) const PLAYER_SUFFIX: &str = "-player";

/// Longest run name, in bytes: it is one mDNS label (63) and also becomes the player name, which
/// the protocol caps at [`MAX_PLAYER_NAME_LEN`] including [`PLAYER_SUFFIX`].
const MAX_RUN_NAME_LEN: usize = MAX_PLAYER_NAME_LEN - PLAYER_SUFFIX.len();

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
/// The specification says a chunk should not be shorter than 15 ms and must not exceed 150 ms, so
/// 20 ms is just above the floor, and it is also the pace the server writes at.
const CHUNK_MS: u64 = 20;

// The bound is the specification's (`roles/player/v1.md`, Server Audio Send Constraints), so a
// change to `CHUNK_MS` that leaves it fails the build rather than a run.
const _: () = assert!(CHUNK_MS >= 15 && CHUNK_MS <= 150);

/// Frames in one chunk at [`SAMPLE_RATE`].
const CHUNK_FRAMES: usize = SAMPLE_RATE as usize / 1000 * CHUNK_MS as usize;

/// Payload bytes in one chunk.
const CHUNK_BYTES: usize = CHUNK_FRAMES * BYTES_PER_FRAME;

/// Frames the sink must receive before the run counts as a success.
const GATE_FRAMES: usize = 20;

/// Payload bytes those frames carry: 76,800, the number the gate asserts rather than prints.
const GATE_BYTES: usize = GATE_FRAMES * CHUNK_BYTES;

/// How long the run waits for the server to report the client's departure, only to keep the log in
/// order. The client's session has already ended by then, so a normal departure arrives at once.
const DEPARTURE_GRACE: Duration = Duration::from_millis(250);

/// Upper bound on each of the two teardown waits - the client's goodbye and the server task - so a
/// stuck peer cannot hold the command open.
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
    if name.len() > MAX_RUN_NAME_LEN {
        bail!(
            "--name is {} bytes, but the run name allows at most {MAX_RUN_NAME_LEN}: it is one \
             mDNS label and the player name is derived from it with `{PLAYER_SUFFIX}`",
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
/// explicit name is used as given and never grown. Either way the result must fit one mDNS label
/// and leave room for [`PLAYER_SUFFIX`] in the player name.
fn run_name(options: &Options, pid: u32) -> Result<String> {
    let name = if options.explicit_name {
        options.name.clone()
    } else {
        format!("{}-{pid}", options.name)
    };
    if name.len() > MAX_RUN_NAME_LEN {
        bail!(
            "the run name {name:?} is {} bytes, but it allows at most {MAX_RUN_NAME_LEN}: it is \
             one mDNS label and the player name is derived from it with `{PLAYER_SUFFIX}`",
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
client whose static key this run generated. Silent frames go to a counting
sink, which exits once the stream has delivered enough of them. Status lines
go to standard output. The server listens on all interfaces for the length of
the run.
"
    )
}

/// Runs the command line and turns the run's outcome into the process's exit code.
///
/// A browse is a synchronous call; `client_role::discover` runs it on the blocking pool, so the
/// server keeps serving on the async worker even on a host with one vCPU.
#[tokio::main]
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
    #[cfg(feature = "mdns")]
    {
        match run(options).await {
            Ok(RunOutcome::Completed) => ExitCode::SUCCESS,
            Ok(RunOutcome::Interrupted) => ExitCode::from(130),
            Err(error) => {
                // The cause chain stays on one line: a captured smoke-test log shows which stage
                // failed and why without a stack of separate lines.
                eprintln!("error: {error:#}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(feature = "mdns"))]
    {
        let _ = options;
        eprintln!("error: the mDNS flow needs the mdns feature: rebuild with --features mdns");
        ExitCode::from(2)
    }
}

/// The process outcome of a run that reached its teardown.
#[cfg(feature = "mdns")]
enum RunOutcome {
    /// The gate was reached and the count checked.
    Completed,
    /// Ctrl-C arrived before the gate.
    Interrupted,
}

/// Runs one discovery, approval and stream pass, then tears both roles down.
#[cfg(feature = "mdns")]
async fn run(options: Options) -> Result<RunOutcome> {
    let run_name = run_name(&options, std::process::id())?;
    // The client identity is generated once and its public half is the `client_id` the server
    // sees. The mDNS TXT record is readable by anyone on the LAN, so the key the handshake proves
    // - not the published name - is what decides who is approved.
    let identity = Identity::generate();
    let client_id = identity.public_base64();
    // The record is published through the real backend and the server's browsing half is the
    // wrapper: the server must not dial unrelated clients that advertise on the network.
    let expected = AudioFormat::pcm(SAMPLE_RATE, CHANNELS, BIT_DEPTH);
    let (sink, counters) = CountingSink::new(GATE_FRAMES, expected.clone());
    let server_identity = Identity::generate();
    let server_id = server_identity.public_base64();
    let mut config = ServerConfig::new(run_name.clone(), server_identity);
    // Port 0: the operating system picks the port, so two runs on one host do not fight over a
    // fixed one, and the record names the port that was actually bound. The wildcard address is
    // deliberate: the record resolves to this host's non-loopback interfaces, and a loopback-only
    // listener would be advertised at addresses nothing listens on. The consequence is that the
    // listener is reachable from the LAN for the length of the run; it admits a connection only
    // after the Noise handshake and approves one static key (see `server_role`), and the run is
    // bounded by `--timeout`.
    config.bind = SocketAddr::from(([0, 0, 0, 0], 0));
    config.discovery = Some(Arc::new(AdvertiseOnly::new(Arc::new(ServerMdns::new()?))));

    // One task owns the signal for the whole run and latches it, so an interrupt that arrives
    // between two phases is seen by the next one instead of being dropped.
    let (interrupt_tx, mut interrupt) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = interrupt_tx.send(true);
        } else {
            // No handler could be installed, so no interrupt can ever arrive. The sender stays
            // alive: a dropped one would make every waiter see a closed channel at once.
            let _keep = interrupt_tx;
            std::future::pending::<()>().await;
        }
    });

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let (departure_tx, departure_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(server_role::serve(
        config,
        ready_tx,
        stop_rx,
        departure_tx,
        client_id.clone(),
    ));
    tokio::select! {
        // The start has the run's own budget: a bind or an advertisement that never returns is a
        // failed run with a named stage, not a hang that only Ctrl-C ends.
        ready = timeout(options.timeout, ready_rx) => match ready {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Err(server_start_error(&mut server_task).await),
            Err(_) => {
                // Ask for a clean shutdown first so the record is withdrawn; abort only when the
                // task does not answer, for instance because the start itself is stuck.
                let _ = stop_tx.send(());
                if timeout(TEARDOWN, &mut server_task).await.is_err() {
                    server_task.abort();
                }
                bail!(
                    "the server did not publish its record within {} s",
                    options.timeout.as_secs()
                );
            }
        },
        Ok(_) = interrupt.wait_for(|fired| *fired) => {
            let _ = stop_tx.send(());
            let _ = timeout(TEARDOWN, &mut server_task).await;
            println!("interrupted; the frame gate was not checked");
            return Ok(RunOutcome::Interrupted);
        }
    }

    // One deadline covers the browse, the handshake and the frames. The phases are awaited on
    // their own so a timeout names the stage, and the handle is owned from `connect_session` on,
    // so every path after that says why the session leaves.
    let deadline = tokio::time::Instant::now() + options.timeout;
    let mut said_goodbye = false;

    let verdict: Result<Flow> = async {
        // The browse owns the deadline: an in-flight browse cannot be cancelled, so the loop lets
        // it finish and stops there, and the daemon is gone before the teardown starts.
        let endpoint =
            match until_interrupt(&mut interrupt, client_role::discover(&run_name, deadline)).await
            {
                None => return Ok(Flow::Interrupted),
                Some(Ok(None)) => bail!(no_service_message(&run_name, options.timeout)),
                Some(Ok(Some(endpoint))) => endpoint,
                Some(Err(error)) => return Err(error),
            };
        // The session exists from this call on; an interrupt before it has no connection to say
        // goodbye on, and no handle to finish.
        let (mut handle, mut events) =
            client_role::connect_session(&run_name, &endpoint, identity, Box::new(sink)).await?;
        let outcome = await_gate(
            &mut interrupt,
            Wait {
                deadline,
                budget: options.timeout,
            },
            &mut events,
            &endpoint,
            &server_id,
            &counters,
        )
        .await;
        // The goodbye first, while the close signal still reaches a session that can send it, then
        // the task, then the event stream: dropping the stream first makes the session loop return
        // on `events.is_closed()` without a `client/goodbye`.
        // `shutdown` is the truthful reason: this process is going away. The spec's advice that a
        // server reconnect after it applies to server-initiated links; here the server is ours and
        // stops right after.
        handle.close(GoodbyeReason::Shutdown);
        said_goodbye = true;
        let _ = timeout(TEARDOWN, handle.finished()).await;
        drop(events);
        outcome
    }
    .await;

    // The server loop ends only on the stop signal: `ClientLeft` carries no client id, so any LAN
    // client leaving after this run's approval would otherwise end the server. The departure is
    // awaited only so the goodbye's log line appears before the stop, and only for a short grace
    // that does not grow with other clients on the LAN; it never gates the run.
    if said_goodbye {
        let _ = timeout(DEPARTURE_GRACE, departure_rx).await;
    }
    // The record goes even when the flow failed once the server has started: the run is a smoke
    // test, not a service, and a withdrawn advertisement is what keeps the next run from finding
    // this one. A start that never returned is aborted, so it has nothing to withdraw.
    let _ = stop_tx.send(());
    let server_error = match timeout(TEARDOWN, &mut server_task).await {
        Ok(Ok(Ok(()))) => None,
        Ok(Ok(Err(error))) => Some(error.context("the server role failed during shutdown")),
        Ok(Err(join_error)) => Some(anyhow!("the server role task failed: {join_error}")),
        Err(_) => Some(anyhow!(
            "the server role did not stop within {} s",
            TEARDOWN.as_secs()
        )),
    };
    if let Some(error) = server_error {
        // A failed flow keeps its own error; the server's is reported beside it rather than
        // replacing the failure that explains the run.
        if matches!(verdict, Ok(Flow::Done)) {
            return Err(error);
        }
        eprintln!("error: {error:#}");
    }
    match verdict? {
        Flow::Interrupted => {
            println!("interrupted; the frame gate was not checked");
            Ok(RunOutcome::Interrupted)
        }
        Flow::Done => Ok(RunOutcome::Completed),
    }
}

/// How a phase of the run ended when it did not fail.
#[cfg(feature = "mdns")]
enum Flow {
    /// The phase finished and, for the last one, the gate was checked.
    Done,
    /// Ctrl-C arrived first; nothing after it ran.
    Interrupted,
}

/// What a waiting phase is bounded by: the run's one deadline and the budget it was derived from,
/// which the stage messages name.
#[cfg(feature = "mdns")]
struct Wait {
    deadline: tokio::time::Instant,
    budget: Duration,
}

/// Runs `work` unless Ctrl-C arrives first, in which case it is dropped and `None` is returned.
///
/// The interrupt is checked first, so one that is already latched wins over work that is ready.
#[cfg(feature = "mdns")]
async fn until_interrupt<T>(
    interrupt: &mut tokio::sync::watch::Receiver<bool>,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        // A closed channel is not an interrupt: only a latched `true` is.
        Ok(_) = interrupt.wait_for(|fired| *fired) => None,
        value = work => Some(value),
    }
}

/// Waits for `Connected` from this run's server, then for the frame gate, and checks the gate.
#[cfg(feature = "mdns")]
async fn await_gate(
    interrupt: &mut tokio::sync::watch::Receiver<bool>,
    wait: Wait,
    events: &mut syncspin_client::EventStream,
    endpoint: &str,
    server_id: &str,
    counters: &Counters,
) -> Result<Flow> {
    match until_interrupt(
        interrupt,
        tokio::time::timeout_at(
            wait.deadline,
            client_role::wait_for_connection(events, endpoint, server_id),
        ),
    )
    .await
    {
        None => return Ok(Flow::Interrupted),
        Some(Err(_)) => bail!(timeout_message(Stage::Connection, wait.budget, GATE_FRAMES)),
        Some(Ok(result)) => result?,
    }
    match until_interrupt(
        interrupt,
        tokio::time::timeout_at(wait.deadline, client_role::wait_for_gate(events, counters)),
    )
    .await
    {
        None => return Ok(Flow::Interrupted),
        Some(Err(_)) => bail!(timeout_message(Stage::Stream, wait.budget, GATE_FRAMES)),
        Some(Ok(result)) => result?,
    }
    verify_gate(counters)?;
    Ok(Flow::Done)
}

/// Turns a closed ready channel into the cause the server task left behind.
///
/// The task is awaited under [`TEARDOWN`] so a start failure is reported with its own error chain
/// instead of the generic message; a task that ended without an error, panicked, or did not end in
/// time each gets its own sentence. The borrow keeps the handle usable by the normal path, which
/// only runs when the ready channel delivered.
#[cfg(feature = "mdns")]
async fn server_start_error(
    server_task: &mut tokio::task::JoinHandle<Result<()>>,
) -> anyhow::Error {
    match timeout(TEARDOWN, &mut *server_task).await {
        Ok(Ok(Ok(()))) => {
            anyhow!("the server role ended before it published its record, without an error")
        }
        Ok(Ok(Err(error))) => {
            anyhow!("the server role failed before it published its record: {error:#}")
        }
        Ok(Err(join_error)) if join_error.is_panic() => {
            anyhow!("the server role panicked before it published its record: {join_error}")
        }
        Ok(Err(join_error)) => {
            anyhow!("the server role was cancelled before it published its record: {join_error}")
        }
        Err(_) => anyhow!(
            "the server role did not end within {} s after its ready channel closed",
            TEARDOWN.as_secs()
        ),
    }
}

/// Checks the two properties that make this run a success: the format and the byte count.
///
/// This is an assertion, not a log line. A run that only printed the numbers would pass on a
/// stream that delivered one chunk or announced another format, and the approval it demonstrates
/// would be unproven.
fn verify_gate(report: &Counters) -> Result<()> {
    // `CountingSink::open` refuses any format but the expected one, so a stored format is always
    // the right one; only a stream that never opened is left to catch here.
    if report.format().is_none() {
        bail!("the stream never announced a format");
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
        let inline = options(&["--name=Kitchen", "--timeout=5"]);
        assert_eq!(inline.name, "Kitchen");
        assert!(inline.explicit_name);
        assert_eq!(inline.timeout, Duration::from_secs(5));

        let separate = options(&["--name", "Hall", "--timeout", "7"]);
        assert_eq!(separate.name, "Hall");
        assert_eq!(separate.timeout, Duration::from_secs(7));
    }

    #[test]
    fn the_timeout_is_bounded() {
        for value in ["0", "1", "4", "121", "not-a-number"] {
            assert!(
                parse(&["--timeout", value]).is_err(),
                "{value:?} must be rejected"
            );
        }
        assert!(parse(&["--timeout", "5"]).is_ok());
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
    fn the_run_name_leaves_room_for_the_player_suffix() {
        let name = "a".repeat(MAX_RUN_NAME_LEN);
        assert!(parse(&["--name", &name]).is_ok());
        let too_long = "a".repeat(MAX_RUN_NAME_LEN + 1);
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
            "the PID suffix pushes 60 bytes over the run-name limit"
        );
    }

    /// A closed interrupt channel (no signal handler) must not read as Ctrl-C, and a latched
    /// `true` must.
    #[cfg(feature = "mdns")]
    #[tokio::test]
    async fn a_closed_interrupt_channel_is_not_an_interrupt() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        drop(tx);
        let ran = until_interrupt(&mut rx, async { 7 }).await;
        assert_eq!(ran, Some(7), "the work runs when no interrupt can arrive");

        let (tx, mut rx) = tokio::sync::watch::channel(false);
        tx.send(true).expect("a receiver exists");
        drop(tx);
        let ran = until_interrupt(&mut rx, async { 7 }).await;
        assert_eq!(ran, None, "a latched interrupt wins over ready work");
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
    fn a_chunk_stays_inside_the_specified_duration_bounds() {
        let chunk_ms = CHUNK_FRAMES as u64 * 1000 / SAMPLE_RATE as u64;
        assert_eq!(chunk_ms, CHUNK_MS, "the byte geometry matches the duration");
        assert!(
            (15..=150).contains(&chunk_ms),
            "a chunk is at least 15 ms and at most 150 ms"
        );
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

        let expected = AudioFormat::pcm(SAMPLE_RATE, CHANNELS, BIT_DEPTH);
        let (mut sink, counters) = CountingSink::new(GATE_FRAMES, expected.clone());
        sink.open(expected.clone())
            .expect("the stream format opens");
        feed(&mut sink, GATE_FRAMES);
        assert!(
            verify_gate(&counters).is_ok(),
            "the full gate passes and prints its count"
        );

        let (mut sink, counters) = CountingSink::new(GATE_FRAMES, expected.clone());
        sink.open(expected.clone())
            .expect("the stream format opens");
        feed(&mut sink, GATE_FRAMES - 1);
        assert!(
            verify_gate(&counters).is_err(),
            "one chunk short fails the byte count"
        );

        let (_sink, counters) = CountingSink::new(GATE_FRAMES, expected.clone());
        assert!(
            verify_gate(&counters).is_err(),
            "a sink that never opened a stream fails the format check"
        );
    }
}
