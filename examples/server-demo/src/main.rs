//! `server-demo` - a minimal Sendspin server: one group, a tone, no files.
//!
//! Start it, then point `player-pipe` at the address it prints:
//!
//! ```sh
//! cargo run -p server-demo
//! cargo run -p player-pipe -- --server <host>:8927 | aplay -f S16_LE -r 48000 -c 2
//! ```
//!
//! With `--features mdns -- --mdns` it also publishes `_sendspin-server._tcp` and dials the clients
//! that advertise `_sendspin._tcp`, which is how a two-machine run without a known address works:
//!
//! ```sh
//! cargo run -p server-demo --features mdns -- --mdns
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
#[cfg(feature = "mdns")]
use syncspin_server::MdnsDiscovery;
use syncspin_server::{
    Discovery, Event, Identity, Server, ServerConfig, StreamWriter, TrackInfo, MAX_SERVER_NAME_LEN,
};
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

/// Address the server binds unless `--bind` says otherwise.
const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8927);

/// Server name announced in `server/hello` unless `--name` says otherwise.
const DEFAULT_NAME: &str = "syncspin-demo";

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

/// What the command line asked for.
struct Options {
    /// Address the listener binds.
    bind: SocketAddr,
    /// Name announced in `server/hello`.
    name: String,
    /// Whether to publish the server over mDNS and dial advertising clients.
    #[cfg(feature = "mdns")]
    mdns: bool,
}

/// Result of parsing the command line.
enum Parse {
    /// Print the usage text and exit.
    Help,
    /// Run the server with these options.
    Run(Options),
}

/// Parses `--flag value`, `--flag=value`, `--help` and `-h`.
fn parse_args<I>(args: I) -> Result<Parse>
where
    I: IntoIterator<Item = String>,
{
    let mut bind = DEFAULT_BIND;
    let mut name = DEFAULT_NAME.to_owned();
    #[cfg(feature = "mdns")]
    let mut mdns = false;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let (flag, inline) = split_flag(&argument);
        match flag {
            "-h" | "--help" => return Ok(Parse::Help),
            "--bind" => {
                let value = take_value(flag, inline, &mut args)?;
                bind = value
                    .parse()
                    .map_err(|_| anyhow!("--bind needs an IP:port address, got {value:?}"))?;
            }
            "--name" => name = take_value(flag, inline, &mut args)?,
            #[cfg(feature = "mdns")]
            "--mdns" => mdns = true,
            #[cfg(not(feature = "mdns"))]
            "--mdns" => {
                bail!("the mDNS advertisement needs the mdns feature: rebuild with --features mdns")
            }
            other => bail!("unknown argument {other:?}; try --help"),
        }
    }
    // The crate validates the name too; checking here reports it before an identity is generated
    // and an address is bound.
    if name.len() > MAX_SERVER_NAME_LEN {
        bail!(
            "--name is {} bytes, but the protocol allows at most {MAX_SERVER_NAME_LEN}",
            name.len()
        );
    }

    Ok(Parse::Run(Options {
        bind,
        name,
        #[cfg(feature = "mdns")]
        mdns,
    }))
}

/// Builds the configuration, with the discovery backend when the run advertises.
///
/// Pure apart from generating the per-run identity: it binds nothing and publishes nothing, so a
/// test can pass a fake backend and check what `--mdns` hands to [`Server::start`].
fn build_config(options: &Options, discovery: Option<Arc<dyn Discovery>>) -> ServerConfig {
    let mut config = ServerConfig::new(options.name.clone(), Identity::generate());
    config.bind = options.bind;
    config.discovery = discovery;
    config
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
    let mut text = format!(
        "\
server-demo - serve one Sendspin client a quiet tone

Usage: server-demo [options]

Options:
      --bind <ip:port>        Address to listen on [default: {DEFAULT_BIND}]
      --name <server name>    Name this server announces [default: {DEFAULT_NAME}]
"
    );
    #[cfg(feature = "mdns")]
    text.push_str(
        "      --mdns                  Publish _sendspin-server._tcp over mDNS and
                              dial the clients that advertise themselves
",
    );
    text.push_str(
        "
  -h, --help                  Print this help and exit

The server approves the first client it sees, opens a stream once that client has
the player role, and writes a 440 Hz tone until Ctrl-C. Its identity is generated
per run, so every start is a new server. Status lines go to standard error.
",
    );
    text
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(Parse::Help) => {
            print!("{}", usage());
            return Ok(());
        }
        Ok(Parse::Run(options)) => options,
        Err(error) => {
            eprint!("error: {error}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    run(options).await
}

/// Starts the server and streams the tone until Ctrl-C.
async fn run(options: Options) -> Result<()> {
    // The backend starts its daemon here, before the listener binds: a daemon that cannot open its
    // sockets is reported before the server looks reachable on an address nobody can discover.
    #[cfg(feature = "mdns")]
    let discovery: Option<Arc<dyn Discovery>> = if options.mdns {
        Some(Arc::new(MdnsDiscovery::new()?))
    } else {
        None
    };
    #[cfg(not(feature = "mdns"))]
    let discovery: Option<Arc<dyn Discovery>> = None;
    let advertising = discovery.is_some();

    let mut server = Server::start(build_config(&options, discovery)).await?;
    eprintln!(
        "listening on {}; point player-pipe at this address",
        server.local_addr()
    );
    if advertising {
        eprintln!(
            "advertising {} as {}",
            syncspin_server::SERVER_SERVICE_TYPE,
            options.name
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a command line given as string slices.
    fn parse(args: &[&str]) -> Result<Parse> {
        parse_args(args.iter().map(|argument| (*argument).to_owned()))
    }

    /// Parses a command line that is expected to describe a run.
    fn options(args: &[&str]) -> Options {
        match parse(args) {
            Ok(Parse::Run(options)) => options,
            Ok(Parse::Help) => panic!("expected options, got the help text"),
            Err(error) => panic!("expected options, got the error {error:#}"),
        }
    }

    #[test]
    fn the_defaults_apply_without_arguments() {
        let options = options(&[]);

        assert_eq!(options.bind, DEFAULT_BIND);
        assert_eq!(options.name, DEFAULT_NAME);
        #[cfg(feature = "mdns")]
        assert!(!options.mdns);
    }

    #[test]
    fn flags_accept_an_inline_value() {
        let options = options(&["--bind=127.0.0.1:0", "--name=Test server"]);

        assert_eq!(options.bind, SocketAddr::from(([127, 0, 0, 1], 0)));
        assert_eq!(options.name, "Test server");
    }

    #[test]
    fn help_is_reported_without_an_address() {
        assert!(matches!(parse(&["--help"]), Ok(Parse::Help)));
        assert!(matches!(parse(&["-h"]), Ok(Parse::Help)));
    }

    #[test]
    fn an_incomplete_or_unknown_command_line_is_rejected() {
        let too_long = "a".repeat(MAX_SERVER_NAME_LEN + 1);
        for args in [
            &["--bind"][..],
            &["--bind", "not-an-address"][..],
            &["--bind", ""][..],
            &["--name"][..],
            &["--name", &too_long][..],
            &["--bogus"][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} must be rejected");
        }
    }

    #[cfg(feature = "mdns")]
    #[test]
    fn the_mdns_switch_is_accepted() {
        assert!(options(&["--mdns"]).mdns);
        assert!(options(&["--mdns", "--bind", "127.0.0.1:0"]).mdns);
    }

    #[cfg(not(feature = "mdns"))]
    #[test]
    fn a_missing_feature_is_named_in_the_error() {
        let Err(error) = parse(&["--mdns"]) else {
            panic!("--mdns without the mdns feature must be rejected");
        };
        let text = format!("{error}");
        assert!(
            text.contains("--features mdns"),
            "the error must name the feature that adds the flag, got: {text}"
        );
    }

    /// The `--mdns` wiring installs a backend and leaves the bind and name alone, without binding.
    #[test]
    fn the_advertisement_is_configured_without_opening_a_socket() {
        /// A [`Discovery`] that answers from memory and publishes nothing.
        struct NoopDiscovery;

        impl Discovery for NoopDiscovery {
            fn advertise(&self, _service: syncspin_server::ServiceAdvertisement) -> Result<()> {
                Ok(())
            }

            fn withdraw(&self, _service_type: &str) -> Result<()> {
                Ok(())
            }

            fn browse(
                &self,
                _service_type: &str,
            ) -> Result<Vec<syncspin_server::DiscoveredClient>> {
                Ok(Vec::new())
            }
        }

        let options = options(&["--bind", "127.0.0.1:0", "--name", "Test server"]);
        let config = build_config(&options, Some(Arc::new(NoopDiscovery)));
        assert_eq!(config.bind, SocketAddr::from(([127, 0, 0, 1], 0)));
        assert_eq!(config.name, "Test server");
        assert!(
            config.discovery.is_some(),
            "the --mdns path installs the backend"
        );

        assert!(
            build_config(&options, None).discovery.is_none(),
            "without --mdns the server only listens"
        );
    }

    #[test]
    fn the_usage_names_the_switches_this_build_has() {
        let text = usage();
        assert!(text.contains("--bind"), "got: {text}");
        assert!(text.contains("--name"), "got: {text}");
        assert!(text.contains("--help"), "got: {text}");
        #[cfg(feature = "mdns")]
        assert!(text.contains("--mdns"), "got: {text}");
        #[cfg(not(feature = "mdns"))]
        assert!(
            !text.contains("--mdns"),
            "a build without the backend must not list the switch, got: {text}"
        );
    }
}
