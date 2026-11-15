//! `player-pipe` - a minimal Sendspin player: raw PCM on stdout, status on stderr.
//!
//! Point it at a server and pipe stdout into anything that plays raw samples:
//!
//! ```sh
//! player-pipe --server music-assistant.local:8927 | aplay -f S16_LE -r 48000 -c 2
//! ```
//!
//! The player keeps its identity in a file so the server sees the same player across restarts. That
//! file holds the bare 43-character base64url X25519 secret on one line, not JSON: the library has
//! no storage format of its own, so the example owns this one.
//!
//! Status lines are for people; audio is the only thing that reaches stdout.

mod pipe_sink;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use syncspin_client::{
    AudioMode, Client, ClientConfig, Event, Identity, VolumePolicy, DEFAULT_PAIRING_TIMEOUT,
    MAX_PLAYER_NAME_LEN,
};
use tokio::signal;

use crate::pipe_sink::PipeSink;

/// Player name used when `--name` is absent.
const DEFAULT_NAME: &str = "syncspin-pipe";

/// Identity file used when `--identity` is absent.
const DEFAULT_IDENTITY: &str = "./identity.key";

/// Longest delay between reconnects, handed to [`ClientConfig::max_backoff`].
const MAX_BACKOFF: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
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
    play(options)
}

/// Builds the runtime, runs the player until Ctrl-C and bounds the shutdown wait.
fn play(options: Options) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the Tokio runtime")?;
    let result = runtime.block_on(run(options));
    // A stdout reader that stopped consuming can leave the session task blocked in a write.
    // Dropping the runtime would wait for that task; bound the wait so Ctrl-C stays responsive.
    runtime.shutdown_timeout(Duration::from_millis(500));
    result
}

/// Connects and prints one status line per event until the user interrupts.
async fn run(options: Options) -> Result<()> {
    let identity = load_or_create_identity(&options.identity)?;
    eprintln!(
        "player {}: identity {}, stored in {}",
        options.name,
        identity.public_base64(),
        options.identity.display()
    );

    let config = ClientConfig {
        server: options.server,
        player_name: options.name,
        // A pipe on a general-purpose host has no hardware to describe; a host that runs on a
        // device passes the product name, manufacturer and version here so the server shows it.
        device_info: None,
        identity,
        storage: None,
        // This example has no decoder, so it asks for raw samples. A host that wants encoded
        // frames selects `AudioMode::Passthrough` and brings its own decoder.
        audio_mode: AudioMode::Decode,
        // Nothing is restored across restarts, so the output starts at full scale and unmuted.
        volume: 100,
        muted: false,
        volume_policy: VolumePolicy::default(),
        max_backoff: MAX_BACKOFF,
        pairing_timeout: DEFAULT_PAIRING_TIMEOUT,
        #[cfg(feature = "pairing-code")]
        static_pairing_code: None,
        #[cfg(feature = "pairing-code")]
        pairing_window: syncspin_client::DEFAULT_PAIRING_WINDOW,
        #[cfg(feature = "pairing-code")]
        pairing_pending_text: None,
    };

    // The client owns the reconnect loop: a dropped session is reported on the stream and retried
    // with the same sink and identity, so this example only prints what it sees.
    let (handle, mut events) = Client::connect(config, Box::new(PipeSink::new())).await?;
    loop {
        tokio::select! {
            interrupted = signal::ctrl_c() => {
                interrupted.context("failed to wait for Ctrl-C")?;
                eprintln!("stopped on Ctrl-C");
                return Ok(());
            }
            event = events.next() => {
                let Some(event) = event else {
                    // The stream ends when the connection does. Its outcome carries the reason, and
                    // a sink failure must not look like a clean shutdown.
                    return handle.finished().await;
                };
                match event {
                    Event::Connected { server_id, encrypted } => {
                        let security = if encrypted { "encrypted" } else { "not encrypted" };
                        eprintln!("connected: server {server_id}, {security}");
                    }
                    Event::StreamStart { format } => eprintln!(
                        "stream: {} {} Hz, {} channels, {}-bit",
                        format.codec, format.sample_rate, format.channels, format.bit_depth
                    ),
                    Event::Track { title, artist, .. } => {
                        let label = match (artist.as_str(), title.as_str()) {
                            ("", "") => "(none)".to_owned(),
                            ("", title) => title.to_owned(),
                            (artist, "") => artist.to_owned(),
                            (artist, title) => format!("{artist} - {title}"),
                        };
                        eprintln!("track: {label}");
                    }
                    Event::Volume {
                        requested,
                        applied,
                        muted,
                    } => {
                        let mut parts = vec![format!("requested {requested}, applied {applied}")];
                        if let Some(muted) = muted {
                            parts.push(if muted { "muted".to_owned() } else { "unmuted".to_owned() });
                        }
                        eprintln!("volume command: {}", parts.join(", "));
                    }
                    Event::StreamEnd { reason } => eprintln!("stream end: {reason:?}"),
                    Event::StreamClear { from_timestamp } => {
                        match from_timestamp {
                            Some(timestamp) => eprintln!("stream clear from {timestamp} us"),
                            None => eprintln!("stream clear"),
                        }
                    }
                    Event::State(state) => {
                        let mut parts: Vec<String> = Vec::new();
                        if let Some(volume) = state.volume {
                            parts.push(format!("volume {volume}"));
                        }
                        if let Some(muted) = state.muted {
                            parts.push(if muted { "muted".to_owned() } else { "unmuted".to_owned() });
                        }
                        if !state.supported_commands.is_empty() {
                            parts.push(format!("commands {}", state.supported_commands.join(",")));
                        }
                        if parts.is_empty() {
                            eprintln!("state: (no detail)");
                        } else {
                            eprintln!("state: {}", parts.join(", "));
                        }
                    }
                    Event::Disconnected { reason, retry_in } => eprintln!(
                        "disconnected: {reason}; retrying in {}s",
                        retry_in.as_secs_f32()
                    ),
                    // A later revision can add events; this example only prints the ones it knows.
                    _ => {}
                }
            }
        }
    }
}

/// Loads the identity from `path`, generating and storing one when the file does not exist.
///
/// The file holds the bare 43-character base64url secret on one line; it is not JSON, because the
/// library has no storage format yet. The secret is never printed, only the derived public key,
/// which is what the server sees.
fn load_or_create_identity(path: &Path) -> Result<Identity> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                bail!("{} is not a regular file", path.display());
            }
            tighten_identity_permissions(path, &metadata)?;
            let text = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Identity::from_secret_base64(text.trim()).with_context(|| {
                format!(
                    "{} does not hold a bare 43-character base64url X25519 secret on one line",
                    path.display()
                )
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let identity = Identity::generate();
            save_identity(path, &identity)?;
            eprintln!("generated a new identity in {}", path.display());
            Ok(identity)
        }
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

/// Warns about and repairs an identity file that group or others can read.
///
/// The file may come from an older build or a careless copy; refusing to start would be worse than
/// repairing the mode, because the player already knows the keypair behind it.
fn tighten_identity_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o777;
    if (mode & 0o077) == 0 {
        return Ok(());
    }
    eprintln!(
        "warning: {} is readable by group or others (mode {mode:03o}); setting it to 0600",
        path.display()
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict the permissions of {}", path.display()))
}

/// Writes a fresh identity so that only its owner can read it.
///
/// The file is created exclusively with mode 0600 and the mode is set again explicitly, because
/// the creation mask is filtered by the process umask. An existing file is never replaced: it may
/// belong to a player the server already knows.
fn save_identity(path: &Path, identity: &Identity) -> Result<()> {
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict the permissions of {}", path.display()))?;
    writeln!(file, "{}", identity.secret_base64())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

/// What the command line asked for.
#[derive(Debug)]
struct Options {
    /// Server address as `host[:port]` or a `ws://` URL.
    server: String,
    /// Player name announced to the server.
    name: String,
    /// File that holds the X25519 identity.
    identity: PathBuf,
}

/// Result of parsing the command line.
enum Parse {
    /// Print the usage text and exit.
    Help,
    /// Run the player with these options.
    Run(Options),
}

/// Parses `--flag value`, `--flag=value`, `--help` and `-h`.
fn parse_args<I>(args: I) -> Result<Parse>
where
    I: IntoIterator<Item = String>,
{
    let mut server = None;
    let mut name = DEFAULT_NAME.to_owned();
    let mut identity = PathBuf::from(DEFAULT_IDENTITY);

    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let (flag, inline) = split_flag(&argument);
        match flag {
            "-h" | "--help" => return Ok(Parse::Help),
            "--server" => server = Some(take_value(flag, inline, &mut args)?),
            "--name" => name = take_value(flag, inline, &mut args)?,
            "--identity" => identity = PathBuf::from(take_value(flag, inline, &mut args)?),
            other => bail!("unknown argument {other:?}; try --help"),
        }
    }

    let server = server.ok_or_else(|| anyhow!("--server is required; try --help"))?;
    check_server(&server)?;
    if name.len() > MAX_PLAYER_NAME_LEN {
        bail!(
            "--name is {} bytes, but the protocol allows at most {MAX_PLAYER_NAME_LEN}",
            name.len()
        );
    }

    Ok(Parse::Run(Options {
        server,
        name,
        identity,
    }))
}

/// Rejects an address this build cannot use, before a connection is attempted.
///
/// The client validates the address too, but only once it connects. Checking here keeps a TLS URL
/// from retrying forever, and keeps it from creating an identity file first.
fn check_server(server: &str) -> Result<()> {
    if server.starts_with("wss://") {
        bail!("TLS is not supported by this build; use a ws:// URL or host:port");
    }
    if server.contains("://") && !server.starts_with("ws://") {
        bail!("unsupported URL scheme in {server:?}; use ws:// or host:port");
    }
    Ok(())
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
player-pipe - stream one Sendspin player's audio to standard output

Usage: player-pipe --server <host[:port] | ws://url> [options]

Options:
      --server <host[:port] | ws://url>
                              Address of the Sendspin server (required), for
                              example music-assistant.local:8927; TLS (wss://)
                              is not supported by this build
      --name <player name>    Name this player announces [default: {DEFAULT_NAME}]
      --identity <path>       File holding the player's X25519 identity: the bare
                              43-character base64url secret on one line, not JSON;
                              created with owner-only permissions when missing
                              [default: {DEFAULT_IDENTITY}]
  -h, --help                  Print this help and exit

Audio goes to standard output as raw samples in the announced format; status
lines go to standard error. The player reconnects with backoff and stops on
Ctrl-C.
"
    )
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
    fn the_defaults_apply_when_only_the_server_is_given() {
        let options = options(&["--server", "music-assistant.local"]);

        assert_eq!(options.server, "music-assistant.local");
        assert_eq!(options.name, DEFAULT_NAME);
        assert_eq!(options.identity, PathBuf::from(DEFAULT_IDENTITY));
    }

    #[test]
    fn flags_accept_an_inline_value() {
        let options = options(&[
            "--server=music-assistant.local:8927",
            "--name=Kitchen",
            "--identity=/tmp/identity.key",
        ]);

        assert_eq!(options.server, "music-assistant.local:8927");
        assert_eq!(options.name, "Kitchen");
        assert_eq!(options.identity, PathBuf::from("/tmp/identity.key"));
    }

    #[test]
    fn help_is_reported_without_a_server() {
        assert!(matches!(parse(&["--help"]), Ok(Parse::Help)));
        assert!(matches!(parse(&["-h"]), Ok(Parse::Help)));
    }

    #[test]
    fn an_incomplete_or_unknown_command_line_is_rejected() {
        let too_long = "a".repeat(MAX_PLAYER_NAME_LEN + 1);
        for args in [
            &[][..],
            &["--name", "x"][..],
            &["--server"][..],
            &["--server", ""][..],
            &["--server", "host", "--bogus"][..],
            &["--server", "host", "--name", &too_long][..],
            &["--server", "--help"][..],
            &["--server", "host", "--identity", "-x"][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} must be rejected");
        }
    }

    #[test]
    fn a_server_this_build_cannot_use_is_rejected_before_connecting() {
        let Err(error) = parse(&["--server", "wss://example.test"]) else {
            panic!("a TLS URL must be rejected");
        };
        assert!(
            format!("{error}").contains("TLS"),
            "the error should name the missing TLS support, got: {error}"
        );

        let Err(error) = parse(&["--server", "https://example.test"]) else {
            panic!("a non-ws scheme must be rejected");
        };
        assert!(
            format!("{error}").contains("unsupported URL scheme"),
            "the error should name the scheme, got: {error}"
        );
    }
}
