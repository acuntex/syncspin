//! `player-pipe` - a minimal Sendspin player: raw PCM on stdout, status on stderr.
//!
//! Point it at a server and pipe stdout into anything that plays raw samples:
//!
//! ```sh
//! player-pipe --server music-assistant.local:8927 | aplay -f S16_LE -r 48000 -c 2
//! ```
//!
//! The player keeps its identity in a file so the server sees the same player across restarts.
//! Status lines are for people; audio is the only thing that reaches stdout.

mod pipe_sink;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use syncspin_client::{AudioMode, Client, ClientConfig, Event, Identity, MAX_PLAYER_NAME_LEN};
use tokio::signal;

use crate::pipe_sink::PipeSink;

/// Player name used when `--name` is absent.
const DEFAULT_NAME: &str = "syncspin-pipe";

/// Identity file used when `--identity` is absent.
const DEFAULT_IDENTITY: &str = "./identity.json";

/// First delay between reconnects; doubles up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Longest delay between reconnects, also handed to [`ClientConfig::max_backoff`].
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

/// Builds the runtime and runs the player until Ctrl-C.
fn play(options: Options) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the Tokio runtime")?
        .block_on(run(options))
}

/// Connects, reconnects with backoff and returns when the user interrupts.
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
        identity,
        audio_mode: if options.passthrough {
            AudioMode::Passthrough
        } else {
            AudioMode::Decode
        },
        max_backoff: MAX_BACKOFF,
    };

    let mut delay = INITIAL_BACKOFF;
    loop {
        let (reason, retry_in) = match serve(&config).await {
            Ok(Ending::Interrupted) => return Ok(()),
            Ok(Ending::Disconnected { reason, retry_in }) => (reason, retry_in),
            Err(error) => (
                format!("cannot connect to {}: {error:#}", config.server),
                Duration::ZERO,
            ),
        };

        // This revision always reports a zero delay, so the player owns the backoff. A server
        // that asks for longer is honoured, up to the configured cap.
        let wait = retry_in.max(delay).min(config.max_backoff);
        eprintln!(
            "disconnected: {reason}; retrying in {}s",
            wait.as_secs_f32()
        );
        tokio::select! {
            interrupted = signal::ctrl_c() => {
                interrupted.context("failed to wait for Ctrl-C")?;
                eprintln!("stopped on Ctrl-C");
                return Ok(());
            }
            () = tokio::time::sleep(wait) => {}
        }
        delay = delay.saturating_mul(2).min(MAX_BACKOFF);
    }
}

/// How one connection ended.
enum Ending {
    /// The connection ended; the caller waits and connects again.
    Disconnected {
        /// Why the connection ended, without key material.
        reason: String,
        /// Delay the session recommends before the next attempt.
        retry_in: Duration,
    },
    /// The user asked the player to stop.
    Interrupted,
}

/// Connects once, prints one status line per event and returns how the connection ended.
async fn serve(config: &ClientConfig) -> Result<Ending> {
    let (_handle, mut events) = Client::connect(config.clone(), Box::new(PipeSink::new())).await?;

    loop {
        tokio::select! {
            interrupted = signal::ctrl_c() => {
                interrupted.context("failed to wait for Ctrl-C")?;
                eprintln!("stopped on Ctrl-C");
                return Ok(Ending::Interrupted);
            }
            event = events.next() => {
                let Some(event) = event else {
                    return Ok(Ending::Disconnected {
                        reason: "the event stream ended without a disconnect event".to_owned(),
                        retry_in: Duration::ZERO,
                    });
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
                    Event::Track { title, artist } => {
                        let label = match (artist.as_str(), title.as_str()) {
                            ("", "") => "(none)".to_owned(),
                            ("", title) => title.to_owned(),
                            (artist, "") => artist.to_owned(),
                            (artist, title) => format!("{artist} - {title}"),
                        };
                        eprintln!("track: {label}");
                    }
                    Event::Volume { level, muted } => {
                        let mute = if muted { ", muted" } else { "" };
                        eprintln!("volume: {level}{mute}");
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
                    Event::Disconnected { reason, retry_in } => {
                        return Ok(Ending::Disconnected { reason, retry_in });
                    }
                }
            }
        }
    }
}

/// Loads the identity from `path`, generating and storing one when the file does not exist.
///
/// The secret is never printed; only the derived public key, which is what the server sees.
fn load_or_create_identity(path: &Path) -> Result<Identity> {
    match fs::read_to_string(path) {
        Ok(text) => Identity::from_secret_base64(text.trim()).with_context(|| {
            format!(
                "{} does not hold a 43-character base64url X25519 secret",
                path.display()
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let identity = Identity::generate();
            save_identity(path, &identity)?;
            eprintln!("generated a new identity in {}", path.display());
            Ok(identity)
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
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
    /// Whether to ask for encoded frames instead of decoded PCM.
    passthrough: bool,
}

/// Result of parsing the command line.
enum Parse {
    /// Print the usage text and exit.
    Help,
    /// Run the player with these options.
    Run(Options),
}

/// Parses `--flag value`, `--flag=value`, `--passthrough`, `--help` and `-h`.
fn parse_args<I>(args: I) -> Result<Parse>
where
    I: IntoIterator<Item = String>,
{
    let mut server = None;
    let mut name = DEFAULT_NAME.to_owned();
    let mut identity = PathBuf::from(DEFAULT_IDENTITY);
    let mut passthrough = false;

    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let (flag, inline) = split_flag(&argument);
        match flag {
            "-h" | "--help" => return Ok(Parse::Help),
            "--passthrough" => {
                if inline.is_some() {
                    bail!("--passthrough takes no value");
                }
                passthrough = true;
            }
            "--server" => server = Some(take_value(flag, inline, &mut args)?),
            "--name" => name = take_value(flag, inline, &mut args)?,
            "--identity" => identity = PathBuf::from(take_value(flag, inline, &mut args)?),
            other => bail!("unknown argument {other:?}; try --help"),
        }
    }

    let server = server.ok_or_else(|| anyhow!("--server is required; try --help"))?;
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
        passthrough,
    }))
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
    Ok(value)
}

/// The help text; the defaults come from the same constants the parser uses.
fn usage() -> String {
    format!(
        "\
player-pipe - stream one Sendspin player's audio to standard output

Usage: player-pipe --server <host[:port]> [options]

Options:
      --server <host[:port]>  Address of the Sendspin server (required),
                              for example music-assistant.local:8927
      --name <player name>    Name this player announces [default: {DEFAULT_NAME}]
      --identity <path>       File holding the player's X25519 identity; created
                              with owner-only permissions when missing
                              [default: {DEFAULT_IDENTITY}]
      --passthrough           Ask for encoded frames instead of decoded PCM; this
                              example carries no decoder, so such a stream stops
                              with an error
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
        assert!(!options.passthrough);
    }

    #[test]
    fn flags_accept_an_inline_value() {
        let options = options(&[
            "--server=music-assistant.local:8927",
            "--name=Kitchen",
            "--identity=/tmp/identity.json",
            "--passthrough",
        ]);

        assert_eq!(options.server, "music-assistant.local:8927");
        assert_eq!(options.name, "Kitchen");
        assert_eq!(options.identity, PathBuf::from("/tmp/identity.json"));
        assert!(options.passthrough);
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
            &["--server", "host", "--passthrough=yes"][..],
            &["--server", "host", "--name", &too_long][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} must be rejected");
        }
    }
}
