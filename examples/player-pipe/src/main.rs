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
//! no storage format of its own, so the example owns this one. Its pairing PSK and records live in
//! a second file, through the client's optional `FileStorage` backend.
//!
//! To pair with a server, print the version-0 pairing token and enter it there:
//!
//! ```sh
//! player-pipe --pairing-token
//! ```
//!
//! The token is a credential: whoever holds it can pair a server with this client. It is printed on
//! stdout, so it can be piped into whatever renders it; every status line in this example is on
//! stderr. A build with `--features pairing-code` also carries the static pairing code flow.
//!
//! A build with `--features discovery` can also find its server, or let the server find it:
//!
//! ```sh
//! player-pipe --discover | aplay -f S16_LE -r 48000 -c 2
//! player-pipe --advertise | aplay -f S16_LE -r 48000 -c 2
//! ```
//!
//! `--discover` browses `_sendspin-server._tcp` and dials the first server it finds; `--advertise`
//! publishes `_sendspin._tcp` and accepts the server that connects. Neither takes `--server`, and
//! the two are exclusive, because `connection.md` allows one connection mode at a time.
//!
//! Status lines are for people. In a playback run, audio is the only thing that reaches stdout.

mod pipe_sink;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
#[cfg(feature = "storage-file")]
use syncspin_client::storage::{FileStorage, Storage};
#[cfg(feature = "discovery")]
use syncspin_client::{
    discover_servers, DiscoveredServer, Discovery, Inbound, MdnsDiscovery, SERVER_SERVICE_TYPE,
};
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

/// Pairing store used when `--pairing-store` is absent.
#[cfg(feature = "storage-file")]
const DEFAULT_PAIRING_STORE: &str = "./pairing.json";

/// Longest delay between reconnects, handed to [`ClientConfig::max_backoff`].
const MAX_BACKOFF: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(Parse::Help) => {
            print!("{}", usage());
            return Ok(());
        }
        #[cfg(feature = "storage-file")]
        Ok(Parse::Token(options)) => return print_pairing_token(options),
        Ok(Parse::Run(options)) => options,
        Err(error) => {
            eprint!("error: {error}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    play(options)
}

/// Prints the version-0 pairing token and exits.
///
/// The token carries the identity's public key and the pairing PSK, which is drawn and stored on
/// this run if the store does not hold one yet. The client would draw the same key on its first
/// connection; doing it here lets the operator enter the token before the server admits anything.
#[cfg(feature = "storage-file")]
fn print_pairing_token(options: TokenOptions) -> Result<()> {
    let identity = load_or_create_identity(&options.identity)?;
    let store = FileStorage::new(&options.pairing_store).with_context(|| {
        format!(
            "failed to open the pairing store {}",
            options.pairing_store.display()
        )
    })?;
    let psk = match store
        .pairing_psk()
        .context("the pairing store did not return the pairing PSK")?
    {
        Some(psk) => psk,
        None => {
            let mut psk = [0u8; 32];
            getrandom::fill(&mut psk)
                .map_err(|error| anyhow!("the operating system CSPRNG is unavailable: {error}"))?;
            store
                .store_pairing_psk(&psk)
                .context("the pairing store did not accept the new pairing PSK")?;
            eprintln!(
                "drew a pairing PSK and stored it in {}",
                options.pairing_store.display()
            );
            psk
        }
    };

    let token = syncspin_core::pairing::token::encode_v0(&identity.public, &psk);
    writeln!(io::stdout().lock(), "{token}").context("failed to write the pairing token")?;
    eprintln!(
        "pairing token for identity {}: a credential, hand it over directly",
        identity.public_base64()
    );
    Ok(())
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

    #[cfg(feature = "storage-file")]
    let storage: Option<std::sync::Arc<dyn Storage>> = {
        let store = FileStorage::new(&options.pairing_store).with_context(|| {
            format!(
                "failed to open the pairing store {}",
                options.pairing_store.display()
            )
        })?;
        eprintln!("pairing store {}", options.pairing_store.display());
        Some(std::sync::Arc::new(store))
    };
    // A build without the file backend offers no pairing method: the host would have to implement
    // `Storage` itself, which is more code than an example of the player loop needs.
    #[cfg(not(feature = "storage-file"))]
    let storage: Option<std::sync::Arc<dyn syncspin_client::storage::Storage>> = None;

    // `--discover` resolves an address before the configuration exists. The daemon lives for one
    // browse and is dropped with it, so a dialling player joins no multicast group afterwards.
    #[cfg(feature = "discovery")]
    let server = if options.discover {
        let discovery =
            MdnsDiscovery::new().context("failed to start the mDNS daemon to discover a server")?;
        let server = discovered_endpoint(&discovery)?;
        eprintln!("discovered a server at {server}");
        server
    } else {
        options.server.clone()
    };
    #[cfg(not(feature = "discovery"))]
    let server = options.server.clone();

    // `--advertise` keeps its backend until the listener and its advertisement exist; a daemon that
    // cannot start is reported before anything else is bound.
    #[cfg(feature = "discovery")]
    let publishing: Option<std::sync::Arc<dyn Discovery>> = if options.advertise {
        Some(std::sync::Arc::new(MdnsDiscovery::new().context(
            "failed to start the mDNS daemon to advertise this player",
        )?))
    } else {
        None
    };

    let mut config = ClientConfig::new(server, options.name.clone(), identity);
    // A pipe on a general-purpose host has no hardware to describe; a host that runs on a device
    // passes the product name, manufacturer and version here so the server shows it.
    config.device_info = None;
    config.storage = storage;
    // This example has no decoder, so it asks for raw samples. A host that wants encoded frames
    // selects `AudioMode::Passthrough` and brings its own decoder.
    config.audio_mode = AudioMode::Decode;
    // Volume and mute are not restored across restarts, so the output starts at full scale and
    // unmuted.
    config.volume = 100;
    config.muted = false;
    config.volume_policy = VolumePolicy::default();
    config.max_backoff = MAX_BACKOFF;
    config.pairing_timeout = DEFAULT_PAIRING_TIMEOUT;
    #[cfg(feature = "pairing-code")]
    {
        config.static_pairing_code = options.static_code.clone();
        config.pairing_window = syncspin_client::DEFAULT_PAIRING_WINDOW;
        config.pairing_pending_text = None;
        // The example has no display and no speaker, so it offers no dynamic pairing code: an
        // empty format list advertises nothing. A host with an out-channel sets both lists and
        // renders `Event::PairingCode`.
        config.code_formats = Vec::new();
        config.code_out_channels = Vec::new();
    }

    // The client owns the reconnect loop: a dropped session is reported on the stream and retried
    // with the same sink and identity, so this example only prints what it sees. The advertise mode
    // has no server address; the inbound listener it binds is what a server dials.
    #[cfg(feature = "discovery")]
    let (handle, mut events) = match publishing {
        Some(discovery) => {
            let (handle, events) = syncspin_client::advertise(
                inbound_config(config, discovery),
                Box::new(PipeSink::new()),
            )
            .await?;
            eprintln!(
                "advertising {} as {}; waiting for a server to connect",
                syncspin_client::CLIENT_SERVICE_TYPE,
                options.name
            );
            (handle, events)
        }
        None => Client::connect(config, Box::new(PipeSink::new())).await?,
    };
    #[cfg(not(feature = "discovery"))]
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
                        // A pairing window belongs to one connection, so a reconnect needs the
                        // gesture again. The operator gave it by starting the player this way.
                        #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
                        if options.open_window {
                            match handle.control().open_pairing_window().await {
                                Ok(()) => eprintln!(
                                    "pairing window open for {}s",
                                    syncspin_client::DEFAULT_PAIRING_WINDOW.as_secs()
                                ),
                                Err(error) => eprintln!("pairing window: {error:#}"),
                            }
                        }
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
                    Event::Paired { server_id } => {
                        eprintln!("paired: record stored for server {server_id}")
                    }
                    Event::Unpaired { server_id } => eprintln!(
                        "unpaired: the server dropped the record for {server_id}"
                    ),
                    Event::PairingRequired { server_id, reason } => eprintln!(
                        "pairing required by {server_id}: {reason:?}"
                    ),
                    Event::PairingFailed { reason } => {
                        eprintln!("pairing failed: {}", reason.as_str())
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
struct Options {
    /// Server address as `host[:port]` or a `ws://` URL.
    ///
    /// Empty in a discovery mode: `--discover` resolves the address at run time and `--advertise`
    /// names none, because it accepts the server that connects.
    server: String,
    /// Player name announced to the server.
    name: String,
    /// File that holds the X25519 identity.
    identity: PathBuf,
    /// Whether to publish `_sendspin._tcp` and accept the server that connects.
    #[cfg(feature = "discovery")]
    advertise: bool,
    /// Whether to browse `_sendspin-server._tcp` and dial the first server found.
    #[cfg(feature = "discovery")]
    discover: bool,
    /// File that holds the pairing PSK and records.
    #[cfg(feature = "storage-file")]
    pairing_store: PathBuf,
    /// Static pairing code, shared with the server.
    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    static_code: Option<String>,
    /// Whether to open a pairing window on every connection.
    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    open_window: bool,
}

/// What `--pairing-token` needs: no server and no player name, only the credentials.
#[cfg(feature = "storage-file")]
struct TokenOptions {
    /// File that holds the X25519 identity.
    identity: PathBuf,
    /// File that holds the pairing PSK and records.
    pairing_store: PathBuf,
}

/// Result of parsing the command line.
enum Parse {
    /// Print the usage text and exit.
    Help,
    /// Print the pairing token and exit.
    #[cfg(feature = "storage-file")]
    Token(TokenOptions),
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
    #[cfg(feature = "discovery")]
    let mut advertise = false;
    #[cfg(feature = "discovery")]
    let mut discover = false;
    #[cfg(feature = "storage-file")]
    let mut pairing_store = PathBuf::from(DEFAULT_PAIRING_STORE);
    #[cfg(feature = "storage-file")]
    let mut pairing_token = false;
    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    let mut static_code: Option<String> = None;
    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    let mut open_window = false;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        let (flag, inline) = split_flag(&argument);
        match flag {
            "-h" | "--help" => return Ok(Parse::Help),
            "--server" => server = Some(take_value(flag, inline, &mut args)?),
            "--name" => name = take_value(flag, inline, &mut args)?,
            "--identity" => identity = PathBuf::from(take_value(flag, inline, &mut args)?),
            #[cfg(feature = "discovery")]
            "--advertise" => advertise = true,
            #[cfg(feature = "discovery")]
            "--discover" => discover = true,
            #[cfg(not(feature = "discovery"))]
            "--advertise" | "--discover" => bail!(
                "discovery needs the discovery feature: rebuild with --features discovery"
            ),
            #[cfg(feature = "storage-file")]
            "--pairing-store" => {
                pairing_store = PathBuf::from(take_value(flag, inline, &mut args)?)
            }
            #[cfg(feature = "storage-file")]
            "--pairing-token" => pairing_token = true,
            #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
            "--static-code" => static_code = Some(take_value(flag, inline, &mut args)?),
            #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
            "--open-window" => open_window = true,
            #[cfg(all(feature = "pairing-code", not(feature = "storage-file")))]
            "--static-code" | "--open-window" => bail!(
                "the code flows need the storage-file feature: a completed pairing has to be stored"
            ),
            #[cfg(all(not(feature = "pairing-code"), feature = "storage-file"))]
            "--static-code" | "--open-window" => bail!(
                "the code flows need the pairing-code feature: rebuild with --features pairing-code"
            ),
            #[cfg(not(any(feature = "pairing-code", feature = "storage-file")))]
            "--static-code" | "--open-window" => bail!(
                "the code flows need two features: rebuild with --features pairing-code,storage-file"
            ),
            other => bail!("unknown argument {other:?}; try --help"),
        }
    }

    #[cfg(feature = "storage-file")]
    if pairing_token {
        if server.is_some() {
            bail!("--pairing-token prints the token and exits; drop --server");
        }
        #[cfg(feature = "discovery")]
        if advertise || discover {
            bail!("--pairing-token prints the token and exits; drop --advertise and --discover");
        }
        #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
        if static_code.is_some() || open_window {
            bail!(
                "--pairing-token prints the token and exits; drop --static-code and --open-window"
            );
        }
        return Ok(Parse::Token(TokenOptions {
            identity,
            pairing_store,
        }));
    }

    #[cfg(feature = "discovery")]
    if advertise && discover {
        bail!("--advertise and --discover are two connection modes: pick one");
    }
    #[cfg(feature = "discovery")]
    let server = match (server, advertise, discover) {
        (Some(_), true, _) => {
            bail!("--advertise accepts the servers that connect; drop --server")
        }
        (Some(_), _, true) => bail!("--discover finds the server itself; drop --server"),
        (Some(server), false, false) => {
            check_server(&server)?;
            server
        }
        (None, false, false) => bail!("--server is required; try --help"),
        // One of the two discovery modes was asked for; neither names an address.
        (None, _, _) => String::new(),
    };
    #[cfg(not(feature = "discovery"))]
    let server = {
        let server = server.ok_or_else(|| anyhow!("--server is required; try --help"))?;
        check_server(&server)?;
        server
    };
    if name.len() > MAX_PLAYER_NAME_LEN {
        bail!(
            "--name is {} bytes, but the protocol allows at most {MAX_PLAYER_NAME_LEN}",
            name.len()
        );
    }

    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    {
        if let Some(code) = &static_code {
            check_static_code(code)?;
        }
        match (static_code.is_some(), open_window) {
            (true, false) => bail!(
                "--static-code needs --open-window: the window is the operator gesture that admits \
                 a static-code attempt"
            ),
            (false, true) => bail!(
                "--open-window needs --static-code: the window admits only the static code flow"
            ),
            _ => {}
        }
    }

    Ok(Parse::Run(Options {
        server,
        name,
        identity,
        #[cfg(feature = "discovery")]
        advertise,
        #[cfg(feature = "discovery")]
        discover,
        #[cfg(feature = "storage-file")]
        pairing_store,
        #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
        static_code,
        #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
        open_window,
    }))
}

/// Rejects a static code that is not exactly the eight decimal digits the protocol defines.
///
/// The code is a credential, so the error names the shape and never echoes the value.
#[cfg(all(feature = "pairing-code", feature = "storage-file"))]
fn check_static_code(code: &str) -> Result<()> {
    if code.len() != syncspin_client::STATIC_PAIRING_CODE_LEN
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!(
            "--static-code must be {} ASCII digits",
            syncspin_client::STATIC_PAIRING_CODE_LEN
        );
    }
    Ok(())
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

/// Returns the endpoint of the first server discovery reports.
///
/// A browse is a snapshot, so the caller starts the server first or retries; this example keeps the
/// command line one-shot instead of hiding a retry loop behind it. A record that cannot name a
/// `ws://` endpoint is skipped rather than guessed at.
#[cfg(feature = "discovery")]
fn discovered_endpoint(discovery: &dyn Discovery) -> Result<String> {
    let servers = discover_servers(discovery)?;
    servers
        .iter()
        .find_map(DiscoveredServer::endpoint)
        .ok_or_else(|| {
            anyhow!(
                "no server advertised {SERVER_SERVICE_TYPE}; start one with `server-demo --mdns` \
                 or pass --server"
            )
        })
}

/// Puts the client in the server-initiated mode over `discovery`.
///
/// Pure apart from the backend it receives: it binds nothing, so a test can pass a fake and inspect
/// the configuration the advertise mode hands to [`syncspin_client::advertise`].
#[cfg(feature = "discovery")]
fn inbound_config(
    mut config: ClientConfig,
    discovery: std::sync::Arc<dyn Discovery>,
) -> ClientConfig {
    config.inbound = Some(Inbound::new(discovery));
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
    let mut text = String::from(
        "\
player-pipe - stream one Sendspin player's audio to standard output

Usage: player-pipe --server <host[:port] | ws://url> [options]
",
    );
    #[cfg(feature = "storage-file")]
    text.push_str(
        "       player-pipe --pairing-token [--identity <path>] [--pairing-store <path>]\n",
    );
    #[cfg(feature = "discovery")]
    text.push_str(
        "       player-pipe --discover [options]
       player-pipe --advertise [options]
",
    );

    text.push_str(&format!(
        "\
Options:
      --server <host[:port] | ws://url>
                              Address of the Sendspin server (required unless a
                              discovery switch finds or accepts one), for
                              example music-assistant.local:8927; TLS (wss://)
                              is not supported by this build
      --name <player name>    Name this player announces [default: {DEFAULT_NAME}]
      --identity <path>       File holding the player's X25519 identity: the bare
                              43-character base64url secret on one line, not JSON;
                              created with owner-only permissions when missing
                              [default: {DEFAULT_IDENTITY}]
"
    ));
    #[cfg(feature = "discovery")]
    text.push_str(
        "
      --advertise             Publish _sendspin._tcp over mDNS and accept the server
                              that connects, instead of dialing one
      --discover              Browse for a server over mDNS and dial the first one
                              found, instead of taking --server
",
    );
    #[cfg(feature = "storage-file")]
    text.push_str(&format!(
        "
      --pairing-token         Print this client's version-0 pairing token (SP:...)
                              and exit; the token carries the identity and the
                              pairing PSK, so treat it as a credential
      --pairing-store <path>  JSON file holding the pairing PSK and the pairing
                              records; created with owner-only permissions
                              [default: {DEFAULT_PAIRING_STORE}]
"
    ));
    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    text.push_str(
        "
      --static-code <code>    Static pairing code, exactly eight digits, shared
                              with the server; treat it as a credential
                              (needs --open-window)
      --open-window           Open a pairing window on every connection
                              (needs --static-code)
",
    );
    text.push_str(
        "
  -h, --help                  Print this help and exit

Audio goes to standard output as raw samples in the announced format; status
lines go to standard error. The player reconnects with backoff and stops on
Ctrl-C.
",
    );
    text
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
            #[cfg(feature = "storage-file")]
            Ok(Parse::Token(_)) => panic!("expected options, got the token mode"),
            Ok(Parse::Help) => panic!("expected options, got the help text"),
            Err(error) => panic!("expected options, got the error {error:#}"),
        }
    }

    /// Parses a command line that is expected to print the pairing token.
    #[cfg(feature = "storage-file")]
    fn token_options(args: &[&str]) -> TokenOptions {
        match parse(args) {
            Ok(Parse::Token(options)) => options,
            Ok(Parse::Run(_)) => panic!("expected the token mode, got a run"),
            Ok(Parse::Help) => panic!("expected the token mode, got the help text"),
            Err(error) => panic!("expected the token mode, got the error {error:#}"),
        }
    }

    #[test]
    fn the_defaults_apply_when_only_the_server_is_given() {
        let options = options(&["--server", "music-assistant.local"]);

        assert_eq!(options.server, "music-assistant.local");
        assert_eq!(options.name, DEFAULT_NAME);
        assert_eq!(options.identity, PathBuf::from(DEFAULT_IDENTITY));
        #[cfg(feature = "discovery")]
        {
            assert!(!options.advertise);
            assert!(!options.discover);
        }
        #[cfg(feature = "storage-file")]
        assert_eq!(options.pairing_store, PathBuf::from(DEFAULT_PAIRING_STORE));
        #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
        {
            assert_eq!(options.static_code, None);
            assert!(!options.open_window);
        }
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

    #[cfg(feature = "storage-file")]
    #[test]
    fn the_token_mode_needs_no_server_and_names_its_own_files() {
        let options = token_options(&["--pairing-token"]);
        assert_eq!(options.identity, PathBuf::from(DEFAULT_IDENTITY));
        assert_eq!(options.pairing_store, PathBuf::from(DEFAULT_PAIRING_STORE));

        let options = token_options(&[
            "--pairing-token",
            "--identity=/tmp/identity.key",
            "--pairing-store=/tmp/pairing.json",
        ]);
        assert_eq!(options.identity, PathBuf::from("/tmp/identity.key"));
        assert_eq!(options.pairing_store, PathBuf::from("/tmp/pairing.json"));
    }

    #[cfg(feature = "storage-file")]
    #[test]
    fn the_token_mode_refuses_a_connection() {
        let Err(error) = parse(&["--pairing-token", "--server", "host"]) else {
            panic!("a token run must not connect");
        };
        assert!(
            format!("{error}").contains("drop --server"),
            "the error should say what to drop, got: {error}"
        );
    }

    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    #[test]
    fn a_static_code_attempt_needs_the_code_and_the_window() {
        let options = options(&[
            "--server",
            "host",
            "--static-code",
            "12345678",
            "--open-window",
        ]);
        assert_eq!(options.static_code.as_deref(), Some("12345678"));
        assert!(options.open_window);

        for args in [
            &["--server", "host", "--static-code", "12345678"][..],
            &["--server", "host", "--open-window"][..],
            &[
                "--server",
                "host",
                "--static-code",
                "1234567",
                "--open-window",
            ][..],
            &[
                "--server",
                "host",
                "--static-code",
                "1234567a",
                "--open-window",
            ][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} must be rejected");
        }
    }

    #[cfg(all(feature = "pairing-code", feature = "storage-file"))]
    #[test]
    fn a_bad_static_code_is_never_echoed() {
        let Err(error) = parse(&[
            "--server",
            "host",
            "--static-code",
            "8765432",
            "--open-window",
        ]) else {
            panic!("a seven-digit code must be rejected");
        };
        let text = format!("{error}");
        assert!(
            text.contains("eight") || text.contains("8 ASCII digits"),
            "the error should name the shape, got: {text}"
        );
        assert!(
            !text.contains("8765432"),
            "the code is a credential and must not be echoed: {text}"
        );
    }

    #[cfg(feature = "storage-file")]
    #[test]
    fn the_usage_lists_the_flags_this_build_has() {
        let text = usage();
        assert!(text.contains("--pairing-token"), "got: {text}");
        assert!(text.contains("--pairing-store"), "got: {text}");
        #[cfg(feature = "pairing-code")]
        assert!(text.contains("--open-window"), "got: {text}");
    }

    #[cfg(feature = "storage-file")]
    #[test]
    fn every_flag_starts_its_own_indented_line() {
        let text = usage();
        for line in [
            "\n      --pairing-token",
            "\n      --pairing-store",
            #[cfg(feature = "discovery")]
            "\n      --advertise",
            #[cfg(feature = "discovery")]
            "\n      --discover",
            "\n  -h, --help",
        ] {
            assert!(
                text.contains(line),
                "the help text must keep {line:?} indented rather than glued to the line above, got: {text}"
            );
        }
    }

    #[cfg(all(feature = "storage-file", not(feature = "pairing-code")))]
    #[test]
    fn a_missing_feature_is_named_in_the_error() {
        let Err(error) = parse(&["--server", "host", "--open-window"]) else {
            panic!("--open-window without the pairing-code feature must be rejected");
        };
        let text = format!("{error}");
        assert!(
            text.contains("--features pairing-code"),
            "the error must name the feature that adds the flag, got: {text}"
        );
    }

    #[test]
    fn help_is_reported_without_a_server() {
        assert!(matches!(parse(&["--help"]), Ok(Parse::Help)));
        assert!(matches!(parse(&["-h"]), Ok(Parse::Help)));
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn advertise_and_discover_are_connection_modes_of_their_own() {
        let advertising = options(&["--advertise", "--name", "Kitchen"]);
        assert!(advertising.advertise);
        assert!(!advertising.discover);
        assert_eq!(advertising.server, "");
        assert_eq!(advertising.name, "Kitchen");

        let discovering = options(&["--discover", "--identity=/tmp/identity.key"]);
        assert!(discovering.discover);
        assert!(!discovering.advertise);
        assert_eq!(discovering.server, "");
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn the_connection_modes_are_mutually_exclusive() {
        for (args, expected) in [
            (&["--server", "host", "--advertise"][..], "drop --server"),
            (&["--server", "host", "--discover"][..], "drop --server"),
            (&["--advertise", "--discover"][..], "pick one"),
        ] {
            let Err(error) = parse(args) else {
                panic!("{args:?} must be rejected");
            };
            assert!(
                format!("{error}").contains(expected),
                "{args:?} should report {expected:?}, got: {error}"
            );
        }
    }

    #[cfg(feature = "storage-file")]
    #[cfg(feature = "discovery")]
    #[test]
    fn the_token_mode_refuses_the_discovery_switches() {
        for args in [
            &["--pairing-token", "--advertise"][..],
            &["--pairing-token", "--discover"][..],
        ] {
            let Err(error) = parse(args) else {
                panic!("{args:?} must be rejected");
            };
            assert!(
                format!("{error}").contains("drop --advertise and --discover"),
                "the error should say what to drop, got: {error}"
            );
        }
    }

    #[cfg(not(feature = "discovery"))]
    #[test]
    fn discovery_flags_name_the_missing_feature() {
        for flag in ["--advertise", "--discover"] {
            let Err(error) = parse(&["--server", "host", flag]) else {
                panic!("{flag} without the discovery feature must be rejected");
            };
            let text = format!("{error}");
            assert!(
                text.contains("--features discovery"),
                "the error must name the feature that adds the flag, got: {text}"
            );
        }
    }

    #[cfg(not(feature = "discovery"))]
    #[test]
    fn a_build_without_discovery_does_not_list_the_switches() {
        let text = usage();
        assert!(!text.contains("--advertise"), "got: {text}");
        assert!(!text.contains("--discover"), "got: {text}");
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn the_usage_lists_the_discovery_switches() {
        let text = usage();
        assert!(text.contains("--advertise"), "got: {text}");
        assert!(text.contains("--discover"), "got: {text}");
    }

    /// A [`Discovery`] that answers from memory, so the wiring is tested without multicast.
    #[cfg(feature = "discovery")]
    #[derive(Default)]
    struct MemoryDiscovery {
        servers: Vec<DiscoveredServer>,
    }

    #[cfg(feature = "discovery")]
    impl Discovery for MemoryDiscovery {
        fn advertise(&self, _service: syncspin_client::ServiceAdvertisement) -> Result<()> {
            Ok(())
        }

        fn withdraw(&self, _service_type: &str) -> Result<()> {
            Ok(())
        }

        fn browse(&self, _service_type: &str) -> Result<Vec<DiscoveredServer>> {
            Ok(self.servers.clone())
        }
    }

    /// The advertise mode adds an inbound listener with the spec's address and path, binding none.
    #[cfg(feature = "discovery")]
    #[test]
    fn the_advertise_mode_builds_the_inbound_config_without_a_socket() {
        let config = inbound_config(
            ClientConfig::new(String::new(), "Test player", Identity::generate()),
            std::sync::Arc::new(MemoryDiscovery::default()),
        );
        let inbound = config
            .inbound
            .expect("the advertise mode sets ClientConfig::inbound");
        assert_eq!(inbound.listen, syncspin_client::DEFAULT_INBOUND_ADDR);
        assert_eq!(inbound.path, syncspin_client::DEFAULT_SENDSPIN_PATH);
    }

    /// The discover mode turns the first reported record into the address the config dials.
    #[cfg(feature = "discovery")]
    #[test]
    fn the_discover_mode_builds_a_ws_dial_target_from_the_first_server() {
        let discovery = MemoryDiscovery {
            servers: vec![DiscoveredServer {
                addresses: vec!["192.0.2.7:8927".to_owned()],
                path: "/sendspin".to_owned(),
                name: Some("A server".to_owned()),
            }],
        };
        assert_eq!(
            discovered_endpoint(&discovery).expect("a server is advertised"),
            "ws://192.0.2.7:8927/sendspin"
        );

        let empty = MemoryDiscovery::default();
        let Err(error) = discovered_endpoint(&empty) else {
            panic!("an empty browse must not name an endpoint");
        };
        assert!(
            format!("{error}").contains(SERVER_SERVICE_TYPE),
            "the error should name what was looked for, got: {error}"
        );
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
