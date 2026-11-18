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

use std::time::Duration;

use anyhow::{anyhow, bail, Result};

mod find;

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

fn main() -> anyhow::Result<()> {
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
    let name = run_name(&options, std::process::id())?;
    // The command line is all this step carries: advertising, discovery, approval and the stream
    // are the subject of the example and are not wired up yet.
    bail!(
        "the run {name:?} (base name {:?}, {} s budget) has no discovery or stream flow yet",
        options.name,
        options.timeout.as_secs()
    )
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
}
