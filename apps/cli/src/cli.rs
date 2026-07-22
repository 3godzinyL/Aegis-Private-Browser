//! The `clap`-derived argument surface for the `aegis` CLI (spec §11).
//!
//! Everything here is pure parsing: it turns `argv` into a typed [`Cli`] value
//! with no I/O, so it can be exercised directly in unit tests via
//! [`clap::Parser::try_parse_from`] / [`clap::CommandFactory::command`].

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Aegis — manage disposable/persistent private browsing environments.
///
/// The CLI is an unprivileged front-end: it renders daemon state and issues
/// requests over the local authorized socket (unix) or the loopback dev
/// endpoint (windows). It performs no privileged operation itself.
#[derive(Debug, Parser)]
#[command(name = "aegis", version, about, long_about = None)]
pub struct Cli {
    /// Global connection / output options.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Options that apply to every subcommand.
#[derive(Debug, Args, Clone, Default)]
pub struct GlobalArgs {
    /// Path to the daemon's Unix control socket (unix only).
    ///
    /// Defaults to the daemon's configured socket path. Ignored on non-unix
    /// hosts, where `--endpoint` selects the loopback dev transport instead.
    #[arg(long, global = true, value_name = "PATH", env = "AEGIS_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Loopback endpoint `host:port` for the Windows development transport.
    ///
    /// Only used on non-unix hosts (the production transport is the Unix socket).
    #[arg(long, global = true, value_name = "HOST:PORT", env = "AEGIS_ENDPOINT")]
    pub endpoint: Option<String>,

    /// Path to the shared-token file for the loopback dev transport (non-unix).
    #[arg(long, global = true, value_name = "PATH", env = "AEGIS_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,

    /// Emit machine-readable JSON instead of human-readable tables.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase logging verbosity (repeatable: -v, -vv).
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// The top-level command groups (spec §11).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create, list, inspect, and remove browsing profiles.
    #[command(subcommand)]
    Profile(ProfileCommand),

    /// Start, stop, and list browsing sessions.
    #[command(subcommand)]
    Session(SessionCommand),

    /// Render the diagnostics panel for a session.
    Diagnostics {
        /// The session id to diagnose.
        #[arg(value_name = "SESSION")]
        session: String,
    },

    /// Show daemon status: platform, isolation level, enforcement, host browser.
    Status,

    /// Inspect and change daemon configuration (advanced).
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Ask the daemon to run its preflight self-test and print pass/fail.
    Doctor,

    /// Update checking and application.
    #[command(subcommand)]
    Update(UpdateCommand),
}

/// `aegis config …`
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show or change the containment enforcement policy (advanced).
    ///
    /// With no flags, prints the current policy. Each flag flips one toggle;
    /// unset flags are left unchanged. Relaxing VM isolation prints an honest
    /// reduced-protection warning.
    Enforcement(EnforcementArgs),
}

/// Arguments for `aegis config enforcement`.
///
/// Every flag is optional; only the ones supplied are changed, so the command
/// is a partial update over the daemon's current policy.
#[derive(Debug, Args, Clone, Default)]
pub struct EnforcementArgs {
    /// Require the browser to run in its own isolated VM.
    #[arg(long = "vm-isolation", value_enum, value_name = "ON|OFF")]
    pub vm_isolation: Option<Toggle>,

    /// Require a dedicated Gateway VM for the network path.
    #[arg(long = "gateway", value_enum, value_name = "ON|OFF")]
    pub gateway: Option<Toggle>,

    /// Permit launching the browser directly on the host (reduced protection).
    #[arg(long = "host-browser", value_enum, value_name = "ON|OFF")]
    pub host_browser: Option<Toggle>,
}

impl EnforcementArgs {
    /// Whether no toggle was supplied (a pure "show current policy" invocation).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vm_isolation.is_none() && self.gateway.is_none() && self.host_browser.is_none()
    }

    /// Apply the supplied toggles over a current [`aegis_core::config::Enforcement`],
    /// returning the updated policy. Unset flags are left unchanged.
    #[must_use]
    pub fn apply(
        &self,
        mut current: aegis_core::config::Enforcement,
    ) -> aegis_core::config::Enforcement {
        if let Some(t) = self.vm_isolation {
            current.require_vm_isolation = t.is_on();
        }
        if let Some(t) = self.gateway {
            current.require_gateway = t.is_on();
        }
        if let Some(t) = self.host_browser {
            current.allow_host_browser = t.is_on();
        }
        current
    }
}

/// An on/off toggle for the enforcement flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Toggle {
    /// Enable the flag.
    On,
    /// Disable the flag.
    Off,
}

impl Toggle {
    /// Whether this toggle is `on`.
    #[must_use]
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }
}

/// `aegis profile …`
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Create a new profile.
    Create(ProfileCreateArgs),
    /// List all profiles as a table.
    List,
    /// Show a single profile in detail.
    Show {
        /// The profile id.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Remove a profile and shred its data.
    Rm {
        /// The profile id.
        #[arg(value_name = "ID")]
        id: String,
    },
}

/// Arguments for `aegis profile create`.
///
/// A single invocation can fully customize a profile: its kind, outbound tunnel
/// (with proxy/bridge details), fingerprint protection, and the per-profile
/// isolation level that the daemon uses to pick the run mode.
#[derive(Debug, Args, Clone)]
pub struct ProfileCreateArgs {
    /// Human-facing profile name.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Whether the profile survives session end.
    #[arg(long, value_enum, default_value_t = ProfileKindArg::Ephemeral)]
    pub kind: ProfileKindArg,

    /// The outbound tunnel the profile is pinned to.
    #[arg(long, value_enum, default_value_t = NetArg::Tor)]
    pub net: NetArg,

    /// Fingerprint-normalization protection level.
    #[arg(long, value_enum, default_value_t = ProtectionArg::Balanced)]
    pub protection: ProtectionArg,

    /// Where the profile runs: a dedicated VM (full isolation, needs KVM) or a
    /// hardened host process routed through a proxy (works on Windows/macOS,
    /// reduced protection). Defaults to `vm`.
    #[arg(long, value_enum, default_value_t = IsolationArg::Vm)]
    pub isolation: IsolationArg,

    /// Browser engine: hardened `chromium` (default) or `firefox` (a Firefox /
    /// Tor Browser binary on the host; set AEGIS_FIREFOX_BIN to point at it).
    #[arg(long, value_enum, default_value_t = BrowserArg::Chromium)]
    pub browser: BrowserArg,

    /// Proxy protocol to use when `--net proxy` (SOCKS5 or HTTP CONNECT).
    #[arg(long = "proxy-kind", value_enum, default_value_t = ProxyKindArg::Socks5)]
    pub proxy_kind: ProxyKindArg,

    /// Proxy host to use when `--net proxy` (required for the proxy tunnel).
    #[arg(long = "proxy-host", value_name = "HOST")]
    pub proxy_host: Option<String>,

    /// Proxy port to use when `--net proxy` (required for the proxy tunnel).
    #[arg(long = "proxy-port", value_name = "PORT")]
    pub proxy_port: Option<u16>,

    /// A Tor bridge line (repeatable) used when `--net tor`. Supplying at least
    /// one bridge sets `TorConfig.use_bridges` and records the lines.
    #[arg(long = "tor-bridge", value_name = "LINE")]
    pub tor_bridge: Vec<String>,
}

/// `aegis session …`
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Start a new browsing session for a profile.
    Start {
        /// The profile id to launch.
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Stop (tear down) a running session.
    Stop {
        /// The session id to stop.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// List active sessions with their protection badges.
    List,
}

/// `aegis update …`
#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    /// Check whether a newer, valid update exists.
    Check,
    /// Apply the newest available, verified update.
    Apply,
}

/// The `--kind` choices for `profile create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ProfileKindArg {
    /// Destroyed at session end — no residue.
    Ephemeral,
    /// Stored in an encrypted, re-openable volume.
    Persistent,
}

impl ProfileKindArg {
    /// Convert to the domain [`aegis_core::profile::ProfileType`].
    #[must_use]
    pub fn to_domain(self) -> aegis_core::profile::ProfileType {
        match self {
            Self::Ephemeral => aegis_core::profile::ProfileType::Ephemeral,
            Self::Persistent => aegis_core::profile::ProfileType::Persistent,
        }
    }
}

/// The `--net` choices for `profile create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum NetArg {
    /// Route through Tor.
    Tor,
    /// Route through a VPN tunnel.
    Vpn,
    /// Route through a SOCKS5/HTTP proxy.
    Proxy,
}

/// The `--isolation` choices for `profile create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum IsolationArg {
    /// Run in a dedicated VM behind a gateway (full isolation).
    Vm,
    /// Run as a hardened host process routed through a proxy (reduced).
    Host,
}

impl IsolationArg {
    /// Convert to the domain [`aegis_core::config::IsolationLevel`].
    #[must_use]
    pub fn to_domain(self) -> aegis_core::config::IsolationLevel {
        match self {
            Self::Vm => aegis_core::config::IsolationLevel::FullVm,
            Self::Host => aegis_core::config::IsolationLevel::HostProcess,
        }
    }
}

/// The `--browser` engine choices for `profile create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum BrowserArg {
    /// Hardened Chromium (default).
    Chromium,
    /// Firefox / Tor Browser on the host.
    Firefox,
}

impl BrowserArg {
    /// Convert to the domain [`aegis_core::browser::BrowserBackendId`].
    #[must_use]
    pub fn to_domain(self) -> aegis_core::browser::BrowserBackendId {
        match self {
            Self::Chromium => aegis_core::browser::BrowserBackendId::Chromium,
            Self::Firefox => aegis_core::browser::BrowserBackendId::Firefox,
        }
    }
}

/// The `--proxy-kind` choices for `profile create` (used with `--net proxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum ProxyKindArg {
    /// SOCKS5 (supports remote DNS via SOCKS5h).
    Socks5,
    /// HTTP CONNECT tunnel.
    Http,
}

impl ProxyKindArg {
    /// Convert to the domain [`aegis_core::network::ProxyProtocol`].
    #[must_use]
    pub fn to_domain(self) -> aegis_core::network::ProxyProtocol {
        match self {
            Self::Socks5 => aegis_core::network::ProxyProtocol::Socks5,
            Self::Http => aegis_core::network::ProxyProtocol::HttpConnect,
        }
    }
}

/// The `--protection` choices for `profile create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ProtectionArg {
    /// Most sites work normally.
    Balanced,
    /// Stronger privacy, more breakage.
    Strict,
}

impl ProtectionArg {
    /// Convert to the domain [`aegis_core::fingerprint::ProtectionLevel`].
    #[must_use]
    pub fn to_domain(self) -> aegis_core::fingerprint::ProtectionLevel {
        match self {
            Self::Balanced => aegis_core::fingerprint::ProtectionLevel::Balanced,
            Self::Strict => aegis_core::fingerprint::ProtectionLevel::Strict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper: parse an argv (with the leading program name) into a [`Cli`].
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn clap_command_is_valid() {
        // Debug-asserts the whole command tree is internally consistent.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn profile_create_full() {
        let cli = parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "shopping",
            "--kind",
            "persistent",
            "--net",
            "vpn",
            "--protection",
            "strict",
        ])
        .expect("parse");
        match cli.command {
            Command::Profile(ProfileCommand::Create(a)) => {
                assert_eq!(a.name, "shopping");
                assert_eq!(a.kind, ProfileKindArg::Persistent);
                assert_eq!(a.net, NetArg::Vpn);
                assert_eq!(a.protection, ProtectionArg::Strict);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn profile_create_defaults() {
        let cli = parse(&["aegis", "profile", "create", "--name", "quick"]).expect("parse");
        match cli.command {
            Command::Profile(ProfileCommand::Create(a)) => {
                assert_eq!(a.kind, ProfileKindArg::Ephemeral);
                assert_eq!(a.net, NetArg::Tor);
                assert_eq!(a.protection, ProtectionArg::Balanced);
                // New flags default to VM isolation, SOCKS5, and no proxy/bridges.
                assert_eq!(a.isolation, IsolationArg::Vm);
                assert_eq!(a.proxy_kind, ProxyKindArg::Socks5);
                assert_eq!(a.proxy_host, None);
                assert_eq!(a.proxy_port, None);
                assert!(a.tor_bridge.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn profile_create_isolation_host_parses() {
        let cli = parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "h",
            "--isolation",
            "host",
        ])
        .expect("parse");
        match cli.command {
            Command::Profile(ProfileCommand::Create(a)) => {
                assert_eq!(a.isolation, IsolationArg::Host);
                assert_eq!(
                    a.isolation.to_domain(),
                    aegis_core::config::IsolationLevel::HostProcess
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn profile_create_proxy_flags_parse() {
        let cli = parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "p",
            "--net",
            "proxy",
            "--proxy-kind",
            "http",
            "--proxy-host",
            "10.0.0.9",
            "--proxy-port",
            "3128",
        ])
        .expect("parse");
        match cli.command {
            Command::Profile(ProfileCommand::Create(a)) => {
                assert_eq!(a.net, NetArg::Proxy);
                assert_eq!(a.proxy_kind, ProxyKindArg::Http);
                assert_eq!(a.proxy_host.as_deref(), Some("10.0.0.9"));
                assert_eq!(a.proxy_port, Some(3128));
                assert_eq!(
                    a.proxy_kind.to_domain(),
                    aegis_core::network::ProxyProtocol::HttpConnect
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn profile_create_tor_bridges_repeatable() {
        let cli = parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "b",
            "--net",
            "tor",
            "--tor-bridge",
            "obfs4 1.2.3.4:443 CERT",
            "--tor-bridge",
            "obfs4 5.6.7.8:80 CERT",
        ])
        .expect("parse");
        match cli.command {
            Command::Profile(ProfileCommand::Create(a)) => {
                assert_eq!(a.tor_bridge.len(), 2);
                assert_eq!(a.tor_bridge[0], "obfs4 1.2.3.4:443 CERT");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn profile_create_rejects_bad_isolation_and_proxy_kind() {
        assert!(parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "x",
            "--isolation",
            "cloud"
        ])
        .is_err());
        assert!(parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "x",
            "--proxy-kind",
            "socks4"
        ])
        .is_err());
        // A non-numeric proxy port is rejected at parse time.
        assert!(parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "x",
            "--proxy-port",
            "notaport"
        ])
        .is_err());
    }

    #[test]
    fn profile_create_requires_name() {
        assert!(parse(&["aegis", "profile", "create"]).is_err());
    }

    #[test]
    fn profile_create_rejects_bad_net() {
        assert!(parse(&[
            "aegis",
            "profile",
            "create",
            "--name",
            "x",
            "--net",
            "carrier-pigeon"
        ])
        .is_err());
    }

    #[test]
    fn profile_list_parses() {
        let cli = parse(&["aegis", "profile", "list"]).expect("parse");
        assert!(matches!(
            cli.command,
            Command::Profile(ProfileCommand::List)
        ));
    }

    #[test]
    fn profile_show_and_rm_take_id() {
        let show = parse(&["aegis", "profile", "show", "abc"]).expect("parse");
        match show.command {
            Command::Profile(ProfileCommand::Show { id }) => assert_eq!(id, "abc"),
            other => panic!("unexpected: {other:?}"),
        }
        let rm = parse(&["aegis", "profile", "rm", "def"]).expect("parse");
        match rm.command {
            Command::Profile(ProfileCommand::Rm { id }) => assert_eq!(id, "def"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn session_start_stop_list() {
        let start = parse(&["aegis", "session", "start", "prof-1"]).expect("parse");
        match start.command {
            Command::Session(SessionCommand::Start { profile }) => assert_eq!(profile, "prof-1"),
            other => panic!("unexpected: {other:?}"),
        }
        let stop = parse(&["aegis", "session", "stop", "sess-1"]).expect("parse");
        match stop.command {
            Command::Session(SessionCommand::Stop { id }) => assert_eq!(id, "sess-1"),
            other => panic!("unexpected: {other:?}"),
        }
        let list = parse(&["aegis", "session", "list"]).expect("parse");
        assert!(matches!(
            list.command,
            Command::Session(SessionCommand::List)
        ));
    }

    #[test]
    fn diagnostics_takes_session() {
        let cli = parse(&["aegis", "diagnostics", "sess-9"]).expect("parse");
        match cli.command {
            Command::Diagnostics { session } => assert_eq!(session, "sess-9"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn doctor_parses() {
        let cli = parse(&["aegis", "doctor"]).expect("parse");
        assert!(matches!(cli.command, Command::Doctor));
    }

    #[test]
    fn status_parses() {
        let cli = parse(&["aegis", "status"]).expect("parse");
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn config_enforcement_no_flags_is_empty() {
        let cli = parse(&["aegis", "config", "enforcement"]).expect("parse");
        match cli.command {
            Command::Config(ConfigCommand::Enforcement(a)) => assert!(a.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn config_enforcement_flags_parse_and_apply() {
        let cli = parse(&[
            "aegis",
            "config",
            "enforcement",
            "--vm-isolation",
            "off",
            "--host-browser",
            "on",
        ])
        .expect("parse");
        match cli.command {
            Command::Config(ConfigCommand::Enforcement(a)) => {
                assert!(!a.is_empty());
                assert_eq!(a.vm_isolation, Some(Toggle::Off));
                assert_eq!(a.host_browser, Some(Toggle::On));
                assert_eq!(a.gateway, None);
                // Applying over the secure default flips only the two set flags.
                let updated = a.apply(aegis_core::config::Enforcement::secure());
                assert!(!updated.require_vm_isolation);
                assert!(updated.allow_host_browser);
                // Gateway was not set, so it stays at the secure default (true).
                assert!(updated.require_gateway);
                assert_eq!(
                    updated.isolation_level(),
                    aegis_core::config::IsolationLevel::HostProcess
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn config_enforcement_rejects_bad_toggle() {
        assert!(parse(&["aegis", "config", "enforcement", "--vm-isolation", "maybe"]).is_err());
    }

    #[test]
    fn update_check_and_apply() {
        let check = parse(&["aegis", "update", "check"]).expect("parse");
        assert!(matches!(
            check.command,
            Command::Update(UpdateCommand::Check)
        ));
        let apply = parse(&["aegis", "update", "apply"]).expect("parse");
        assert!(matches!(
            apply.command,
            Command::Update(UpdateCommand::Apply)
        ));
    }

    #[test]
    fn global_flags_are_parsed_anywhere() {
        // --json / -v / --socket may appear after the subcommand (global = true).
        let cli = parse(&[
            "aegis",
            "profile",
            "list",
            "--json",
            "-vv",
            "--socket",
            "/tmp/aegis.sock",
        ])
        .expect("parse");
        assert!(cli.global.json);
        assert_eq!(cli.global.verbose, 2);
        assert_eq!(
            cli.global.socket.as_deref(),
            Some(std::path::Path::new("/tmp/aegis.sock"))
        );
    }

    #[test]
    fn endpoint_flag_parses() {
        let cli =
            parse(&["aegis", "--endpoint", "127.0.0.1:7777", "session", "list"]).expect("parse");
        assert_eq!(cli.global.endpoint.as_deref(), Some("127.0.0.1:7777"));
    }

    #[test]
    fn no_subcommand_is_error() {
        assert!(parse(&["aegis"]).is_err());
    }
}
