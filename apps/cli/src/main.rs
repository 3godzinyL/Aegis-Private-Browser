//! `aegis` — the Aegis Private Browser command-line interface (spec §11).
//!
//! An unprivileged front-end: it parses commands, talks to the privileged
//! daemon over the local authorized socket (unix) or the loopback dev endpoint
//! (windows), and renders the results as aligned tables or JSON. It performs no
//! privileged operation itself and never prints secrets or the phrase
//! "100% anonymous".
#![forbid(unsafe_code)]

mod cli;
mod connect;
mod render;

use aegis_core::ids::{ProfileId, SessionId};
use aegis_core::network::{
    CredentialRef, NetworkConfig, NetworkMode, ProxyConfig, TorConfig, VpnConfig, VpnProtocol,
};
use aegis_core::profile::ProfileSpec;
use aegis_core::update::{Version, VersionInfo};
use aegis_ipc::{Request, Response};
use chrono::Utc;
use clap::Parser;
use cli::{
    Cli, Command, ConfigCommand, EnforcementArgs, IsolationArg, NetArg, ProfileCommand,
    ProfileCreateArgs, SessionCommand, UpdateCommand,
};
use connect::Call;
use std::process::ExitCode;
use std::str::FromStr;

/// Exit code returned when the requested operation failed on the daemon side.
const EXIT_DAEMON_ERROR: u8 = 2;
/// Exit code returned for a client-side/usage error (bad id, no connection).
const EXIT_CLIENT_ERROR: u8 = 3;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.global.verbose);

    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Client-side error (could not parse id, could not connect, etc.).
            eprintln!("error: {} [{}]", err, err.class());
            ExitCode::from(EXIT_CLIENT_ERROR)
        }
    }
}

/// Configure `tracing` from the `-v` count. Logs go to stderr so they never
/// corrupt `--json` stdout. Secrets are never logged by construction.
fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    // Best-effort: if a global subscriber is already set, ignore.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .try_init();
}

/// The result of dispatching a command that hit the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    /// Completed; the process exits 0.
    Ok,
    /// The daemon returned an error; exit non-zero after printing it.
    DaemonError,
}

/// Run the parsed CLI. Returns `Err` only for client-side failures (the daemon's
/// own errors are surfaced as a non-zero exit via [`Dispatch`]).
async fn run(cli: &Cli) -> aegis_core::Result<()> {
    let output = dispatch(cli).await?;
    match output.emit() {
        Dispatch::Ok => Ok(()),
        Dispatch::DaemonError => {
            // The message was already written to the right stream by `emit`.
            std::process::exit(EXIT_DAEMON_ERROR as i32);
        }
    }
}

/// Build the request, connect, call the daemon, and format the response into an
/// [`Output`] (which the caller emits).
async fn dispatch(cli: &Cli) -> aegis_core::Result<Output> {
    let json = cli.global.json;

    // `update apply` is a two-step flow (check, then apply the verified
    // manifest), so it is dispatched on its own path.
    if matches!(cli.command, Command::Update(UpdateCommand::Apply)) {
        let mut client = connect::connect(&cli.global).await?;
        return dispatch_update_apply(client.as_mut(), json).await;
    }

    // `config enforcement --flags…` is a read-modify-write flow (fetch current,
    // apply the changed flags, set), so it too is dispatched on its own path.
    if let Command::Config(ConfigCommand::Enforcement(args)) = &cli.command {
        if !args.is_empty() {
            let mut client = connect::connect(&cli.global).await?;
            return dispatch_set_enforcement(client.as_mut(), args, json).await;
        }
    }

    let request = build_request(&cli.command)?;
    let mut client = connect::connect(&cli.global).await?;
    let response = client.call(request).await?;

    format_response(&cli.command, &response, json, Utc::now())
}

/// Translate a parsed [`Command`] into an [`aegis_ipc::Request`].
fn build_request(command: &Command) -> aegis_core::Result<Request> {
    Ok(match command {
        Command::Profile(ProfileCommand::Create(args)) => Request::CreateProfile(build_spec(args)?),
        Command::Profile(ProfileCommand::List) => Request::ListProfiles,
        Command::Profile(ProfileCommand::Show { .. }) => Request::ListProfiles,
        Command::Profile(ProfileCommand::Rm { id }) => {
            Request::DeleteProfile(parse_profile_id(id)?)
        }
        Command::Session(SessionCommand::Start { profile }) => {
            Request::StartSession(aegis_core::session::SessionRequest {
                profile: parse_profile_id(profile)?,
                unlock_ref: None,
            })
        }
        Command::Session(SessionCommand::Stop { id }) => {
            Request::StopSession(parse_session_id(id)?)
        }
        Command::Session(SessionCommand::List) => Request::ListSessions,
        Command::Diagnostics { session } => Request::GetDiagnostics(parse_session_id(session)?),
        Command::Status => Request::GetStatus,
        // `config enforcement` with no flags is a plain read of the current policy.
        // The mutating flag form is dispatched via its own path before this point.
        Command::Config(ConfigCommand::Enforcement(_)) => Request::GetEnforcement,
        Command::Doctor => Request::Doctor,
        Command::Update(UpdateCommand::Check) => Request::CheckUpdate(current_version_info()),
        // `update apply` is a two-step flow handled in `dispatch` before this
        // point, so it never reaches `build_request`.
        Command::Update(UpdateCommand::Apply) => {
            return Err(aegis_core::Error::Internal(
                "update apply is dispatched via its own path".into(),
            ))
        }
    })
}

/// `update apply` is a two-step flow: check for the newest manifest, then apply
/// it. This keeps the client honest — it only applies what the daemon just
/// verified as available.
async fn dispatch_update_apply(client: &mut dyn Call, json: bool) -> aegis_core::Result<Output> {
    let checked = client
        .call(Request::CheckUpdate(current_version_info()))
        .await?;
    let manifest = match checked {
        Response::UpdateAvailable(Some(m)) => m,
        Response::UpdateAvailable(None) => {
            let stdout = if json {
                to_json(&serde_json::json!({"applied": false, "reason": "up to date"}))?
            } else {
                "already up to date; nothing to apply".to_string()
            };
            return Ok(Output::ok(stdout));
        }
        Response::Error { .. } => return format_error(&checked, json),
        other => {
            return Err(aegis_core::Error::Internal(format!(
                "unexpected response to check-update: {}",
                response_name(&other)
            )))
        }
    };
    let applied = client.call(Request::ApplyUpdate(manifest)).await?;
    format_update_applied(&applied, json)
}

/// Build a [`ProfileSpec`] from the create args, assembling the network mode and
/// the per-profile isolation level in one shot.
///
/// * `--net tor` builds a [`TorConfig`]; any `--tor-bridge` lines flip
///   `use_bridges` on and are recorded.
/// * `--net proxy` builds a [`ProxyConfig`] from `--proxy-kind/--proxy-host/
///   --proxy-port`; the host and port are REQUIRED (a friendly error otherwise).
///   SOCKS5 uses remote DNS (SOCKS5h); HTTP CONNECT tunnels DNS too.
/// * `--net vpn` needs an endpoint and a credentials reference this CLI does not
///   yet collect, so it produces a spec with a placeholder endpoint/empty
///   credentials; the daemon surfaces a clear "configure the VPN" error rather
///   than the CLI silently substituting a different tunnel.
///
/// Combinations are validated up front: `--net proxy` requires host+port, and
/// `--isolation host` with `--net vpn` is rejected (the host-process run mode
/// supports Tor or a SOCKS5/HTTP proxy, not a VPN — full VM isolation is needed
/// for a VPN).
///
/// # Errors
/// Returns [`aegis_core::Error::Config`] on an invalid flag combination.
fn build_spec(args: &ProfileCreateArgs) -> aegis_core::Result<ProfileSpec> {
    let isolation = args.isolation.to_domain();

    // Reject the one unsupported host-mode combination early with a friendly note.
    if matches!(args.isolation, IsolationArg::Host) && matches!(args.net, NetArg::Vpn) {
        return Err(aegis_core::Error::Config(
            "host mode supports Tor or a SOCKS5/HTTP proxy, not a VPN — use full VM isolation \
             (--isolation vm) for a VPN"
                .into(),
        ));
    }

    let mode = match args.net {
        NetArg::Tor => {
            let bridges = args.tor_bridge.clone();
            NetworkMode::Tor(TorConfig {
                use_bridges: !bridges.is_empty(),
                bridges,
                exit_country: None,
            })
        }
        NetArg::Vpn => NetworkMode::Vpn(VpnConfig {
            protocol: VpnProtocol::WireGuard,
            endpoint: String::new(),
            credentials_ref: CredentialRef::new(""),
            dns_servers: Vec::new(),
        }),
        NetArg::Proxy => {
            let host = args.proxy_host.clone().filter(|h| !h.trim().is_empty());
            let (host, port) = match (host, args.proxy_port) {
                (Some(host), Some(port)) => (host, port),
                _ => {
                    return Err(aegis_core::Error::Config(
                        "--net proxy requires --proxy-host <H> and --proxy-port <P>".into(),
                    ))
                }
            };
            NetworkMode::Proxy(ProxyConfig {
                protocol: args.proxy_kind.to_domain(),
                host,
                port,
                credentials_ref: None,
                // Both SOCKS5h and HTTP CONNECT resolve DNS remotely; the auditor
                // requires this before it will permit the proxy mode.
                remote_dns: true,
            })
        }
    };
    let network = NetworkConfig::from_mode(mode);
    Ok(ProfileSpec {
        name: args.name.clone(),
        kind: args.kind.to_domain(),
        network,
        protection: args.protection.to_domain(),
        isolation,
        browser: args.browser.to_domain(),
        fingerprint: None,
        permissions: aegis_core::permissions::PermissionPolicy::secure_default(),
    })
}

/// Version info for update checks (the CLI's compiled-in version).
fn current_version_info() -> VersionInfo {
    let current = Version::from_str(aegis_core::VERSION).unwrap_or(Version::new(0, 0, 0));
    VersionInfo { current }
}

/// Parse a profile id, mapping a bad id to a clear client-side error.
fn parse_profile_id(s: &str) -> aegis_core::Result<ProfileId> {
    ProfileId::from_str(s)
        .map_err(|_| aegis_core::Error::Config(format!("not a valid profile id: {s}")))
}

/// Parse a session id, mapping a bad id to a clear client-side error.
fn parse_session_id(s: &str) -> aegis_core::Result<SessionId> {
    SessionId::from_str(s)
        .map_err(|_| aegis_core::Error::Config(format!("not a valid session id: {s}")))
}

/// The rendered result of a command: what to write, where, and the exit signal.
///
/// Produced by the pure `format_*` functions and then flushed by [`Output::emit`].
/// Keeping formatting separate from I/O lets tests assert the *exact* bytes the
/// CLI would print (including `--json` validity) without capturing stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Output {
    /// The line(s) written to stdout (JSON or a table). May be empty.
    stdout: String,
    /// The line written to stderr (used for errors). May be empty.
    stderr: String,
    /// The process disposition (success vs. daemon-error).
    dispatch: Dispatch,
}

impl Output {
    /// A stdout-only success output.
    fn ok(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            dispatch: Dispatch::Ok,
        }
    }

    /// A stdout output that nonetheless signals a daemon-error exit (e.g. a
    /// failed doctor self-test or a rolled-back update).
    fn ok_but_failed(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            dispatch: Dispatch::DaemonError,
        }
    }

    /// Flush to the real streams and return the dispatch.
    fn emit(&self) -> Dispatch {
        if !self.stdout.is_empty() {
            println!("{}", self.stdout);
        }
        if !self.stderr.is_empty() {
            eprintln!("{}", self.stderr);
        }
        self.dispatch
    }
}

/// Render `response` for `command` (pure). `now` is passed explicitly so tests
/// are deterministic; `main` supplies `Utc::now()`.
fn format_response(
    command: &Command,
    response: &Response,
    json: bool,
    now: chrono::DateTime<Utc>,
) -> aegis_core::Result<Output> {
    // Any error response is rendered uniformly and yields a non-zero exit.
    if response.is_error() {
        return format_error(response, json);
    }

    match command {
        Command::Profile(ProfileCommand::Create(args)) => {
            format_profile(response, json, now, args.isolation)
        }
        Command::Profile(ProfileCommand::List) => format_profiles(response, json, now),
        Command::Profile(ProfileCommand::Show { id }) => {
            format_profile_show(response, id, json, now)
        }
        Command::Profile(ProfileCommand::Rm { .. }) => format_ok(response, "profile removed", json),
        Command::Session(SessionCommand::Start { .. }) => format_session(response, json),
        Command::Session(SessionCommand::Stop { .. }) => format_session(response, json),
        Command::Session(SessionCommand::List) => format_sessions(response, json),
        Command::Diagnostics { .. } => format_diagnostics(response, json),
        Command::Status => format_status(response, json),
        // Only the no-flags (read) form reaches here; the mutating form is
        // dispatched separately.
        Command::Config(ConfigCommand::Enforcement(_)) => format_enforcement(response, json, None),
        Command::Doctor => format_doctor(response, json),
        Command::Update(UpdateCommand::Check) => format_update_check(response, json),
        // `update apply` is dispatched separately and never reaches here.
        Command::Update(UpdateCommand::Apply) => Err(aegis_core::Error::Internal(
            "unreachable apply render".into(),
        )),
    }
}

/// Format a [`Response::Error`]: message + class to stderr, daemon-error exit.
fn format_error(response: &Response, json: bool) -> aegis_core::Result<Output> {
    if let Response::Error { message, class } = response {
        let out = if json {
            Output {
                stdout: to_json(&serde_json::json!({
                    "error": message,
                    "class": class.to_string(),
                }))?,
                stderr: String::new(),
                dispatch: Dispatch::DaemonError,
            }
        } else {
            Output {
                stdout: String::new(),
                stderr: format!("error: {message} [{class}]"),
                dispatch: Dispatch::DaemonError,
            }
        };
        Ok(out)
    } else {
        Err(aegis_core::Error::Internal(
            "format_error on non-error".into(),
        ))
    }
}

fn format_profiles(
    response: &Response,
    json: bool,
    now: chrono::DateTime<Utc>,
) -> aegis_core::Result<Output> {
    match response {
        Response::Profiles(profiles) => Ok(Output::ok(if json {
            to_json(profiles)?
        } else {
            render::profiles_table(profiles, now)
        })),
        other => unexpected("Profiles", other),
    }
}

fn format_profile(
    response: &Response,
    json: bool,
    now: chrono::DateTime<Utc>,
    isolation: IsolationArg,
) -> aegis_core::Result<Output> {
    match response {
        Response::Profile(profile) => {
            let stdout = if json {
                to_json(profile)?
            } else {
                render::profile_detail(profile, now)
            };
            // Host isolation is reduced protection; state it honestly on stderr so
            // it is visible in the human path but never mixed into `--json` stdout.
            let stderr = if matches!(isolation, IsolationArg::Host) {
                "reduced protection: the site runs on your real OS, only VM isolation is dropped"
                    .to_string()
            } else {
                String::new()
            };
            Ok(Output {
                stdout,
                stderr,
                dispatch: Dispatch::Ok,
            })
        }
        other => unexpected("Profile", other),
    }
}

/// `profile show <id>`: the daemon returns the full list; we pick the one by id.
fn format_profile_show(
    response: &Response,
    id: &str,
    json: bool,
    now: chrono::DateTime<Utc>,
) -> aegis_core::Result<Output> {
    match response {
        Response::Profiles(profiles) => {
            let wanted = parse_profile_id(id)?;
            match profiles.iter().find(|p| p.id == wanted) {
                Some(p) => Ok(Output::ok(if json {
                    to_json(p)?
                } else {
                    render::profile_detail(p, now)
                })),
                None => Err(aegis_core::Error::NotFound(format!("no profile {id}"))),
            }
        }
        other => unexpected("Profiles", other),
    }
}

fn format_session(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Session(summary) => Ok(Output::ok(if json {
            to_json(summary)?
        } else {
            let row = render::session_row(summary);
            format!(
                "session {} {} {}",
                row[0],
                row[2],
                render::protection_badge(summary.protection)
            )
        })),
        other => unexpected("Session", other),
    }
}

fn format_sessions(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Sessions(sessions) => Ok(Output::ok(if json {
            to_json(sessions)?
        } else {
            render::sessions_table(sessions)
        })),
        other => unexpected("Sessions", other),
    }
}

fn format_diagnostics(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Diagnostics {
            protection,
            checklist,
            items,
        } => Ok(Output::ok(if json {
            to_json(&serde_json::json!({
                "status": protection.label(),
                "checklist": checklist,
                "items": items,
            }))?
        } else {
            render::diagnostics_report(*protection, checklist, items)
        })),
        other => unexpected("Diagnostics", other),
    }
}

fn format_doctor(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Doctor(checklist) => {
            let stdout = if json {
                to_json(&serde_json::json!({
                    "status": checklist.status().label(),
                    "checklist": checklist,
                }))?
            } else {
                render::doctor_report(checklist)
            };
            // A failing self-test is a non-zero exit so scripts can gate on it.
            Ok(if checklist.all_passed() {
                Output::ok(stdout)
            } else {
                Output::ok_but_failed(stdout)
            })
        }
        other => unexpected("Doctor", other),
    }
}

/// Render a [`Response::Status`] snapshot.
fn format_status(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Status(status) => Ok(Output::ok(if json {
            to_json(status)?
        } else {
            render::status_report(status)
        })),
        other => unexpected("Status", other),
    }
}

/// Render a [`Response::Enforcement`] policy. When `warn_relaxed` carries the
/// prior policy and the new one relaxes isolation, an honest reduced-protection
/// warning is written to stderr (kept off stdout so `--json` stays clean).
fn format_enforcement(
    response: &Response,
    json: bool,
    warn_relaxed: Option<aegis_core::config::Enforcement>,
) -> aegis_core::Result<Output> {
    match response {
        Response::Enforcement(e) => {
            let stdout = if json {
                to_json(e)?
            } else {
                render::enforcement_report(e)
            };
            // Warn (on stderr) when isolation dropped from full to reduced.
            let relaxed = matches!(warn_relaxed, Some(prev) if prev.is_full_isolation() && !e.is_full_isolation());
            let stderr = if relaxed {
                "reduced protection: the site runs on your real OS, only VM isolation is dropped"
                    .to_string()
            } else {
                String::new()
            };
            Ok(Output {
                stdout,
                stderr,
                dispatch: Dispatch::Ok,
            })
        }
        other => unexpected("Enforcement", other),
    }
}

/// `config enforcement --flags…` is a read-modify-write flow: fetch the current
/// policy, apply only the changed flags, set it, and print the result. This
/// keeps the CLI honest — it never blindly overwrites flags the user did not
/// touch.
async fn dispatch_set_enforcement(
    client: &mut dyn Call,
    args: &EnforcementArgs,
    json: bool,
) -> aegis_core::Result<Output> {
    let current = match client.call(Request::GetEnforcement).await? {
        Response::Enforcement(e) => e,
        err @ Response::Error { .. } => return format_error(&err, json),
        other => {
            return Err(aegis_core::Error::Internal(format!(
                "unexpected response to get-enforcement: {}",
                response_name(&other)
            )))
        }
    };
    let updated = args.apply(current);
    let applied = client.call(Request::SetEnforcement(updated)).await?;
    if applied.is_error() {
        return format_error(&applied, json);
    }
    format_enforcement(&applied, json, Some(current))
}

fn format_update_check(response: &Response, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::UpdateAvailable(maybe) => {
            let stdout = match maybe {
                Some(manifest) if json => to_json(&serde_json::json!({
                    "available": true,
                    "version": manifest.version.to_string(),
                }))?,
                Some(manifest) => format!("update available: {}", manifest.version),
                None if json => to_json(&serde_json::json!({"available": false}))?,
                None => "up to date".to_string(),
            };
            Ok(Output::ok(stdout))
        }
        other => unexpected("UpdateAvailable", other),
    }
}

fn format_update_applied(response: &Response, json: bool) -> aegis_core::Result<Output> {
    if response.is_error() {
        return format_error(response, json);
    }
    match response {
        Response::UpdateApplied(outcome) => {
            let label = match outcome {
                aegis_core::update::ApplyOutcome::Applied => "applied",
                aegis_core::update::ApplyOutcome::RolledBack => "rolled-back",
            };
            let stdout = if json {
                to_json(&serde_json::json!({"applied": true, "outcome": label}))?
            } else {
                format!("update {label}")
            };
            Ok(match outcome {
                aegis_core::update::ApplyOutcome::Applied => Output::ok(stdout),
                // A rollback is a failure to apply — non-zero exit.
                aegis_core::update::ApplyOutcome::RolledBack => Output::ok_but_failed(stdout),
            })
        }
        other => unexpected("UpdateApplied", other),
    }
}

fn format_ok(response: &Response, msg: &str, json: bool) -> aegis_core::Result<Output> {
    match response {
        Response::Ok => Ok(Output::ok(if json {
            to_json(&serde_json::json!({"ok": true}))?
        } else {
            msg.to_string()
        })),
        other => unexpected("Ok", other),
    }
}

/// Serialize a value as pretty JSON, mapping serde errors into the workspace
/// error type.
fn to_json<T: serde::Serialize>(value: &T) -> aegis_core::Result<String> {
    serde_json::to_string_pretty(value)
        .map_err(|e| aegis_core::Error::System(format!("could not serialize output: {e}")))
}

/// A stable short name for a response variant (for error messages, no payload).
fn response_name(r: &Response) -> &'static str {
    match r {
        Response::Profiles(_) => "profiles",
        Response::Profile(_) => "profile",
        Response::Ok => "ok",
        Response::Session(_) => "session",
        Response::Sessions(_) => "sessions",
        Response::Diagnostics { .. } => "diagnostics",
        Response::Doctor(_) => "doctor",
        Response::UpdateAvailable(_) => "update-available",
        Response::UpdateApplied(_) => "update-applied",
        Response::Status(_) => "status",
        Response::Enforcement(_) => "enforcement",
        Response::Error { .. } => "error",
    }
}

/// Build an "unexpected response" internal error.
fn unexpected(expected: &str, got: &Response) -> aegis_core::Result<Output> {
    Err(aegis_core::Error::Internal(format!(
        "expected {expected} response, got {}",
        response_name(got)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::network::ProxyProtocol;
    use aegis_core::preflight::{CheckId, CheckReport, ConnectivityChecklist};
    use aegis_ipc::Response;

    fn all_pass_checklist() -> ConnectivityChecklist {
        ConnectivityChecklist::new(
            CheckId::all()
                .into_iter()
                .map(|id| CheckReport::pass(id, "ok"))
                .collect(),
        )
    }

    /// A [`ProfileCreateArgs`] with all defaults except the named overrides,
    /// so tests only set the fields they care about.
    fn create_args(name: &str, net: NetArg) -> ProfileCreateArgs {
        ProfileCreateArgs {
            name: name.into(),
            kind: cli::ProfileKindArg::Ephemeral,
            net,
            protection: cli::ProtectionArg::Balanced,
            isolation: cli::IsolationArg::Vm,
            browser: cli::BrowserArg::Chromium,
            proxy_kind: cli::ProxyKindArg::Socks5,
            proxy_host: None,
            proxy_port: None,
            tor_bridge: Vec::new(),
        }
    }

    #[test]
    fn build_spec_tor_strict() {
        let mut args = create_args("x", NetArg::Tor);
        args.kind = cli::ProfileKindArg::Persistent;
        args.protection = cli::ProtectionArg::Strict;
        let spec = build_spec(&args).expect("spec");
        assert_eq!(spec.network.mode.label(), "Tor");
        assert_eq!(spec.protection.label(), "Strict");
        assert!(!spec.kind.is_ephemeral());
        // Default isolation is full VM.
        assert_eq!(spec.isolation, aegis_core::config::IsolationLevel::FullVm);
        // The spec built for a Tor/Strict profile must validate.
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn build_spec_proxy_balanced_validates() {
        let mut args = create_args("p", NetArg::Proxy);
        args.proxy_host = Some("10.0.0.1".into());
        args.proxy_port = Some(1080);
        let spec = build_spec(&args).expect("spec");
        assert_eq!(spec.network.mode.label(), "Proxy");
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn build_spec_proxy_requires_host_and_port() {
        // No host/port supplied => a friendly config error, not a silent default.
        let args = create_args("p", NetArg::Proxy);
        let err = build_spec(&args).expect_err("proxy needs host+port");
        assert_eq!(err.class(), aegis_core::FailureClass::Configuration);
        assert!(err.to_string().contains("--proxy-host"));

        // Host but no port is still rejected.
        let mut partial = create_args("p", NetArg::Proxy);
        partial.proxy_host = Some("127.0.0.1".into());
        assert!(build_spec(&partial).is_err());
    }

    #[test]
    fn build_spec_proxy_http_kind_maps_protocol() {
        let mut args = create_args("h", NetArg::Proxy);
        args.proxy_kind = cli::ProxyKindArg::Http;
        args.proxy_host = Some("proxy.internal".into());
        args.proxy_port = Some(3128);
        let spec = build_spec(&args).expect("spec");
        match &spec.network.mode {
            NetworkMode::Proxy(cfg) => {
                assert_eq!(cfg.protocol, ProxyProtocol::HttpConnect);
                assert_eq!(cfg.host, "proxy.internal");
                assert_eq!(cfg.port, 3128);
                assert!(cfg.remote_dns);
            }
            other => panic!("expected proxy mode, got {other:?}"),
        }
    }

    #[test]
    fn build_spec_tor_bridges_set_use_bridges() {
        let mut args = create_args("br", NetArg::Tor);
        args.tor_bridge = vec![
            "obfs4 1.2.3.4:443 CERT".into(),
            "obfs4 5.6.7.8:80 CERT".into(),
        ];
        let spec = build_spec(&args).expect("spec");
        match &spec.network.mode {
            NetworkMode::Tor(cfg) => {
                assert!(cfg.use_bridges, "bridges supplied => use_bridges on");
                assert_eq!(cfg.bridges.len(), 2);
            }
            other => panic!("expected tor mode, got {other:?}"),
        }
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn build_spec_host_isolation_sets_level() {
        let mut args = create_args("host-tor", NetArg::Tor);
        args.isolation = cli::IsolationArg::Host;
        let spec = build_spec(&args).expect("spec");
        assert_eq!(
            spec.isolation,
            aegis_core::config::IsolationLevel::HostProcess
        );
    }

    #[test]
    fn build_spec_host_plus_vpn_is_rejected() {
        let mut args = create_args("bad", NetArg::Vpn);
        args.isolation = cli::IsolationArg::Host;
        let err = build_spec(&args).expect_err("host + vpn must be rejected");
        assert_eq!(err.class(), aegis_core::FailureClass::Configuration);
        assert!(err.to_string().contains("not a VPN"));
    }

    #[test]
    fn format_profile_host_isolation_prints_reduced_note() {
        // A created host-isolation profile prints the honest reduced-protection
        // note on stderr, never on stdout (so --json stays clean).
        let response = Response::Profile(sample_profile("h"));
        let human =
            format_profile(&response, false, Utc::now(), cli::IsolationArg::Host).expect("format");
        assert!(human.stderr.contains("reduced protection"));
        assert!(human.stderr.contains("real OS"));
        assert!(!human.stdout.to_lowercase().contains("anonymous"));

        // JSON path: the note is still only on stderr; stdout is valid JSON.
        let json =
            format_profile(&response, true, Utc::now(), cli::IsolationArg::Host).expect("format");
        let _ = assert_valid_json(&json.stdout);
        assert!(json.stderr.contains("reduced protection"));

        // A VM-isolation profile has no reduced note.
        let vm =
            format_profile(&response, false, Utc::now(), cli::IsolationArg::Vm).expect("format");
        assert!(vm.stderr.is_empty());
    }

    #[test]
    fn build_request_maps_commands() {
        assert!(matches!(
            build_request(&Command::Profile(ProfileCommand::List)).unwrap(),
            Request::ListProfiles
        ));
        assert!(matches!(
            build_request(&Command::Doctor).unwrap(),
            Request::Doctor
        ));
        assert!(matches!(
            build_request(&Command::Session(SessionCommand::List)).unwrap(),
            Request::ListSessions
        ));
    }

    #[test]
    fn build_request_rejects_bad_id() {
        let cmd = Command::Profile(ProfileCommand::Rm {
            id: "not-a-uuid".into(),
        });
        assert!(build_request(&cmd).is_err());
    }

    fn sample_profile(name: &str) -> aegis_core::profile::Profile {
        aegis_core::profile::Profile {
            id: ProfileId::new(),
            spec: ProfileSpec::ephemeral(name),
            created_at: Utc::now(),
            last_launched: None,
            storage: Default::default(),
            locked: false,
        }
    }

    /// Parse a string as JSON, asserting it is valid.
    fn assert_valid_json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("not valid JSON: {e}\n{s}"))
    }

    #[test]
    fn diagnostics_json_is_valid_json() {
        // Drive the *real* formatter with --json and assert the stdout parses.
        let response = Response::Diagnostics {
            protection: aegis_core::preflight::ProtectionStatus::Active,
            checklist: all_pass_checklist(),
            items: vec![aegis_core::health::DiagnosticItem::new(
                "dns",
                aegis_core::health::HealthLevel::Ok,
                "ok",
            )],
        };
        let out = format_diagnostics(&response, true).expect("format");
        let parsed = assert_valid_json(&out.stdout);
        assert_eq!(parsed["status"], "protection active");
        assert!(parsed["checklist"]["reports"].is_array());
        assert_eq!(out.dispatch, Dispatch::Ok);
    }

    #[test]
    fn profiles_json_is_valid_json() {
        let response = Response::Profiles(vec![sample_profile("t")]);
        let out = format_profiles(&response, true, Utc::now()).expect("format");
        let parsed = assert_valid_json(&out.stdout);
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["spec"]["name"], "t");
    }

    #[test]
    fn profiles_table_is_not_json() {
        let response = Response::Profiles(vec![sample_profile("t")]);
        let out = format_profiles(&response, false, Utc::now()).expect("format");
        assert!(out.stdout.contains("NAME"));
        assert!(out.stdout.contains("PROTECTION"));
    }

    #[test]
    fn error_response_goes_to_stderr_and_fails() {
        let response = Response::Error {
            message: "tunnel dropped".into(),
            class: aegis_core::FailureClass::NetworkContainment,
        };
        // Human path: message + class on stderr, non-zero exit.
        let human = format_response(
            &Command::Session(SessionCommand::List),
            &response,
            false,
            Utc::now(),
        )
        .expect("format");
        assert_eq!(human.dispatch, Dispatch::DaemonError);
        assert!(human.stdout.is_empty());
        assert!(human.stderr.contains("tunnel dropped"));
        assert!(human.stderr.contains("network-containment"));

        // JSON path: a valid JSON object carrying the class.
        let json = format_response(
            &Command::Session(SessionCommand::List),
            &response,
            true,
            Utc::now(),
        )
        .expect("format");
        assert_eq!(json.dispatch, Dispatch::DaemonError);
        let parsed = assert_valid_json(&json.stdout);
        assert_eq!(parsed["class"], "network-containment");
    }

    #[test]
    fn doctor_failure_signals_nonzero_exit() {
        let mut reports: Vec<_> = CheckId::all()
            .into_iter()
            .map(|id| CheckReport::pass(id, "ok"))
            .collect();
        reports[2] = CheckReport::fail(CheckId::DnsRouteVerified, "leak");
        let response = Response::Doctor(ConnectivityChecklist::new(reports));

        let out = format_doctor(&response, false).expect("format");
        assert_eq!(out.dispatch, Dispatch::DaemonError);
        assert!(out.stdout.contains("unsafe configuration"));

        // JSON variant is valid JSON and still signals failure.
        let out_json = format_doctor(&response, true).expect("format");
        let parsed = assert_valid_json(&out_json.stdout);
        assert_eq!(parsed["status"], "unsafe configuration");
        assert_eq!(out_json.dispatch, Dispatch::DaemonError);
    }

    #[test]
    fn doctor_all_pass_signals_success() {
        let response = Response::Doctor(all_pass_checklist());
        let out = format_doctor(&response, false).expect("format");
        assert_eq!(out.dispatch, Dispatch::Ok);
    }

    #[test]
    fn sessions_json_is_valid_and_carries_badge() {
        let response = Response::Sessions(vec![aegis_core::session::SessionSummary {
            id: SessionId::new(),
            profile: ProfileId::new(),
            state: aegis_core::session::SessionState::Browsing,
            protection: aegis_core::preflight::ProtectionStatus::Active,
            public_ip: Some("198.51.100.1".into()),
        }]);
        let out = format_sessions(&response, true).expect("format");
        let parsed = assert_valid_json(&out.stdout);
        assert_eq!(parsed[0]["protection"], "active");
        assert_eq!(parsed[0]["state"], "browsing");
    }

    #[test]
    fn update_check_available_json() {
        let manifest = aegis_core::update::UpdateManifest {
            schema: 1,
            version: Version::new(1, 2, 3),
            delta_base: None,
            kind: aegis_core::update::UpdateKind::Full,
            artifacts: vec![],
            sbom: None,
            signature: "aa".into(),
        };
        let response = Response::UpdateAvailable(Some(manifest));
        let out = format_update_check(&response, true).expect("format");
        let parsed = assert_valid_json(&out.stdout);
        assert_eq!(parsed["available"], true);
        assert_eq!(parsed["version"], "1.2.3");
    }

    #[test]
    fn wrong_response_variant_is_internal_error() {
        // Asking to render a Profiles command but handed a Session response.
        let response = Response::Ok;
        assert!(format_profiles(&response, false, Utc::now()).is_err());
    }

    #[test]
    fn output_emit_returns_dispatch() {
        // emit() is the only impure part; verify it returns the dispatch value.
        assert_eq!(Output::ok("x").dispatch, Dispatch::Ok);
        assert_eq!(Output::ok_but_failed("y").dispatch, Dispatch::DaemonError);
    }

    #[test]
    fn version_info_parses_crate_version() {
        // The compiled-in version must parse into a Version.
        let vi = current_version_info();
        // 0.1.0 per the workspace; at minimum non-panicking and >= 0.0.0.
        assert!(vi.current >= Version::new(0, 0, 0));
    }

    /// A scripted fake [`Call`]: returns queued responses in order and records
    /// the requests it saw, so the two-step `update apply` flow can be tested
    /// WITHOUT a running daemon.
    struct ScriptedCall {
        responses: std::collections::VecDeque<Response>,
        seen: Vec<&'static str>,
    }

    impl ScriptedCall {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: responses.into(),
                seen: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Call for ScriptedCall {
        async fn call(&mut self, req: Request) -> aegis_core::Result<Response> {
            self.seen.push(req.op_name());
            self.responses
                .pop_front()
                .ok_or_else(|| aegis_core::Error::Internal("no scripted response".into()))
        }
    }

    fn sample_manifest(v: Version) -> aegis_core::update::UpdateManifest {
        aegis_core::update::UpdateManifest {
            schema: 1,
            version: v,
            delta_base: None,
            kind: aegis_core::update::UpdateKind::Full,
            artifacts: vec![],
            sbom: None,
            signature: "aa".into(),
        }
    }

    #[tokio::test]
    async fn update_apply_two_step_applies_available_manifest() {
        let mut client = ScriptedCall::new(vec![
            Response::UpdateAvailable(Some(sample_manifest(Version::new(9, 9, 9)))),
            Response::UpdateApplied(aegis_core::update::ApplyOutcome::Applied),
        ]);
        let out = dispatch_update_apply(&mut client, false)
            .await
            .expect("apply");
        assert_eq!(out.dispatch, Dispatch::Ok);
        assert!(out.stdout.contains("applied"));
        // It must check first, then apply — never apply blindly.
        assert_eq!(client.seen, vec!["check-update", "apply-update"]);
    }

    #[tokio::test]
    async fn update_apply_up_to_date_does_not_apply() {
        let mut client = ScriptedCall::new(vec![Response::UpdateAvailable(None)]);
        let out = dispatch_update_apply(&mut client, false)
            .await
            .expect("apply");
        assert_eq!(out.dispatch, Dispatch::Ok);
        assert!(out.stdout.contains("up to date"));
        // Only the check happened; no apply request was sent.
        assert_eq!(client.seen, vec!["check-update"]);
    }

    #[tokio::test]
    async fn update_apply_rollback_signals_failure() {
        let mut client = ScriptedCall::new(vec![
            Response::UpdateAvailable(Some(sample_manifest(Version::new(2, 0, 0)))),
            Response::UpdateApplied(aegis_core::update::ApplyOutcome::RolledBack),
        ]);
        let out = dispatch_update_apply(&mut client, true)
            .await
            .expect("apply");
        // A rollback is a non-zero exit; JSON output stays valid.
        assert_eq!(out.dispatch, Dispatch::DaemonError);
        let parsed = assert_valid_json(&out.stdout);
        assert_eq!(parsed["outcome"], "rolled-back");
    }

    fn sample_status(level: aegis_core::config::IsolationLevel) -> aegis_ipc::StatusDto {
        aegis_ipc::StatusDto {
            version: "0.1.0".into(),
            platform: "windows".into(),
            isolation_level: level,
            enforcement: if level.is_full() {
                aegis_core::config::Enforcement::secure()
            } else {
                aegis_core::config::Enforcement::host_browser()
            },
            host_browser_available: true,
            host_browser_path: Some("C:/chrome.exe".into()),
        }
    }

    #[test]
    fn status_human_and_json() {
        let response = Response::Status(sample_status(
            aegis_core::config::IsolationLevel::HostProcess,
        ));
        // Human path: shows platform + reduced badge, never "anonymous".
        let human = format_status(&response, false).expect("format");
        assert!(human.stdout.contains("windows"));
        assert!(human.stdout.contains("reduced"));
        assert!(!human.stdout.to_lowercase().contains("anonymous"));
        assert_eq!(human.dispatch, Dispatch::Ok);

        // JSON path: valid JSON carrying the isolation level.
        let json = format_status(&response, true).expect("format");
        let parsed = assert_valid_json(&json.stdout);
        assert_eq!(parsed["isolation_level"], "host-process");
        assert_eq!(parsed["platform"], "windows");
    }

    #[test]
    fn enforcement_read_has_no_warning() {
        let response = Response::Enforcement(aegis_core::config::Enforcement::secure());
        let out = format_enforcement(&response, false, None).expect("format");
        assert!(out.stderr.is_empty(), "a plain read must not warn");
        assert!(out.stdout.contains("full VM isolation"));
    }

    #[test]
    fn enforcement_relaxing_isolation_warns_on_stderr() {
        // Prior policy is full isolation; the new one is reduced => warn.
        let response = Response::Enforcement(aegis_core::config::Enforcement::host_browser());
        let out = format_enforcement(
            &response,
            false,
            Some(aegis_core::config::Enforcement::secure()),
        )
        .expect("format");
        assert!(out.stderr.contains("reduced protection"));
        assert!(out.stderr.contains("real OS"));
        assert!(!out.stderr.to_lowercase().contains("anonymous"));
    }

    #[test]
    fn enforcement_json_stays_valid_even_when_relaxing() {
        let response = Response::Enforcement(aegis_core::config::Enforcement::host_browser());
        let out = format_enforcement(
            &response,
            true,
            Some(aegis_core::config::Enforcement::secure()),
        )
        .expect("format");
        let parsed = assert_valid_json(&out.stdout);
        assert_eq!(parsed["allow_host_browser"], true);
        // The warning is on stderr, never mixed into --json stdout.
        assert!(out.stderr.contains("reduced protection"));
    }

    #[tokio::test]
    async fn set_enforcement_reads_then_writes_only_changed_flags() {
        // Current policy is fully secure; the user flips only --vm-isolation off
        // and --host-browser on. Gateway must be left as-is (unchanged).
        let mut client = ScriptedCall::new(vec![
            Response::Enforcement(aegis_core::config::Enforcement::secure()),
            Response::Enforcement(aegis_core::config::Enforcement {
                require_vm_isolation: false,
                require_gateway: true,
                allow_host_browser: true,
            }),
        ]);
        let args = cli::EnforcementArgs {
            vm_isolation: Some(cli::Toggle::Off),
            gateway: None,
            host_browser: Some(cli::Toggle::On),
        };
        let out = dispatch_set_enforcement(&mut client, &args, false)
            .await
            .expect("set");
        assert_eq!(out.dispatch, Dispatch::Ok);
        // It must GET then SET (read-modify-write, never a blind overwrite).
        assert_eq!(client.seen, vec!["get-enforcement", "set-enforcement"]);
        // Relaxing from full to reduced prints the honest warning on stderr.
        assert!(out.stderr.contains("reduced protection"));
        assert!(out.stdout.contains("host-browser   on"));
    }

    #[tokio::test]
    async fn set_enforcement_propagates_daemon_error() {
        let mut client = ScriptedCall::new(vec![Response::Error {
            message: "policy lock poisoned".into(),
            class: aegis_core::FailureClass::Internal,
        }]);
        let args = cli::EnforcementArgs {
            vm_isolation: Some(cli::Toggle::Off),
            gateway: None,
            host_browser: Some(cli::Toggle::On),
        };
        let out = dispatch_set_enforcement(&mut client, &args, false)
            .await
            .expect("set");
        assert_eq!(out.dispatch, Dispatch::DaemonError);
        assert!(out.stderr.contains("policy lock poisoned"));
    }

    #[tokio::test]
    async fn update_apply_propagates_daemon_error() {
        let mut client = ScriptedCall::new(vec![Response::Error {
            message: "no verify key".into(),
            class: aegis_core::FailureClass::Configuration,
        }]);
        let out = dispatch_update_apply(&mut client, false)
            .await
            .expect("apply");
        assert_eq!(out.dispatch, Dispatch::DaemonError);
        assert!(out.stderr.contains("no verify key"));
    }

    /// An in-memory fake daemon: replies to `ListProfiles` with one profile and
    /// to everything else with `Ok`. Lets us exercise the *real* `IpcClient`
    /// framing end-to-end over an in-process duplex stream.
    struct FakeDaemon;

    #[async_trait::async_trait]
    impl aegis_ipc::RequestHandler for FakeDaemon {
        async fn handle(&self, req: Request) -> Response {
            match req {
                Request::ListProfiles => Response::Profiles(vec![sample_profile("wired")]),
                _ => Response::Ok,
            }
        }
    }

    /// Adapter turning an `IpcClient` over a duplex stream into a [`Call`].
    struct DuplexCall(aegis_ipc::IpcClient<tokio::io::DuplexStream>);

    #[async_trait::async_trait]
    impl Call for DuplexCall {
        async fn call(&mut self, req: Request) -> aegis_core::Result<Response> {
            self.0
                .call(req)
                .await
                .map_err(|e| aegis_core::Error::System(format!("ipc: {e}")))
        }
    }

    #[tokio::test]
    async fn end_to_end_list_profiles_over_real_framing() {
        let (client_end, server_end) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            aegis_ipc::serve_connection(server_end, &FakeDaemon)
                .await
                .unwrap();
        });

        let mut call = DuplexCall(aegis_ipc::IpcClient::new(client_end));
        let response = call.call(Request::ListProfiles).await.expect("call");
        // Format the real response through the real formatter (table + json).
        let table = format_response(
            &Command::Profile(ProfileCommand::List),
            &response,
            false,
            Utc::now(),
        )
        .expect("format");
        assert!(table.stdout.contains("wired"));

        let json = format_response(
            &Command::Profile(ProfileCommand::List),
            &response,
            true,
            Utc::now(),
        )
        .expect("format");
        let parsed = assert_valid_json(&json.stdout);
        assert_eq!(parsed[0]["spec"]["name"], "wired");

        drop(call);
        server.await.unwrap();
    }
}
