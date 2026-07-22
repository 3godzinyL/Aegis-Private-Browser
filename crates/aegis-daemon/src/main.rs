//! aegis-daemon — the privileged orchestration daemon (binary entry point).
//!
//! Parses `--config`, loads the [`AppConfig`](aegis_core::config::AppConfig) from
//! TOML (falling back to the built-in default), wires the **production**
//! capability implementations into an [`Orchestrator`], and runs the `aegis-ipc`
//! serve loop on the platform listener:
//!
//! * **unix**: a `UnixListener` with `SO_PEERCRED` peer authorization.
//! * **non-unix (Windows dev)**: a loopback-TCP listener guarded by a shared
//!   token — development only.
//!
//! Graceful shutdown is driven by SIGINT/SIGTERM (via [`tokio::signal`]).
//!
//! On non-Linux hosts the daemon still starts and serves; the privileged
//! operations return [`aegis_core::Error::Unsupported`] at runtime (documented
//! development behaviour).

#![forbid(unsafe_code)]

use aegis_core::traits::{BrowserBackend, UpdateClient, VmController};
use aegis_daemon::{Capabilities, DaemonHandler, FileAuditSink, Orchestrator, TcpHostProbe};
use aegis_ipc::serve;
use anyhow::Context as _;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

/// Command-line options for the daemon.
#[derive(Debug, Parser)]
#[command(
    name = "aegis-daemon",
    version,
    about = "Aegis privileged orchestration daemon"
)]
struct Cli {
    /// Path to the TOML configuration file. If absent, built-in defaults are used.
    #[arg(long, value_name = "FILE", env = "AEGIS_CONFIG")]
    config: Option<PathBuf>,

    /// Loopback TCP port for the development transport (non-unix only). 0 =
    /// ephemeral. Ignored on unix, which always uses the configured socket path.
    #[arg(long, default_value_t = 0, env = "AEGIS_DEV_PORT")]
    dev_port: u16,

    /// Path to the shared-token file for the development TCP transport (non-unix).
    #[arg(long, value_name = "FILE", env = "AEGIS_DEV_TOKEN")]
    dev_token: Option<PathBuf>,
}

/// An update client used when no verifying key is configured: it refuses every
/// operation (fail-closed) rather than pretending updates can be trusted.
#[derive(Debug)]
struct DisabledUpdateClient;

#[async_trait::async_trait]
impl UpdateClient for DisabledUpdateClient {
    async fn check_for_update(
        &self,
        _info: &aegis_core::update::VersionInfo,
    ) -> aegis_core::Result<Option<aegis_core::update::UpdateManifest>> {
        Err(aegis_core::Error::Config(
            "update checking is disabled: no update_verify_key configured".into(),
        ))
    }

    async fn verify(
        &self,
        _manifest: &aegis_core::update::UpdateManifest,
        _info: &aegis_core::update::VersionInfo,
    ) -> aegis_core::Result<aegis_core::update::VerifiedArtifact> {
        Err(aegis_core::Error::Config(
            "update verification is disabled: no update_verify_key configured".into(),
        ))
    }

    async fn apply(
        &self,
        _verified: &aegis_core::update::VerifiedArtifact,
    ) -> aegis_core::Result<aegis_core::update::ApplyOutcome> {
        Err(aegis_core::Error::Config(
            "update application is disabled: no update_verify_key configured".into(),
        ))
    }
}

/// Initialize tracing (fmt to stderr). Never logs secrets: only structured,
/// secret-free fields reach the subscriber. The default level is `info`; override
/// with `RUST_LOG`.
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Write to stderr so stdout stays clean for any structured output.
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Build the production capability set from the loaded config.
fn build_capabilities(config: &aegis_core::config::AppConfig) -> Capabilities {
    // VM controller: real virsh/qemu-img runner (Unsupported off-Linux).
    let vm_runner: Arc<dyn vm_controller::CommandRunner> =
        Arc::new(vm_controller::SystemRunner::new());
    let vm: Arc<dyn VmController> =
        Arc::new(vm_controller::LibvirtController::with_runner(vm_runner));

    // Gateway controller: nftables via the real system runner.
    let gateway: Arc<dyn aegis_core::traits::GatewayController> = Arc::new(
        gateway_controller::NftGatewayController::new(gateway_controller::SystemRunner::new()),
    );

    // Network auditor: system probe (measures inside the Linux VMs).
    let auditor: Arc<dyn aegis_core::traits::NetworkAuditor> =
        Arc::new(network_audit::Auditor::new(network_audit::SystemProbe));

    // Browser backend: hardened Chromium via the guest-channel runner (full VM).
    let browser: Arc<dyn aegis_core::traits::BrowserBackend> =
        Arc::new(browser_launcher::ChromiumBackend::new(
            browser_launcher::GuestChannelRunner::default(),
            "chromium",
            "vm-browser",
        ));

    // Host-browser backend (reduced HostProcess mode): hardened Chromium launched
    // directly on the host via HostBrowserRunner. Resolved once at wiring time;
    // when no Chromium-family browser is found the host mode stays disabled.
    let (host_browser, host_browser_path): (Option<Arc<dyn BrowserBackend>>, Option<String>) =
        match browser_launcher::resolve_browser_binary(None, &browser_launcher::SystemEnv) {
            Ok(path) => {
                let path_str = path.to_string_lossy().into_owned();
                let runner = browser_launcher::HostBrowserRunner::with_binary(path.clone());
                let backend: Arc<dyn BrowserBackend> = Arc::new(
                    browser_launcher::ChromiumBackend::new(runner, "chromium", "host"),
                );
                (Some(backend), Some(path_str))
            }
            Err(e) => {
                tracing::info!(error = %e, "no host browser found; host-process mode unavailable");
                (None, None)
            }
        };

    // Reduced, fail-closed proxy reachability probe for the host mode.
    let host_probe: Arc<dyn aegis_daemon::HostNetworkProbe> = Arc::new(TcpHostProbe::default());

    // Profile store: file-backed under the configured profiles dir.
    let profiles: Arc<dyn aegis_core::traits::ProfileRepository> = Arc::new(
        profile_store::FileProfileStore::new(config.paths.profiles_dir.clone()),
    );

    // Secure storage: OS CSPRNG.
    let secure: Arc<dyn aegis_core::traits::SecureStore> =
        Arc::new(secure_storage::SecureStorage::new());

    // Update client: only usable when a verifying key is configured.
    let updates: Arc<dyn UpdateClient> = match &config.update_verify_key {
        Some(key_hex) => {
            let transport: Arc<dyn update_client::Transport> = Arc::new(
                update_client::FileTransport::new(config.paths.images_dir.clone()),
            );
            match update_client::SignedUpdateClient::new("manifest.json", key_hex, transport) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::warn!(error = %e, "invalid update_verify_key; update client disabled");
                    Arc::new(DisabledUpdateClient)
                }
            }
        }
        None => Arc::new(DisabledUpdateClient),
    };

    // Audit sink: append-only JSON lines at the configured path.
    let audit: Arc<dyn aegis_core::traits::AuditSink> =
        Arc::new(FileAuditSink::new(config.paths.audit_log.clone()));

    Capabilities {
        vm,
        gateway,
        auditor,
        browser,
        host_browser,
        host_browser_path,
        host_probe,
        profiles,
        secure,
        updates,
        audit,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    // Load config (fallback to default if the path is absent/unset).
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/aegis/config.toml"));
    let config = aegis_daemon::load_config(&config_path).context("loading configuration")?;

    tracing::info!(
        version = aegis_core::VERSION,
        socket = %config.paths.daemon_socket.display(),
        "aegis-daemon starting"
    );

    if !cfg!(target_os = "linux") {
        tracing::warn!(
            "running on a non-Linux host: privileged operations (libvirt, nftables, \
             guest channel) will return Unsupported at runtime (development mode)"
        );
    }

    let orchestrator = Arc::new(Orchestrator::new(
        build_capabilities(&config),
        config.clone(),
    ));
    let handler = Arc::new(DaemonHandler::new(Arc::clone(&orchestrator)));

    run_server(&config, handler).await
}

/// Run the IPC serve loop on the platform listener until a shutdown signal.
#[cfg(unix)]
async fn run_server(
    config: &aegis_core::config::AppConfig,
    handler: Arc<DaemonHandler>,
) -> anyhow::Result<()> {
    use aegis_ipc::transport::unix::UnixSocketListener;
    use aegis_ipc::transport::AuthPolicy;

    // Authorize only the daemon's own uid by default (peer-cred check on unix).
    let self_uid = current_uid();
    let policy = AuthPolicy::same_uid(self_uid);
    let listener = UnixSocketListener::bind(&config.paths.daemon_socket, policy)
        .context("binding daemon unix socket")?;
    tracing::info!(socket = %config.paths.daemon_socket.display(), "listening on unix socket");

    let serve_fut = serve(listener, handler);
    tokio::select! {
        res = serve_fut => {
            res.context("ipc serve loop failed")?;
        }
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping");
        }
    }
    Ok(())
}

/// The current process uid, for the peer-credential authorization policy.
#[cfg(unix)]
fn current_uid() -> u32 {
    // `std::os::unix` exposes the uid without any `unsafe`.
    // `getuid` is not in std; read it via the `id -u`-equivalent env is unreliable,
    // so use the libc-free `std::os::unix::fs::MetadataExt` on `/proc/self` when
    // available. As a portable fallback (and to keep #![forbid(unsafe_code)]), we
    // read the effective uid from the `USER`-independent `/proc/self/status`.
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(tok) = rest.split_whitespace().next() {
                        if let Ok(uid) = tok.parse::<u32>() {
                            return uid;
                        }
                    }
                }
            }
        }
    }
    // Fallback: assume a dedicated service account is not in use and only the
    // same-uid peer is allowed; 0 (root) is the common daemon uid. This is only a
    // belt-and-braces default beneath the kernel peer-cred check.
    0
}

/// Run the IPC serve loop on the loopback-TCP development transport (non-unix).
#[cfg(not(unix))]
async fn run_server(
    config: &aegis_core::config::AppConfig,
    handler: Arc<DaemonHandler>,
) -> anyhow::Result<()> {
    use aegis_ipc::transport::tcp::{read_token, TcpDevListener};

    let _ = config; // the dev transport binds loopback, not the unix socket path

    // Read (or refuse to run without) the shared token. The token file must be
    // provided via --dev-token; the daemon never invents a token.
    let cli = Cli::parse();
    let token_path = cli.dev_token.ok_or_else(|| {
        anyhow::anyhow!(
            "the development TCP transport requires --dev-token <FILE> (a shared secret token)"
        )
    })?;
    let token = read_token(&token_path).context("reading dev token")?;

    let listener = TcpDevListener::bind(cli.dev_port, token)
        .await
        .context("binding loopback dev listener")?;
    let addr = listener.local_addr().context("reading dev listener addr")?;
    tracing::warn!(%addr, "listening on loopback TCP (development transport only)");

    let serve_fut = serve(listener, handler);
    tokio::select! {
        res = serve_fut => {
            res.context("ipc serve loop failed")?;
        }
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping");
        }
    }
    Ok(())
}

/// Resolve when the process receives SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return futures_ctrl_c().await,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return futures_ctrl_c().await,
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        futures_ctrl_c().await;
    }
}

/// Fallback: wait for Ctrl-C via the portable tokio helper.
async fn futures_ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
}
