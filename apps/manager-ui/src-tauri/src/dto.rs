//! Serde-friendly data-transfer objects returned to the webview.
//!
//! The daemon speaks in [`aegis_core`] domain types; the frontend wants flat,
//! display-ready records. This module owns that translation so the JS side never
//! has to understand the domain enums' internal tagging. Every string here is
//! secret-free (the domain types are secret-free by construction).
//!
//! The protection badge deliberately carries BOTH a machine token
//! (`protection_status`, one of `active|partial|unsafe|none`) and the exact
//! human label from [`aegis_core::preflight::ProtectionStatus::label`] so the UI
//! can color-code without ever inventing its own wording (spec §11, §16).

use aegis_core::browser::BrowserBackendId;
use aegis_core::config::{Enforcement, IsolationLevel};
use aegis_core::fingerprint::{
    CanvasMode, FingerprintPolicy, LetterboxMode, ProtectionLevel, WebGlMode,
};
use aegis_core::health::DiagnosticItem;
use aegis_core::network::{
    CredentialRef, NetworkConfig, NetworkMode, ProxyConfig, ProxyProtocol, TorConfig,
};
use aegis_core::permissions::PermissionPolicy;
use aegis_core::preflight::{CheckId, ConnectivityChecklist, ProtectionStatus};
use aegis_core::preview::ProfilePreview;
use aegis_core::profile::{Profile, ProfileSpec, ProfileType};
use aegis_core::session::{SessionState, SessionSummary};
use aegis_ipc::StatusDto;
use serde::{Deserialize, Serialize};

/// A profile row for the profiles table (spec §11 profiles view).
#[derive(Debug, Clone, Serialize)]
pub struct ProfileView {
    /// Stable profile id (uuid string).
    pub id: String,
    /// Human-facing name.
    pub name: String,
    /// `ephemeral` or `persistent`.
    pub kind: String,
    /// Network mode label: `Tor` / `VPN` / `Proxy`.
    pub network_mode: String,
    /// Protection level label: `Balanced` / `Strict`.
    pub protection_level: String,
    /// Whether a session currently holds the single-writer lock (proxy for the
    /// gateway/session being live for this profile).
    pub locked: bool,
    /// Coarse gateway/session state derived for the table's "gateway state"
    /// column: `running` when locked, otherwise `idle`.
    pub gateway_state: String,
    /// The last observed public IP for this profile's active session, if any.
    /// Populated by cross-referencing live sessions; `None` when not running.
    pub public_ip: Option<String>,
    /// Human-readable age (e.g. "3d 4h").
    pub age: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Size on disk (base-1024, e.g. "5.0 MiB").
    pub size_on_disk: String,
    /// ISO-8601 last-launched timestamp, or `None` if never run.
    pub last_run: Option<String>,
}

impl ProfileView {
    /// Build a view from a domain [`Profile`], relative to `now` for age.
    #[must_use]
    pub fn from_profile(p: &Profile, now: chrono::DateTime<chrono::Utc>) -> Self {
        let age = p.age(now);
        Self {
            id: p.id.to_string(),
            name: p.spec.name.clone(),
            kind: p.spec.kind.label().to_string(),
            network_mode: p.spec.network.mode.label().to_string(),
            protection_level: p.spec.protection.label().to_string(),
            locked: p.locked,
            gateway_state: if p.locked { "running" } else { "idle" }.to_string(),
            public_ip: None,
            age: humanize_age(age),
            created_at: p.created_at.to_rfc3339(),
            size_on_disk: p.storage.human(),
            last_run: p.last_launched.map(|t| t.to_rfc3339()),
        }
    }
}

/// A session row / summary for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    /// Session id (uuid string).
    pub id: String,
    /// Owning profile id.
    pub profile_id: String,
    /// Lifecycle state token (kebab-case, e.g. `browsing`).
    pub state: String,
    /// Whether the session currently has live internet access.
    pub is_browsing: bool,
    /// Whether the session is safe to use (browsing AND protection active).
    pub is_safe: bool,
    /// Machine token for the protection status: `active|partial|unsafe|none`.
    pub protection_status: String,
    /// The exact UI label from [`ProtectionStatus::label`].
    pub protection_label: String,
    /// The public IP visible from inside the session, if known.
    pub public_ip: Option<String>,
}

impl SessionView {
    /// Build a view from a domain [`SessionSummary`].
    #[must_use]
    pub fn from_summary(s: &SessionSummary) -> Self {
        Self {
            id: s.id.to_string(),
            profile_id: s.profile.to_string(),
            state: session_state_token(s.state).to_string(),
            is_browsing: s.state.is_browsing(),
            is_safe: s.is_safe(),
            protection_status: protection_token(s.protection).to_string(),
            protection_label: s.protection.label().to_string(),
            public_ip: s.public_ip.clone(),
        }
    }
}

/// A single diagnostics row (subsystem + level + detail).
#[derive(Debug, Clone, Serialize)]
pub struct DiagItemView {
    /// Machine key (e.g. `dns`, `ipv6`, `webrtc`, `render_mode`).
    pub key: String,
    /// Health level token: `ok|degraded|down|unknown`.
    pub level: String,
    /// Human-readable detail (no secrets).
    pub detail: String,
}

impl From<&DiagnosticItem> for DiagItemView {
    fn from(d: &DiagnosticItem) -> Self {
        Self {
            key: d.key.clone(),
            level: d.level.label().to_string(),
            detail: d.detail.clone(),
        }
    }
}

/// A single preflight check row for the diagnostics panel.
#[derive(Debug, Clone, Serialize)]
pub struct CheckView {
    /// Stable check id string (e.g. `dns_route_verified`).
    pub id: String,
    /// `pass|fail|skipped`.
    pub outcome: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// The full diagnostics panel for a session (spec §11 diagnostics panel).
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsView {
    /// Machine token for the aggregate protection status.
    pub protection_status: String,
    /// The exact four-label badge text.
    pub protection_label: String,
    /// Whether browsing is permitted in this state (only when `active`).
    pub permits_browsing: bool,
    /// Public IP observed from inside the session, if any.
    pub public_ip: Option<String>,
    /// Whether the observed IP was via the tunnel.
    pub public_ip_via_tunnel: Option<bool>,
    /// Whether the observed IP differs from the host's real IP.
    pub public_ip_differs_from_host: Option<bool>,
    /// The six preflight checks, in execution order.
    pub checks: Vec<CheckView>,
    /// Per-subsystem diagnostics items (dns, ipv6, webrtc, devices, render mode,
    /// profile persistence, kill-switch activity, ...).
    pub items: Vec<DiagItemView>,
}

impl DiagnosticsView {
    /// Build from the daemon's checklist + diagnostics items.
    #[must_use]
    pub fn build(checklist: &ConnectivityChecklist, items: &[DiagnosticItem]) -> Self {
        let status = checklist.status();
        let checks = CheckId::all()
            .into_iter()
            .map(|id| {
                let report = checklist.report(id);
                let passed = report.map(|r| r.outcome.is_pass()).unwrap_or(false);
                CheckView {
                    id: id.as_str().to_string(),
                    outcome: report
                        .map(|r| check_outcome_token(r.outcome).to_string())
                        .unwrap_or_else(|| "skipped".to_string()),
                    passed,
                    detail: report
                        .map(|r| r.detail.clone())
                        .unwrap_or_else(|| "not reported".to_string()),
                }
            })
            .collect();
        Self {
            protection_status: protection_token(status).to_string(),
            protection_label: status.label().to_string(),
            permits_browsing: status.permits_browsing(),
            public_ip: checklist.observed_ip.as_ref().map(|o| o.ip.clone()),
            public_ip_via_tunnel: checklist.observed_ip.as_ref().map(|o| o.via_tunnel),
            public_ip_differs_from_host: checklist
                .observed_ip
                .as_ref()
                .map(|o| o.differs_from_host),
            checks,
            items: items.iter().map(DiagItemView::from).collect(),
        }
    }
}

/// The doctor self-test result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorView {
    /// Machine token for the aggregate status.
    pub protection_status: String,
    /// The exact four-label badge text.
    pub protection_label: String,
    /// The six preflight checks.
    pub checks: Vec<CheckView>,
}

impl DoctorView {
    /// Build from the doctor checklist.
    #[must_use]
    pub fn build(checklist: &ConnectivityChecklist) -> Self {
        let status = checklist.status();
        let checks = CheckId::all()
            .into_iter()
            .map(|id| {
                let report = checklist.report(id);
                let passed = report.map(|r| r.outcome.is_pass()).unwrap_or(false);
                CheckView {
                    id: id.as_str().to_string(),
                    outcome: report
                        .map(|r| check_outcome_token(r.outcome).to_string())
                        .unwrap_or_else(|| "skipped".to_string()),
                    passed,
                    detail: report
                        .map(|r| r.detail.clone())
                        .unwrap_or_else(|| "not reported".to_string()),
                }
            })
            .collect();
        Self {
            protection_status: protection_token(status).to_string(),
            protection_label: status.label().to_string(),
            checks,
        }
    }
}

/// Inputs from the unified "New Private Session" create-profile form.
///
/// The redesigned form merges the basic and advanced options into one coherent
/// panel, so this DTO now carries every choice the user can make: name,
/// persistence, isolation level, the full network selection (Tor with optional
/// bridges, a SOCKS5/HTTP proxy with host/port/optional credentials), and the
/// protection level. Everything is validated fail-closed by
/// [`CreateProfileArgs::to_spec`] before it is ever sent to the daemon, and the
/// daemon remains the ultimate authority.
///
/// No secret ever crosses this boundary as a secret: proxy credentials arrive as
/// a plain `user:pass` string only so the UI can construct an opaque
/// [`CredentialRef`] token; the reference — never the password — is what reaches
/// the daemon and any serialized config (spec §16).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateProfileArgs {
    /// Profile name.
    pub name: String,
    /// `ephemeral` (default) or `persistent`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Isolation level: `full-vm` (default) or `host-process`.
    #[serde(default)]
    pub isolation: Option<String>,
    /// Network mode: `tor` (default), `socks5`, `http`, or `vpn`.
    ///
    /// The legacy value `proxy` is accepted as an alias for `socks5` so older
    /// callers keep working.
    #[serde(default)]
    pub network_mode: Option<String>,
    /// Optional Tor bridge lines (one per line), used only in `tor` mode.
    #[serde(default)]
    pub bridges: Option<String>,
    /// Proxy host, used only in `socks5` / `http` mode.
    #[serde(default)]
    pub proxy_host: Option<String>,
    /// Proxy port, used only in `socks5` / `http` mode.
    #[serde(default)]
    pub proxy_port: Option<u16>,
    /// Optional `user:pass` for the proxy. Turned into an opaque credential
    /// reference; the password itself never reaches the daemon or config.
    #[serde(default)]
    pub proxy_credentials: Option<String>,
    /// Protection level: `balanced` (default) or `strict`.
    ///
    /// This is the coarse tier chosen by the four one-click safety cards
    /// (Compatibility/Balanced → `balanced`, Strict/Paranoid → `strict`). The
    /// fingerprint override below fine-tunes on top of it.
    #[serde(default)]
    pub protection: Option<String>,
    /// Browser engine: `chromium` (default) or `firefox` (Firefox / Tor Browser).
    #[serde(default)]
    pub browser: Option<String>,
    /// Optional fine-grained fingerprint override built by the "Advanced" panel.
    ///
    /// When present, it is applied on top of the chosen preset so the exact
    /// switches the user toggled are what the profile carries. When absent, the
    /// policy is derived from `protection` by the daemon (`fingerprint: None`).
    #[serde(default)]
    pub fingerprint: Option<FingerprintArgs>,
}

/// A fine-grained fingerprint override from the "Advanced" panel.
///
/// Every field is optional so the frontend can send only what the user actually
/// changed; anything omitted falls back to the value implied by the chosen
/// [`ProtectionLevel`]. The assembled [`FingerprintPolicy`] is always validated
/// (device APIs stay blocked, WebGPU stays off in Strict) before it reaches the
/// spec — fail-closed. Secret-free by construction.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FingerprintArgs {
    /// WebGL treatment: `virtual-backend`, `restricted`, or `disabled`.
    #[serde(default)]
    pub webgl: Option<String>,
    /// Whether WebGPU is exposed. Forced off in Strict by validation.
    #[serde(default)]
    pub webgpu_enabled: Option<bool>,
    /// Canvas treatment: `passthrough` or `limited`.
    #[serde(default)]
    pub canvas: Option<String>,
    /// Whether letterboxing (window-size bucketing) is on.
    #[serde(default)]
    pub letterbox: Option<bool>,
    /// Reported `navigator.hardwareConcurrency`. `0` (or omitted) exposes the
    /// real virtual CPU count.
    #[serde(default)]
    pub hardware_concurrency: Option<u32>,
    /// A shared, canonical IANA timezone (e.g. `UTC`). Empty falls back to the
    /// preset's timezone.
    #[serde(default)]
    pub timezone: Option<String>,
    /// A shared, canonical primary language tag (e.g. `en-US`). Empty falls back
    /// to the preset's language.
    #[serde(default)]
    pub language: Option<String>,
}

impl FingerprintArgs {
    /// Apply this override on top of the given base policy, returning the merged,
    /// validated [`FingerprintPolicy`].
    ///
    /// The base is the policy implied by the coarse protection level; only the
    /// fields the user actually set are overridden. The result is validated so a
    /// UI choice can never relax a non-negotiable rule (device APIs blocked,
    /// WebGPU off in Strict).
    ///
    /// # Errors
    /// Returns a friendly, secret-free message when a switch value is unknown or
    /// the merged policy fails [`FingerprintPolicy::validate`].
    fn apply_to(&self, base: FingerprintPolicy) -> Result<FingerprintPolicy, String> {
        let mut fp = base;
        if let Some(raw) = self.webgl.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            fp.webgl = match raw {
                "virtual-backend" | "virtual" => WebGlMode::VirtualBackend,
                "restricted" => WebGlMode::Restricted,
                "disabled" | "off" => WebGlMode::Disabled,
                other => return Err(format!("unknown WebGL mode: {other}")),
            };
        }
        if let Some(enabled) = self.webgpu_enabled {
            fp.webgpu_enabled = enabled;
        }
        if let Some(raw) = self.canvas.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            fp.canvas = match raw {
                "passthrough" => CanvasMode::Passthrough,
                "limited" => CanvasMode::Limited,
                other => return Err(format!("unknown canvas mode: {other}")),
            };
        }
        if let Some(on) = self.letterbox {
            fp.letterbox = if on { LetterboxMode::On } else { LetterboxMode::Off };
        }
        if let Some(cores) = self.hardware_concurrency {
            // A zero value means "expose the real (virtual) CPU count".
            fp.hardware_concurrency = if cores == 0 { None } else { Some(cores) };
        }
        if let Some(tz) = self.timezone.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            fp.timezone = Some(tz.to_string());
        }
        if let Some(lang) = self.language.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            fp.primary_language = lang.to_string();
        }
        if let Some(reason) = fp.validate() {
            return Err(format!("invalid fingerprint override: {reason}"));
        }
        Ok(fp)
    }
}

impl CreateProfileArgs {
    /// Parse the requested profile type, defaulting to ephemeral.
    #[must_use]
    pub fn profile_type(&self) -> ProfileType {
        match self.kind.as_deref() {
            Some("persistent") => ProfileType::Persistent,
            _ => ProfileType::Ephemeral,
        }
    }

    /// Parse the requested isolation level, defaulting to full VM isolation.
    #[must_use]
    pub fn isolation_level(&self) -> IsolationLevel {
        match self.isolation.as_deref() {
            Some("host-process") | Some("host") => IsolationLevel::HostProcess,
            _ => IsolationLevel::FullVm,
        }
    }

    /// Parse the requested protection level, defaulting to balanced.
    #[must_use]
    pub fn protection_level(&self) -> ProtectionLevel {
        match self.protection.as_deref() {
            Some("strict") => ProtectionLevel::Strict,
            _ => ProtectionLevel::Balanced,
        }
    }

    /// Parse the requested browser engine, defaulting to hardened Chromium.
    #[must_use]
    pub fn browser_backend(&self) -> BrowserBackendId {
        match self.browser.as_deref() {
            Some("firefox") | Some("tor") | Some("tor-browser") => BrowserBackendId::Firefox,
            _ => BrowserBackendId::Chromium,
        }
    }

    /// Build the optional fingerprint override for the spec.
    ///
    /// Returns `Ok(None)` when the "Advanced" panel supplied no override (so the
    /// daemon derives the policy from `protection`), or `Ok(Some(policy))` with
    /// the merged, validated override otherwise.
    ///
    /// # Errors
    /// Propagates a friendly, secret-free message from [`FingerprintArgs::apply_to`]
    /// when a switch value is unknown or the merged policy is invalid.
    pub fn fingerprint_override(&self) -> Result<Option<FingerprintPolicy>, String> {
        match &self.fingerprint {
            Some(args) => {
                let base = self.protection_level().policy();
                Ok(Some(args.apply_to(base)?))
            }
            None => Ok(None),
        }
    }

    /// Split the collected bridge textarea into non-empty, trimmed lines.
    fn bridge_lines(&self) -> Vec<String> {
        self.bridges
            .as_deref()
            .map(|raw| {
                raw.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Build the [`NetworkConfig`] implied by the form's network selection.
    ///
    /// # Errors
    /// Returns a friendly, secret-free message when the selection is incomplete
    /// (e.g. a proxy without a host) or unsupported for the chosen isolation
    /// (VPN requires the full-VM model with a stored endpoint/credentials, which
    /// this form cannot supply — fail-closed rather than build a broken profile).
    pub fn network_config(&self) -> Result<NetworkConfig, String> {
        let host_mode = self.isolation_level() == IsolationLevel::HostProcess;
        match self.network_mode.as_deref() {
            None | Some("tor") => {
                let bridges = self.bridge_lines();
                Ok(NetworkConfig::from_mode(NetworkMode::Tor(TorConfig {
                    use_bridges: !bridges.is_empty(),
                    bridges,
                    exit_country: None,
                })))
            }
            // `proxy` kept as a backward-compatible alias for the SOCKS5 choice.
            Some("socks5") | Some("proxy") => self
                .proxy_config(ProxyProtocol::Socks5)
                .map(|p| NetworkConfig::from_mode(NetworkMode::Proxy(p))),
            Some("http") => self
                .proxy_config(ProxyProtocol::HttpConnect)
                .map(|p| NetworkConfig::from_mode(NetworkMode::Proxy(p))),
            Some("vpn") => {
                if host_mode {
                    Err("VPN is available only with full-VM isolation; use Tor or a proxy for host mode".to_string())
                } else {
                    Err("VPN profiles require an endpoint and stored credentials; create them via the CLI/config".to_string())
                }
            }
            Some(other) => Err(format!("unknown network mode: {other}")),
        }
    }

    /// Build a [`ProxyConfig`] from the proxy sub-fields, validating host/port and
    /// turning any `user:pass` into an opaque credential reference (never the
    /// secret). `remote_dns` is forced on so DNS traverses the proxy (spec §5).
    fn proxy_config(&self, protocol: ProxyProtocol) -> Result<ProxyConfig, String> {
        let host = self
            .proxy_host
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .ok_or_else(|| "proxy host must not be empty".to_string())?
            .to_string();
        let port = self.proxy_port.filter(|p| *p != 0).ok_or_else(|| {
            "proxy port must be between 1 and 65535".to_string()
        })?;
        // Only a *reference* to the credentials is carried, derived from the
        // username so the daemon can resolve it against secure storage. The
        // password is never inlined into the reference or logged.
        let credentials_ref = self
            .proxy_credentials
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| {
                let user = c.split(':').next().unwrap_or("").trim();
                let id = if user.is_empty() {
                    "proxy".to_string()
                } else {
                    format!("proxy:{user}")
                };
                CredentialRef::new(id)
            });
        Ok(ProxyConfig {
            protocol,
            host,
            port,
            credentials_ref,
            remote_dns: true,
        })
    }

    /// Map the validated form inputs into a [`ProfileSpec`] ready for the daemon.
    ///
    /// This is the single mapping used by the create-profile command; it applies
    /// every default and fail-closed rule in one place so the behaviour is
    /// testable without a running daemon.
    ///
    /// # Errors
    /// Returns a friendly, secret-free message when the name is empty, the
    /// network selection is incomplete/unsupported, or the assembled spec fails
    /// [`ProfileSpec::validate`].
    pub fn to_spec(&self) -> Result<ProfileSpec, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("profile name must not be empty".to_string());
        }
        self.spec_with_name(name)
    }

    /// Assemble a [`ProfileSpec`] from the form, using `name` verbatim.
    ///
    /// Shared by [`to_spec`](Self::to_spec) (which enforces a non-empty name) and
    /// [`preview`](Self::preview) (which substitutes a placeholder name so the
    /// live preview works before the user has typed one). Applies the browser
    /// choice and the merged fingerprint override, then validates fail-closed.
    fn spec_with_name(&self, name: String) -> Result<ProfileSpec, String> {
        let spec = ProfileSpec {
            name,
            kind: self.profile_type(),
            network: self.network_config()?,
            protection: self.protection_level(),
            isolation: self.isolation_level(),
            browser: self.browser_backend(),
            fingerprint: self.fingerprint_override()?,
            permissions: PermissionPolicy::secure_default(),
        };
        spec.validate().map_err(|e| format!("invalid profile: {e}"))?;
        Ok(spec)
    }

    /// Compute the live [`ProfilePreview`] for the current form inputs.
    ///
    /// Unlike [`to_spec`](Self::to_spec) this tolerates an empty name (a
    /// placeholder is substituted) so the Preview tab can update as the user
    /// types. The preview is derived entirely from the spec, so it always matches
    /// exactly what a created profile would present to websites.
    ///
    /// # Errors
    /// Returns a friendly, secret-free message when the network selection is
    /// incomplete/unsupported or a fingerprint switch value is invalid.
    pub fn preview(&self) -> Result<ProfilePreview, String> {
        let name = self.name.trim();
        let name = if name.is_empty() {
            "preview".to_string()
        } else {
            name.to_string()
        };
        Ok(self.spec_with_name(name)?.preview())
    }
}

// --- advanced / enforcement views ------------------------------------------

/// The enforcement policy as three booleans, mirroring [`Enforcement`].
///
/// This is the shape the "Advanced" toggles bind to. It round-trips to and from
/// the domain [`Enforcement`] type so the frontend never has to know the
/// field-level serde defaults. Secret-free by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementView {
    /// Require the browser to run in its own isolated VM.
    pub require_vm_isolation: bool,
    /// Require a dedicated gateway VM for the network path.
    pub require_gateway: bool,
    /// Permit launching the browser directly on the host (reduced protection).
    pub allow_host_browser: bool,
}

impl From<Enforcement> for EnforcementView {
    fn from(e: Enforcement) -> Self {
        Self {
            require_vm_isolation: e.require_vm_isolation,
            require_gateway: e.require_gateway,
            allow_host_browser: e.allow_host_browser,
        }
    }
}

impl From<EnforcementView> for Enforcement {
    fn from(v: EnforcementView) -> Self {
        Self {
            require_vm_isolation: v.require_vm_isolation,
            require_gateway: v.require_gateway,
            allow_host_browser: v.allow_host_browser,
        }
    }
}

/// The daemon status snapshot for the "Advanced" section (spec §11).
///
/// Flattens [`aegis_ipc::StatusDto`] into display-ready fields: the machine
/// isolation token (`full-vm` / `host-process`), the exact human label from
/// [`IsolationLevel::label`], whether full isolation is in force, and the
/// current enforcement policy. Secret-free (the host-browser *path* is
/// deliberately omitted so no local filesystem path reaches the webview).
#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    /// The daemon's compiled-in version.
    pub version: String,
    /// The host platform (`windows`, `linux`, `macos`, ...).
    pub platform: String,
    /// Machine token for the isolation level: `full-vm` or `host-process`.
    pub isolation_status: String,
    /// The exact UI label from [`IsolationLevel::label`]
    /// (`full VM isolation` / `host process (reduced)`).
    pub isolation_label: String,
    /// Whether the full VM-isolation model is in force.
    pub is_full_isolation: bool,
    /// The current enforcement policy (drives the three Advanced toggles).
    pub enforcement: EnforcementView,
    /// Whether a Chromium-family host browser is available for the reduced mode.
    pub host_browser_available: bool,
}

impl StatusView {
    /// Build a status view from the IPC [`StatusDto`].
    ///
    /// The host-browser *path* is intentionally dropped: the frontend only needs
    /// to know whether one is available, never where it lives on disk.
    #[must_use]
    pub fn from_status(s: &StatusDto) -> Self {
        Self {
            version: s.version.clone(),
            platform: s.platform.clone(),
            isolation_status: isolation_token(s.isolation_level).to_string(),
            isolation_label: s.isolation_level.label().to_string(),
            is_full_isolation: s.isolation_level.is_full(),
            enforcement: EnforcementView::from(s.enforcement),
            host_browser_available: s.host_browser_available,
        }
    }
}

/// Stable machine token for the isolation level.
#[must_use]
pub fn isolation_token(level: IsolationLevel) -> &'static str {
    match level {
        IsolationLevel::FullVm => "full-vm",
        IsolationLevel::HostProcess => "host-process",
    }
}

// --- token helpers ---------------------------------------------------------

/// Stable machine token for the four-state protection status.
#[must_use]
pub fn protection_token(s: ProtectionStatus) -> &'static str {
    match s {
        ProtectionStatus::Active => "active",
        ProtectionStatus::Partial => "partial",
        ProtectionStatus::Unsafe => "unsafe",
        ProtectionStatus::None => "none",
    }
}

fn session_state_token(s: SessionState) -> &'static str {
    match s {
        SessionState::Requested => "requested",
        SessionState::Provisioning => "provisioning",
        SessionState::GatewayStarting => "gateway-starting",
        SessionState::Preflight => "preflight",
        SessionState::Browsing => "browsing",
        SessionState::Closing => "closing",
        SessionState::Destroyed => "destroyed",
        SessionState::Failed => "failed",
    }
}

fn check_outcome_token(o: aegis_core::preflight::CheckOutcome) -> &'static str {
    use aegis_core::preflight::CheckOutcome::*;
    match o {
        Pass => "pass",
        Fail => "fail",
        Skipped => "skipped",
    }
}

/// Render a duration as a compact human string (e.g. "3d 4h", "12m", "just now").
#[must_use]
pub fn humanize_age(d: chrono::Duration) -> String {
    let secs = d.num_seconds().max(0);
    if secs < 60 {
        return "just now".to_string();
    }
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::preflight::{CheckReport, IpObservation};

    #[test]
    fn protection_tokens_are_stable() {
        assert_eq!(protection_token(ProtectionStatus::Active), "active");
        assert_eq!(protection_token(ProtectionStatus::Partial), "partial");
        assert_eq!(protection_token(ProtectionStatus::Unsafe), "unsafe");
        assert_eq!(protection_token(ProtectionStatus::None), "none");
    }

    #[test]
    fn protection_labels_are_the_exact_four() {
        // These MUST match aegis_core exactly (spec §11, §16). No "100% anonymous".
        assert_eq!(ProtectionStatus::Active.label(), "protection active");
        assert_eq!(ProtectionStatus::Partial.label(), "partial protection");
        assert_eq!(ProtectionStatus::Unsafe.label(), "unsafe configuration");
        assert_eq!(ProtectionStatus::None.label(), "no protection");
    }

    #[test]
    fn diagnostics_view_has_all_six_checks() {
        let reports: Vec<CheckReport> = CheckId::all()
            .into_iter()
            .map(|id| CheckReport::pass(id, "ok"))
            .collect();
        let mut cl = ConnectivityChecklist::new(reports);
        cl.observed_ip = Some(IpObservation {
            ip: "198.51.100.7".into(),
            via_tunnel: true,
            differs_from_host: true,
        });
        let view = DiagnosticsView::build(&cl, &[]);
        assert_eq!(view.checks.len(), 6);
        assert_eq!(view.protection_status, "active");
        assert_eq!(view.protection_label, "protection active");
        assert!(view.permits_browsing);
        assert_eq!(view.public_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(view.public_ip_via_tunnel, Some(true));
    }

    #[test]
    fn humanize_age_buckets() {
        assert_eq!(humanize_age(chrono::Duration::seconds(30)), "just now");
        assert_eq!(humanize_age(chrono::Duration::minutes(5)), "5m");
        assert_eq!(humanize_age(chrono::Duration::hours(2)), "2h 0m");
        assert_eq!(
            humanize_age(chrono::Duration::days(3) + chrono::Duration::hours(4)),
            "3d 4h"
        );
    }

    /// A minimal args value with everything defaulted; individual tests tweak
    /// only the fields they care about.
    fn args(name: &str) -> CreateProfileArgs {
        CreateProfileArgs {
            name: name.into(),
            kind: None,
            isolation: None,
            network_mode: None,
            bridges: None,
            proxy_host: None,
            proxy_port: None,
            proxy_credentials: None,
            protection: None,
            browser: None,
            fingerprint: None,
        }
    }

    #[test]
    fn create_args_default_to_ephemeral() {
        let a = args("x");
        assert_eq!(a.profile_type(), ProfileType::Ephemeral);
        let mut a2 = args("y");
        a2.kind = Some("persistent".into());
        assert_eq!(a2.profile_type(), ProfileType::Persistent);
    }

    #[test]
    fn to_spec_defaults_are_ephemeral_full_vm_tor_balanced() {
        // The friendly defaults: an ephemeral, full-VM, Tor, Balanced profile.
        let spec = args("research").to_spec().unwrap();
        assert_eq!(spec.name, "research");
        assert_eq!(spec.kind, ProfileType::Ephemeral);
        assert_eq!(spec.isolation, IsolationLevel::FullVm);
        assert_eq!(spec.network.mode.label(), "Tor");
        assert_eq!(spec.protection, ProtectionLevel::Balanced);
    }

    #[test]
    fn to_spec_empty_name_is_rejected() {
        let mut a = args("   ");
        assert!(a.to_spec().is_err());
        a.name = "".into();
        assert!(a.to_spec().is_err());
    }

    #[test]
    fn safety_tiers_collapse_onto_the_two_protection_levels() {
        // The redesigned "How safe?" step offers four one-click tiers, but they
        // collapse onto the two coarse protection levels the daemon uses:
        // Compatibility/Balanced -> Balanced, Strict/Paranoid -> Strict. The
        // frontend sends the collapsed `protection` string; pin that mapping so a
        // tier can never silently land on the wrong level.
        let cases = [
            // (protection string the JS sends, expected ProtectionLevel)
            (None, ProtectionLevel::Balanced), // default (Balanced pre-selected)
            (Some("balanced"), ProtectionLevel::Balanced),
            (Some("strict"), ProtectionLevel::Strict),
        ];
        for (proto, expected) in cases {
            let mut a = args("tiered");
            a.protection = proto.map(str::to_string);
            let spec = a.to_spec().expect("spec builds");
            assert_eq!(
                spec.protection, expected,
                "protection {proto:?} must map to {expected:?}"
            );
        }
    }

    #[test]
    fn to_spec_carries_isolation_and_strict_protection() {
        let mut a = args("host-strict");
        a.isolation = Some("host-process".into());
        a.protection = Some("strict".into());
        let spec = a.to_spec().unwrap();
        assert_eq!(spec.isolation, IsolationLevel::HostProcess);
        assert!(!spec.isolation.is_full());
        assert_eq!(spec.protection, ProtectionLevel::Strict);
    }

    #[test]
    fn to_spec_tor_bridges_are_parsed_and_enable_use_bridges() {
        let mut a = args("bridged");
        a.network_mode = Some("tor".into());
        a.bridges = Some("obfs4 1.2.3.4:443 CERT\n\n  obfs4 5.6.7.8:80 CERT2  \n".into());
        let spec = a.to_spec().unwrap();
        match spec.network.mode {
            NetworkMode::Tor(cfg) => {
                assert!(cfg.use_bridges);
                assert_eq!(cfg.bridges.len(), 2);
                assert_eq!(cfg.bridges[0], "obfs4 1.2.3.4:443 CERT");
                // Whitespace-only lines are dropped and each line is trimmed.
                assert_eq!(cfg.bridges[1], "obfs4 5.6.7.8:80 CERT2");
            }
            other => panic!("expected Tor mode, got {}", other.label()),
        }
    }

    #[test]
    fn to_spec_socks5_proxy_maps_host_port_and_remote_dns() {
        let mut a = args("proxied");
        a.network_mode = Some("socks5".into());
        a.proxy_host = Some("10.0.0.9".into());
        a.proxy_port = Some(1080);
        let spec = a.to_spec().unwrap();
        match spec.network.mode {
            NetworkMode::Proxy(cfg) => {
                assert_eq!(cfg.protocol, ProxyProtocol::Socks5);
                assert_eq!(cfg.host, "10.0.0.9");
                assert_eq!(cfg.port, 1080);
                assert!(cfg.remote_dns, "proxy DNS must be remote (no leak)");
                assert!(cfg.credentials_ref.is_none());
            }
            other => panic!("expected Proxy mode, got {}", other.label()),
        }
        // DNS is forced to block plaintext regardless of mode.
        assert!(spec.network.dns.block_plain_dns);
    }

    #[test]
    fn to_spec_http_proxy_credentials_become_a_reference_not_a_secret() {
        let mut a = args("http-auth");
        a.network_mode = Some("http".into());
        a.proxy_host = Some("proxy.example".into());
        a.proxy_port = Some(8080);
        a.proxy_credentials = Some("alice:hunter2".into());
        let spec = a.to_spec().unwrap();
        let cred = match &spec.network.mode {
            NetworkMode::Proxy(cfg) => {
                assert_eq!(cfg.protocol, ProxyProtocol::HttpConnect);
                cfg.credentials_ref.clone().expect("a credential ref")
            }
            other => panic!("expected Proxy mode, got {}", other.label()),
        };
        // The reference is derived from the username only; the password must NOT
        // appear anywhere in the serialized spec (spec §16: no plaintext proxy
        // passwords).
        assert_eq!(cred.0, "proxy:alice");
        let json = serde_json::to_string(&spec).unwrap();
        assert!(!json.contains("hunter2"), "password leaked into spec JSON");
    }

    #[test]
    fn to_spec_proxy_without_host_is_rejected() {
        let mut a = args("bad-proxy");
        a.network_mode = Some("socks5".into());
        a.proxy_port = Some(1080);
        assert!(a.to_spec().is_err());
    }

    #[test]
    fn to_spec_vpn_on_host_isolation_points_to_tor_or_proxy() {
        let mut a = args("vpn-host");
        a.network_mode = Some("vpn".into());
        a.isolation = Some("host-process".into());
        let err = a.to_spec().unwrap_err();
        assert!(err.contains("Tor or a proxy"), "unexpected error: {err}");
    }

    #[test]
    fn to_spec_vpn_on_full_vm_is_rejected_pending_cli_config() {
        let mut a = args("vpn-full");
        a.network_mode = Some("vpn".into());
        assert!(a.to_spec().is_err());
    }

    #[test]
    fn enforcement_view_roundtrips_through_domain() {
        // A round trip EnforcementView -> Enforcement -> EnforcementView must be
        // lossless so the Advanced toggles reflect exactly what the daemon holds.
        for e in [Enforcement::secure(), Enforcement::host_browser()] {
            let view = EnforcementView::from(e);
            let back: Enforcement = view.into();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn status_view_maps_full_isolation() {
        let s = StatusDto {
            version: "0.1.0".into(),
            platform: "windows".into(),
            isolation_level: IsolationLevel::FullVm,
            enforcement: Enforcement::secure(),
            host_browser_available: false,
            host_browser_path: None,
        };
        let v = StatusView::from_status(&s);
        assert_eq!(v.isolation_status, "full-vm");
        assert_eq!(v.isolation_label, "full VM isolation");
        assert!(v.is_full_isolation);
        assert!(v.enforcement.require_vm_isolation);
        assert!(v.enforcement.require_gateway);
        assert!(!v.enforcement.allow_host_browser);
    }

    #[test]
    fn status_view_maps_host_process_and_drops_path() {
        let s = StatusDto {
            version: "0.1.0".into(),
            platform: "windows".into(),
            isolation_level: IsolationLevel::HostProcess,
            enforcement: Enforcement::host_browser(),
            host_browser_available: true,
            // A local filesystem path that must NOT reach the webview.
            host_browser_path: Some("C:/Program Files/chrome.exe".into()),
        };
        let v = StatusView::from_status(&s);
        assert_eq!(v.isolation_status, "host-process");
        assert_eq!(v.isolation_label, "host process (reduced)");
        assert!(!v.is_full_isolation);
        assert!(v.host_browser_available);
        // The path is intentionally not part of StatusView; assert it never
        // appears in the serialized JSON the frontend receives.
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("chrome.exe"));
        assert!(!json.contains("Program Files"));
    }

    #[test]
    fn isolation_tokens_are_stable() {
        assert_eq!(isolation_token(IsolationLevel::FullVm), "full-vm");
        assert_eq!(isolation_token(IsolationLevel::HostProcess), "host-process");
    }

    // --- browser + fingerprint-override mapping --------------------------------

    #[test]
    fn to_spec_defaults_to_chromium_and_no_override() {
        let spec = args("x").to_spec().unwrap();
        assert_eq!(spec.browser, BrowserBackendId::Chromium);
        // No Advanced override => derive from `protection`.
        assert!(spec.fingerprint.is_none());
    }

    #[test]
    fn to_spec_maps_firefox_browser() {
        let mut a = args("ffx");
        a.browser = Some("firefox".into());
        assert_eq!(a.to_spec().unwrap().browser, BrowserBackendId::Firefox);
        // The Tor Browser aliases map to the same Firefox backend.
        let mut b = args("torb");
        b.browser = Some("tor-browser".into());
        assert_eq!(b.to_spec().unwrap().browser, BrowserBackendId::Firefox);
    }

    #[test]
    fn to_spec_applies_fingerprint_override_on_top_of_preset() {
        // Start from Balanced, then flip individual Advanced switches.
        let mut a = args("tuned");
        a.protection = Some("balanced".into());
        a.fingerprint = Some(FingerprintArgs {
            webgl: Some("disabled".into()),
            webgpu_enabled: Some(false),
            canvas: Some("limited".into()),
            letterbox: Some(true),
            hardware_concurrency: Some(6),
            timezone: Some("Europe/Warsaw".into()),
            language: Some("pl-PL".into()),
        });
        let spec = a.to_spec().unwrap();
        let fp = spec.fingerprint.expect("an override policy");
        // The coarse level is still Balanced (the override tunes on top of it).
        assert_eq!(fp.level, ProtectionLevel::Balanced);
        assert_eq!(fp.webgl, WebGlMode::Disabled);
        assert!(!fp.webgpu_enabled);
        assert_eq!(fp.canvas, CanvasMode::Limited);
        assert_eq!(fp.letterbox, LetterboxMode::On);
        assert_eq!(fp.hardware_concurrency, Some(6));
        assert_eq!(fp.timezone.as_deref(), Some("Europe/Warsaw"));
        assert_eq!(fp.primary_language, "pl-PL");
        // Non-negotiable rules survive the override.
        assert!(fp.block_device_apis);
    }

    #[test]
    fn fingerprint_override_zero_cores_means_real_count() {
        let mut a = args("real-cpu");
        a.fingerprint = Some(FingerprintArgs {
            hardware_concurrency: Some(0),
            ..Default::default()
        });
        let fp = a.to_spec().unwrap().fingerprint.expect("an override");
        assert_eq!(fp.hardware_concurrency, None);
    }

    #[test]
    fn fingerprint_override_rejects_webgpu_in_strict() {
        // Strict must never expose WebGPU; a UI toggle cannot relax that.
        let mut a = args("bad-strict");
        a.protection = Some("strict".into());
        a.fingerprint = Some(FingerprintArgs {
            webgpu_enabled: Some(true),
            ..Default::default()
        });
        assert!(a.to_spec().is_err());
    }

    #[test]
    fn fingerprint_override_rejects_unknown_webgl_value() {
        let mut a = args("bad-webgl");
        a.fingerprint = Some(FingerprintArgs {
            webgl: Some("nonsense".into()),
            ..Default::default()
        });
        assert!(a.to_spec().is_err());
    }

    // --- preview mapping -------------------------------------------------------

    #[test]
    fn preview_tolerates_empty_name_and_reflects_defaults() {
        // The Preview tab must render before a name is typed.
        let a = args("");
        let p = a.preview().expect("preview builds with a placeholder name");
        assert_eq!(p.browser, BrowserBackendId::Chromium);
        assert!(p.user_agent.contains("Chrome"));
        assert_eq!(p.network, "Tor");
        assert_eq!(p.timezone, "UTC");
        assert_eq!(p.language, "en-US");
    }

    #[test]
    fn preview_reflects_browser_and_fingerprint_override() {
        let mut a = args("preview-strict");
        a.browser = Some("firefox".into());
        a.protection = Some("strict".into());
        a.isolation = Some("host-process".into());
        a.fingerprint = Some(FingerprintArgs {
            hardware_concurrency: Some(2),
            timezone: Some("UTC".into()),
            ..Default::default()
        });
        let p = a.preview().unwrap();
        assert_eq!(p.browser, BrowserBackendId::Firefox);
        assert!(p.user_agent.contains("Firefox"));
        assert_eq!(p.isolation, IsolationLevel::HostProcess);
        assert_eq!(p.isolation_label, "host process (reduced)");
        // Strict preset => WebGL disabled, letterboxing on, WebGPU off.
        assert_eq!(p.webgl, "disabled");
        assert!(p.letterbox);
        assert!(!p.webgpu_enabled);
        assert_eq!(p.hardware_concurrency, Some(2));
        assert!(p.device_apis_blocked);
    }

    #[test]
    fn preview_surfaces_network_selection_errors() {
        // An incomplete proxy selection must fail the preview too (fail-closed).
        let mut a = args("bad-preview");
        a.network_mode = Some("socks5".into());
        assert!(a.preview().is_err());
    }

    #[test]
    fn preview_json_uses_the_tokens_the_frontend_reads() {
        // The Preview-tab JS compares `browser === "firefox"`, `protection ===
        // "strict"` and reads `isolation_label`. Pin those serialized tokens so a
        // rename in aegis-core can't silently break the frontend rendering.
        let mut a = args("json-shape");
        a.browser = Some("firefox".into());
        a.protection = Some("strict".into());
        let json = serde_json::to_value(a.preview().unwrap()).unwrap();
        assert_eq!(json["browser"], "firefox");
        assert_eq!(json["protection"], "strict");
        assert_eq!(json["isolation"], "full-vm");
        assert_eq!(json["isolation_label"], "full VM isolation");
        // Never a "100% anonymous" style claim anywhere in the preview payload.
        let s = json.to_string();
        assert!(!s.contains("100%"));
        assert!(!s.to_lowercase().contains("anonymous"));
    }
}
