//! The Firefox / Tor-Browser host backend (spec §6 Variant A).
//!
//! This backend brings the Tor/Mullvad anti-fingerprinting line
//! (`privacy.resistFingerprinting`, letterboxing, WebRTC off, first-party
//! isolation) to Aegis' reduced-protection **host** mode: it launches a real
//! Firefox / Tor Browser binary on the host OS, routed through the host-side
//! SOCKS proxy.
//!
//! [`FirefoxBackend::render_policy`] is **pure**: it turns a
//! [`BrowserLaunchRequest`] into a [`BackendPolicyBundle`] whose
//!
//! * `preferences` map is a Firefox `user.js` pref set that hardens the browser
//!   *and* routes every connection through the host SOCKS proxy
//!   (`network.proxy.type = 1`, `network.proxy.socks*`), disables WebRTC
//!   (`media.peerconnection.enabled = false`), turns on
//!   `privacy.resistFingerprinting` (with letterboxing under Strict/Paranoid),
//!   and disables telemetry / sync / the updater; and
//! * `command_line` launches Firefox with `-no-remote`, `-new-instance` and
//!   `-profile <user_data_dir>` so the profile is isolated and never joins an
//!   already-running Firefox.
//!
//! All values are derived from `req.fingerprint` + `req.permissions`, so every
//! guarantee is asserted by a unit test rather than trusted by inspection
//! (spec §16). Because the `user.js` must exist in the profile directory *before*
//! Firefox starts, [`FirefoxBackend::launch`] writes it via
//! [`write_user_js`] before handing the command line to the [`BrowserRunner`].
//!
//! The process control is delegated to a [`BrowserRunner`] exactly like the
//! Chromium backend, so the launcher can drive a real host process
//! ([`crate::HostBrowserRunner`]) while the tests use an in-memory mock. A backend
//! constructed with [`FirefoxBackend::new`] (no runner) keeps the previous
//! pure/host-independent behaviour and fails closed with [`Error::Unsupported`]
//! on launch.

use crate::runner::{BrowserRunner, LaunchSpec};
use aegis_core::browser::{
    BackendCapabilities, BackendPolicyBundle, BrowserBackendId, BrowserHandle, BrowserLaunchRequest,
};
use aegis_core::error::{Error, Result};
use aegis_core::fingerprint::{LetterboxMode, ProtectionLevel, WebGlMode};
use aegis_core::traits::BrowserBackend;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// The preferences filename the launcher writes into the Firefox profile.
pub const PREFS_FILE: &str = "user.js";

/// The planned/real Firefox / Tor-Browser backend.
///
/// `render_policy` emits a hardened `user.js` pref set + a Firefox command line
/// (both pure). When constructed with a [`BrowserRunner`] via
/// [`FirefoxBackend::with_runner`], `launch`/`is_running`/`terminate` drive that
/// runner (writing `user.js` into the profile first). A backend built with
/// [`FirefoxBackend::new`] has no runner and fails closed with
/// [`Error::Unsupported`] on launch — matching the previous stub behaviour so the
/// crate is usable on any host.
pub struct FirefoxBackend<R: BrowserRunner = NoRunner> {
    runner: R,
    /// The executable name handed to the runner. For the host runner the actual
    /// binary is fixed at construction time, so this is informational only.
    program: String,
    /// The runner target slug (a VM slug in the guest model; ignored in host
    /// mode). Opaque and host-independent.
    slug: String,
}

/// A placeholder runner for a [`FirefoxBackend`] built without process control.
///
/// Every method fails closed with [`Error::Unsupported`], so a
/// [`FirefoxBackend::new`] backend can still render policy on any host while
/// refusing to *launch* anything (matching the previous stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRunner;

/// The reason string used when a runner-less backend is asked to launch.
const NO_RUNNER: &str =
    "this FirefoxBackend was built without a runner; construct it with FirefoxBackend::with_runner \
     (e.g. a HostBrowserRunner) to launch";

#[async_trait]
impl BrowserRunner for NoRunner {
    async fn start(&self, _slug: &str, _spec: &LaunchSpec) -> Result<String> {
        Err(Error::Unsupported(NO_RUNNER.to_string()))
    }
    async fn is_running(&self, _token: &str) -> Result<bool> {
        Err(Error::Unsupported(NO_RUNNER.to_string()))
    }
    async fn stop(&self, _token: &str) -> Result<()> {
        Err(Error::Unsupported(NO_RUNNER.to_string()))
    }
}

impl<R: BrowserRunner> std::fmt::Debug for FirefoxBackend<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirefoxBackend")
            .field("program", &self.program)
            .field("slug", &self.slug)
            .finish_non_exhaustive()
    }
}

impl FirefoxBackend<NoRunner> {
    /// Construct a policy-only Firefox backend (no process control).
    ///
    /// `render_policy` works on any host; `launch` fails closed with
    /// [`Error::Unsupported`]. Use [`FirefoxBackend::with_runner`] to make it
    /// launchable.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: NoRunner,
            program: "firefox".to_string(),
            slug: "firefox".to_string(),
        }
    }
}

impl Default for FirefoxBackend<NoRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: BrowserRunner> FirefoxBackend<R> {
    /// Construct a launchable Firefox backend bound to a [`BrowserRunner`]
    /// (e.g. a [`crate::HostBrowserRunner`] resolved to a Firefox / Tor Browser
    /// binary), a program name, and a runner target slug.
    pub fn with_runner(runner: R, program: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            runner,
            program: program.into(),
            slug: slug.into(),
        }
    }

    /// Build the [`LaunchSpec`] (program + args + env) for a vetted bundle.
    ///
    /// The command line is taken verbatim from the already-vetted bundle. As with
    /// Chromium, the canonical timezone (`TZ`) and language (`LANG`/`LANGUAGE`) are
    /// applied via the environment for a consistent locale.
    fn launch_spec(&self, req: &BrowserLaunchRequest, bundle: &BackendPolicyBundle) -> LaunchSpec {
        let fp = &req.fingerprint;
        let mut env = Vec::new();
        if let Some(tz) = &fp.timezone {
            env.push(("TZ".to_string(), tz.clone()));
        }
        let lang = &fp.primary_language;
        env.push((
            "LANG".to_string(),
            format!("{}.UTF-8", lang.replace('-', "_")),
        ));
        env.push(("LANGUAGE".to_string(), lang.clone()));

        LaunchSpec {
            program: self.program.clone(),
            args: bundle.command_line.clone(),
            env,
        }
    }
}

/// Parse the SOCKS host and port from a proxy endpoint like
/// `socks5://127.0.0.1:9050` or `127.0.0.1:9050`.
///
/// Returns `(host, port)`. Firefox is always pointed at a SOCKS proxy in host
/// mode, so the scheme (if any) is informational; only the `host:port` authority
/// matters.
///
/// # Errors
/// Returns [`Error::Config`] if the endpoint has no `host:port` authority or the
/// port is not a valid `u16`.
fn parse_socks_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let authority = endpoint.split("://").last().unwrap_or(endpoint);
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        Error::Config(format!(
            "Firefox proxy endpoint '{endpoint}' is missing a host:port"
        ))
    })?;
    if host.is_empty() {
        return Err(Error::Config(format!(
            "Firefox proxy endpoint '{endpoint}' is missing a host"
        )));
    }
    let port: u16 = port.parse().map_err(|_| {
        Error::Config(format!(
            "Firefox proxy endpoint '{endpoint}' has an invalid port"
        ))
    })?;
    Ok((host.to_string(), port))
}

/// Render the hardened Firefox `user.js` pref set from the request. Pure.
///
/// # Errors
/// Returns [`Error::Config`] if the proxy endpoint cannot be parsed into a
/// SOCKS `host:port` (fail closed — Firefox must never fall back to a direct
/// connection).
fn render_preferences(req: &BrowserLaunchRequest) -> Result<BTreeMap<String, Value>> {
    let fp = &req.fingerprint;
    let (socks_host, socks_port) = parse_socks_endpoint(&req.proxy_endpoint)?;
    let mut prefs: BTreeMap<String, Value> = BTreeMap::new();

    // --- Route EVERYTHING through the host SOCKS proxy (spec §5) ------------
    // type 1 = manual proxy configuration. socks_remote_dns keeps DNS inside the
    // proxy (no local DNS leak); proxy the SOCKS host verbatim.
    prefs.insert("network.proxy.type".into(), json!(1));
    prefs.insert("network.proxy.socks".into(), json!(socks_host));
    prefs.insert("network.proxy.socks_port".into(), json!(socks_port));
    prefs.insert("network.proxy.socks_version".into(), json!(5));
    prefs.insert("network.proxy.socks_remote_dns".into(), json!(true));
    // No bypass: not even localhost is exempt, so nothing escapes the proxy.
    prefs.insert("network.proxy.no_proxies_on".into(), json!(""));
    // Disable Firefox's own DNS-over-HTTPS resolver so DNS goes through SOCKS.
    prefs.insert("network.trr.mode".into(), json!(5));

    // --- WebRTC OFF (spec §5, §7) ------------------------------------------
    // The whole API is disabled so no path can leak the local interface.
    prefs.insert("media.peerconnection.enabled".into(), json!(false));
    prefs.insert("media.peerconnection.ice.no_host".into(), json!(true));
    prefs.insert(
        "media.peerconnection.ice.default_address_only".into(),
        json!(true),
    );

    // --- Anti-fingerprinting (Tor uplift, spec §7) -------------------------
    prefs.insert("privacy.resistFingerprinting".into(), json!(true));
    // Letterboxing rounds the content area to shared buckets — on for the
    // stronger levels (Strict/Paranoid map to ProtectionLevel::Strict) or when
    // the policy explicitly requests it.
    let letterbox =
        matches!(fp.letterbox, LetterboxMode::On) || fp.level == ProtectionLevel::Strict;
    prefs.insert(
        "privacy.resistFingerprinting.letterboxing".into(),
        json!(letterbox),
    );
    prefs.insert("privacy.firstparty.isolate".into(), json!(true));
    prefs.insert("privacy.trackingprotection.enabled".into(), json!(true));

    // --- WebGL / WebGPU per fingerprint policy (spec §7) -------------------
    let webgl_disabled = matches!(fp.webgl, WebGlMode::Disabled);
    prefs.insert("webgl.disabled".into(), json!(webgl_disabled));
    // WebGPU is disabled outright in host mode (matches the Chromium backend and
    // the Strict invariant; Balanced also keeps it off).
    prefs.insert("dom.webgpu.enabled".into(), json!(false));

    // --- Device APIs blocked (spec §7, §9) ---------------------------------
    prefs.insert(
        "dom.webbluetooth.enabled".into(),
        json!(!fp.block_device_apis),
    );
    prefs.insert("dom.webusb.enabled".into(), json!(!fp.block_device_apis));
    prefs.insert("dom.serial.enabled".into(), json!(!fp.block_device_apis));
    prefs.insert("dom.webmidi.enabled".into(), json!(!fp.block_device_apis));

    // --- Sensors / battery -------------------------------------------------
    prefs.insert(
        "device.sensors.enabled".into(),
        json!(!fp.disable_sensor_apis),
    );
    prefs.insert("dom.battery.enabled".into(), json!(!fp.disable_battery_api));

    // --- Language / timezone normalization ---------------------------------
    prefs.insert("intl.accept_languages".into(), json!(fp.primary_language));
    prefs.insert("javascript.use_us_english_locale".into(), json!(true));

    // --- Telemetry / studies / phone-home OFF (spec §6) --------------------
    prefs.insert("toolkit.telemetry.enabled".into(), json!(false));
    prefs.insert("toolkit.telemetry.unified".into(), json!(false));
    prefs.insert("toolkit.telemetry.archive.enabled".into(), json!(false));
    prefs.insert(
        "datareporting.healthreport.uploadEnabled".into(),
        json!(false),
    );
    prefs.insert(
        "datareporting.policy.dataSubmissionEnabled".into(),
        json!(false),
    );
    prefs.insert("app.shield.optoutstudies.enabled".into(), json!(false));
    prefs.insert(
        "browser.newtabpage.activity-stream.feeds.telemetry".into(),
        json!(false),
    );
    prefs.insert(
        "browser.newtabpage.activity-stream.telemetry".into(),
        json!(false),
    );

    // --- Sync OFF (spec §6) ------------------------------------------------
    prefs.insert("identity.fxaccounts.enabled".into(), json!(false));
    prefs.insert("services.sync.enabled".into(), json!(false));

    // --- Updater OFF (host mode: Aegis controls the binary, spec §6) -------
    prefs.insert("app.update.enabled".into(), json!(false));
    prefs.insert("app.update.auto".into(), json!(false));
    prefs.insert("app.update.service.enabled".into(), json!(false));
    prefs.insert("extensions.update.enabled".into(), json!(false));
    prefs.insert("browser.search.update".into(), json!(false));

    Ok(prefs)
}

/// Render the Firefox command line for a request. Pure.
///
/// `-no-remote` + `-new-instance` guarantee a *fresh, isolated* Firefox that
/// never joins an already-running instance (which would ignore our proxy/prefs);
/// `-profile <user_data_dir>` pins the isolated profile whose `user.js` we write.
fn render_command_line(req: &BrowserLaunchRequest) -> Vec<String> {
    vec![
        "-no-remote".to_string(),
        "-new-instance".to_string(),
        "-profile".to_string(),
        req.user_data_dir.display().to_string(),
    ]
}

/// Serialize a `user.js` pref set into the Firefox `user_pref("key", value);`
/// text format. Pure — no I/O.
///
/// Each entry becomes one `user_pref(...)` line; JSON values serialize to their
/// JS literal (booleans, numbers, and JSON-escaped strings), which is exactly the
/// `user.js` syntax Firefox parses.
#[must_use]
pub fn render_user_js(preferences: &BTreeMap<String, Value>) -> String {
    let mut out = String::from(
        "// Generated by Aegis Private Browser. Do not edit; regenerated on every launch.\n",
    );
    for (key, value) in preferences {
        // serde_json renders booleans/numbers as JS literals and strings with
        // the required double quotes + escaping — matching user.js syntax.
        out.push_str(&format!("user_pref(\"{key}\", {value});\n"));
    }
    out
}

/// Write the rendered `user.js` into the Firefox profile directory, creating the
/// directory if needed. This MUST run before Firefox is launched so the prefs
/// (proxy, resistFingerprinting, WebRTC off) take effect on startup.
///
/// # Errors
/// Returns [`Error::System`] if the profile directory or `user.js` cannot be
/// written.
pub async fn write_user_js(
    user_data_dir: &Path,
    preferences: &BTreeMap<String, Value>,
) -> Result<()> {
    tokio::fs::create_dir_all(user_data_dir)
        .await
        .map_err(|e| {
            Error::System(format!(
                "failed to create Firefox profile dir {}: {e}",
                user_data_dir.display()
            ))
        })?;
    let path = user_data_dir.join(PREFS_FILE);
    let body = render_user_js(preferences);
    tokio::fs::write(&path, body).await.map_err(|e| {
        Error::System(format!(
            "failed to write Firefox {} at {}: {e}",
            PREFS_FILE,
            path.display()
        ))
    })?;
    Ok(())
}

/// Free function so callers/tests can render without constructing a runner.
///
/// # Errors
/// Propagates a malformed fingerprint policy or proxy endpoint as
/// [`Error::Config`], and any [`BackendPolicyBundle::assert_safe`] failure.
pub fn render_firefox_policy(req: &BrowserLaunchRequest) -> Result<BackendPolicyBundle> {
    // Fail closed on a malformed fingerprint policy, same as Chromium.
    if let Some(reason) = req.fingerprint.validate() {
        return Err(Error::Config(format!(
            "invalid fingerprint policy: {reason}"
        )));
    }
    let bundle = BackendPolicyBundle {
        backend: BrowserBackendId::Firefox,
        managed_policies: BTreeMap::new(),
        command_line: render_command_line(req),
        preferences: render_preferences(req)?,
    };
    bundle.assert_safe(req.production)?;
    Ok(bundle)
}

#[async_trait]
impl<R: BrowserRunner> BrowserBackend for FirefoxBackend<R> {
    fn id(&self) -> BrowserBackendId {
        BrowserBackendId::Firefox
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            // Letterboxing is the headline feature of the Tor/Mullvad line.
            letterboxing: true,
            site_isolation: true,
            renderer_sandbox: true,
            webrtc_policy: true,
        }
    }

    fn render_policy(&self, req: &BrowserLaunchRequest) -> Result<BackendPolicyBundle> {
        render_firefox_policy(req)
    }

    async fn launch(
        &self,
        req: &BrowserLaunchRequest,
        bundle: &BackendPolicyBundle,
    ) -> Result<BrowserHandle> {
        // Never trust a caller-supplied bundle blindly: re-vet it before launch.
        bundle.assert_safe(req.production)?;
        if bundle.backend != BrowserBackendId::Firefox {
            return Err(Error::Config(
                "bundle backend does not match FirefoxBackend".to_string(),
            ));
        }

        // The user.js MUST exist in the profile dir before Firefox starts, or the
        // proxy/hardening prefs would not apply on first launch.
        write_user_js(&req.user_data_dir, &bundle.preferences).await?;

        let spec = self.launch_spec(req, bundle);
        let token = self.runner.start(&self.slug, &spec).await?;
        Ok(BrowserHandle {
            session: req.session,
            backend: BrowserBackendId::Firefox,
            process_token: token,
        })
    }

    async fn is_running(&self, handle: &BrowserHandle) -> Result<bool> {
        self.runner.is_running(&handle.process_token).await
    }

    async fn terminate(&self, handle: &BrowserHandle) -> Result<()> {
        self.runner.stop(&handle.process_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;
    use aegis_core::config::RenderMode;
    use aegis_core::fingerprint::FingerprintPolicy;
    use aegis_core::ids::{ProfileId, SessionId};
    use aegis_core::permissions::PermissionPolicy;
    use std::path::PathBuf;

    fn request(fp: FingerprintPolicy) -> BrowserLaunchRequest {
        request_with_dir(fp, "/profile")
    }

    fn request_with_dir(fp: FingerprintPolicy, dir: &str) -> BrowserLaunchRequest {
        BrowserLaunchRequest {
            session: SessionId::new(),
            profile: ProfileId::new(),
            user_data_dir: PathBuf::from(dir),
            fingerprint: fp,
            permissions: PermissionPolicy::secure_default(),
            proxy_endpoint: "socks5://127.0.0.1:9050".into(),
            render_mode: RenderMode::Software,
            production: true,
        }
    }

    fn cmd_has(cmd: &[String], needle: &str) -> bool {
        cmd.iter().any(|a| a == needle)
    }

    #[test]
    fn id_and_capabilities() {
        let b = FirefoxBackend::new();
        assert_eq!(b.id(), BrowserBackendId::Firefox);
        let caps = b.capabilities();
        assert!(caps.letterboxing);
        assert!(caps.site_isolation);
        assert!(caps.webrtc_policy);
    }

    #[test]
    fn render_policy_sets_socks_proxy_from_endpoint() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::balanced()))
            .unwrap();
        let p = &bundle.preferences;
        // Routed through the host SOCKS proxy, port parsed from the endpoint.
        assert_eq!(p["network.proxy.type"], json!(1));
        assert_eq!(p["network.proxy.socks"], json!("127.0.0.1"));
        assert_eq!(p["network.proxy.socks_port"], json!(9050));
        assert_eq!(p["network.proxy.socks_version"], json!(5));
        assert_eq!(p["network.proxy.socks_remote_dns"], json!(true));
    }

    #[test]
    fn socks_port_parsed_from_alternate_endpoint() {
        let b = FirefoxBackend::new();
        let mut req = request(FingerprintPolicy::balanced());
        // Tor Browser bundle SOCKS port, no scheme.
        req.proxy_endpoint = "127.0.0.1:9150".into();
        let bundle = b.render_policy(&req).unwrap();
        assert_eq!(bundle.preferences["network.proxy.socks_port"], json!(9150));
        assert_eq!(
            bundle.preferences["network.proxy.socks"],
            json!("127.0.0.1")
        );
    }

    #[test]
    fn render_policy_disables_webrtc_and_enables_resist_fingerprinting() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::balanced()))
            .unwrap();
        let p = &bundle.preferences;
        assert_eq!(p["media.peerconnection.enabled"], json!(false));
        assert_eq!(p["privacy.resistFingerprinting"], json!(true));
        // Telemetry / sync / updater all off.
        assert_eq!(p["toolkit.telemetry.enabled"], json!(false));
        assert_eq!(p["services.sync.enabled"], json!(false));
        assert_eq!(p["app.update.enabled"], json!(false));
    }

    #[test]
    fn command_line_launches_firefox_with_profile_and_no_forbidden() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request_with_dir(
                FingerprintPolicy::balanced(),
                "/home/user/.aegis/ff-profile",
            ))
            .unwrap();
        assert!(cmd_has(&bundle.command_line, "-no-remote"));
        assert!(cmd_has(&bundle.command_line, "-new-instance"));
        assert!(cmd_has(&bundle.command_line, "-profile"));
        assert!(cmd_has(
            &bundle.command_line,
            "/home/user/.aegis/ff-profile"
        ));
        // -profile is immediately followed by the dir.
        let idx = bundle
            .command_line
            .iter()
            .position(|a| a == "-profile")
            .unwrap();
        assert_eq!(bundle.command_line[idx + 1], "/home/user/.aegis/ff-profile");
        // No forbidden Chromium-style flags; assert_safe passes.
        assert!(!cmd_has(&bundle.command_line, "--no-sandbox"));
        assert!(!cmd_has(&bundle.command_line, "--disable-web-security"));
        assert!(bundle.assert_safe(true).is_ok());
    }

    #[test]
    fn strict_enables_letterboxing_and_disables_webgl() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::strict()))
            .unwrap();
        let p = &bundle.preferences;
        assert_eq!(p["privacy.resistFingerprinting.letterboxing"], json!(true));
        assert_eq!(p["webgl.disabled"], json!(true));
        assert_eq!(p["dom.webgpu.enabled"], json!(false));
        assert_eq!(p["dom.webusb.enabled"], json!(false));
    }

    #[test]
    fn balanced_keeps_webgl_enabled_and_no_letterbox() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::balanced()))
            .unwrap();
        assert_eq!(bundle.preferences["webgl.disabled"], json!(false));
        assert_eq!(
            bundle.preferences["privacy.resistFingerprinting.letterboxing"],
            json!(false)
        );
    }

    #[test]
    fn invalid_proxy_endpoint_is_rejected() {
        let b = FirefoxBackend::new();
        let mut req = request(FingerprintPolicy::balanced());
        req.proxy_endpoint = "socks5://no-port-here".into();
        let e = b.render_policy(&req).unwrap_err();
        assert!(matches!(e, Error::Config(_)));
    }

    #[test]
    fn invalid_fingerprint_policy_is_rejected() {
        let b = FirefoxBackend::new();
        let mut req = request(FingerprintPolicy::strict());
        req.fingerprint.webgpu_enabled = true; // violates a Strict invariant
        let e = b.render_policy(&req).unwrap_err();
        assert!(matches!(e, Error::Config(_)));
    }

    #[test]
    fn render_user_js_produces_user_pref_lines() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::balanced()))
            .unwrap();
        let text = render_user_js(&bundle.preferences);
        assert!(text.contains(r#"user_pref("network.proxy.type", 1);"#));
        assert!(text.contains(r#"user_pref("network.proxy.socks", "127.0.0.1");"#));
        assert!(text.contains(r#"user_pref("network.proxy.socks_port", 9050);"#));
        assert!(text.contains(r#"user_pref("media.peerconnection.enabled", false);"#));
        assert!(text.contains(r#"user_pref("privacy.resistFingerprinting", true);"#));
    }

    #[tokio::test]
    async fn launch_without_runner_is_unsupported() {
        let b = FirefoxBackend::new();
        let req = request(FingerprintPolicy::balanced());
        let bundle = b.render_policy(&req).unwrap();
        let e = b.launch(&req, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)));
    }

    #[tokio::test]
    async fn launch_with_runner_writes_user_js_and_returns_handle() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join("ff-profile");
        let b = FirefoxBackend::with_runner(MockRunner::new(), "firefox", "host");
        let req = request_with_dir(FingerprintPolicy::balanced(), profile_dir.to_str().unwrap());
        let bundle = b.render_policy(&req).unwrap();

        let handle = b.launch(&req, &bundle).await.unwrap();
        assert_eq!(handle.backend, BrowserBackendId::Firefox);
        assert!(!handle.process_token.is_empty());

        // The user.js was written into the profile dir BEFORE launch, containing
        // the SOCKS proxy prefs.
        let user_js = std::fs::read_to_string(profile_dir.join(PREFS_FILE)).unwrap();
        assert!(user_js.contains(r#"user_pref("network.proxy.socks_port", 9050);"#));
        assert!(user_js.contains(r#"user_pref("media.peerconnection.enabled", false);"#));

        // The runner saw the firefox command line with -profile.
        let launched = b.runner.launched();
        let (_, spec) = &launched[0];
        assert!(cmd_has(&spec.args, "-no-remote"));
        assert!(cmd_has(&spec.args, "-profile"));

        // Lifecycle works through the runner.
        assert!(b.is_running(&handle).await.unwrap());
        b.terminate(&handle).await.unwrap();
        assert!(!b.is_running(&handle).await.unwrap());
    }

    #[tokio::test]
    async fn launch_rejects_bundle_from_wrong_backend() {
        let b = FirefoxBackend::with_runner(MockRunner::new(), "firefox", "host");
        let req = request(FingerprintPolicy::balanced());
        let mut bundle = b.render_policy(&req).unwrap();
        bundle.backend = BrowserBackendId::Chromium;
        let e = b.launch(&req, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::Config(_)));
    }
}
