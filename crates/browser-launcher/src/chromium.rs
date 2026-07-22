//! The hardened Chromium backend (MVP, spec §6 Variant B / "Decyzja dla agenta").
//!
//! [`ChromiumBackend::render_policy`] is **pure**: it turns a
//! [`BrowserLaunchRequest`] into a [`BackendPolicyBundle`] (managed enterprise
//! policies + a vetted command line) with no I/O, so every guarantee can be
//! asserted by a unit test (spec §16: "każdą ochronę potwierdzić testem
//! automatycznym"). The rendered command line:
//!
//! * keeps the Chromium sandbox (never emits `--no-sandbox`),
//! * keeps Site Isolation (never `--disable-web-security` / disables isolation),
//! * pins `--user-data-dir` to the request's guest-side directory,
//! * forces *all* traffic through the gateway via `--proxy-server` with an empty
//!   bypass list, and blocks non-proxied UDP for WebRTC via
//!   `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` (spec §5),
//! * disables sync/telemetry/background-networking/first-run (spec §6),
//! * never includes `--remote-debugging*` in production builds (spec §16), and
//! * under Strict fingerprint policy disables WebGL and WebGPU (spec §7).
//!
//! The launch/terminate side effects are delegated to a [`BrowserRunner`].

use crate::runner::{BrowserRunner, LaunchSpec};
use aegis_core::browser::{
    BackendCapabilities, BackendPolicyBundle, BrowserBackendId, BrowserHandle, BrowserLaunchRequest,
};
use aegis_core::error::{Error, Result};
use aegis_core::fingerprint::{ProtectionLevel, WebGlMode};
use aegis_core::permissions::{Feature, PermissionState};
use aegis_core::traits::BrowserBackend;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The managed-policy filename Chromium reads from the managed-policy directory.
pub const MANAGED_POLICY_FILE: &str = "aegis-managed.json";

/// Content-setting values used in Chromium enterprise policies.
/// `2` means "block", `3` means "ask". (`1` is "allow".)
const SETTING_BLOCK: i64 = 2;
const SETTING_ASK: i64 = 3;

/// The hardened Chromium backend.
///
/// Construct with [`ChromiumBackend::new`], supplying the [`BrowserRunner`] that
/// performs the actual (VM-side) process control and the browser slug/program
/// used inside the guest.
pub struct ChromiumBackend<R: BrowserRunner> {
    runner: R,
    /// The executable name invoked inside the Browser VM.
    program: String,
    /// The Browser VM slug the runner addresses. Opaque, host-independent.
    vm_slug: String,
}

impl<R: BrowserRunner> std::fmt::Debug for ChromiumBackend<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChromiumBackend")
            .field("program", &self.program)
            .field("vm_slug", &self.vm_slug)
            .finish_non_exhaustive()
    }
}

impl<R: BrowserRunner> ChromiumBackend<R> {
    /// Create a backend bound to a runner, a guest-side program name, and the
    /// Browser VM slug the runner addresses.
    pub fn new(runner: R, program: impl Into<String>, vm_slug: impl Into<String>) -> Self {
        Self {
            runner,
            program: program.into(),
            vm_slug: vm_slug.into(),
        }
    }

    /// Build the [`LaunchSpec`] (program + args + env) for a vetted bundle.
    ///
    /// Timezone (`TZ`) and language (`LANG`/`LANGUAGE`) are applied via the
    /// environment per the fingerprint policy; the command line is taken verbatim
    /// from the already-vetted bundle.
    fn launch_spec(&self, req: &BrowserLaunchRequest, bundle: &BackendPolicyBundle) -> LaunchSpec {
        let fp = &req.fingerprint;
        let mut env = Vec::new();
        if let Some(tz) = &fp.timezone {
            env.push(("TZ".to_string(), tz.clone()));
        }
        // Language is set both on the command line (--lang) and via the locale
        // environment for a consistent Accept-Language and UI locale.
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

/// Render the vetted Chromium command line for a request. Pure.
fn render_command_line(req: &BrowserLaunchRequest) -> Vec<String> {
    let fp = &req.fingerprint;
    let mut args: Vec<String> = Vec::new();

    // --- Profile isolation -------------------------------------------------
    // Separate user-data-dir per profile/session (spec §6, §8). This path is a
    // guest-side path, never a host path.
    args.push(format!("--user-data-dir={}", req.user_data_dir.display()));

    // --- Force all traffic through the gateway (spec §5) --------------------
    // No bypass: the empty bypass list means *everything* (including localhost
    // for our purposes) is proxied. A single leaked direct connection defeats
    // the whole isolation, so we never emit a bypass entry.
    args.push(format!("--proxy-server={}", req.proxy_endpoint));
    // An empty bypass list means nothing is exempt from the proxy.
    args.push("--proxy-bypass-list=".to_string());

    // --- WebRTC: block non-proxied UDP (spec §5, §7) -----------------------
    args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string());

    // --- Kill sync / telemetry / phone-home (spec §6) ----------------------
    args.push("--disable-sync".to_string());
    args.push("--disable-background-networking".to_string());
    args.push("--disable-component-update".to_string());
    args.push("--disable-domain-reliability".to_string());
    args.push("--disable-breakpad".to_string());
    args.push("--no-pings".to_string());
    args.push("--no-default-browser-check".to_string());
    args.push("--no-first-run".to_string());
    args.push("--disable-first-run-ui".to_string());
    args.push("--metrics-recording-only".to_string());
    args.push("--disable-features=Translate,MediaRouter,OptimizationHints".to_string());

    // --- Keep security posture (documented so nobody "helpfully" flips it) --
    // Site Isolation strengthened, not weakened.
    args.push("--site-per-process".to_string());
    args.push("--enable-features=StrictOriginIsolation".to_string());

    // --- Fingerprint normalization (spec §7) -------------------------------
    // Language / Accept-Language.
    args.push(format!("--lang={}", fp.primary_language));
    args.push(format!("--accept-lang={}", fp.primary_language));

    // WebGL / WebGPU handling.
    let webgl_disabled = matches!(fp.webgl, WebGlMode::Disabled);
    if webgl_disabled {
        args.push("--disable-webgl".to_string());
        args.push("--disable-webgl2".to_string());
    }
    if !fp.webgpu_enabled {
        // Disable the WebGPU/Unsafe-WebGPU features explicitly.
        args.push("--disable-features=WebGPU,WebGPUService".to_string());
        args.push("--disable-webgpu".to_string());
    }

    // Suppress background/idle phone-home surfaces further under Strict.
    if fp.level == ProtectionLevel::Strict {
        args.push("--disable-3d-apis".to_string());
    }

    args
}

/// Map the effective permission state to a Chromium content-setting value.
fn content_setting(state: PermissionState) -> i64 {
    match state {
        PermissionState::Allow | PermissionState::ConfinedToVm | PermissionState::Limited => 1,
        PermissionState::Ask => SETTING_ASK,
        PermissionState::Block | PermissionState::Quarantine => SETTING_BLOCK,
    }
}

/// Render the enterprise managed policies for a request. Pure.
///
/// Derives capture/geolocation/notification/clipboard settings from
/// `req.permissions` where sensible, and hard-pins the non-negotiable hardening
/// (sync off, metrics off, signin off, remote debugging disallowed, all device
/// guards blocked).
fn render_managed_policies(req: &BrowserLaunchRequest) -> BTreeMap<String, Value> {
    let perms = &req.permissions;

    // The default origin used to resolve feature defaults for policy purposes.
    // Chromium's Default*Setting policies are global; per-origin grants are
    // applied at runtime through the permission table, not baked into the file.
    let default_origin = "https://example.invalid";
    let geo = perms.effective(default_origin, Feature::Location);
    let cam = perms.effective(default_origin, Feature::Camera);
    let mic = perms.effective(default_origin, Feature::Microphone);
    let notif = perms.effective(default_origin, Feature::Notifications);

    // Capture is only allowed if the resolved state is Allow; anything else
    // (Block/Ask) collapses to "not allowed" for the coarse boolean policies.
    let audio_allowed = matches!(mic, PermissionState::Allow);
    let video_allowed = matches!(cam, PermissionState::Allow);

    let policy = json!({
        // --- Account / sync / telemetry (spec §6) ---
        "SyncDisabled": true,
        "MetricsReportingEnabled": false,
        "BrowserSignin": 0,
        "RemoteDebuggingAllowed": false,
        "BackgroundModeEnabled": false,
        "PromotionalTabsEnabled": false,
        "SpellCheckServiceEnabled": false,
        "UrlKeyedAnonymizedDataCollectionEnabled": false,
        "SafeBrowsingExtendedReportingEnabled": false,

        // --- Geolocation / sensors (spec §7, §9) ---
        // 2 = block by default. Derived from permissions but never weaker than block.
        "DefaultGeolocationSetting": if matches!(geo, PermissionState::Allow) { 1 } else { SETTING_BLOCK },
        "DefaultSensorsSetting": SETTING_BLOCK,

        // --- Capture (spec §9) ---
        "AudioCaptureAllowed": audio_allowed,
        "VideoCaptureAllowed": video_allowed,

        // --- Hard-blocked device classes (spec §7, §9) — always 2 (block) ---
        "DefaultWebBluetoothGuardSetting": SETTING_BLOCK,
        "DefaultWebUsbGuardSetting": SETTING_BLOCK,
        "DefaultSerialGuardSetting": SETTING_BLOCK,
        "DefaultHidGuardSetting": SETTING_BLOCK,

        // --- Notifications (ask/block from permissions) ---
        "DefaultNotificationsSetting": content_setting(notif),

        // --- Clipboard / downloads hardening (spec §9) ---
        // Clipboard read blocked by default; sites cannot silently read it.
        "DefaultClipboardSetting": content_setting(perms.effective(default_origin, Feature::ClipboardRead)),
        // Prompt for the location of every download so nothing lands silently
        // (the daemon routes these to quarantine, spec §9).
        "PromptForDownloadLocation": true,
        "DownloadRestrictions": 0,

        // --- Extensions / external surfaces ---
        "DefaultPopupsSetting": SETTING_BLOCK,
        "DefaultInsecureContentSetting": SETTING_BLOCK,
        "BlockThirdPartyCookies": true,
    });

    // DefaultHidGuardSetting is not a real Chromium key in older versions; the
    // real one is "DefaultWebHidGuardSetting". Emit both to be robust, but the
    // spec/tests key on device guards == block, so include the canonical spec key.
    let mut obj = policy.as_object().cloned().unwrap_or_default();
    obj.insert(
        "DefaultWebHidGuardSetting".to_string(),
        json!(SETTING_BLOCK),
    );

    let mut out = BTreeMap::new();
    out.insert(MANAGED_POLICY_FILE.to_string(), Value::Object(obj));
    out
}

/// Free function so tests can render without constructing a runner.
///
/// # Errors
/// Propagates any [`BackendPolicyBundle::assert_safe`] failure.
pub fn render_chromium_policy(req: &BrowserLaunchRequest) -> Result<BackendPolicyBundle> {
    // Validate the fingerprint policy first — a malformed policy (e.g. Strict
    // exposing WebGPU) is a configuration error, fail closed.
    if let Some(reason) = req.fingerprint.validate() {
        return Err(Error::Config(format!(
            "invalid fingerprint policy: {reason}"
        )));
    }

    let bundle = BackendPolicyBundle {
        backend: BrowserBackendId::Chromium,
        managed_policies: render_managed_policies(req),
        command_line: render_command_line(req),
        preferences: BTreeMap::new(),
    };

    // The single source of truth for "no forbidden flag / no prod remote debug".
    bundle.assert_safe(req.production)?;
    Ok(bundle)
}

#[async_trait]
impl<R: BrowserRunner> BrowserBackend for ChromiumBackend<R> {
    fn id(&self) -> BrowserBackendId {
        BrowserBackendId::Chromium
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            // Chromium does not letterbox natively (that is a Firefox/Tor
            // feature); Aegis normalizes size at the fingerprint layer instead.
            letterboxing: false,
            site_isolation: true,
            renderer_sandbox: true,
            webrtc_policy: true,
        }
    }

    fn render_policy(&self, req: &BrowserLaunchRequest) -> Result<BackendPolicyBundle> {
        render_chromium_policy(req)
    }

    async fn launch(
        &self,
        req: &BrowserLaunchRequest,
        bundle: &BackendPolicyBundle,
    ) -> Result<BrowserHandle> {
        // Never trust a caller-supplied bundle blindly: re-vet it before we hand
        // anything to the runner (fail closed, spec §16).
        bundle.assert_safe(req.production)?;
        if bundle.backend != BrowserBackendId::Chromium {
            return Err(Error::Config(
                "bundle backend does not match ChromiumBackend".to_string(),
            ));
        }

        let spec = self.launch_spec(req, bundle);
        let token = self.runner.start(&self.vm_slug, &spec).await?;
        Ok(BrowserHandle {
            session: req.session,
            backend: BrowserBackendId::Chromium,
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

    fn request(level: ProtectionLevel, production: bool) -> BrowserLaunchRequest {
        let fp = match level {
            ProtectionLevel::Balanced => FingerprintPolicy::balanced(),
            ProtectionLevel::Strict => FingerprintPolicy::strict(),
        };
        BrowserLaunchRequest {
            session: SessionId::new(),
            profile: ProfileId::new(),
            user_data_dir: PathBuf::from("/home/user/.aegis/profile"),
            fingerprint: fp,
            permissions: PermissionPolicy::secure_default(),
            proxy_endpoint: "socks5://10.152.152.10:9050".to_string(),
            render_mode: RenderMode::Software,
            production,
        }
    }

    fn cmd_has(cmd: &[String], needle: &str) -> bool {
        cmd.iter().any(|a| a == needle)
    }
    fn cmd_has_prefix(cmd: &[String], prefix: &str) -> bool {
        cmd.iter().any(|a| a.starts_with(prefix))
    }

    #[test]
    fn balanced_command_line_has_core_flags_and_no_forbidden() {
        let req = request(ProtectionLevel::Balanced, true);
        let b = render_chromium_policy(&req).unwrap();

        assert!(cmd_has(
            &b.command_line,
            "--user-data-dir=/home/user/.aegis/profile"
        ));
        assert!(cmd_has(
            &b.command_line,
            "--proxy-server=socks5://10.152.152.10:9050"
        ));
        assert!(cmd_has(
            &b.command_line,
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
        ));
        assert!(cmd_has(&b.command_line, "--disable-sync"));

        // Forbidden flags must never appear.
        assert!(!cmd_has(&b.command_line, "--no-sandbox"));
        assert!(!cmd_has(&b.command_line, "--disable-web-security"));
        assert!(!cmd_has(&b.command_line, "--disable-site-isolation-trials"));
        // No remote debugging in production.
        assert!(!cmd_has_prefix(&b.command_line, "--remote-debugging"));

        // assert_safe must pass for the produced bundle.
        assert!(b.assert_safe(true).is_ok());
    }

    #[test]
    fn strict_reflects_webgl_and_webgpu_disabled() {
        let req = request(ProtectionLevel::Strict, true);
        let b = render_chromium_policy(&req).unwrap();

        assert!(cmd_has(&b.command_line, "--disable-webgl"));
        assert!(cmd_has(&b.command_line, "--disable-webgl2"));
        assert!(cmd_has(&b.command_line, "--disable-webgpu"));
        assert!(b
            .command_line
            .iter()
            .any(|a| a.contains("WebGPU") && a.starts_with("--disable-features")));

        // Still has the essentials and no forbidden flags.
        assert!(cmd_has(
            &b.command_line,
            "--user-data-dir=/home/user/.aegis/profile"
        ));
        assert!(cmd_has(
            &b.command_line,
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
        ));
        assert!(!cmd_has(&b.command_line, "--no-sandbox"));
        assert!(!cmd_has_prefix(&b.command_line, "--remote-debugging"));
        assert!(b.assert_safe(true).is_ok());
    }

    #[test]
    fn balanced_keeps_webgl_backend_enabled() {
        let req = request(ProtectionLevel::Balanced, false);
        let b = render_chromium_policy(&req).unwrap();
        // Balanced uses the virtual WebGL backend, so it must NOT disable WebGL.
        assert!(!cmd_has(&b.command_line, "--disable-webgl"));
        // WebGPU is off in both levels per the core policy.
        assert!(cmd_has(&b.command_line, "--disable-webgpu"));
    }

    #[test]
    fn managed_policies_are_hardened() {
        let req = request(ProtectionLevel::Balanced, true);
        let b = render_chromium_policy(&req).unwrap();
        let doc = b
            .managed_policies
            .get(MANAGED_POLICY_FILE)
            .expect("managed policy file present");

        assert_eq!(doc["SyncDisabled"], json!(true));
        assert_eq!(doc["MetricsReportingEnabled"], json!(false));
        assert_eq!(doc["BrowserSignin"], json!(0));
        assert_eq!(doc["RemoteDebuggingAllowed"], json!(false));
        assert_eq!(doc["DefaultGeolocationSetting"], json!(2));
        assert_eq!(doc["AudioCaptureAllowed"], json!(false));
        assert_eq!(doc["VideoCaptureAllowed"], json!(false));
        assert_eq!(doc["DefaultSensorsSetting"], json!(2));

        // Device guards all blocked (== 2).
        for k in [
            "DefaultWebBluetoothGuardSetting",
            "DefaultWebUsbGuardSetting",
            "DefaultSerialGuardSetting",
            "DefaultHidGuardSetting",
            "DefaultWebHidGuardSetting",
        ] {
            assert_eq!(doc[k], json!(2), "device guard {k} must be block(2)");
        }

        // Notifications default is Ask (3) from the secure default table.
        assert_eq!(doc["DefaultNotificationsSetting"], json!(3));
        // Clipboard read is blocked by default.
        assert_eq!(doc["DefaultClipboardSetting"], json!(2));
        // Downloads prompt for location (quarantine hardening).
        assert_eq!(doc["PromptForDownloadLocation"], json!(true));
    }

    #[test]
    fn capture_reflects_granted_permission() {
        let mut req = request(ProtectionLevel::Balanced, true);
        // Grant camera + mic for the policy-default origin used by the renderer.
        req.permissions
            .grant("https://example.invalid", Feature::Camera)
            .unwrap();
        req.permissions
            .grant("https://example.invalid", Feature::Microphone)
            .unwrap();
        let b = render_chromium_policy(&req).unwrap();
        let doc = b.managed_policies.get(MANAGED_POLICY_FILE).unwrap();
        assert_eq!(doc["VideoCaptureAllowed"], json!(true));
        assert_eq!(doc["AudioCaptureAllowed"], json!(true));
        // Device guards remain blocked regardless.
        assert_eq!(doc["DefaultWebUsbGuardSetting"], json!(2));
    }

    #[test]
    fn non_production_permits_no_debugging_but_allows_it_if_present() {
        // In dev builds render_policy does not itself add remote-debugging, but a
        // bundle that had it would still pass assert_safe(false).
        let req = request(ProtectionLevel::Balanced, false);
        let b = render_chromium_policy(&req).unwrap();
        assert!(!cmd_has_prefix(&b.command_line, "--remote-debugging"));
        assert!(b.assert_safe(false).is_ok());
    }

    #[test]
    fn production_render_with_debug_attempt_is_rejected() {
        // Simulate a caller trying to sneak remote debugging into a prod bundle:
        // assert_safe (called inside render + launch) must reject it.
        let req = request(ProtectionLevel::Balanced, true);
        let mut b = render_chromium_policy(&req).unwrap();
        b.command_line
            .push("--remote-debugging-port=9222".to_string());
        assert!(b.assert_safe(true).is_err());
    }

    #[test]
    fn invalid_fingerprint_policy_is_rejected() {
        let mut req = request(ProtectionLevel::Strict, true);
        // Corrupt the policy so it violates an invariant (WebGPU on in Strict).
        req.fingerprint.webgpu_enabled = true;
        let e = render_chromium_policy(&req).unwrap_err();
        assert!(matches!(e, Error::Config(_)));
    }

    #[tokio::test]
    async fn launch_returns_handle_and_lifecycle_works() {
        let backend = ChromiumBackend::new(MockRunner::new(), "chromium", "vm-browser-01");
        let req = request(ProtectionLevel::Strict, true);
        let bundle = backend.render_policy(&req).unwrap();

        let handle = backend.launch(&req, &bundle).await.unwrap();
        assert_eq!(handle.backend, BrowserBackendId::Chromium);
        assert_eq!(handle.session, req.session);
        assert!(!handle.process_token.is_empty());

        assert!(backend.is_running(&handle).await.unwrap());
        backend.terminate(&handle).await.unwrap();
        assert!(!backend.is_running(&handle).await.unwrap());
    }

    #[tokio::test]
    async fn launch_sets_tz_and_lang_env() {
        let runner = MockRunner::new();
        let backend = ChromiumBackend::new(runner, "chromium", "vm-1");
        let req = request(ProtectionLevel::Balanced, true);
        let bundle = backend.render_policy(&req).unwrap();
        let _ = backend.launch(&req, &bundle).await.unwrap();

        let launched = backend.runner_launched();
        let (_, spec) = &launched[0];
        assert!(spec.env.iter().any(|(k, v)| k == "TZ" && v == "UTC"));
        assert!(spec
            .env
            .iter()
            .any(|(k, v)| k == "LANGUAGE" && v == "en-US"));
        assert!(cmd_has(&spec.args, "--lang=en-US"));
    }

    #[tokio::test]
    async fn launch_rejects_tampered_bundle_in_production() {
        let backend = ChromiumBackend::new(MockRunner::new(), "chromium", "vm-1");
        let req = request(ProtectionLevel::Balanced, true);
        let mut bundle = backend.render_policy(&req).unwrap();
        bundle.command_line.push("--no-sandbox".to_string());
        let e = backend.launch(&req, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::Config(_)));
    }

    #[tokio::test]
    async fn launch_propagates_runner_failure() {
        let backend = ChromiumBackend::new(MockRunner::failing(), "chromium", "vm-1");
        let req = request(ProtectionLevel::Balanced, true);
        let bundle = backend.render_policy(&req).unwrap();
        let e = backend.launch(&req, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::System(_)));
    }

    // Small test accessor to reach the mock runner's recorded launches.
    impl ChromiumBackend<MockRunner> {
        fn runner_launched(&self) -> Vec<(String, crate::runner::LaunchSpec)> {
            self.runner.launched()
        }
    }
}
