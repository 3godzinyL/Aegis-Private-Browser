//! The Firefox/Mullvad backend stub (planned, spec §6 Variant A).
//!
//! The MVP ships Chromium; the Firefox/Mullvad backend is *planned* because the
//! Tor/Mullvad line brings mature anti-fingerprinting (letterboxing, timer
//! coarsening, font/device restriction, first-party isolation) to a larger
//! shared-fingerprint anonymity set (spec §6 "Wariant A").
//!
//! This stub exists so the daemon can already reason about the backend's
//! capabilities and even render `arkenfox`-style preferences, while
//! [`FirefoxBackend::launch`] returns [`aegis_core::Error::Unsupported`] until the
//! backend is finished. Everything here is pure/host-independent, so it compiles
//! and is unit-tested on any platform.

use aegis_core::browser::{
    BackendCapabilities, BackendPolicyBundle, BrowserBackendId, BrowserHandle, BrowserLaunchRequest,
};
use aegis_core::error::{Error, Result};
use aegis_core::fingerprint::{LetterboxMode, ProtectionLevel, WebGlMode};
use aegis_core::traits::BrowserBackend;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The preferences filename the launcher would write into the Firefox profile.
pub const PREFS_FILE: &str = "user.js";

/// The planned Firefox/Mullvad backend.
///
/// `render_policy` emits `arkenfox`-style hardening preferences derived from the
/// fingerprint policy; `launch`/`is_running`/`terminate` are not yet implemented
/// and fail closed with [`Error::Unsupported`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct FirefoxBackend;

impl FirefoxBackend {
    /// Construct the (planned) Firefox backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// The reason string used by the not-yet-implemented lifecycle methods.
const NOT_YET: &str =
    "Firefox/Mullvad backend is planned (spec §6 Variant A) and not yet implemented";

/// Render arkenfox-style hardening preferences from the fingerprint policy. Pure.
fn render_preferences(req: &BrowserLaunchRequest) -> BTreeMap<String, Value> {
    let fp = &req.fingerprint;
    let mut prefs: BTreeMap<String, Value> = BTreeMap::new();

    // Core Tor-uplift resist-fingerprinting switch and its letterboxing.
    prefs.insert("privacy.resistFingerprinting".into(), json!(true));
    prefs.insert(
        "privacy.resistFingerprinting.letterboxing".into(),
        json!(matches!(fp.letterbox, LetterboxMode::On) || fp.level == ProtectionLevel::Strict),
    );
    prefs.insert("privacy.firstparty.isolate".into(), json!(true));

    // WebRTC: keep it from leaking the local interface; the network layer forces
    // everything through the gateway.
    prefs.insert("media.peerconnection.ice.no_host".into(), json!(true));
    prefs.insert(
        "media.peerconnection.ice.default_address_only".into(),
        json!(true),
    );

    // Telemetry / studies / phone-home off (spec §6).
    prefs.insert("toolkit.telemetry.enabled".into(), json!(false));
    prefs.insert("toolkit.telemetry.unified".into(), json!(false));
    prefs.insert(
        "datareporting.healthreport.uploadEnabled".into(),
        json!(false),
    );
    prefs.insert("app.shield.optoutstudies.enabled".into(), json!(false));
    prefs.insert(
        "browser.newtabpage.activity-stream.feeds.telemetry".into(),
        json!(false),
    );

    // WebGL / WebGPU per fingerprint policy.
    let webgl_disabled = matches!(fp.webgl, WebGlMode::Disabled);
    prefs.insert("webgl.disabled".into(), json!(webgl_disabled));
    prefs.insert("dom.webgpu.enabled".into(), json!(fp.webgpu_enabled));

    // Device APIs blocked (spec §7).
    prefs.insert(
        "dom.webbluetooth.enabled".into(),
        json!(!fp.block_device_apis),
    );
    prefs.insert("dom.webusb.enabled".into(), json!(!fp.block_device_apis));
    prefs.insert("dom.serial.enabled".into(), json!(!fp.block_device_apis));
    prefs.insert("dom.webmidi.enabled".into(), json!(!fp.block_device_apis));

    // Sensors / battery.
    prefs.insert(
        "device.sensors.enabled".into(),
        json!(!fp.disable_sensor_apis),
    );
    prefs.insert("dom.battery.enabled".into(), json!(!fp.disable_battery_api));

    // Language / timezone normalization.
    prefs.insert("intl.accept_languages".into(), json!(fp.primary_language));
    prefs.insert("javascript.use_us_english_locale".into(), json!(true));

    prefs
}

#[async_trait]
impl BrowserBackend for FirefoxBackend {
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
        // Fail closed on a malformed fingerprint policy, same as Chromium.
        if let Some(reason) = req.fingerprint.validate() {
            return Err(Error::Config(format!(
                "invalid fingerprint policy: {reason}"
            )));
        }
        let bundle = BackendPolicyBundle {
            backend: BrowserBackendId::Firefox,
            managed_policies: BTreeMap::new(),
            command_line: Vec::new(),
            preferences: render_preferences(req),
        };
        bundle.assert_safe(req.production)?;
        Ok(bundle)
    }

    async fn launch(
        &self,
        _req: &BrowserLaunchRequest,
        _bundle: &BackendPolicyBundle,
    ) -> Result<BrowserHandle> {
        Err(Error::Unsupported(NOT_YET.to_string()))
    }

    async fn is_running(&self, _handle: &BrowserHandle) -> Result<bool> {
        Err(Error::Unsupported(NOT_YET.to_string()))
    }

    async fn terminate(&self, _handle: &BrowserHandle) -> Result<()> {
        Err(Error::Unsupported(NOT_YET.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::config::RenderMode;
    use aegis_core::fingerprint::FingerprintPolicy;
    use aegis_core::ids::{ProfileId, SessionId};
    use aegis_core::permissions::PermissionPolicy;
    use std::path::PathBuf;

    fn request(fp: FingerprintPolicy) -> BrowserLaunchRequest {
        BrowserLaunchRequest {
            session: SessionId::new(),
            profile: ProfileId::new(),
            user_data_dir: PathBuf::from("/profile"),
            fingerprint: fp,
            permissions: PermissionPolicy::secure_default(),
            proxy_endpoint: "socks5://10.152.152.10:9050".into(),
            render_mode: RenderMode::Software,
            production: true,
        }
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
    fn render_policy_emits_arkenfox_prefs_for_strict() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::strict()))
            .unwrap();
        let p = &bundle.preferences;
        assert_eq!(p["privacy.resistFingerprinting"], json!(true));
        assert_eq!(p["privacy.resistFingerprinting.letterboxing"], json!(true));
        assert_eq!(p["webgl.disabled"], json!(true));
        assert_eq!(p["dom.webgpu.enabled"], json!(false));
        assert_eq!(p["dom.webusb.enabled"], json!(false));
        assert_eq!(p["toolkit.telemetry.enabled"], json!(false));
        // An empty command line still passes the forbidden-flag check.
        assert!(bundle.assert_safe(true).is_ok());
    }

    #[test]
    fn balanced_keeps_webgl_enabled_in_prefs() {
        let b = FirefoxBackend::new();
        let bundle = b
            .render_policy(&request(FingerprintPolicy::balanced()))
            .unwrap();
        assert_eq!(bundle.preferences["webgl.disabled"], json!(false));
        assert_eq!(bundle.preferences["dom.webgpu.enabled"], json!(false));
    }

    #[tokio::test]
    async fn launch_is_unsupported() {
        let b = FirefoxBackend::new();
        let req = request(FingerprintPolicy::balanced());
        let bundle = b.render_policy(&req).unwrap();
        let e = b.launch(&req, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)));

        let handle = BrowserHandle {
            session: req.session,
            backend: BrowserBackendId::Firefox,
            process_token: "x".into(),
        };
        assert!(matches!(
            b.is_running(&handle).await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            b.terminate(&handle).await.unwrap_err(),
            Error::Unsupported(_)
        ));
    }
}
