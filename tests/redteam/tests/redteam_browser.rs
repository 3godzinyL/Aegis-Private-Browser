//! Red-team: the browser-policy properties (spec §15.5 WebRTC STUN, §15.7 media
//! devices) plus the §14 acceptance criterion "User-Agent matches the engine
//! (no spoofing)". Asserted against the pure
//! [`browser_launcher::render_chromium_policy`] output — the same bundle the
//! orchestrator launches — so no VM or browser is needed.

use aegis_core::browser::BrowserLaunchRequest;
use aegis_core::config::RenderMode;
use aegis_core::fingerprint::{FingerprintPolicy, ProtectionLevel};
use aegis_core::ids::{ProfileId, SessionId};
use aegis_core::permissions::{Feature, PermissionPolicy};
use browser_launcher::{render_chromium_policy, MANAGED_POLICY_FILE};
use serde_json::json;
use std::path::PathBuf;

/// Build a launch request for the given protection level (production build).
fn request(level: ProtectionLevel) -> BrowserLaunchRequest {
    let fingerprint = match level {
        ProtectionLevel::Balanced => FingerprintPolicy::balanced(),
        ProtectionLevel::Strict => FingerprintPolicy::strict(),
    };
    BrowserLaunchRequest {
        session: SessionId::new(),
        profile: ProfileId::new(),
        user_data_dir: PathBuf::from("/home/user/.aegis/profile"),
        fingerprint,
        permissions: PermissionPolicy::secure_default(),
        proxy_endpoint: "socks5://10.152.152.1:9050".to_string(),
        render_mode: RenderMode::Software,
        production: true,
    }
}

fn cmd_has(cmd: &[String], needle: &str) -> bool {
    cmd.iter().any(|a| a == needle)
}
fn cmd_has_prefix(cmd: &[String], prefix: &str) -> bool {
    cmd.iter().any(|a| a.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// §15.5 — WebRTC STUN attempt must not leak the host interface.
// ---------------------------------------------------------------------------

/// §15.5: the rendered command line forces WebRTC to block non-proxied UDP, so a
/// STUN candidate gathering attempt cannot surface the host interface. And the
/// bundle must never contain `--no-sandbox` / `--disable-web-security` (spec §16)
/// — `assert_safe` must pass for both protection levels.
#[test]
fn s15_5_webrtc_stun_is_blocked_and_bundle_is_safe() {
    for level in [ProtectionLevel::Balanced, ProtectionLevel::Strict] {
        let bundle = render_chromium_policy(&request(level)).expect("render ok");

        assert!(
            cmd_has(
                &bundle.command_line,
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
            ),
            "§15.5 ({level:?}): WebRTC must be pinned to disable_non_proxied_udp"
        );
        // All traffic is forced through the gateway proxy with no bypass, so even
        // proxied WebRTC cannot reach a host-visible interface.
        assert!(cmd_has_prefix(&bundle.command_line, "--proxy-server="));
        assert!(
            cmd_has(&bundle.command_line, "--proxy-bypass-list="),
            "§15.5: an empty bypass list means nothing escapes the proxy"
        );

        // Forbidden flags must never appear (spec §16).
        assert!(
            !cmd_has(&bundle.command_line, "--no-sandbox"),
            "§15.5: sandbox kept"
        );
        assert!(
            !cmd_has(&bundle.command_line, "--disable-web-security"),
            "§15.5: web security kept"
        );
        assert!(
            !cmd_has(&bundle.command_line, "--disable-site-isolation-trials"),
            "§15.5: Site Isolation kept"
        );
        assert!(
            !cmd_has_prefix(&bundle.command_line, "--remote-debugging"),
            "§15.5: no remote debugging in production"
        );

        // The single source of truth for "no forbidden flag".
        assert!(
            bundle.assert_safe(true).is_ok(),
            "§15.5 ({level:?}): assert_safe must pass"
        );
    }
}

/// §15.5: Site Isolation is strengthened, not weakened — the ruleset opts into
/// `--site-per-process` / StrictOriginIsolation.
#[test]
fn s15_5_site_isolation_is_strengthened() {
    let bundle = render_chromium_policy(&request(ProtectionLevel::Balanced)).unwrap();
    assert!(cmd_has(&bundle.command_line, "--site-per-process"));
    assert!(bundle
        .command_line
        .iter()
        .any(|a| a.contains("StrictOriginIsolation")));
}

// ---------------------------------------------------------------------------
// §15.7 — a site reading the media devices must be blocked.
// ---------------------------------------------------------------------------

/// §15.7: the managed enterprise policy blocks audio/video capture by default
/// (`AudioCaptureAllowed`/`VideoCaptureAllowed` == false) and blocks every device
/// guard class (Bluetooth/USB/Serial/HID). A page cannot obtain the host's
/// physical camera, microphone, or device list.
#[test]
fn s15_7_media_and_device_access_is_blocked() {
    let bundle = render_chromium_policy(&request(ProtectionLevel::Balanced)).unwrap();
    let doc = bundle
        .managed_policies
        .get(MANAGED_POLICY_FILE)
        .expect("managed policy document present");

    // Capture off by default.
    assert_eq!(
        doc["AudioCaptureAllowed"],
        json!(false),
        "§15.7: mic capture blocked"
    );
    assert_eq!(
        doc["VideoCaptureAllowed"],
        json!(false),
        "§15.7: camera capture blocked"
    );

    // Every hard device-guard class is blocked (== 2).
    for key in [
        "DefaultWebBluetoothGuardSetting",
        "DefaultWebUsbGuardSetting",
        "DefaultSerialGuardSetting",
        "DefaultHidGuardSetting",
        "DefaultWebHidGuardSetting",
    ] {
        assert_eq!(
            doc[key],
            json!(2),
            "§15.7: device guard {key} must be block(2)"
        );
    }

    // Sensors and geolocation are blocked too, so a page cannot enumerate them.
    assert_eq!(
        doc["DefaultSensorsSetting"],
        json!(2),
        "§15.7: sensors blocked"
    );
    assert_eq!(
        doc["DefaultGeolocationSetting"],
        json!(2),
        "§15.7: geolocation blocked"
    );
}

/// §15.7 (positive control): granting the camera/mic to the policy-default origin
/// flips only the capture flags — the hard device guards stay blocked regardless,
/// proving the guards are non-negotiable rather than merely defaulted.
#[test]
fn s15_7_device_guards_stay_blocked_even_when_capture_granted() {
    let mut req = request(ProtectionLevel::Balanced);
    req.permissions
        .grant("https://example.invalid", Feature::Camera)
        .unwrap();
    req.permissions
        .grant("https://example.invalid", Feature::Microphone)
        .unwrap();
    let bundle = render_chromium_policy(&req).unwrap();
    let doc = bundle.managed_policies.get(MANAGED_POLICY_FILE).unwrap();

    assert_eq!(doc["VideoCaptureAllowed"], json!(true));
    assert_eq!(doc["AudioCaptureAllowed"], json!(true));
    // Guards are unaffected — a granted capture never opens USB/HID/etc.
    assert_eq!(doc["DefaultWebUsbGuardSetting"], json!(2));
    assert_eq!(doc["DefaultHidGuardSetting"], json!(2));
}

// ---------------------------------------------------------------------------
// §14 acceptance — "wersja User-Agenta odpowiada wersji silnika" (no spoofing).
// ---------------------------------------------------------------------------

/// §14: the rendered command line must NOT spoof or override the User-Agent. The
/// spec is explicit (§7, §14): the UA keeps the real engine version and Aegis
/// does not fabricate one, so there must be no `--user-agent` flag (nor a managed
/// `UserAgent`/override policy) in the bundle.
#[test]
fn acceptance_user_agent_is_not_spoofed() {
    for level in [ProtectionLevel::Balanced, ProtectionLevel::Strict] {
        let bundle = render_chromium_policy(&request(level)).unwrap();

        // No UA override on the command line.
        assert!(
            !cmd_has_prefix(&bundle.command_line, "--user-agent"),
            "§14 ({level:?}): must not pass --user-agent (no UA spoofing)"
        );
        // Also reject the common typo'd/aliased variants just in case.
        assert!(
            !bundle
                .command_line
                .iter()
                .any(|a| a.to_ascii_lowercase().contains("useragent")
                    || a.to_ascii_lowercase().contains("user-agent")),
            "§14 ({level:?}): no argument may reference the user agent"
        );

        // No managed policy may pin/override the UA either.
        let doc = bundle.managed_policies.get(MANAGED_POLICY_FILE).unwrap();
        assert!(
            doc.get("UserAgent").is_none() && doc.get("UserAgentClientHintsEnabled").is_none(),
            "§14 ({level:?}): managed policy must not override the User-Agent"
        );
    }
}
