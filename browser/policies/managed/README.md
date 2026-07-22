# Aegis managed Chromium policies — key reference

This directory holds the two Chromium **enterprise managed-policy** documents
Aegis installs into the Browser VM:

| File | Protection level (`aegis_core::fingerprint::ProtectionLevel`) |
|------|--------------------------------------------------------------|
| `balanced.json` | `Balanced` — normalization on, most sites work |
| `strict.json`   | `Strict` — stronger uniformity, more breakage |

All keys below are **real Chromium enterprise policies**
(<https://chromeenterprise.google/policies/>). They are applied via the OS
managed-policy channel **inside the Browser VM**, e.g. on Linux at
`/etc/chromium/policies/managed/<file>.json`. Because they are *mandatory*
managed policies, the enrolled user cannot override them from `chrome://settings`.

> These files do **not** perform fingerprint normalization. Letterboxing,
> timer coarsening, font limiting, Canvas/WebGL/WebGPU control, timezone/language
> pinning and `hardwareConcurrency` clamping are done by the C++ patch set in
> `../../chromium-patches/` (a policy JSON cannot change those web APIs). This
> file governs the **account, telemetry, permission and network surface** only.
> The two layers are complementary and both are required by spec §7/§10/§16.

Guard-setting integer values used below (Chromium convention):

* `1` = allow / ask depending on the setting family
* `2` = **block**
* For the device *guard* families (`WebBluetoothGuard`, `WebUsbGuard`,
  `SerialGuard`, `WebHidGuard`, `FileSystem*Guard`), `2` = "Do not allow any
  site to request access" — the hard block the spec (§9) and
  `permissions::Feature::is_hard_blocked` demand.

---

## Account / sync removal (spec §6: "usunąć logowanie i synchronizację z kontem Google")

| Key | Value | Why |
|-----|-------|-----|
| `SyncDisabled` | `true` | Turns off Chrome Sync entirely — no profile data leaves the VM to a Google account. |
| `BrowserSignin` | `0` | Disables browser sign-in (0 = disabled). A signed-in profile would be a cross-session identifier tied to a real account. |
| `SigninAllowed` | `false` | Belt-and-suspenders with `BrowserSignin`; blocks the sign-in UI. |
| `SyncTypesListDisabled` | list | Explicitly disables every syncable data type so nothing can be synced even if a future build re-enabled sign-in. |

## Telemetry / metrics removal (spec §6: "wyłączyć niepotrzebną telemetrię"; §10)

| Key | Value | Why |
|-----|-------|-----|
| `MetricsReportingEnabled` | `false` | Core UMA/crash metrics reporting off — required by the task. |
| `UserFeedbackAllowed`, `FeedbackSurveysEnabled` | `false` | No feedback/survey uploads. |
| `DeviceMetricsReportingEnabled` | `false` | No device-level metrics. |
| `UrlKeyedAnonymizedDataCollectionEnabled` | `false` | Disables URL-keyed anonymized data collection (page-content signals). |
| `SpellCheckServiceEnabled` | `false` | No text sent to Google's spell-check service. |
| `SearchSuggestEnabled` | `false` | No keystroke-by-keystroke suggestion queries to the search provider. |
| `AutofillAddressEnabled`, `AutofillCreditCardEnabled`, `PaymentMethodQueryEnabled` | `false` | No stored PII / payment identifiers (spec §1: "nie podawać prawdziwych danych"). |
| `DomainReliabilityAllowed` | `false` | Disables Google's Domain Reliability beaconing. |
| `ShoppingListEnabled` | `false` | No shopping/price-tracking phone-home. |

## No remote debugging (spec §10, §16: "brak zdalnego debugowania w buildach produkcyjnych")

| Key | Value | Why |
|-----|-------|-----|
| `RemoteDebuggingAllowed` | `false` | Hard-blocks `--remote-debugging-port`/`-pipe` even if the flag is somehow present. Mirrors `browser::BackendPolicyBundle::assert_safe(production=true)` in Rust. |
| `RemoteAccessHostFirewallTraversal` | `false` | No Chrome Remote Desktop firewall traversal. |
| `DeveloperToolsAvailability` | `1` | 1 = DevTools disabled on force-installed extensions; combined with `RemoteDebuggingAllowed=false` there is no CDP surface exposed on a network interface (spec §10). |

## Device / sensor guards (spec §9 default table; §7 "zablokowane API Bluetooth, USB, Serial, HID i MIDI")

| Key | Value | Maps to |
|-----|-------|---------|
| `DefaultWebBluetoothGuardSetting` | `2` | `Feature::Bluetooth` = `Block` (hard-blocked) |
| `DefaultWebUsbGuardSetting` | `2` | `Feature::Usb` = `Block` (hard-blocked) |
| `DefaultSerialGuardSetting` | `2` | `Feature::Serial` = `Block` (hard-blocked) |
| `DefaultWebHidGuardSetting` | `2` | `Feature::Hid` = `Block` (hard-blocked) |
| `DefaultSensorsSetting` | `2` | `FingerprintPolicy.disable_sensor_apis = true` |
| `DefaultGeolocationSetting` | `2` | `Feature::Location` = `Block` |
| `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | `2` | `Feature::FileSystemAccess` = `ConfinedToVm`. The managed guard blocks the *web* File System Access API entirely; any in-VM confined directory access is mediated by the launcher, not by web pages. |
| `DefaultClipboardSetting` | `2` | `Feature::ClipboardRead` = `Block` |
| `DefaultLocalFontsSetting` | `2` | Blocks the `local-fonts` permission → no host/VM font enumeration via the Local Font Access API (spec §7 "brak wyliczania fontów"). Complements the C++ font-limiting patch. |
| `DefaultWindowManagementSetting` | `2` | Blocks the Window Management API (multi-screen enumeration) — a screen-layout fingerprint vector. |

> **MIDI note:** Chromium has no dedicated `DefaultMidiGuardSetting` managed
> policy key. `Feature::Midi` (hard-blocked in Rust) is enforced by the patch
> set (Web MIDI SysEx is gated behind the sensors/permissions path we compile
> out in Strict and block by default); this is documented in
> `../../chromium-patches/README.md`. The policy layer covers Bluetooth/USB/
> Serial/HID; MIDI is covered at the C++ layer to keep enforcement complete.

## Camera / microphone / screen capture (spec §9: Camera/Mic = block)

| Key | Value | Maps to |
|-----|-------|---------|
| `AudioCaptureAllowed` | `false` | `Feature::Microphone` = `Block` |
| `VideoCaptureAllowed` | `false` | `Feature::Camera` = `Block` |
| `ScreenCaptureAllowed` | `false` | No `getDisplayMedia` — screen content is host-adjacent; blocked. |
| `AudioCaptureAllowedUrls`, `VideoCaptureAllowedUrls` | `[]` | No allow-list exceptions. |

(The VM also does not pass through any host camera/microphone — spec §4/§16 —
so these are defense-in-depth over an already-empty device set.)

## Notifications

| Key | Balanced | Strict | Maps to |
|-----|----------|--------|---------|
| `DefaultNotificationsSetting` | `2` (block) | `2` (block) | `Feature::Notifications` = `Ask` |

Spec §9 allows notifications to be **"ask or block"**. `aegis-core` defaults the
feature to `Ask`, but the *managed policy* pins it to `2` (block) in **both**
files as the safe default. If a deployment wants the "ask" behavior for
Balanced, change `balanced.json`'s `DefaultNotificationsSetting` to `3` (ask);
the launcher chooses the value from the resolved `PermissionState` so the two
stay consistent. The stricter block-by-default is intentional per spec §16
("priorytet: brak wycieku przed kompatybilnością").

## Safe Browsing

| Key | Value | Why |
|-----|-------|-----|
| `SafeBrowsingProtectionLevel` | `1` | **Standard** protection (1). Not `2` (Enhanced) because Enhanced sends more browsing data to Google — a telemetry/linkage vector we reject. Not `0` (off) because standard protection still guards against malicious pages (spec §2 "podstawowy złośliwy kod strony"). Standard uses the local hash-prefix database, minimizing phone-home. |
| `SafeBrowsingExtendedReportingEnabled` | `false` | No extended threat reports uploaded. |
| `SafeBrowsingProxiedRealTimeChecksAllowed` | `false` | No real-time URL lookups (those are per-navigation network calls that could correlate). |
| `SafeBrowsingSurveysEnabled`, `SafeBrowsingDeepScanningEnabled` | `false` | No surveys, no content upload for deep scanning. |
| `PasswordLeakDetectionEnabled` | `false` | No password-hash checks against Google's breach service. |

## WebRTC handling (spec §5, §14: "WebRTC nie ujawnia interfejsu hosta")

| Key | Value | Why |
|-----|-------|-----|
| `WebRtcLocalIpsAllowedUrls` | `[]` | Empty allow-list → **no** site may see local IPs via WebRTC (mDNS host candidates stay obfuscated). |
| `WebRtcUdpPortRange` | `""` | No pinned UDP range. |
| `WebRtcEventLogCollectionAllowed`, `WebRtcTextLogCollectionAllowed` | `false` | No WebRTC logs uploaded to Google. |
| `WebRtcAllowLegacyTLSProtocols` | `false` | No downgraded DTLS. |

> **The primary non-proxied-UDP block is NOT a managed-policy key** in current
> Chromium — the old `WebRtcUdpPortRange`/enterprise IP-handling policy was
> removed. Aegis forces `default_public_interface_only` / the equivalent of the
> legacy `disable_non_proxied_udp` behavior through a **managed pref + launch
> flag** so WebRTC cannot open plain UDP outside the gateway route. That
> mechanism, and why (leaks of the host/VM interface and real IP), is documented
> in `../README.md` under "WebRTC: disable_non_proxied_udp". The Gateway VM
> firewall (spec §5) is the authoritative backstop: even a WebRTC leak cannot
> reach the internet except through the tunnel.

## Cookie / network hardening (defense-in-depth for profile isolation, spec §8)

| Key | Value | Why |
|-----|-------|-----|
| `BlockThirdPartyCookies`, `ThirdPartyBlockingEnabled` | `true` | Third-party cookies blocked — reduces cross-site tracking within a session. |
| `DefaultThirdPartyStoragePartitioningSetting` | `1` | Storage partitioned by top-level site. |
| `DnsOverHttpsMode` | `"off"`, `BuiltInDnsClientEnabled` `false` | DNS must go through the **Gateway VM** resolver (spec §5, §14 "DNS nie wychodzi poza Gateway"); the browser must not open its own DoH channel that could bypass the gateway. |
| `NetworkPredictionOptions` | `2` | Disables predictive prefetch/preconnect — no speculative connections outside user intent. |
| `AlternateErrorPagesEnabled` | `false` | No error-page suggestions fetched from Google. |
| `HardwareAccelerationModeEnabled` | `true` (Balanced) / `false` (Strict) | Balanced keeps the virtio-gpu path for the virtual WebGL backend; Strict forces the software path (WebGL disabled), matching `WebGlMode::VirtualBackend` vs `Disabled`. |

## Product-noise / phone-home removal

`PromotionalTabsEnabled`, `WelcomePageOnOSUpgradeEnabled`, `BackgroundModeEnabled`,
`EnableMediaRouter`, `MediaRouterCastAllowLocalDiscovery` (no local network Cast
discovery — an LAN-fingerprint vector), the `PrivacySandbox*` topics/measurement
keys, `PasswordManagerEnabled`, `ImportAutofillFormData`/`ImportSavedPasswords`,
`DefaultBrowserSettingEnabled`, `TranslateEnabled` are all disabled to remove
background network calls, on-device profiling, and PII surfaces. `ComponentUpdatesEnabled`
stays `true` so security components (CRLSets, Safe Browsing lists) still update
(spec §10 "automatyczne aktualizacje bezpieczeństwa"). `ExtensionInstallBlocklist: ["*"]`
blocks all non-force-installed extensions (spec §16: privacy is enforced in the
browser, not via ad-hoc content scripts).
