# `browser/chromium-patches/` — fingerprint-NORMALIZATION patch set

This is the documented plan for the C++ changes Aegis makes to its Chromium fork
(spec §6 Variant B, §7, §16). Every control below is a **normalization**, not a
random spoof: values are chosen to make **every Aegis session of a given
`ProtectionLevel` look like every other one** — a large anonymity set — and are
**stable within a session** across all contexts. Nothing here fabricates
hardware the VM lacks (spec §4: no fake RTX/Radeon).

> **Governing rules (spec §16):**
> *"każdą modyfikację Chromium opisać i objąć testem regresji"* — every Chromium
> modification is documented (this file) **and** covered by a regression test.
> *"priorytet: brak wycieku przed kompatybilnością"* — leak-safety beats
> compatibility. The sandbox, Site Isolation, and the **real engine version in
> the User-Agent** are never touched (spec §6/§14).

## Non-negotiable invariants (apply to every control)

1. **Session-stable.** A value is computed once per session (seeded from the
   session key held in RAM, spec §8) and is identical for the lifetime of the
   session. It never jitters per call.
2. **Uniform across users.** The *value itself* is a shared constant for the
   level (e.g. `hardwareConcurrency = 2` in Strict), not a per-user random draw.
   The session seed only affects things that must differ between sessions to
   avoid cross-session linkage of the same disposable VM; where the spec wants a
   shared constant (timezone `UTC`, language `en-US`, font set), it is a literal
   constant, not seeded.
3. **Consistent across every context (spec §7 "Stabilizacja").** The same value
   is returned in: main frame, same-origin and cross-origin **iframes**,
   dedicated/shared **Workers**, **Service Workers**, **WebGL**, **Canvas**, and
   **AudioContext**. Implementation rule: each control is applied in the
   **browser process** or in `blink::RuntimeEnabledFeatures` / a value plumbed
   through `WebPreferences` / `content::WebContents`, **not** in a single
   renderer entry point — so worker and iframe execution contexts inherit the
   same value. Every regression test below has a *cross-context* case that opens
   the API from a Worker and an iframe and asserts equality with the main frame.
4. **No faked hardware.** Where the VM genuinely has no device (battery,
   sensors, cameras), the API is **absent/blocked**, not populated with a
   plausible lie. Where the VM has a real (virtual) value (CPU count, GPU
   backend), we **clamp/normalize** the real value rather than invent a
   different physical part.

## Where the tests live

Regression tests are Chromium-style tests plus Aegis web-platform assertions:

* `//content/test/...` and `//third_party/blink/web_tests/aegis/...` — the
  in-tree browser tests / web tests referenced as `RT-*` below.
* `tests/browser-api/` (repo root) — black-box assertions run against a real
  Browser VM in CI, cross-referenced by the same `RT-*` id (spec §14: WPT pass
  rate must stay acceptable; §15 red-team: Canvas in iframe/worker/main).

Each patch file in this directory is prefixed with the control name and carries a
header comment repeating its `RT-*` id.

---

## The controls

### 1. Letterboxing — window-size buckets

* **Goal.** Stop the exact content-area size from being a fingerprint; make many
  users report the same size (spec §7 "rozmiar treści okna zaokrąglany do
  wspólnych koszyków"). Strict only (`LetterboxMode::On`); Balanced reports the
  virtualized viewport (`Off`).
* **Approach.** Round the *layout viewport* the page sees down to the nearest
  bucket (e.g. 100×100 steps) and center the real render inside a neutral
  margin, exactly like Tor/Mullvad letterboxing. Values are shared buckets, not
  per-user. `innerWidth/innerHeight`, `screen.width/height/availWidth`,
  `visualViewport`, and `matchMedia` size queries all read the bucketed value.
* **Subsystem.** Blink layout / `LocalDOMWindow`, `Screen`, `VisualViewport`;
  the margin is drawn by the compositor. Bucket applied via `WebPreferences`.
* **Regression test — `RT-LETTERBOX`.** Set Strict, resize the VM window to
  several odd sizes; assert `innerWidth/innerHeight` are always multiples of the
  bucket and drawn from the shared bucket list. **Cross-context:** read the same
  values from an iframe and a Worker (`self.screen` is unavailable in workers, so
  the worker case asserts `devicePixelRatio` and any exposed size match the main
  frame). Assert Balanced is unbucketed but still host-independent.

### 2. Timer coarsening

* **Goal.** Remove high-resolution timing side channels used for
  cache/hardware fingerprinting (spec §7 "stała precyzja timerów").
* **Approach.** Clamp resolution of `performance.now()`, `Date.now`, timestamps
  in `PerformanceEntry`, `AudioContext.currentTime`, and event `timeStamp` to a
  **fixed** coarsening: `timer_coarsening_us` = 100 µs (Balanced) / 100 000 µs =
  100 ms (Strict). A **fixed** clamp, never randomized jitter (jitter is itself a
  signal and breaks stability rule 1).
* **Subsystem.** `blink::TimeClamper` (Blink `time_clamper.cc`), the
  `Performance` interface, and the worker/worklet variants so workers get the
  same clamp.
* **Regression test — `RT-TIMER`.** Call `performance.now()` in a tight loop;
  assert every delta is a multiple of the level's coarsening and that resolution
  never exceeds it. **Cross-context:** run the identical loop in a dedicated
  Worker, a Service Worker (`fetch` handler), and an `AudioWorklet`; assert the
  clamp value matches the main frame for the level.

### 3. Font set limiting + no host font enumeration

* **Goal.** Present one standard, uniform font set and never let a page discover
  which fonts exist (spec §7 "ograniczony standardowy zestaw fontów; brak
  wyliczania fontów hosta"). The VM ships only the standard set, so there are no
  host fonts to leak; the patch guarantees enumeration and fallback can't
  distinguish sessions.
* **Approach.** Restrict the font-matching backend to the bundled standard
  family list; make missing-font fallback deterministic; block the Local Font
  Access API (also blocked by `DefaultLocalFontsSetting=2` in the managed
  policy); ensure `@font-face`/measurement side channels (text-metrics,
  `measureText`) resolve against the fixed set only.
* **Subsystem.** Blink `FontCache` / `FontMatcher`, the platform font manager
  (`FontMgr`), and the Local Font Access module (disabled).
* **Regression test — `RT-FONTS`.** Probe a list of well-known
  system/OEM fonts via `document.fonts.check()` and via width-measurement; assert
  only the bundled standard families resolve and every non-standard probe returns
  the identical fallback metrics across two fresh sessions. **Cross-context:**
  measure the same string in an OffscreenCanvas in a Worker; assert identical
  metrics to the main frame. Assert Local Font Access `query()` rejects.

### 4. `mediaDevices` enumeration limiting

* **Goal.** Don't expose a device list that reveals VM/host media hardware or a
  stable per-machine device set (spec §7 "ograniczony dostęp do listy urządzeń
  multimedialnych"; §15 red-team "próbę odczytu urządzeń multimedialnych").
* **Approach.** `navigator.mediaDevices.enumerateDevices()` returns a
  **normalized, minimal** list (no camera/mic — capture is policy-blocked, so no
  real devices exist to enumerate), with empty/zeroed `deviceId`/`groupId`/
  `label` so no stable device identifier leaks. This reflects the true VM state
  (no capture devices), it does not invent devices.
* **Subsystem.** `content::MediaDevicesDispatcherHost` / `blink` MediaDevices;
  coordinated with the managed `AudioCaptureAllowed`/`VideoCaptureAllowed=false`.
* **Regression test — `RT-MEDIADEVICES`.** Call `enumerateDevices()`; assert no
  entries carry a non-empty `deviceId`/`groupId` and no camera/microphone
  `kind` appears, and that two sessions return identical shapes. **Cross-context:**
  call from an iframe and assert identity with the main frame.

### 5. Canvas readback control

* **Goal.** Prevent Canvas from being a per-machine hash while keeping rendering
  correct (spec §7 "kontrolowane odczyty Canvas i WebGL"; §15 "Canvas w iframe,
  workerze i głównym oknie").
* **Approach.** Balanced (`CanvasMode::Passthrough`): pass the virtualized
  renderer output through unchanged — it is already host-independent (software /
  virtio-gpu). Strict (`CanvasMode::Limited`): apply a **session-stable**
  transform to readback (`toDataURL`, `getImageData`, `toBlob`,
  `OffscreenCanvas.convertToBlob`) so the value is uniform for the session and
  identical across contexts, never a per-read random. The transform is derived
  once from the session seed, so a page reading twice gets the same bytes.
* **Subsystem.** Blink `CanvasRenderingContext2D` / `HTMLCanvasElement` readback,
  `OffscreenCanvas`, and the image-data path shared with Workers.
* **Regression test — `RT-CANVAS`.** Render a fixed scene, read it back twice in
  the same session → assert byte-identical (stability). **Cross-context:** render
  the same scene in the main frame, a same-origin iframe, a cross-origin iframe,
  a dedicated Worker (OffscreenCanvas), and a Service Worker; assert **all
  readbacks are byte-identical** in Strict, and identical passthrough in
  Balanced. Assert two *different* sessions differ (unlinkable across sessions)
  but are internally consistent.

### 6. WebGL virtual-backend normalization / disable in Strict

* **Goal.** Never expose host GPU strings; present the real virtual backend, or
  disable WebGL (spec §4 "Nie deklarować fikcyjnego modelu RTX czy Radeon"; §7
  Balanced "WebGL włączony przez wirtualny backend", Strict "ograniczony lub
  wyłączony WebGL").
* **Approach.** Balanced (`WebGlMode::VirtualBackend`): keep WebGL on the
  virtio-gpu / SwiftShader software backend and **normalize** the identifying
  strings to the true virtual environment — `UNMASKED_VENDOR_WEBGL` /
  `UNMASKED_RENDERER_WEBGL`, `getParameter` limits, and the extension list are
  reported as the virtual backend actually provides them, **not** a faked
  discrete GPU. Strict (`WebGlMode::Disabled`): `getContext('webgl'|'webgl2')`
  returns `null`. WebGPU is off in both (control 7).
* **Subsystem.** `gpu::` command buffer / ANGLE backend selection, Blink
  `WebGLRenderingContext` `getParameter`/`getExtension`, GPU info collection.
* **Regression test — `RT-WEBGL`.** Balanced: assert `UNMASKED_RENDERER_WEBGL`
  matches the virtual backend allow-list (SwiftShader / virtio-gpu string) and
  **never** matches a discrete-GPU regex (`/RTX|Radeon|GeForce|Intel Arc/`).
  Assert the same renderer string from an iframe and a Worker
  (OffscreenCanvas WebGL). Strict: assert `getContext('webgl')` is `null` in main
  frame, iframe, and Worker.

### 7. WebGPU off

* **Goal.** WebGPU is disabled everywhere (spec §4/§7 "brak WebGPU";
  `FingerprintPolicy.webgpu_enabled = false` for both levels, enforced by
  `validate()` in Strict).
* **Approach.** `navigator.gpu` is `undefined`; the feature is compiled/flagged
  off (`--disable-features=WebGPU`, runtime feature disabled) so no adapter
  enumeration (a rich GPU fingerprint) is possible.
* **Subsystem.** `blink::RuntimeEnabledFeatures::WebGPUEnabled`, the WebGPU
  service, `navigator.gpu` binding.
* **Regression test — `RT-WEBGPU`.** Assert `navigator.gpu === undefined` in main
  frame, iframe, dedicated Worker, and Service Worker. Assert
  `('gpu' in navigator)` is `false`.

### 8. `hardwareConcurrency` clamp

* **Goal.** Report a **standard** logical-CPU count, not the VM's exact vCPU
  count (spec §7 "ustandaryzowana liczba logicznych procesorów").
* **Approach.** `navigator.hardwareConcurrency` returns the level constant:
  `4` (Balanced) / `2` (Strict), from `FingerprintPolicy.hardware_concurrency`.
  A shared constant per level → large anonymity set. This clamps the real value
  down to a common number; it does not claim a different CPU model.
* **Subsystem.** Blink `NavigatorConcurrentHardware` (`navigator_concurrent_hardware.cc`),
  which already backs both `Navigator` and `WorkerNavigator`.
* **Regression test — `RT-HWCONCURRENCY`.** Assert
  `navigator.hardwareConcurrency === 2` (Strict) / `=== 4` (Balanced).
  **Cross-context:** assert identical value from `self.navigator.hardwareConcurrency`
  in a dedicated Worker, shared Worker, and Service Worker, and from an iframe.
  (Illustrative diff: `patches/0001-hardware-concurrency-clamp.patch`.)

### 9. Battery / Sensors off

* **Goal.** Remove the Battery Status API and all motion/environment sensors —
  both are known fingerprint/linkage vectors and the VM has no real battery or
  sensors (spec §7 "brak informacji o baterii; brak dostępu do sensorów").
* **Approach.** `navigator.getBattery` is `undefined`
  (`disable_battery_api = true`); `DeviceMotionEvent`/`DeviceOrientationEvent`,
  the Generic Sensor APIs (`Accelerometer`, `Gyroscope`, `AmbientLightSensor`,
  `Magnetometer`, …) are disabled and their permission is `denied`
  (`disable_sensor_apis = true`, plus `DefaultSensorsSetting=2`). Absent, not
  faked — the VM has no such hardware (invariant 4).
* **Subsystem.** `blink::RuntimeEnabledFeatures` (BatteryStatus, Sensor),
  the device service sensor providers, `navigator.getBattery` binding.
* **Regression test — `RT-BATTERY-SENSORS`.** Assert `navigator.getBattery`
  is `undefined`; assert `Accelerometer`/`Gyroscope`/`AmbientLightSensor` either
  are undefined or throw/`NotAllowedError` on start; assert `DeviceMotionEvent`
  never fires. **Cross-context:** repeat `getBattery` check in a Worker.

### 10. Timezone + language pinning

* **Goal.** One shared timezone and language for the session so the clock/locale
  don't reveal the host and match the network egress (spec §7 "wspólna polityka
  języka oraz strefy czasowej").
* **Approach.** Pin timezone to `FingerprintPolicy.timezone` (`UTC`) and primary
  language to `primary_language` (`en-US`). This drives
  `Intl.DateTimeFormat().resolvedOptions().timeZone`, `Date` offset,
  `navigator.language`/`languages`, and the `Accept-Language` header
  consistently. Shared constants → uniform across users; identical in every
  context. (If a deployment prefers to derive the zone from the tunnel exit,
  `timezone = None` selects the gateway-derived zone — still shared per exit, not
  per host.)
* **Subsystem.** ICU timezone override (`base::i18n` / `icu::TimeZone::adoptDefault`
  plumbed to renderers), Blink `NavigatorLanguage`, and the network
  `Accept-Language` provider.
* **Regression test — `RT-TZ-LANG`.** Assert
  `Intl.DateTimeFormat().resolvedOptions().timeZone === "UTC"`,
  `new Date().getTimezoneOffset() === 0`, `navigator.language === "en-US"`, and
  the outgoing `Accept-Language` is `en-US`. **Cross-context:** assert the same
  `timeZone` and `navigator.language` from an iframe, a dedicated Worker, and a
  Service Worker (all four must agree — a mismatch between frame and worker is
  exactly the inconsistency spec §7 forbids).

---

## Coverage / traceability matrix

| Control | `FingerprintPolicy` field(s) | Regression test | Cross-context asserted |
|---------|------------------------------|-----------------|------------------------|
| 1 Letterboxing | `letterbox` | `RT-LETTERBOX` | iframe, worker |
| 2 Timer coarsening | `timer_coarsening_us` | `RT-TIMER` | worker, service worker, audioworklet |
| 3 Fonts | `fonts` | `RT-FONTS` | worker (OffscreenCanvas) |
| 4 mediaDevices | `limit_media_device_enumeration` | `RT-MEDIADEVICES` | iframe |
| 5 Canvas | `canvas` | `RT-CANVAS` | iframe (x2), worker, service worker |
| 6 WebGL | `webgl` | `RT-WEBGL` | iframe, worker |
| 7 WebGPU | `webgpu_enabled` | `RT-WEBGPU` | iframe, worker, service worker |
| 8 hardwareConcurrency | `hardware_concurrency` | `RT-HWCONCURRENCY` | worker, shared worker, service worker, iframe |
| 9 Battery/Sensors | `disable_battery_api`, `disable_sensor_apis` | `RT-BATTERY-SENSORS` | worker |
| 10 Timezone/Language | `timezone`, `primary_language` | `RT-TZ-LANG` | iframe, worker, service worker |

Every row is required to pass before a Chromium build is accepted (spec §14/§16).
The `patches/` files here are **illustrative** shapes for two of these controls
(hardwareConcurrency clamp, timezone pinning); the full set is generated against
the pinned Chromium tag during the build (`../build/README.md`).
