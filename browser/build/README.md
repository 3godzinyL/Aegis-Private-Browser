# `browser/build/` — hardened Chromium build

This directory pins the **release** build configuration for the Aegis Chromium
fork (spec §6 Variant B, §10, §16) and the orchestration that turns a pinned
Chromium source tree + the `../chromium-patches/` set into a signed browser
image for the Browser VM.

```
build/
├── args.gn      ← hardened GN release args (sandbox kept, telemetry/RLZ/signin off)
└── README.md    ← this file (build orchestration + rationale)
```

## What `args.gn` guarantees (and what it must never do)

`args.gn` is a **release, official-style, optimized** build:

* `is_debug = false`, `is_official_build = true`, static (`is_component_build = false`).
* **Sandbox and Site Isolation stay ON.** `use_seccomp_bpf = true`; there is no
  flag that disables the sandbox or Site Isolation, and none may be added
  (spec §10/§16). The launcher independently rejects `--no-sandbox`,
  `--disable-web-security`, and `--disable-site-isolation-trials` via
  `aegis_core::browser::BackendPolicyBundle::assert_safe`.
* **Google sign-in / sync signin removed at build time:** empty
  `google_api_key`/`google_default_client_id`/`google_default_client_secret` and
  `use_official_google_api_keys = false` make Google account integrations inert
  even before the managed policy (`SyncDisabled`, `BrowserSignin=0`) is read.
* **Telemetry / RLZ / field-trial phone-home off:** `enable_rlz = false`,
  `enable_reporting = false`, `enable_service_discovery = false`,
  `enable_hangout_services_extension = false`.
* **Proprietary codecs: OFF** (`proprietary_codecs = false`,
  `ffmpeg_branding = "Chromium"`). Decision recorded inline in `args.gn`: open
  codecs only; flip both flags together and record in the SBOM if a deployment
  needs H.264/AAC. **Widevine/CDM off** (identifiable/provisioning component).
* **No remote-debugging conveniences.** Production builds never expose CDP on a
  network interface (spec §10); the managed policy also sets
  `RemoteDebuggingAllowed=false` and `DeveloperToolsAvailability=1`.

> The **real engine version stays in the User-Agent** (spec §6/§14). Nothing in
> this build spoofs the Chromium version — normalization is about *hardware and
> environment* uniformity, not lying about the engine.

## Build orchestration outline

The build is deterministic-ish and reproducible from a pinned tag. Stages:

1. **Pin + fetch source.**
   * Pin an exact upstream Chromium tag (e.g. `CHROMIUM_TAG=<M.N.O.P>`); record
     it and the `depot_tools` revision in the release manifest.
   * `fetch --nohooks chromium`; `git checkout $CHROMIUM_TAG`; `gclient sync -D`.

2. **Apply the Aegis patch set.**
   * Apply `../chromium-patches/patches/*.patch` **in numeric order**
     (`0001-…`, `0002-…`, …) with `git am`/`git apply --3way`.
   * The two shipped files (`0001-hardware-concurrency-clamp`,
     `0002-timezone-language-pinning`) are **illustrative shapes**; the full set
     for all ten controls in `../chromium-patches/README.md` is
     generated/rebased against `$CHROMIUM_TAG` here. A rebase that fails to apply
     cleanly is a build failure — no silent skips (spec §16: every modification
     is tracked).

3. **Configure.**
   * `gn gen out/aegis-release --args="$(cat browser/build/args.gn)"`.
   * **Guard check:** parse the resolved args (`gn args out/aegis-release --list
     --short --overrides-only`) and **fail the build** if any of these are set to
     an unsafe value: seccomp disabled, ASan/dev sanitizers on, Site Isolation
     off, `proprietary_codecs`/`enable_widevine` unexpectedly true,
     `enable_rlz`/`enable_reporting` true, or non-empty Google API keys. This is
     the build-time mirror of `assert_safe`.

4. **Compile.**
   * `autoninja -C out/aegis-release chrome`.
   * Build the Aegis web tests target so the `RT-*` regression tests
     (`//third_party/blink/web_tests/aegis/...`) are available.

5. **Regression tests (spec §16 — required to pass before packaging).**
   * Run every `RT-*` test from `../chromium-patches/README.md`:
     `RT-LETTERBOX, RT-TIMER, RT-FONTS, RT-MEDIADEVICES, RT-CANVAS, RT-WEBGL,
     RT-WEBGPU, RT-HWCONCURRENCY, RT-BATTERY-SENSORS, RT-TZ-LANG` — each under
     **both** Balanced and Strict, each with its **cross-context** case
     (main frame / iframe / worker / service worker) so spec §7 stability is
     proven.
   * Run the repo-root black-box suite `tests/browser-api/` against a real
     Browser VM (same `RT-*` ids) plus a Web Platform Tests subset to confirm the
     normalization does not break WPT beyond the accepted budget (spec §14).
   * A failing `RT-*` blocks the release.

6. **Sandbox / isolation smoke test.**
   * Launch the built browser and assert the renderer is sandboxed
     (`chrome://sandbox` / `--audit` smoke) and Site Isolation is active
     (`chrome://process-internals` shows per-site processes). Fail closed.

7. **Package + provenance (spec §5-etap5 / §10).**
   * Produce the Browser VM browser package; generate the **SBOM** (all
     components with version + hash), sign the artifact, and record
     `$CHROMIUM_TAG`, the patch-set hash, and the resolved `args.gn` hash in the
     signed release manifest.
   * Feed the package into the VM image build (`../../images/browser/`); the VM
     ships **only the standard font set** (control 3 relies on there being no
     host fonts) and installs the managed policies from `../policies/managed/`
     into `/etc/chromium/policies/managed/`.

8. **Downgrade protection.**
   * The update manifest is monotonic; the updater rejects a lower
     `$CHROMIUM_TAG`/build version (spec §10/§14 "blokada downgrade'u").

## Validation of this directory's JSON/config

`args.gn` is GN syntax (not JSON) and is validated by `gn gen` + the guard check
in stage 3. The managed-policy **JSON** documents in `../policies/managed/` are
validated separately (a `node`/`python` `JSON.parse` check is run in CI; both
`balanced.json` and `strict.json` must parse). This build directory contains no
JSON to validate on its own.
