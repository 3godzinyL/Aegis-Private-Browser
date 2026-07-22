//! A [`BrowserRunner`] that launches a **real browser process on the host OS**.
//!
//! This is the reduced-protection escape hatch
//! ([`aegis_core::config::IsolationLevel::HostProcess`]) that makes Aegis usable
//! on hosts without a hypervisor (Windows/macOS dev machines). Instead of driving
//! a Chromium process *inside a Browser VM* through the guest channel (see
//! [`crate::runner::GuestChannelRunner`], which is left untouched), it execs a
//! Chromium-family binary directly on the host via [`tokio::process::Command`].
//!
//! ## Security posture
//!
//! The runner is a **dumb executor**: it runs *exactly* the argument vector it is
//! handed in the [`LaunchSpec`] and never appends, rewrites, or removes a flag.
//! The [`crate::ChromiumBackend`] renders that vector as an already-hardened
//! command line (sandbox kept, `--user-data-dir` pinned, all traffic forced
//! through `--proxy-server`, WebRTC non-proxied UDP blocked). Because the runner
//! never injects flags, it can never weaken that posture — it cannot emit
//! `--no-sandbox` or `--disable-web-security`.
//!
//! Running the site on the real OS is honestly *reduced* protection (no VM
//! isolation); higher layers surface that to the user and never claim full
//! anonymity in this mode.
//!
//! ## Binary resolution
//!
//! [`resolve_browser_binary`] is a **pure**, unit-tested function. Precedence:
//!
//! 1. an explicit override (constructor argument or the `AEGIS_BROWSER_BIN`
//!    environment variable),
//! 2. a platform search for a Chromium-family binary
//!    ([`search_default_browser`]).
//!
//! On Windows it looks for `chrome.exe` under `%ProgramFiles%`,
//! `%ProgramFiles(x86)%` and `%LOCALAPPDATA%` (Google Chrome, then Chromium),
//! then `msedge.exe`, then `PATH`. On Linux it probes `chromium`,
//! `chromium-browser`, `google-chrome` and `brave-browser` on `PATH`.

use crate::runner::{BrowserRunner, LaunchSpec};
use aegis_core::error::{Error, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::process::{Child, Command};

/// Environment variable that overrides browser-binary resolution.
pub const BROWSER_BIN_ENV: &str = "AEGIS_BROWSER_BIN";

/// Environment variable that overrides Firefox / Tor-Browser binary resolution.
pub const FIREFOX_BIN_ENV: &str = "AEGIS_FIREFOX_BIN";

/// Abstracts the environment/filesystem lookups that binary resolution needs, so
/// [`resolve_browser_binary`] can stay pure and be exercised deterministically in
/// tests (no real Chrome, no dependence on the host's installed browsers).
pub trait ResolverEnv {
    /// Read an environment variable, returning `None` when unset/empty.
    fn var(&self, key: &str) -> Option<String>;
    /// Whether a path exists as a regular file on the host.
    fn is_file(&self, path: &Path) -> bool;
    /// Locate `program` on `PATH`, returning its absolute path if found.
    fn which(&self, program: &str) -> Option<PathBuf>;
}

/// The production [`ResolverEnv`]: reads the real process environment and
/// filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl ResolverEnv for SystemEnv {
    fn var(&self, key: &str) -> Option<String> {
        match std::env::var(key) {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => None,
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        // A minimal, dependency-free PATH search: split `PATH` on the platform
        // separator and probe `dir/program` (adding `.exe` on Windows if the
        // caller did not).
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(program);
            if self.is_file(&candidate) {
                return Some(candidate);
            }
            #[cfg(windows)]
            if !program.to_ascii_lowercase().ends_with(".exe") {
                let exe = dir.join(format!("{program}.exe"));
                if self.is_file(&exe) {
                    return Some(exe);
                }
            }
        }
        None
    }
}

/// The Chromium-family binaries searched on `PATH` on Linux (in priority order).
#[cfg(not(windows))]
const LINUX_PATH_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
];

/// Search the host for a default Chromium-family browser binary. Pure w.r.t. the
/// injected [`ResolverEnv`] (all environment/filesystem access goes through it).
///
/// Returns `None` when nothing suitable is found; callers turn that into a clear
/// [`Error`].
#[must_use]
pub fn search_default_browser<E: ResolverEnv>(env: &E) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        search_windows(env)
    }
    #[cfg(not(windows))]
    {
        for name in LINUX_PATH_CANDIDATES {
            if let Some(p) = env.which(name) {
                return Some(p);
            }
        }
        None
    }
}

/// Windows browser search: well-known install locations first, then `PATH`.
#[cfg(windows)]
fn search_windows<E: ResolverEnv>(env: &E) -> Option<PathBuf> {
    // Root dirs to probe, most-specific first. Missing env vars simply drop out.
    let roots: Vec<PathBuf> = [
        env.var("ProgramFiles"),
        env.var("ProgramFiles(x86)"),
        env.var("LOCALAPPDATA"),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .collect();

    // (vendor subdir, exe) pairs, in priority order: Chrome, then Chromium.
    const RELATIVE: &[(&str, &str)] = &[
        (r"Google\Chrome\Application", "chrome.exe"),
        (r"Chromium\Application", "chrome.exe"),
    ];

    for root in &roots {
        for (subdir, exe) in RELATIVE {
            let candidate = root.join(subdir).join(exe);
            if env.is_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    // Edge is Chromium-family and always present on modern Windows.
    for root in &roots {
        let candidate = root.join(r"Microsoft\Edge\Application").join("msedge.exe");
        if env.is_file(&candidate) {
            return Some(candidate);
        }
    }

    // Last resort: PATH.
    for name in ["chrome.exe", "msedge.exe"] {
        if let Some(p) = env.which(name) {
            return Some(p);
        }
    }
    None
}

/// Resolve the browser binary to launch. **Pure** w.r.t. the injected
/// [`ResolverEnv`].
///
/// Precedence:
/// 1. `override_bin` (constructor argument), if `Some`;
/// 2. the `AEGIS_BROWSER_BIN` environment variable, if set;
/// 3. the platform search ([`search_default_browser`]).
///
/// The explicit override (1 and 2) is taken *verbatim and is not required to
/// exist yet* — a launch of a missing path fails later with a clear
/// [`Error::System`], which the tests rely on. The platform search (3) only
/// returns paths that exist.
///
/// # Errors
/// Returns [`Error::NotFound`] when no override is given and the platform search
/// finds no Chromium-family browser installed.
pub fn resolve_browser_binary<E: ResolverEnv>(
    override_bin: Option<&str>,
    env: &E,
) -> Result<PathBuf> {
    if let Some(explicit) = override_bin.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(from_env) = env.var(BROWSER_BIN_ENV) {
        return Ok(PathBuf::from(from_env));
    }
    search_default_browser(env).ok_or_else(|| {
        Error::NotFound(
            "no Chromium-family browser found on this host; set AEGIS_BROWSER_BIN or install \
             Chrome/Chromium/Edge"
                .to_string(),
        )
    })
}

/// The Firefox-family binaries searched on `PATH` on Linux (in priority order):
/// Tor Browser's wrapper first, then a plain Firefox.
#[cfg(not(windows))]
const LINUX_FIREFOX_PATH_CANDIDATES: &[&str] =
    &["tor-browser", "firefox", "firefox-esr", "firefox-bin"];

/// Relative `…/Tor Browser/Browser/firefox.exe` layout under a root dir.
#[cfg(windows)]
const TOR_BROWSER_REL: &str = r"Tor Browser\Browser\firefox.exe";

/// Search the host for a Firefox / Tor-Browser binary. Pure w.r.t. the injected
/// [`ResolverEnv`].
///
/// Tor Browser is preferred over a standalone Firefox (it ships the strongest
/// uplifted anti-fingerprinting defaults and a matching UA). Returns `None` when
/// nothing suitable is found; callers turn that into a clear [`Error`].
#[must_use]
pub fn search_default_firefox<E: ResolverEnv>(env: &E) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        search_firefox_windows(env)
    }
    #[cfg(not(windows))]
    {
        search_firefox_unix(env)
    }
}

/// Windows Firefox / Tor-Browser search: Tor Browser locations first (Desktop,
/// Program Files, common user dirs), then standard Firefox install paths, then
/// `PATH`.
#[cfg(windows)]
fn search_firefox_windows<E: ResolverEnv>(env: &E) -> Option<PathBuf> {
    // 1. Tor Browser under likely roots. `…/Desktop/Tor Browser/…` is the default
    //    "extract-and-run" location; also probe user home, Program Files and
    //    LOCALAPPDATA.
    let tor_roots: Vec<PathBuf> = [
        env.var("USERPROFILE")
            .map(|u| PathBuf::from(u).join("Desktop")),
        env.var("USERPROFILE").map(PathBuf::from),
        env.var("USERPROFILE")
            .map(|u| PathBuf::from(u).join("Downloads")),
        env.var("ProgramFiles").map(PathBuf::from),
        env.var("ProgramFiles(x86)").map(PathBuf::from),
        env.var("LOCALAPPDATA").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    .collect();

    for root in &tor_roots {
        let candidate = root.join(TOR_BROWSER_REL);
        if env.is_file(&candidate) {
            return Some(candidate);
        }
    }

    // 2. Standard Mozilla Firefox install locations.
    let ff_roots: Vec<PathBuf> = [
        env.var("ProgramFiles"),
        env.var("ProgramFiles(x86)"),
        env.var("LOCALAPPDATA"),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .collect();

    for root in &ff_roots {
        let candidate = root.join(r"Mozilla Firefox").join("firefox.exe");
        if env.is_file(&candidate) {
            return Some(candidate);
        }
    }

    // 3. Last resort: PATH.
    env.which("firefox.exe")
}

/// Unix Firefox / Tor-Browser search: Tor Browser under common user dirs first,
/// then `PATH` (`tor-browser`, `firefox`, `firefox-esr`).
#[cfg(not(windows))]
fn search_firefox_unix<E: ResolverEnv>(env: &E) -> Option<PathBuf> {
    // Tor Browser's Linux launcher lives at
    // `<extract>/tor-browser/Browser/start-tor-browser` or ships a
    // `firefox.real`; probe the common extract roots for the launcher.
    if let Some(home) = env.var("HOME") {
        let home = PathBuf::from(home);
        const TOR_REL: &[&str] = &[
            "tor-browser/Browser/start-tor-browser",
            "Desktop/tor-browser/Browser/start-tor-browser",
            "Downloads/tor-browser/Browser/start-tor-browser",
            ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser",
        ];
        for rel in TOR_REL {
            let candidate = home.join(rel);
            if env.is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    for name in LINUX_FIREFOX_PATH_CANDIDATES {
        if let Some(p) = env.which(name) {
            return Some(p);
        }
    }
    None
}

/// Resolve the Firefox / Tor-Browser binary to launch. **Pure** w.r.t. the
/// injected [`ResolverEnv`].
///
/// Precedence:
/// 1. `override_bin` (constructor argument), if `Some`;
/// 2. the `AEGIS_FIREFOX_BIN` environment variable, if set;
/// 3. the platform search ([`search_default_firefox`]): Tor Browser locations
///    first, then standard Firefox install paths.
///
/// The explicit override (1 and 2) is taken *verbatim and is not required to
/// exist yet* — a launch of a missing path fails later with a clear
/// [`Error::System`]. The platform search (3) only returns paths that exist.
///
/// # Errors
/// Returns [`Error::NotFound`] when no override is given and the platform search
/// finds no Firefox / Tor Browser installed.
pub fn resolve_firefox_binary<E: ResolverEnv>(
    override_bin: Option<&str>,
    env: &E,
) -> Result<PathBuf> {
    if let Some(explicit) = override_bin.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(from_env) = env.var(FIREFOX_BIN_ENV) {
        return Ok(PathBuf::from(from_env));
    }
    search_default_firefox(env).ok_or_else(|| {
        Error::NotFound(
            "no Firefox or Tor Browser found on this host; set AEGIS_FIREFOX_BIN or install \
             Firefox / the Tor Browser bundle"
                .to_string(),
        )
    })
}

/// A [`BrowserRunner`] that launches a real browser process on the host OS.
///
/// The resolved binary is fixed at construction time (via
/// [`resolve_browser_binary`]); [`LaunchSpec::program`] is ignored so the backend
/// cannot be tricked into running a different executable than the vetted one.
/// Only the *arguments* and *environment* from the spec are applied.
#[derive(Debug)]
pub struct HostBrowserRunner {
    /// The resolved, host-side browser executable.
    binary: PathBuf,
    /// Live child processes keyed by their process token (the OS pid as a
    /// string). Kept so [`BrowserRunner::is_running`]/[`BrowserRunner::stop`] can
    /// address and reap the child reliably.
    children: Mutex<HashMap<String, Child>>,
}

impl HostBrowserRunner {
    /// Construct a runner, resolving the browser binary now via
    /// [`resolve_browser_binary`] using the real process environment.
    ///
    /// `override_bin` takes precedence over the `AEGIS_BROWSER_BIN` env var and
    /// the platform search. Pass `None` to auto-detect.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if no override is given and no Chromium-family
    /// browser can be located.
    pub fn new(override_bin: Option<&str>) -> Result<Self> {
        let binary = resolve_browser_binary(override_bin, &SystemEnv)?;
        Ok(Self::with_binary(binary))
    }

    /// Construct a runner bound to an already-resolved binary path. Performs no
    /// resolution or existence check (a missing path fails at launch time with
    /// [`Error::System`]). Useful for tests and for callers that resolved the
    /// binary themselves.
    #[must_use]
    pub fn with_binary(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            children: Mutex::new(HashMap::new()),
        }
    }

    /// The resolved browser executable this runner launches.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }
}

#[async_trait]
impl BrowserRunner for HostBrowserRunner {
    /// Launch the host browser. `vm_slug` is ignored (there is no VM in host
    /// mode); it is accepted only to satisfy the shared [`BrowserRunner`] trait.
    ///
    /// The runner execs the resolved binary with `spec.args` and `spec.env`
    /// verbatim — it never adds, removes, or rewrites a flag.
    ///
    /// # Errors
    /// Returns [`Error::System`] if the process cannot be spawned (e.g. the
    /// binary does not exist).
    async fn start(&self, _vm_slug: &str, spec: &LaunchSpec) -> Result<String> {
        let mut cmd = Command::new(&self.binary);
        // Verbatim args/env from the vetted bundle. Nothing is added here.
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        // Don't leak our own stdio semantics onto the child beyond the default;
        // the browser detaches its own windows. `kill_on_drop(false)` so a
        // dropped handle does not silently kill a running browser.
        cmd.kill_on_drop(false);

        let child = cmd
            .spawn()
            .map_err(|e| Error::System(format!("failed to launch host browser: {e}")))?;

        // The pid is the opaque process token. A just-spawned child always has a
        // pid; if the platform somehow withholds it, fail closed.
        let pid = child.id().ok_or_else(|| {
            Error::System("host browser exited before yielding a pid".to_string())
        })?;
        let token = pid.to_string();
        self.children
            .lock()
            .expect("host runner lock")
            .insert(token.clone(), child);
        Ok(token)
    }

    /// Whether the child addressed by `token` is still alive.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if the token was never launched by this
    /// runner, or [`Error::System`] if liveness cannot be determined.
    async fn is_running(&self, token: &str) -> Result<bool> {
        let mut guard = self.children.lock().expect("host runner lock");
        let child = guard
            .get_mut(token)
            .ok_or_else(|| Error::NotFound(format!("unknown process token: {token}")))?;
        // `try_wait` reaps the child if it has exited; `Ok(None)` => still running.
        match child.try_wait() {
            Ok(None) => Ok(true),
            Ok(Some(_status)) => Ok(false),
            Err(e) => Err(Error::System(format!("failed to poll host browser: {e}"))),
        }
    }

    /// Terminate the child addressed by `token`. Idempotent: an unknown or
    /// already-exited token is not an error.
    ///
    /// On Windows the process *tree* is killed where practical (via `taskkill /T`)
    /// so renderer/GPU helper processes do not outlive the parent; elsewhere the
    /// child itself is killed.
    ///
    /// # Errors
    /// Returns [`Error::System`] only if the kill itself fails unexpectedly.
    async fn stop(&self, token: &str) -> Result<()> {
        let mut child = {
            let mut guard = self.children.lock().expect("host runner lock");
            match guard.remove(token) {
                Some(c) => c,
                // Idempotent: nothing to stop.
                None => return Ok(()),
            }
        };

        // If it already exited, we're done.
        if let Ok(Some(_)) = child.try_wait() {
            return Ok(());
        }

        #[cfg(windows)]
        {
            // Best-effort tree kill so helper processes don't linger. If taskkill
            // is unavailable we fall through to the direct kill below.
            if let Some(pid) = child.id() {
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .output()
                    .await;
            }
        }

        // Direct kill (and reap) — idempotent even if taskkill already ended it.
        child
            .kill()
            .await
            .map_err(|e| Error::System(format!("failed to terminate host browser: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A fully in-memory [`ResolverEnv`] for deterministic resolution tests.
    #[derive(Default)]
    struct FakeEnv {
        vars: HashMap<String, String>,
        files: HashSet<PathBuf>,
        path: HashMap<String, PathBuf>,
    }

    impl FakeEnv {
        fn with_var(mut self, k: &str, v: &str) -> Self {
            self.vars.insert(k.to_string(), v.to_string());
            self
        }
        fn with_file(mut self, p: &str) -> Self {
            self.files.insert(PathBuf::from(p));
            self
        }
        fn with_on_path(mut self, program: &str, at: &str) -> Self {
            self.path.insert(program.to_string(), PathBuf::from(at));
            self
        }
    }

    impl ResolverEnv for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
        fn is_file(&self, path: &Path) -> bool {
            self.files.contains(path)
        }
        fn which(&self, program: &str) -> Option<PathBuf> {
            self.path.get(program).cloned()
        }
    }

    #[test]
    fn override_argument_wins_over_everything() {
        // Even with an env var set and a browser "installed", the explicit
        // override is returned verbatim.
        let env = FakeEnv::default()
            .with_var(BROWSER_BIN_ENV, "/env/chrome")
            .with_on_path("chromium", "/usr/bin/chromium");
        let got = resolve_browser_binary(Some("/explicit/browser"), &env).unwrap();
        assert_eq!(got, PathBuf::from("/explicit/browser"));
    }

    #[test]
    fn blank_override_falls_through_to_env() {
        let env = FakeEnv::default().with_var(BROWSER_BIN_ENV, "/env/chrome");
        // A whitespace-only override is treated as "no override".
        let got = resolve_browser_binary(Some("   "), &env).unwrap();
        assert_eq!(got, PathBuf::from("/env/chrome"));
    }

    #[test]
    fn env_var_wins_over_platform_search() {
        let env = FakeEnv::default()
            .with_var(BROWSER_BIN_ENV, "/env/chrome")
            .with_on_path("chromium", "/usr/bin/chromium");
        let got = resolve_browser_binary(None, &env).unwrap();
        assert_eq!(got, PathBuf::from("/env/chrome"));
    }

    #[test]
    fn missing_binary_is_a_clear_not_found_error() {
        // No override, no env, nothing installed => clear resolution error.
        let env = FakeEnv::default();
        let err = resolve_browser_binary(None, &env).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
        assert!(err.to_string().contains("AEGIS_BROWSER_BIN"));
    }

    // --- Firefox / Tor-Browser resolution ---------------------------------

    #[test]
    fn firefox_override_argument_wins_over_everything() {
        let env = FakeEnv::default()
            .with_var(FIREFOX_BIN_ENV, "/env/firefox")
            .with_on_path("firefox", "/usr/bin/firefox");
        let got = resolve_firefox_binary(Some("/explicit/firefox"), &env).unwrap();
        assert_eq!(got, PathBuf::from("/explicit/firefox"));
    }

    #[test]
    fn firefox_env_var_is_honored() {
        // AEGIS_FIREFOX_BIN wins over the platform search (verbatim, not checked).
        let env = FakeEnv::default().with_var(FIREFOX_BIN_ENV, "/opt/tor-browser/firefox");
        let got = resolve_firefox_binary(None, &env).unwrap();
        assert_eq!(got, PathBuf::from("/opt/tor-browser/firefox"));
    }

    #[test]
    fn firefox_missing_is_a_clear_not_found_error() {
        let env = FakeEnv::default();
        let err = resolve_firefox_binary(None, &env).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
        assert!(err.to_string().contains("AEGIS_FIREFOX_BIN"));
    }

    #[cfg(windows)]
    #[test]
    fn firefox_finds_tor_browser_on_desktop_before_plain_firefox() {
        let profile = r"C:\Users\tester";
        let desktop_tor = format!(r"{profile}\Desktop\Tor Browser\Browser\firefox.exe");
        let pf_firefox = r"C:\Program Files\Mozilla Firefox\firefox.exe";

        // Both a Desktop Tor Browser and a plain Firefox exist: Tor Browser wins.
        let env = FakeEnv::default()
            .with_var("USERPROFILE", profile)
            .with_var("ProgramFiles", r"C:\Program Files")
            .with_file(&desktop_tor)
            .with_file(pf_firefox);
        assert_eq!(
            search_default_firefox(&env).unwrap(),
            PathBuf::from(&desktop_tor)
        );
        // resolve_firefox_binary (no override/env) uses the same search.
        assert_eq!(
            resolve_firefox_binary(None, &env).unwrap(),
            PathBuf::from(&desktop_tor)
        );
    }

    #[cfg(windows)]
    #[test]
    fn firefox_falls_back_to_standard_install_then_path() {
        // No Tor Browser => standard Firefox under Program Files.
        let pf_firefox = r"C:\Program Files\Mozilla Firefox\firefox.exe";
        let env = FakeEnv::default()
            .with_var("ProgramFiles", r"C:\Program Files")
            .with_file(pf_firefox);
        assert_eq!(
            search_default_firefox(&env).unwrap(),
            PathBuf::from(pf_firefox)
        );

        // Nothing installed => PATH fallback.
        let env2 = FakeEnv::default().with_on_path("firefox.exe", r"C:\tools\firefox.exe");
        assert_eq!(
            search_default_firefox(&env2).unwrap(),
            PathBuf::from(r"C:\tools\firefox.exe")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn firefox_finds_tor_browser_under_home_then_path() {
        let home = "/home/tester";
        let tor = format!("{home}/tor-browser/Browser/start-tor-browser");
        // Tor Browser under HOME is preferred over a PATH firefox.
        let env = FakeEnv::default()
            .with_var("HOME", home)
            .with_file(&tor)
            .with_on_path("firefox", "/usr/bin/firefox");
        assert_eq!(search_default_firefox(&env).unwrap(), PathBuf::from(&tor));

        // No Tor Browser => PATH firefox.
        let env2 = FakeEnv::default().with_on_path("firefox", "/usr/bin/firefox");
        assert_eq!(
            search_default_firefox(&env2).unwrap(),
            PathBuf::from("/usr/bin/firefox")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_search_prefers_path_order() {
        // google-chrome present but chromium is higher priority and also present.
        let env = FakeEnv::default()
            .with_on_path("chromium", "/usr/bin/chromium")
            .with_on_path("google-chrome", "/usr/bin/google-chrome");
        let got = search_default_browser(&env).unwrap();
        assert_eq!(got, PathBuf::from("/usr/bin/chromium"));

        // Only a lower-priority browser present => it is chosen.
        let env2 = FakeEnv::default().with_on_path("brave-browser", "/usr/bin/brave-browser");
        assert_eq!(
            search_default_browser(&env2).unwrap(),
            PathBuf::from("/usr/bin/brave-browser")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_search_prefers_chrome_then_edge_then_path() {
        let pf = r"C:\Program Files";
        let chrome = format!(r"{pf}\Google\Chrome\Application\chrome.exe");
        let edge = format!(r"{pf}\Microsoft\Edge\Application\msedge.exe");

        // Chrome installed under ProgramFiles wins.
        let env = FakeEnv::default()
            .with_var("ProgramFiles", pf)
            .with_file(&chrome)
            .with_file(&edge);
        assert_eq!(
            search_default_browser(&env).unwrap(),
            PathBuf::from(&chrome)
        );

        // No Chrome/Chromium => Edge is chosen.
        let env2 = FakeEnv::default()
            .with_var("ProgramFiles", pf)
            .with_file(&edge);
        assert_eq!(search_default_browser(&env2).unwrap(), PathBuf::from(&edge));

        // Nothing in install dirs => PATH fallback.
        let env3 = FakeEnv::default().with_on_path("chrome.exe", r"C:\tools\chrome.exe");
        assert_eq!(
            search_default_browser(&env3).unwrap(),
            PathBuf::from(r"C:\tools\chrome.exe")
        );
    }

    #[test]
    fn with_binary_exposes_the_path() {
        let r = HostBrowserRunner::with_binary("/x/chrome");
        assert_eq!(r.binary(), Path::new("/x/chrome"));
    }

    #[tokio::test]
    async fn launching_a_nonexistent_binary_returns_system_error_not_panic() {
        // A path that cannot exist on either platform.
        let runner = HostBrowserRunner::with_binary(
            "/nonexistent/aegis-test/definitely-not-a-real-browser-xyz",
        );
        let spec = LaunchSpec {
            program: "ignored".into(),
            args: vec!["--version".into()],
            env: vec![],
        };
        let err = runner.start("host", &spec).await.unwrap_err();
        assert!(matches!(err, Error::System(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn is_running_on_unknown_token_is_not_found() {
        let runner = HostBrowserRunner::with_binary("/x/chrome");
        let err = runner.is_running("nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn stop_on_unknown_token_is_idempotent() {
        let runner = HostBrowserRunner::with_binary("/x/chrome");
        // Stopping something never launched must be a no-op, not an error.
        runner.stop("never-launched").await.unwrap();
    }

    #[tokio::test]
    async fn handle_round_trips_through_a_real_short_lived_process() {
        // Use a harmless, always-present OS utility as a stand-in "browser" so we
        // exercise the real spawn/pid/liveness/kill path WITHOUT opening Chrome.
        #[cfg(windows)]
        let (bin, args) = ("cmd", vec!["/C".to_string(), "exit".to_string()]);
        #[cfg(not(windows))]
        let (bin, args) = ("/bin/true", Vec::<String>::new());

        let runner = HostBrowserRunner::with_binary(bin);
        let spec = LaunchSpec {
            program: "ignored".into(),
            args,
            env: vec![],
        };
        // The token round-trips: it is the child's pid as a string.
        let token = runner.start("host", &spec).await.unwrap();
        assert!(!token.is_empty());
        assert!(
            token.parse::<u32>().is_ok(),
            "token should be a pid: {token}"
        );

        // is_running must resolve the token (true while alive, false once reaped).
        // Either outcome is fine here; what matters is the token is addressable
        // and we get a definite bool, not an error.
        let _ = runner.is_running(&token).await.unwrap();

        // Terminate is idempotent and must succeed even if it already exited.
        runner.stop(&token).await.unwrap();
        // After stop the token is forgotten, so it is unknown again.
        assert!(matches!(
            runner.is_running(&token).await.unwrap_err(),
            Error::NotFound(_)
        ));
    }
}
