//! Aegis Private Browser — desktop manager (Tauri v2).
//!
//! This library is the Rust backend of the manager UI. It exposes a small set of
//! `#[tauri::command]` handlers that the static frontend (under `../dist`) invokes
//! through `window.__TAURI__`. Each handler opens a short-lived connection to the
//! privileged Aegis daemon over [`aegis_ipc`], issues one request, and maps the
//! reply into a serde-friendly DTO for the webview.
//!
//! ## Boundaries
//!
//! * The UI is **unprivileged**. It never touches libvirt/nftables/secure storage
//!   directly; everything goes through the daemon IPC surface (spec §3, §4).
//! * No secrets cross this boundary: unlock passwords are referenced by
//!   [`aegis_core::network::CredentialRef`] inside the daemon, never here.
//! * Fail-closed: any transport or daemon error is surfaced to the UI as a
//!   structured error string; the UI must not "fall back" to anything.
//! * The UI must never claim "100% anonymous" / "undetectable" and must state that
//!   stronger protection can reduce site compatibility (spec §11, §16). That copy
//!   lives in the static frontend; the protection badge uses exactly the four
//!   [`aegis_core::preflight::ProtectionStatus`] labels.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod dto;
mod ipc;

use dto::{
    CreateProfileArgs, DiagnosticsView, DoctorView, EnforcementView, ProfileView, SessionView,
    StatusView,
};

/// Result alias for command handlers: `Ok(T)` or a human-readable error string
/// that the frontend renders in a toast/banner. Strings are secret-free.
type CmdResult<T> = Result<T, String>;

/// List all known profiles (spec §11 profiles view).
#[tauri::command]
async fn list_profiles() -> CmdResult<Vec<ProfileView>> {
    ipc::list_profiles().await
}

/// Create a new profile from the form inputs.
#[tauri::command]
async fn create_profile(args: CreateProfileArgs) -> CmdResult<ProfileView> {
    ipc::create_profile(args).await
}

/// Compute the live profile preview (Preview tab) from the current form inputs.
///
/// Local and side-effect-free: it never touches the daemon. The returned
/// [`aegis_core::preview::ProfilePreview`] shows exactly what a site would see,
/// derived from the same [`aegis_core::profile::ProfileSpec`] the create command
/// would build, so the preview can never drift from the created profile.
#[tauri::command]
fn preview_profile(args: CreateProfileArgs) -> CmdResult<aegis_core::preview::ProfilePreview> {
    ipc::preview_profile(args)
}

/// Delete a profile (the daemon shreds its data).
#[tauri::command]
async fn delete_profile(id: String) -> CmdResult<()> {
    ipc::delete_profile(id).await
}

/// Start a new browsing session for a profile ("New Private Session").
#[tauri::command]
async fn start_session(profile_id: String) -> CmdResult<SessionView> {
    ipc::start_session(profile_id).await
}

/// Stop (tear down) a running session.
#[tauri::command]
async fn stop_session(session_id: String) -> CmdResult<SessionView> {
    ipc::stop_session(session_id).await
}

/// List active sessions.
#[tauri::command]
async fn list_sessions() -> CmdResult<Vec<SessionView>> {
    ipc::list_sessions().await
}

/// Fetch the diagnostics panel for a session (spec §11 diagnostics panel).
#[tauri::command]
async fn get_diagnostics(session_id: String) -> CmdResult<DiagnosticsView> {
    ipc::get_diagnostics(session_id).await
}

/// Run the daemon self-test ("doctor").
#[tauri::command]
async fn doctor() -> CmdResult<DoctorView> {
    ipc::doctor().await
}

/// Fetch the daemon status snapshot for the Advanced section (version, platform,
/// isolation level, enforcement policy).
#[tauri::command]
async fn get_status() -> CmdResult<StatusView> {
    ipc::get_status().await
}

/// Fetch the current containment enforcement policy.
#[tauri::command]
async fn get_enforcement() -> CmdResult<EnforcementView> {
    ipc::get_enforcement().await
}

/// Replace the containment enforcement policy; returns the applied policy.
///
/// Relaxing isolation is a *reduced-protection* choice; the frontend surfaces a
/// bilingual warning before calling this. The daemon remains the authority and
/// validates the policy fail-closed.
#[tauri::command]
async fn set_enforcement(enforcement: EnforcementView) -> CmdResult<EnforcementView> {
    ipc::set_enforcement(enforcement).await
}

/// Build and run the Tauri application.
///
/// Kept separate from `main` so the mobile entry point (if ever added) and the
/// desktop binary can share it. Panics only if the generated Tauri context is
/// itself invalid, which is a build-time guarantee.
pub fn run() {
    // Install a lightweight tracing subscriber for the UI process. It never logs
    // request/response bodies — only coarse operation names emitted by the ipc
    // module — so it is safe to leave on.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_manager_ui_lib=info,warn".into()),
        )
        .try_init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            create_profile,
            preview_profile,
            delete_profile,
            start_session,
            stop_session,
            list_sessions,
            get_diagnostics,
            doctor,
            get_status,
            get_enforcement,
            set_enforcement,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Aegis manager UI");
}
