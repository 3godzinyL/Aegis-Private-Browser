//! Daemon IPC client wiring for the manager UI.
//!
//! Each public function here corresponds to one `#[tauri::command]`: it opens a
//! short-lived connection to the daemon, issues exactly one [`aegis_ipc::Request`],
//! and maps the [`aegis_ipc::Response`] into a UI DTO (or an error string).
//!
//! ## Transport selection
//!
//! * **unix** (production/Linux): a Unix-domain socket. The path comes from
//!   `$AEGIS_IPC_SOCKET`, defaulting to `/run/aegis/daemon.sock`. Peer-credential
//!   authorization is enforced by the daemon.
//! * **non-unix** (Windows dev only): a loopback-TCP + shared-token transport.
//!   The address comes from `$AEGIS_IPC_ADDR` (default `127.0.0.1:7420`) and the
//!   token from the file named by `$AEGIS_IPC_TOKEN_FILE`. This is development
//!   only and never ships (see [`aegis_ipc::transport`]).
//!
//! We never open a long-lived connection here: the daemon's contract is one
//! response per request over a fresh stream, which keeps this client trivially
//! correct and lets a daemon restart heal transparently between commands. Errors
//! are mapped to short, secret-free strings for display.

use crate::dto::{
    CreateProfileArgs, DiagnosticsView, DoctorView, EnforcementView, ProfileView, SessionView,
    StatusView,
};
use aegis_core::config::Enforcement;
use aegis_core::ids::{ProfileId, SessionId};
use aegis_core::session::SessionRequest;
use aegis_ipc::{Request, Response};
use std::str::FromStr;

/// Map a domain error / transport fault into a display string. Never leaks
/// secrets — the IPC surface is secret-free by construction.
fn err_to_string(context: &str, e: impl std::fmt::Display) -> String {
    format!("{context}: {e}")
}

/// A response we did not expect for the request we sent.
fn unexpected(op: &str) -> String {
    format!("daemon returned an unexpected reply for {op}")
}

/// Turn a [`Response::Error`] into a display string carrying its fail-closed
/// class so the UI can decide how loud to be (e.g. a kill-switch banner).
fn response_error(resp: &Response) -> Option<String> {
    match resp {
        Response::Error { message, class } => {
            Some(format!("{message} [{class:?}]"))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Transport: connect, send one request, return the response.
// ---------------------------------------------------------------------------

/// Issue a single request against the daemon and return the response.
///
/// Opens a fresh connection per call (see module docs).
async fn call(req: Request) -> Result<Response, String> {
    let op = req.op_name();
    #[cfg(unix)]
    {
        use aegis_ipc::transport::unix as tx;
        let path = std::env::var("AEGIS_IPC_SOCKET")
            .unwrap_or_else(|_| "/run/aegis/daemon.sock".to_string());
        let mut client = tx::connect(&path)
            .await
            .map_err(|e| err_to_string("cannot reach the Aegis daemon", e))?;
        client
            .call(req)
            .await
            .map_err(|e| err_to_string(&format!("ipc call {op} failed"), e))
    }
    #[cfg(not(unix))]
    {
        use aegis_ipc::transport::tcp as tx;
        let addr = std::env::var("AEGIS_IPC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:7420".to_string());
        let addr = addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| err_to_string("invalid AEGIS_IPC_ADDR", e))?;
        let token_file = std::env::var("AEGIS_IPC_TOKEN_FILE").map_err(|_| {
            "AEGIS_IPC_TOKEN_FILE is not set (required for the Windows dev transport)"
                .to_string()
        })?;
        let token = tx::read_token(&token_file)
            .map_err(|e| err_to_string("cannot read the IPC token file", e))?;
        let mut client = tx::connect(addr, token)
            .await
            .map_err(|e| err_to_string("cannot reach the Aegis daemon", e))?;
        client
            .call(req)
            .await
            .map_err(|e| err_to_string(&format!("ipc call {op} failed"), e))
    }
}

// ---------------------------------------------------------------------------
// Command implementations.
// ---------------------------------------------------------------------------

/// List all profiles, decorating each with any live session's public IP / state.
pub async fn list_profiles() -> Result<Vec<ProfileView>, String> {
    let resp = call(Request::ListProfiles).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    let profiles = match resp {
        Response::Profiles(p) => p,
        _ => return Err(unexpected("list-profiles")),
    };

    // Best-effort: fold in live-session info so the profiles table can show the
    // public IP and a "running" gateway state. A failure to list sessions is not
    // fatal for rendering profiles.
    let sessions = match call(Request::ListSessions).await {
        Ok(Response::Sessions(s)) => s,
        _ => Vec::new(),
    };

    let now = chrono::Utc::now();
    let mut views: Vec<ProfileView> = profiles
        .iter()
        .map(|p| ProfileView::from_profile(p, now))
        .collect();

    for v in &mut views {
        if let Some(s) = sessions
            .iter()
            .find(|s| s.profile.to_string() == v.id && s.state.is_browsing())
            .or_else(|| sessions.iter().find(|s| s.profile.to_string() == v.id))
        {
            v.public_ip = s.public_ip.clone();
            // A session that is still provisioning/browsing means the gateway is
            // live for this profile; a destroyed/failed one is not.
            if session_is_live(s.state) {
                v.gateway_state = "running".to_string();
            }
        }
    }
    Ok(views)
}

/// Create a new profile from the unified form inputs.
///
/// All validation and the args → [`aegis_core::profile::ProfileSpec`] mapping
/// live in [`CreateProfileArgs::to_spec`], so this handler is a thin wrapper:
/// map, send, decode. The daemon still validates the spec itself (the UI's
/// validation is only for an immediate, friendly error).
pub async fn create_profile(args: CreateProfileArgs) -> Result<ProfileView, String> {
    let spec = args.to_spec()?;
    let resp = call(Request::CreateProfile(spec)).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Profile(p) => Ok(ProfileView::from_profile(&p, chrono::Utc::now())),
        _ => Err(unexpected("create-profile")),
    }
}

/// Compute the live [`aegis_core::preview::ProfilePreview`] for the current
/// create-form inputs. Pure/local: no daemon round trip.
///
/// The preview is derived entirely from the assembled [`ProfileSpec`], so it
/// always matches exactly what a created profile would present to websites. A
/// placeholder name is substituted when the field is still empty so the Preview
/// tab updates live as the user types.
pub fn preview_profile(
    args: CreateProfileArgs,
) -> Result<aegis_core::preview::ProfilePreview, String> {
    args.preview()
}

/// Delete a profile by id string.
pub async fn delete_profile(id: String) -> Result<(), String> {
    let pid = ProfileId::from_str(&id).map_err(|e| err_to_string("invalid profile id", e))?;
    let resp = call(Request::DeleteProfile(pid)).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Ok => Ok(()),
        _ => Err(unexpected("delete-profile")),
    }
}

/// Start a session for a profile ("New Private Session").
pub async fn start_session(profile_id: String) -> Result<SessionView, String> {
    let pid =
        ProfileId::from_str(&profile_id).map_err(|e| err_to_string("invalid profile id", e))?;
    // The UI does not carry unlock secrets; persistent-profile unlock is resolved
    // by the daemon against secure storage (spec §16).
    let req = Request::StartSession(SessionRequest {
        profile: pid,
        unlock_ref: None,
    });
    let resp = call(req).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Session(s) => Ok(SessionView::from_summary(&s)),
        _ => Err(unexpected("start-session")),
    }
}

/// Stop a session by id string.
pub async fn stop_session(session_id: String) -> Result<SessionView, String> {
    let sid =
        SessionId::from_str(&session_id).map_err(|e| err_to_string("invalid session id", e))?;
    let resp = call(Request::StopSession(sid)).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Session(s) => Ok(SessionView::from_summary(&s)),
        _ => Err(unexpected("stop-session")),
    }
}

/// List active sessions.
pub async fn list_sessions() -> Result<Vec<SessionView>, String> {
    let resp = call(Request::ListSessions).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Sessions(s) => Ok(s.iter().map(SessionView::from_summary).collect()),
        _ => Err(unexpected("list-sessions")),
    }
}

/// Fetch the diagnostics panel for a session.
pub async fn get_diagnostics(session_id: String) -> Result<DiagnosticsView, String> {
    let sid =
        SessionId::from_str(&session_id).map_err(|e| err_to_string("invalid session id", e))?;
    let resp = call(Request::GetDiagnostics(sid)).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Diagnostics { checklist, items } => {
            Ok(DiagnosticsView::build(&checklist, &items))
        }
        _ => Err(unexpected("get-diagnostics")),
    }
}

/// Run the daemon self-test.
pub async fn doctor() -> Result<DoctorView, String> {
    let resp = call(Request::Doctor).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Doctor(checklist) => Ok(DoctorView::build(&checklist)),
        _ => Err(unexpected("doctor")),
    }
}

/// Fetch the daemon status snapshot for the Advanced section (version, platform,
/// isolation level, enforcement policy).
pub async fn get_status() -> Result<StatusView, String> {
    let resp = call(Request::GetStatus).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Status(s) => Ok(StatusView::from_status(&s)),
        _ => Err(unexpected("get-status")),
    }
}

/// Fetch the current containment enforcement policy.
pub async fn get_enforcement() -> Result<EnforcementView, String> {
    let resp = call(Request::GetEnforcement).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Enforcement(e) => Ok(EnforcementView::from(e)),
        _ => Err(unexpected("get-enforcement")),
    }
}

/// Replace the containment enforcement policy and return the applied policy.
///
/// The frontend sends three booleans; we map them straight onto the domain
/// [`Enforcement`] type (fail-closed: the daemon still validates and applies the
/// canonical policy, which we echo back).
pub async fn set_enforcement(view: EnforcementView) -> Result<EnforcementView, String> {
    let policy: Enforcement = view.into();
    let resp = call(Request::SetEnforcement(policy)).await?;
    if let Some(msg) = response_error(&resp) {
        return Err(msg);
    }
    match resp {
        Response::Enforcement(e) => Ok(EnforcementView::from(e)),
        _ => Err(unexpected("set-enforcement")),
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Whether a session state means the gateway is currently live for its profile.
/// Destroyed and Failed are gone; everything else is in-flight or browsing.
fn session_is_live(state: aegis_core::session::SessionState) -> bool {
    use aegis_core::session::SessionState::*;
    !matches!(state, Destroyed | Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_error_carries_class() {
        let resp = Response::Error {
            message: "tunnel down".into(),
            class: aegis_core::FailureClass::NetworkContainment,
        };
        let s = response_error(&resp).unwrap();
        assert!(s.contains("tunnel down"));
        assert!(s.contains("NetworkContainment"));
    }
}
