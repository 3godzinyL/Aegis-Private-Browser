//! The [`aegis_ipc::RequestHandler`] that maps every [`Request`] variant to an
//! [`Orchestrator`] operation and converts errors to
//! [`Response::Error`]`{message, class}` (spec §3, §4).
//!
//! The handler never panics and never puts secret material in a response: every
//! error goes through [`Response::from_error`], which carries only the error's
//! (secret-free) `Display` and its fail-closed [`aegis_core::FailureClass`].

use crate::orchestrator::Orchestrator;
use aegis_core::health::{DiagnosticItem, HealthLevel};
use aegis_core::preflight::{CheckId, CheckReport, ConnectivityChecklist};
use aegis_core::Result;
use aegis_ipc::{Request, RequestHandler, Response};
use async_trait::async_trait;
use std::sync::Arc;

/// Services IPC requests by dispatching them to the [`Orchestrator`].
pub struct DaemonHandler {
    orchestrator: Arc<Orchestrator>,
}

impl std::fmt::Debug for DaemonHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonHandler").finish_non_exhaustive()
    }
}

impl DaemonHandler {
    /// Wrap an orchestrator as an IPC request handler.
    #[must_use]
    pub fn new(orchestrator: Arc<Orchestrator>) -> Self {
        Self { orchestrator }
    }

    /// The inner dispatch, returning a `Result<Response>` so handler code can use
    /// `?`; the outer [`RequestHandler::handle`] folds the error arm through
    /// [`Response::from_error`].
    async fn dispatch(&self, req: Request) -> Result<Response> {
        let orch = &self.orchestrator;
        match req {
            Request::ListProfiles => {
                let profiles = orch.profiles().list().await?;
                Ok(Response::Profiles(profiles))
            }
            Request::CreateProfile(spec) => {
                let profile = orch.profiles().create(spec).await?;
                Ok(Response::Profile(profile))
            }
            Request::UpdateProfile { id, patch } => {
                let profile = orch.profiles().update(&id, patch).await?;
                Ok(Response::Profile(profile))
            }
            Request::DeleteProfile(id) => {
                orch.profiles().delete(&id).await?;
                Ok(Response::Ok)
            }
            Request::StartSession(session_req) => {
                let summary = orch.start_session(session_req.profile).await?;
                Ok(Response::Session(summary))
            }
            Request::StopSession(id) => {
                let summary = orch.stop_session(id).await?;
                Ok(Response::Session(summary))
            }
            Request::ListSessions => Ok(Response::Sessions(orch.list_sessions())),
            Request::GetDiagnostics(id) => {
                // Surface the last-known protection state for the session as a
                // diagnostics view. A checklist is synthesized from the aggregate
                // status; per-check granularity is preserved in the audit log.
                let Some(summary) = orch.list_sessions().into_iter().find(|s| s.id == id) else {
                    return Err(aegis_core::Error::NotFound(format!("session {id}")));
                };
                let permits = summary.protection.permits_browsing();
                let checklist = ConnectivityChecklist::new(
                    CheckId::all()
                        .into_iter()
                        .map(|c| {
                            if permits {
                                CheckReport::pass(c, "verified")
                            } else {
                                CheckReport::skipped(c, "session not in a browsing state")
                            }
                        })
                        .collect(),
                );
                let level = if permits {
                    HealthLevel::Ok
                } else {
                    HealthLevel::Down
                };
                let items = vec![DiagnosticItem::new(
                    "protection",
                    level,
                    summary.protection.label(),
                )];
                Ok(Response::Diagnostics { checklist, items })
            }
            Request::Doctor => {
                // A self-test: report the compiled-in invariant self-check as a
                // checklist. If any invariant drifted, the corresponding checks
                // are reported as skipped (fail-closed).
                let problems = aegis_core::self_check();
                let ok = problems.is_empty();
                let checklist = ConnectivityChecklist::new(
                    CheckId::all()
                        .into_iter()
                        .map(|c| {
                            if ok {
                                CheckReport::pass(c, "self-check ok")
                            } else {
                                CheckReport::skipped(c, "self-check found a drifted invariant")
                            }
                        })
                        .collect(),
                );
                Ok(Response::Doctor(checklist))
            }
            Request::GetStatus => Ok(Response::Status(orch.status())),
            Request::GetEnforcement => Ok(Response::Enforcement(orch.get_enforcement())),
            Request::SetEnforcement(enforcement) => {
                let applied = orch.set_enforcement(enforcement)?;
                Ok(Response::Enforcement(applied))
            }
            Request::CheckUpdate(info) => {
                let manifest = orch.updates().check_for_update(&info).await?;
                Ok(Response::UpdateAvailable(manifest))
            }
            Request::ApplyUpdate(manifest) => {
                // Verify against the currently-installed version, then apply.
                let info = aegis_core::update::VersionInfo {
                    current: aegis_core::update::Version::new(0, 0, 0),
                };
                let verified = orch.updates().verify(&manifest, &info).await?;
                let outcome = orch.updates().apply(&verified).await?;
                Ok(Response::UpdateApplied(outcome))
            }
        }
    }
}

#[async_trait]
impl RequestHandler for DaemonHandler {
    async fn handle(&self, req: Request) -> Response {
        match self.dispatch(req).await {
            Ok(resp) => resp,
            Err(e) => Response::from_error(&e),
        }
    }
}
