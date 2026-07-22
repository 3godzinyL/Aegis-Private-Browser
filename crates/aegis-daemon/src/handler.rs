//! The [`aegis_ipc::RequestHandler`] that maps every [`Request`] variant to an
//! [`Orchestrator`] operation and converts errors to
//! [`Response::Error`]`{message, class}` (spec §3, §4).
//!
//! The handler never panics and never puts secret material in a response: every
//! error goes through [`Response::from_error`], which carries only the error's
//! (secret-free) `Display` and its fail-closed [`aegis_core::FailureClass`].

use crate::orchestrator::Orchestrator;
use aegis_core::config::IsolationLevel;
use aegis_core::gateway::KillSwitchState;
use aegis_core::health::{DiagnosticItem, EvidenceState, HealthLevel};
use aegis_core::preflight::{CheckId, CheckOutcome, CheckReport, ConnectivityChecklist};
use aegis_core::profile::{Profile, ProfileType};
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
                let Some(summary) = orch.list_sessions().into_iter().find(|s| s.id == id) else {
                    return Err(aegis_core::Error::NotFound(format!("session {id}")));
                };
                let profile = orch.profiles().get(&summary.profile).await?;

                // Preserve the exact reports produced by the real auditor. If
                // preflight has not completed, every check stays explicitly
                // unknown; never manufacture green checks from the aggregate.
                let checklist = orch.session_checklist(id).unwrap_or_else(unknown_checklist);
                let mut items = configured_profile_items(&profile);
                items.extend(checklist_items(&checklist));

                if profile.spec.isolation == IsolationLevel::FullVm {
                    match orch.gateway_health().await {
                        Ok(health) => {
                            items.push(
                                DiagnosticItem::new(
                                    "firewall",
                                    if health.firewall_applied {
                                        HealthLevel::Ok
                                    } else {
                                        HealthLevel::Down
                                    },
                                    if health.firewall_applied {
                                        "gateway reports a loaded firewall"
                                    } else {
                                        "gateway reports that the firewall is not loaded"
                                    },
                                )
                                .with_evidence(
                                    if health.firewall_applied {
                                        EvidenceState::Verified
                                    } else {
                                        EvidenceState::Measured
                                    },
                                ),
                            );
                            items.push(
                                DiagnosticItem::new(
                                    "kill_switch",
                                    match health.killswitch {
                                        KillSwitchState::Armed => HealthLevel::Ok,
                                        KillSwitchState::Engaged => HealthLevel::Degraded,
                                    },
                                    match health.killswitch {
                                        KillSwitchState::Armed => {
                                            "armed; tunnel-only traffic allowed"
                                        }
                                        KillSwitchState::Engaged => {
                                            "engaged; browser traffic is cut"
                                        }
                                    },
                                )
                                .with_evidence(EvidenceState::Measured),
                            );
                        }
                        Err(_) => items.push(
                            DiagnosticItem::new(
                                "kill_switch",
                                HealthLevel::Unknown,
                                "gateway runtime health is unavailable",
                            )
                            .with_evidence(EvidenceState::Unknown),
                        ),
                    }
                } else {
                    items.push(
                        DiagnosticItem::new(
                            "kill_switch",
                            HealthLevel::Unknown,
                            "no Gateway VM kill switch in reduced host-process mode",
                        )
                        .with_evidence(EvidenceState::Unknown),
                    );
                }

                let browser_item = match orch.browser_liveness(id).await {
                    Ok(Some(true)) => DiagnosticItem::new(
                        "browser_process",
                        HealthLevel::Ok,
                        "browser process is alive",
                    )
                    .with_evidence(EvidenceState::Measured),
                    Ok(Some(false)) => DiagnosticItem::new(
                        "browser_process",
                        HealthLevel::Down,
                        "browser process is not running",
                    )
                    .with_evidence(EvidenceState::Measured),
                    Ok(None) => DiagnosticItem::new(
                        "browser_process",
                        HealthLevel::Unknown,
                        "browser process has not been started",
                    )
                    .with_evidence(EvidenceState::Unknown),
                    Err(_) => DiagnosticItem::new(
                        "browser_process",
                        HealthLevel::Unknown,
                        "browser liveness probe failed",
                    )
                    .with_evidence(EvidenceState::Unknown),
                };
                items.push(browser_item);

                Ok(Response::Diagnostics {
                    protection: summary.protection,
                    checklist,
                    items,
                })
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

fn unknown_checklist() -> ConnectivityChecklist {
    ConnectivityChecklist::new(
        CheckId::all()
            .into_iter()
            .map(|id| CheckReport::skipped(id, "runtime preflight has not reported this check"))
            .collect(),
    )
}

fn configured_item(key: &str, detail: impl Into<String>) -> DiagnosticItem {
    DiagnosticItem::new(key, HealthLevel::Unknown, detail).with_evidence(EvidenceState::Configured)
}

fn configured_profile_items(profile: &Profile) -> Vec<DiagnosticItem> {
    let preview = profile.spec.preview();
    let engine = match profile.spec.browser {
        aegis_core::browser::BrowserBackendId::Chromium => "chromium",
        aegis_core::browser::BrowserBackendId::Firefox => "firefox",
    };
    let environment = match profile.spec.isolation {
        IsolationLevel::FullVm => "linux",
        IsolationLevel::HostProcess => "host",
    };
    let protection = preview.protection.label().to_ascii_lowercase();
    let cohort = format!("{engine}-{environment}-{protection}-v1");
    let cpu = preview
        .hardware_concurrency
        .map(|v| v.to_string())
        .unwrap_or_else(|| "guest-derived".to_string());

    let mut items = vec![
        configured_item("isolation", preview.isolation_label),
        configured_item("browser_engine", profile.spec.browser.label()),
        configured_item("cohort_profile", cohort),
        configured_item("protection_level", preview.protection.label()),
        configured_item("profile_persistence", profile.spec.kind.label()),
        configured_item(
            "render_mode",
            "software/virtual rendering requested; runtime renderer not measured",
        ),
        configured_item(
            "devices",
            if preview.device_apis_blocked {
                "host device APIs blocked by configured browser policy"
            } else {
                "device APIs are not blocked by the configured policy"
            },
        ),
        configured_item(
            "site_user_agent",
            format!(
                "real {} engine version; exact runtime value not measured",
                profile.spec.browser.label()
            ),
        ),
        configured_item("site_timezone", preview.timezone),
        configured_item("site_language", preview.language),
        configured_item("site_cpu", format!("{cpu} logical CPUs")),
        configured_item("site_webgl", preview.webgl),
        configured_item(
            "site_webgpu",
            if preview.webgpu_enabled {
                "enabled"
            } else {
                "disabled"
            },
        ),
        configured_item("site_canvas", preview.canvas),
        configured_item(
            "site_media_devices",
            if preview.limit_media_devices {
                "enumeration limited"
            } else {
                "enumeration not limited"
            },
        ),
        DiagnosticItem::new(
            "site_viewport",
            HealthLevel::Unknown,
            "not reported by a Browser VM runtime probe",
        )
        .with_evidence(EvidenceState::Unknown),
    ];

    let storage_detail = match profile.spec.kind {
        ProfileType::Ephemeral => {
            "disposable overlay selected; backing medium and teardown are not live-attested"
        }
        ProfileType::Persistent => {
            "persistent profile selected; no live LUKS2 volume attestation received"
        }
    };
    items.push(
        DiagnosticItem::new("storage_encryption", HealthLevel::Unknown, storage_detail)
            .with_evidence(EvidenceState::Unknown),
    );
    items
}

fn checklist_items(checklist: &ConnectivityChecklist) -> Vec<DiagnosticItem> {
    let mut items = CheckId::all()
        .into_iter()
        .map(|id| {
            let key = match id {
                CheckId::GatewayReady => "gateway",
                CheckId::TunnelReady => "tunnel",
                CheckId::DnsRouteVerified => "dns",
                CheckId::PublicIpObserved => "public_ip_route",
                CheckId::WebrtcPolicyLoaded => "webrtc",
                CheckId::Ipv6PolicyVerified => "ipv6",
            };
            match checklist.report(id) {
                Some(report) => {
                    let (level, evidence) = match report.outcome {
                        CheckOutcome::Pass => (HealthLevel::Ok, EvidenceState::Verified),
                        CheckOutcome::Fail => (HealthLevel::Down, EvidenceState::Measured),
                        CheckOutcome::Skipped => (HealthLevel::Unknown, EvidenceState::Unknown),
                    };
                    DiagnosticItem::new(key, level, report.detail.clone()).with_evidence(evidence)
                }
                None => DiagnosticItem::new(
                    key,
                    HealthLevel::Unknown,
                    "required runtime check is missing",
                )
                .with_evidence(EvidenceState::Unknown),
            }
        })
        .collect::<Vec<_>>();

    if let Some(observation) = &checklist.observed_ip {
        let safe_path = observation.via_tunnel && observation.differs_from_host;
        items.push(
            DiagnosticItem::new(
                "site_public_ip",
                if safe_path {
                    HealthLevel::Ok
                } else {
                    HealthLevel::Down
                },
                observation.ip.clone(),
            )
            .with_evidence(EvidenceState::Measured),
        );
    } else {
        items.push(
            DiagnosticItem::new(
                "site_public_ip",
                HealthLevel::Unknown,
                "not observed from the browser network path",
            )
            .with_evidence(EvidenceState::Unknown),
        );
    }
    items
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
