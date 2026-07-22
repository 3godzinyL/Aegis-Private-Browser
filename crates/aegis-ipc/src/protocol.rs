//! The IPC command surface: [`Request`] and [`Response`] (spec §3, §4).
//!
//! Both enums are internally tagged (`{"op": "...", ...}` / `{"result": "...",
//! ...}`) so the wire format is self-describing and forward-compatible: adding a
//! variant does not shift the meaning of existing ones. Every payload type is
//! re-used verbatim from [`aegis_core`] so the daemon never has to translate
//! between an "IPC shape" and a "domain shape".
//!
//! ## Secret hygiene
//!
//! No request or response carries secret material. Unlock passwords are passed
//! by reference ([`aegis_core::network::CredentialRef`]) inside
//! [`aegis_core::session::SessionRequest`]; the daemon resolves them against
//! secure storage locally. This keeps the protocol safe to trace/log at the
//! frame level.

use aegis_core::config::{Enforcement, IsolationLevel};
use aegis_core::health::DiagnosticItem;
use aegis_core::ids::{ProfileId, SessionId};
use aegis_core::preflight::ConnectivityChecklist;
use aegis_core::profile::{Profile, ProfilePatch, ProfileSpec};
use aegis_core::session::{SessionRequest, SessionSummary};
use aegis_core::update::{ApplyOutcome, UpdateManifest, VersionInfo};
use aegis_core::{Error, FailureClass};
use serde::{Deserialize, Serialize};

/// A daemon status snapshot (spec §3, §11) returned by [`Request::GetStatus`].
///
/// Carries the daemon version, the host platform, the isolation level the
/// current [`Enforcement`] policy yields, the policy itself, and whether a
/// host-browser binary is available (for the reduced host-process mode). No
/// secret material is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDto {
    /// The daemon's compiled-in version (`aegis_core::VERSION`).
    pub version: String,
    /// The host platform (`std::env::consts::OS`, e.g. `windows`, `linux`).
    pub platform: String,
    /// The isolation level a new session will get under the current policy.
    pub isolation_level: IsolationLevel,
    /// The current enforcement policy.
    pub enforcement: Enforcement,
    /// Whether a Chromium-family host browser could be located (host mode).
    pub host_browser_available: bool,
    /// The resolved host-browser path, if one was located.
    pub host_browser_path: Option<String>,
}

/// A command sent from a front-end (UI/CLI) to the privileged daemon.
///
/// Serialized with an *adjacently-tagged* representation: a `"op"` discriminator
/// plus a `"body"` payload, e.g.
/// `{"op":"delete-profile","body":"<uuid>"}` or
/// `{"op":"update-profile","body":{"id":"…","patch":{…}}}`. Adjacent tagging is
/// used (rather than internal tagging) because it can carry *every* payload shape
/// — newtype/string/sequence/struct — uniformly. Treat the exact JSON as opaque
/// and use the typed enum, not hand-written JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "body", rename_all = "kebab-case")]
pub enum Request {
    /// List all known profiles.
    ListProfiles,
    /// Create a new profile from a spec.
    CreateProfile(ProfileSpec),
    /// Apply a patch to an existing profile.
    UpdateProfile {
        /// The profile to modify.
        id: ProfileId,
        /// The changes to apply.
        patch: ProfilePatch,
    },
    /// Delete a profile (and shred its data).
    DeleteProfile(ProfileId),
    /// Start a new browsing session for a profile.
    StartSession(SessionRequest),
    /// Stop (tear down) a running session.
    StopSession(SessionId),
    /// List active sessions.
    ListSessions,
    /// Fetch the diagnostics panel items for a session.
    GetDiagnostics(SessionId),
    /// Run the daemon's preflight self-test ("doctor").
    Doctor,
    /// Check whether a newer, valid update exists for the given version.
    CheckUpdate(VersionInfo),
    /// Apply a previously-checked update manifest.
    ApplyUpdate(UpdateManifest),
    /// Fetch the daemon's status snapshot (version, platform, isolation).
    GetStatus,
    /// Fetch the current containment [`Enforcement`] policy.
    GetEnforcement,
    /// Replace the current containment [`Enforcement`] policy.
    SetEnforcement(Enforcement),
}

impl Request {
    /// A stable, machine-readable name for the operation (for tracing/metrics).
    ///
    /// Contains no arguments and therefore no potentially-sensitive values.
    #[must_use]
    pub const fn op_name(&self) -> &'static str {
        match self {
            Self::ListProfiles => "list-profiles",
            Self::CreateProfile(_) => "create-profile",
            Self::UpdateProfile { .. } => "update-profile",
            Self::DeleteProfile(_) => "delete-profile",
            Self::StartSession(_) => "start-session",
            Self::StopSession(_) => "stop-session",
            Self::ListSessions => "list-sessions",
            Self::GetDiagnostics(_) => "get-diagnostics",
            Self::Doctor => "doctor",
            Self::CheckUpdate(_) => "check-update",
            Self::ApplyUpdate(_) => "apply-update",
            Self::GetStatus => "get-status",
            Self::GetEnforcement => "get-enforcement",
            Self::SetEnforcement(_) => "set-enforcement",
        }
    }
}

/// The daemon's reply to a [`Request`].
///
/// Each success variant carries the matching [`aegis_core`] payload. Failures
/// are collapsed into [`Response::Error`], which preserves the fail-closed
/// [`FailureClass`] so the front-end can decide how to react (e.g. surface a
/// kill-switch banner for a containment failure) without re-deriving it.
///
/// Uses the same adjacently-tagged (`"result"` + `"body"`) representation as
/// [`Request`], so every payload shape serializes uniformly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "kebab-case")]
pub enum Response {
    /// Reply to [`Request::ListProfiles`].
    Profiles(Vec<Profile>),
    /// Reply to [`Request::CreateProfile`] / [`Request::UpdateProfile`].
    Profile(Profile),
    /// Acknowledgement of a mutation with no payload (e.g. delete).
    Ok,
    /// Reply to [`Request::StartSession`] / [`Request::StopSession`] — the
    /// current summary of the affected session.
    Session(SessionSummary),
    /// Reply to [`Request::ListSessions`].
    Sessions(Vec<SessionSummary>),
    /// Reply to [`Request::GetDiagnostics`] — the connectivity checklist plus
    /// the diagnostics-panel items.
    Diagnostics {
        /// The preflight connectivity checklist for the session.
        checklist: ConnectivityChecklist,
        /// Per-subsystem diagnostics items.
        items: Vec<DiagnosticItem>,
    },
    /// Reply to [`Request::Doctor`] — the self-test connectivity checklist.
    Doctor(ConnectivityChecklist),
    /// Reply to [`Request::CheckUpdate`] — `Some` if an update is available.
    UpdateAvailable(Option<UpdateManifest>),
    /// Reply to [`Request::ApplyUpdate`].
    UpdateApplied(ApplyOutcome),
    /// Reply to [`Request::GetStatus`] — the daemon status snapshot.
    Status(StatusDto),
    /// Reply to [`Request::GetEnforcement`] / [`Request::SetEnforcement`] — the
    /// current (or just-applied) enforcement policy.
    Enforcement(Enforcement),
    /// Any failure. Carries a human-readable message and its fail-closed class.
    Error {
        /// Human-readable, secret-free description of the failure.
        message: String,
        /// The fail-closed classification the front-end should honour.
        class: FailureClass,
    },
}

impl Response {
    /// Build an error response from an [`aegis_core::Error`], preserving its
    /// [`FailureClass`].
    #[must_use]
    pub fn from_error(err: &Error) -> Self {
        Self::Error {
            message: err.to_string(),
            class: err.class(),
        }
    }

    /// Whether this response is an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// The fail-closed class of an error response, if any.
    #[must_use]
    pub const fn error_class(&self) -> Option<FailureClass> {
        match self {
            Self::Error { class, .. } => Some(*class),
            _ => None,
        }
    }
}

impl From<Error> for Response {
    fn from(err: Error) -> Self {
        Self::from_error(&err)
    }
}

/// Convert a `Result<Response>` into a `Response`, mapping the error arm through
/// [`Response::from_error`] so handler code can use `?` freely.
impl From<aegis_core::Result<Response>> for Response {
    fn from(r: aegis_core::Result<Response>) -> Self {
        match r {
            Ok(resp) => resp,
            Err(e) => Response::from_error(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::health::HealthLevel;
    use aegis_core::network::CredentialRef;
    use aegis_core::preflight::{CheckId, CheckReport, ProtectionStatus};
    use aegis_core::profile::{ProfileSpec, ProfileType, StorageUsage};
    use aegis_core::update::{ApplyOutcome, ArtifactKind, UpdateManifest, Version, VersionInfo};
    use chrono::Utc;

    fn sample_profile() -> Profile {
        Profile {
            id: ProfileId::new(),
            spec: ProfileSpec::ephemeral("test"),
            created_at: Utc::now(),
            last_launched: None,
            storage: StorageUsage { bytes: 4096 },
            locked: false,
        }
    }

    fn sample_summary() -> SessionSummary {
        SessionSummary {
            id: SessionId::new(),
            profile: ProfileId::new(),
            state: aegis_core::session::SessionState::Browsing,
            protection: ProtectionStatus::Active,
            public_ip: Some("198.51.100.7".into()),
        }
    }

    fn sample_checklist() -> ConnectivityChecklist {
        ConnectivityChecklist::new(
            CheckId::all()
                .into_iter()
                .map(|id| CheckReport::pass(id, "ok"))
                .collect(),
        )
    }

    fn sample_manifest() -> UpdateManifest {
        UpdateManifest {
            schema: 1,
            version: Version::new(1, 2, 3),
            delta_base: None,
            kind: aegis_core::update::UpdateKind::Full,
            artifacts: vec![aegis_core::update::Artifact {
                kind: ArtifactKind::AppPackage,
                location: "aegis-1.2.3.pkg".into(),
                sha256: "aa".repeat(32),
                size: 1024,
            }],
            sbom: None,
            signature: "bb".repeat(32),
        }
    }

    /// Roundtrip a value through JSON and assert equality.
    fn roundtrip_req(req: &Request) {
        let json = serde_json::to_string(req).expect("serialize");
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, &back, "request roundtrip mismatch: {json}");
    }

    fn roundtrip_resp(resp: &Response) {
        let json = serde_json::to_string(resp).expect("serialize");
        let back: Response = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(resp, &back, "response roundtrip mismatch: {json}");
    }

    #[test]
    fn request_roundtrip_every_variant() {
        let spec = ProfileSpec {
            name: "persistent".into(),
            kind: ProfileType::Persistent,
            network: Default::default(),
            protection: aegis_core::fingerprint::ProtectionLevel::Strict,
            isolation: aegis_core::config::IsolationLevel::FullVm,
            permissions: Default::default(),
        };
        let variants = vec![
            Request::ListProfiles,
            Request::CreateProfile(spec.clone()),
            Request::UpdateProfile {
                id: ProfileId::new(),
                patch: ProfilePatch {
                    name: Some("renamed".into()),
                    ..Default::default()
                },
            },
            Request::DeleteProfile(ProfileId::new()),
            Request::StartSession(SessionRequest {
                profile: ProfileId::new(),
                unlock_ref: Some(CredentialRef::new("unlock-1")),
            }),
            Request::StopSession(SessionId::new()),
            Request::ListSessions,
            Request::GetDiagnostics(SessionId::new()),
            Request::Doctor,
            Request::CheckUpdate(VersionInfo {
                current: Version::new(1, 0, 0),
            }),
            Request::ApplyUpdate(sample_manifest()),
            Request::GetStatus,
            Request::GetEnforcement,
            Request::SetEnforcement(aegis_core::config::Enforcement::host_browser()),
        ];
        for v in &variants {
            roundtrip_req(v);
        }
    }

    #[test]
    fn response_roundtrip_every_variant() {
        let variants = vec![
            Response::Profiles(vec![sample_profile(), sample_profile()]),
            Response::Profile(sample_profile()),
            Response::Ok,
            Response::Session(sample_summary()),
            Response::Sessions(vec![sample_summary()]),
            Response::Diagnostics {
                checklist: sample_checklist(),
                items: vec![DiagnosticItem::new("dns", HealthLevel::Ok, "verified")],
            },
            Response::Doctor(sample_checklist()),
            Response::UpdateAvailable(Some(sample_manifest())),
            Response::UpdateAvailable(None),
            Response::UpdateApplied(ApplyOutcome::Applied),
            Response::Status(StatusDto {
                version: "0.1.0".into(),
                platform: "windows".into(),
                isolation_level: aegis_core::config::IsolationLevel::HostProcess,
                enforcement: aegis_core::config::Enforcement::host_browser(),
                host_browser_available: true,
                host_browser_path: Some("C:/chrome.exe".into()),
            }),
            Response::Enforcement(aegis_core::config::Enforcement::secure()),
            Response::Error {
                message: "boom".into(),
                class: FailureClass::NetworkContainment,
            },
        ];
        for v in &variants {
            roundtrip_resp(v);
        }
    }

    #[test]
    fn error_response_preserves_class() {
        let err = Error::NetworkContainment("tunnel down".into());
        let resp = Response::from_error(&err);
        assert!(resp.is_error());
        assert_eq!(resp.error_class(), Some(FailureClass::NetworkContainment));
        // And the message is carried through verbatim.
        match resp {
            Response::Error { message, .. } => assert!(message.contains("tunnel down")),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn result_into_response_uses_error_arm() {
        let r: aegis_core::Result<Response> = Err(Error::Busy("profile in use".into()));
        let resp: Response = r.into();
        assert_eq!(resp.error_class(), Some(FailureClass::Precondition));
    }

    #[test]
    fn op_name_is_argument_free() {
        // op_name must not depend on arguments; the same op yields the same name.
        assert_eq!(
            Request::DeleteProfile(ProfileId::new()).op_name(),
            Request::DeleteProfile(ProfileId::new()).op_name()
        );
        assert_eq!(Request::Doctor.op_name(), "doctor");
    }
}
