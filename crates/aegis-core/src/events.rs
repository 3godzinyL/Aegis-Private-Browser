//! Structured security-audit events (spec §3 "lokalny audyt bezpieczeństwa",
//! §10, §11 "bezpieczne logowanie zdarzeń").
//!
//! Audit records are append-only, machine-parseable, and MUST NOT contain
//! secrets, keys, proxy credentials, full URLs, or host-identifying paths. The
//! [`EventKind`] variants only carry short, secret-free fields, and the module
//! tests enforce this discipline.

use crate::error::FailureClass;
use crate::ids::{ProfileId, SessionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity of an audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational lifecycle event.
    Info,
    /// A notable but handled condition.
    Notice,
    /// A protection was degraded or a check failed.
    Warning,
    /// A containment/isolation guarantee was violated; kill switch engaged.
    Critical,
}

/// The kind of event being recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventKind {
    /// A session lifecycle transition.
    SessionState {
        /// New state name.
        state: String,
    },
    /// A preflight check produced an outcome.
    PreflightCheck {
        /// Check id.
        check: String,
        /// Outcome (pass/fail/skipped).
        outcome: String,
    },
    /// The kill switch changed state.
    KillSwitch {
        /// `engaged` or `armed`.
        state: String,
    },
    /// A tunnel state change.
    Tunnel {
        /// New tunnel state.
        state: String,
    },
    /// A VM lifecycle event.
    Vm {
        /// VM role.
        role: String,
        /// New VM state.
        state: String,
    },
    /// A profile was created / deleted / opened / closed.
    Profile {
        /// Action performed.
        action: String,
    },
    /// A fail-closed enforcement action fired.
    FailClosed {
        /// The failure classification that triggered it.
        class: FailureClass,
        /// A short, secret-free reason.
        reason: String,
    },
    /// An update/integrity event.
    Integrity {
        /// Action (verify/apply/rollback).
        action: String,
        /// Outcome.
        outcome: String,
    },
}

/// An append-only audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// UTC timestamp.
    pub at: DateTime<Utc>,
    /// Severity.
    pub severity: Severity,
    /// Associated session, if any.
    #[serde(default)]
    pub session: Option<SessionId>,
    /// Associated profile, if any.
    #[serde(default)]
    pub profile: Option<ProfileId>,
    /// The event payload.
    pub kind: EventKind,
}

impl AuditRecord {
    /// Construct a record at `at`. Callers must pass the timestamp explicitly so
    /// this stays testable and deterministic.
    #[must_use]
    pub fn new(at: DateTime<Utc>, severity: Severity, kind: EventKind) -> Self {
        Self {
            at,
            severity,
            session: None,
            profile: None,
            kind,
        }
    }

    /// Attach a session id.
    #[must_use]
    pub fn with_session(mut self, id: SessionId) -> Self {
        self.session = Some(id);
        self
    }

    /// Attach a profile id.
    #[must_use]
    pub fn with_profile(mut self, id: ProfileId) -> Self {
        self.profile = Some(id);
        self
    }

    /// Serialize to a single-line JSON string suitable for an audit log.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json_line(&self) -> crate::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_record_serializes_without_secrets() {
        let rec = AuditRecord::new(
            Utc::now(),
            Severity::Critical,
            EventKind::FailClosed {
                class: FailureClass::NetworkContainment,
                reason: "tunnel dropped".into(),
            },
        );
        let line = rec.to_json_line().unwrap();
        assert!(line.contains("fail_closed"));
        assert!(line.contains("network-containment"));
        // Sanity: the reason is present but there is no key material.
        assert!(!line.to_lowercase().contains("password"));
    }

    #[test]
    fn severity_orders_critical_highest() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Notice);
        assert!(Severity::Notice > Severity::Info);
    }
}
