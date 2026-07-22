//! Error taxonomy shared across the Aegis workspace.
//!
//! The cardinal rule of the project is **fail-closed**: any error in the
//! network or isolation path must terminate connectivity, never silently
//! degrade to a direct connection. To make that auditable, errors carry a
//! [`FailureClass`] so higher layers can decide, uniformly, whether an error is
//! *safe to continue past* or must trigger the kill switch.

use std::fmt;

/// Convenient result alias used throughout `aegis-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Classifies how the system must react to a failure.
///
/// This is the machine-readable half of the fail-closed policy. The daemon maps
/// every error to a class and, for [`FailureClass::NetworkContainment`] or
/// [`FailureClass::Isolation`], engages the kill switch before surfacing the
/// error to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    /// A network-containment guarantee could not be upheld (tunnel down, DNS
    /// route unverified, WebRTC policy missing, IPv6 leak possible). MUST cut
    /// connectivity.
    NetworkContainment,
    /// A VM/host isolation guarantee could not be upheld (device passthrough
    /// detected, shared folder present, write layer not destroyed). MUST cut
    /// connectivity and refuse to proceed.
    Isolation,
    /// Cryptographic / secure-storage failure (bad key, tampered blob).
    Cryptography,
    /// Integrity failure on an update or image (bad signature, downgrade).
    Integrity,
    /// Invalid configuration supplied by the user or on disk.
    Configuration,
    /// A precondition was not met but the situation is recoverable and does not
    /// by itself compromise containment (e.g. profile is busy).
    Precondition,
    /// An underlying system/tooling error (process spawn failed, I/O error).
    System,
    /// A programming invariant was violated. Should never reach the user.
    Internal,
}

impl FailureClass {
    /// Whether reaching this failure means connectivity MUST be severed.
    #[must_use]
    pub const fn requires_killswitch(self) -> bool {
        matches!(self, Self::NetworkContainment | Self::Isolation)
    }

    /// Whether the operation may be retried without weakening any guarantee.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Precondition | Self::System)
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NetworkContainment => "network-containment",
            Self::Isolation => "isolation",
            Self::Cryptography => "cryptography",
            Self::Integrity => "integrity",
            Self::Configuration => "configuration",
            Self::Precondition => "precondition",
            Self::System => "system",
            Self::Internal => "internal",
        };
        f.write_str(s)
    }
}

/// The workspace-wide error type.
///
/// Library crates convert their local errors into `Error` at their public
/// boundary so the daemon and UI can handle failures uniformly. The
/// [`Error::class`] method exposes the fail-closed classification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Network containment could not be guaranteed. Fail-closed: cut the tunnel.
    #[error("network containment failure: {0}")]
    NetworkContainment(String),

    /// A VM/host isolation guarantee was violated.
    #[error("isolation failure: {0}")]
    Isolation(String),

    /// A required preflight connectivity check did not pass.
    #[error("preflight check '{check}' failed: {detail}")]
    Preflight {
        /// Machine-readable identifier of the failing check.
        check: String,
        /// Human-readable reason.
        detail: String,
    },

    /// Cryptographic or secure-storage failure.
    #[error("cryptography failure: {0}")]
    Crypto(String),

    /// Integrity verification failed (signature, hash, or downgrade).
    #[error("integrity failure: {0}")]
    Integrity(String),

    /// The supplied configuration is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// A precondition for the operation was not satisfied.
    #[error("precondition not met: {0}")]
    Precondition(String),

    /// A requested resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// A resource is already in use (e.g. profile opened by another session).
    #[error("resource busy: {0}")]
    Busy(String),

    /// The operation is not supported on the current platform/build.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// An underlying system error (I/O, process spawn, serialization).
    #[error("system error: {0}")]
    System(String),

    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// The fail-closed classification of this error.
    #[must_use]
    pub fn class(&self) -> FailureClass {
        match self {
            Self::NetworkContainment(_) | Self::Preflight { .. } => {
                FailureClass::NetworkContainment
            }
            Self::Isolation(_) => FailureClass::Isolation,
            Self::Crypto(_) => FailureClass::Cryptography,
            Self::Integrity(_) => FailureClass::Integrity,
            Self::Config(_) => FailureClass::Configuration,
            Self::Precondition(_) | Self::NotFound(_) | Self::Busy(_) => FailureClass::Precondition,
            Self::Unsupported(_) | Self::System(_) => FailureClass::System,
            Self::Internal(_) => FailureClass::Internal,
        }
    }

    /// Whether reaching this error must sever connectivity.
    #[must_use]
    pub fn requires_killswitch(&self) -> bool {
        self.class().requires_killswitch()
    }

    /// Construct a preflight failure for a given [`crate::preflight::CheckId`].
    pub fn preflight(check: impl fmt::Display, detail: impl fmt::Display) -> Self {
        Self::Preflight {
            check: check.to_string(),
            detail: detail.to_string(),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::System(format!("json: {e}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::System(format!("io: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn killswitch_classes() {
        assert!(Error::NetworkContainment("x".into()).requires_killswitch());
        assert!(Error::Isolation("x".into()).requires_killswitch());
        assert!(Error::preflight("dns_route_verified", "leak").requires_killswitch());
        assert!(!Error::Config("x".into()).requires_killswitch());
        assert!(!Error::Busy("x".into()).requires_killswitch());
    }

    #[test]
    fn retryable_only_for_transient() {
        assert!(FailureClass::System.is_retryable());
        assert!(FailureClass::Precondition.is_retryable());
        assert!(!FailureClass::NetworkContainment.is_retryable());
        assert!(!FailureClass::Integrity.is_retryable());
    }
}
