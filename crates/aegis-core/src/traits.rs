//! The contract layer: every capability the daemon orchestrates is expressed as
//! a trait here so implementations can be swapped (real ↔ mock, Chromium ↔
//! Firefox, libvirt ↔ something else) without changing callers.
//!
//! Impl crates (`vm-controller`, `gateway-controller`, `secure-storage`,
//! `profile-store`, `network-audit`, `browser-launcher`, `update-client`)
//! implement these and depend ONLY on `aegis-core`. The daemon wires concrete
//! implementations together. This is what keeps the workspace a DAG and lets the
//! whole thing be unit-tested with in-memory fakes.

use crate::browser::{
    BackendCapabilities, BackendPolicyBundle, BrowserBackendId, BrowserHandle, BrowserLaunchRequest,
};
use crate::error::Result;
use crate::events::AuditRecord;
use crate::gateway::{FirewallPolicy, GatewayConfig, GatewayHealth, KillSwitchState, TunnelStatus};
use crate::ids::{ProfileId, SessionId, VmId};
use crate::network::{DnsPolicy, Ipv6Policy};
use crate::preflight::{CheckId, CheckReport, ConnectivityChecklist};
use crate::profile::{Profile, ProfilePatch, ProfileSpec};
use crate::secure::{KdfParams, Plaintext, SealedBlob, Secret, SecretKey};
use crate::update::{ApplyOutcome, UpdateManifest, VerifiedArtifact, VersionInfo};
use crate::vm::{DestroyReport, VmHandle, VmProvisionRequest, VmState};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// How a VM should be stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Request a clean ACPI shutdown.
    Graceful,
    /// Force power-off immediately (used on fail-closed teardown).
    Forced,
}

/// Controls VM lifecycle (spec §4, Etap 2). Implemented by `vm-controller`.
#[async_trait]
pub trait VmController: Send + Sync {
    /// Provision a VM from a validated request (creates the disposable overlay).
    async fn provision(&self, req: &VmProvisionRequest) -> Result<VmHandle>;
    /// Start a provisioned VM.
    async fn start(&self, id: &VmId) -> Result<()>;
    /// Stop a running VM.
    async fn shutdown(&self, id: &VmId, mode: ShutdownMode) -> Result<()>;
    /// Destroy a VM and (for ephemeral) shred its writable overlay.
    async fn destroy(&self, id: &VmId) -> Result<DestroyReport>;
    /// Query current VM state.
    async fn state(&self, id: &VmId) -> Result<VmState>;
    /// List known VMs.
    async fn list(&self) -> Result<Vec<VmHandle>>;
}

/// Controls the Gateway VM's firewall, tunnel, and kill switch (spec §5).
/// Implemented by `gateway-controller`.
#[async_trait]
pub trait GatewayController: Send + Sync {
    /// Apply the full gateway configuration (tunnel selection, DNS, IPv6).
    async fn configure(&self, cfg: &GatewayConfig) -> Result<()>;
    /// Apply the fail-closed firewall policy (nftables default-deny).
    async fn apply_firewall(&self, policy: &FirewallPolicy) -> Result<()>;
    /// Query current tunnel status.
    async fn tunnel_status(&self) -> Result<TunnelStatus>;
    /// Cut all traffic immediately (engage kill switch).
    async fn engage_killswitch(&self) -> Result<()>;
    /// Re-arm the kill switch after a verified-safe reconfiguration.
    async fn release_killswitch(&self) -> Result<()>;
    /// Current kill-switch state.
    async fn killswitch_state(&self) -> Result<KillSwitchState>;
    /// Aggregate gateway health.
    async fn health(&self) -> Result<GatewayHealth>;
}

/// A browser engine backend (spec §6). Implemented by `browser-launcher`.
///
/// `render_policy` is synchronous and pure: it turns a launch request into the
/// exact policy bundle, so tests can assert the generated flags/policies without
/// launching anything.
#[async_trait]
pub trait BrowserBackend: Send + Sync {
    /// The backend identifier.
    fn id(&self) -> BrowserBackendId;
    /// Static capabilities.
    fn capabilities(&self) -> BackendCapabilities;
    /// Render managed policies + command line for a launch request (pure).
    fn render_policy(&self, req: &BrowserLaunchRequest) -> Result<BackendPolicyBundle>;
    /// Launch the browser inside the VM using a pre-rendered bundle.
    async fn launch(
        &self,
        req: &BrowserLaunchRequest,
        bundle: &BackendPolicyBundle,
    ) -> Result<BrowserHandle>;
    /// Whether the browser process is still running.
    async fn is_running(&self, handle: &BrowserHandle) -> Result<bool>;
    /// Terminate the browser.
    async fn terminate(&self, handle: &BrowserHandle) -> Result<()>;
}

/// Cryptographic sealing/opening and key derivation (spec §8, §10).
/// Implemented by `secure-storage`. Synchronous — CPU-bound crypto.
pub trait SecureStore: Send + Sync {
    /// Generate a fresh random 32-byte key (used for ephemeral RAM keys).
    fn generate_key(&self) -> Result<SecretKey>;
    /// Fresh KDF parameters with a random salt.
    fn new_kdf_params(&self) -> Result<KdfParams>;
    /// Derive a key from a password using the given parameters.
    fn derive_key(&self, password: &Secret, params: &KdfParams) -> Result<SecretKey>;
    /// Seal (encrypt + authenticate) plaintext under a key.
    fn seal(&self, key: &SecretKey, plaintext: &[u8]) -> Result<SealedBlob>;
    /// Open (verify + decrypt) a sealed blob under a key.
    fn open(&self, key: &SecretKey, blob: &SealedBlob) -> Result<Plaintext>;
}

/// A lease proving exclusive ownership of a profile (single-writer, spec §8).
/// Dropping/releasing the lease frees the profile for a future session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLease {
    /// The leased profile.
    pub profile: ProfileId,
    /// An opaque token identifying the holder.
    pub token: String,
}

/// Persistent + ephemeral profile storage (spec §8). Implemented by
/// `profile-store`.
#[async_trait]
pub trait ProfileRepository: Send + Sync {
    /// Create a profile from a spec.
    async fn create(&self, spec: ProfileSpec) -> Result<Profile>;
    /// Fetch a profile by id.
    async fn get(&self, id: &ProfileId) -> Result<Profile>;
    /// List all profiles.
    async fn list(&self) -> Result<Vec<Profile>>;
    /// Apply a patch to a profile.
    async fn update(&self, id: &ProfileId, patch: ProfilePatch) -> Result<Profile>;
    /// Delete a profile (and shred its data).
    async fn delete(&self, id: &ProfileId) -> Result<()>;
    /// Acquire the single-writer lock; fails with `Busy` if already held.
    async fn acquire_lock(&self, id: &ProfileId) -> Result<ProfileLease>;
    /// Release a previously-acquired lock.
    async fn release_lock(&self, lease: &ProfileLease) -> Result<()>;
    /// Record the last-launched timestamp.
    async fn touch_launch(&self, id: &ProfileId, at: DateTime<Utc>) -> Result<()>;
}

/// Context handed to the network auditor for a preflight run.
///
/// It is deliberately abstract: it names the endpoints and expected policies but
/// does not itself perform I/O. The concrete auditor uses these to run probes
/// (typically from inside the Browser VM via the daemon's guest channel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightContext {
    /// The session being verified.
    pub session: SessionId,
    /// The gateway's downstream address the browser routes through.
    pub gateway_address: String,
    /// A short label of the tunnel mode (Tor/VPN/Proxy) for reporting.
    pub mode_label: String,
    /// The DNS policy that must be in force.
    pub dns: DnsPolicy,
    /// The IPv6 policy that must be in force.
    pub ipv6: Ipv6Policy,
    /// Whether a browser WebRTC policy document has been installed.
    pub webrtc_policy_installed: bool,
    /// The host's real public IP, if known, so the auditor can assert the
    /// observed exit IP differs from it. Never logged.
    pub host_public_ip: Option<String>,
}

/// Runs the preflight connectivity checklist (spec §5). Implemented by
/// `network-audit`.
#[async_trait]
pub trait NetworkAuditor: Send + Sync {
    /// Run the full checklist.
    async fn run_preflight(&self, ctx: &PreflightContext) -> Result<ConnectivityChecklist>;
    /// Run a single check.
    async fn run_check(&self, id: CheckId, ctx: &PreflightContext) -> Result<CheckReport>;
}

/// Update checking, verification, and application (spec Etap 5, §14).
/// Implemented by `update-client`.
#[async_trait]
pub trait UpdateClient: Send + Sync {
    /// Check whether a newer, valid update exists.
    async fn check_for_update(&self, info: &VersionInfo) -> Result<Option<UpdateManifest>>;
    /// Verify a manifest's signature, artifact hashes, and downgrade rule.
    async fn verify(
        &self,
        manifest: &UpdateManifest,
        info: &VersionInfo,
    ) -> Result<VerifiedArtifact>;
    /// Apply a verified update, rolling back on failure.
    async fn apply(&self, verified: &VerifiedArtifact) -> Result<ApplyOutcome>;
}

/// An append-only audit sink (spec §11 "bezpieczne logowanie zdarzeń").
pub trait AuditSink: Send + Sync {
    /// Append a record. Implementations must never persist secrets.
    fn record(&self, record: &AuditRecord) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that the object-safe traits can be used as trait objects.
    #[allow(dead_code)]
    struct Holder {
        vm: Box<dyn VmController>,
        gw: Box<dyn GatewayController>,
        browser: Box<dyn BrowserBackend>,
        store: Box<dyn SecureStore>,
        profiles: Box<dyn ProfileRepository>,
        auditor: Box<dyn NetworkAuditor>,
        updates: Box<dyn UpdateClient>,
        audit: Box<dyn AuditSink>,
    }

    #[test]
    fn traits_are_object_safe() {
        // If this module compiles, the traits above are object-safe.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProfileLease>();
    }
}
