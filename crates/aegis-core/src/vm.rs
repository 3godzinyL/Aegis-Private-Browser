//! Virtual-machine domain model and the host-isolation policy (spec §4, §10).
//!
//! The [`IsolationPolicy`] encodes every "must not" from the spec as a checked
//! boolean. A VM cannot be provisioned unless its policy satisfies
//! [`IsolationPolicy::validate`]. This turns prose guarantees ("brak USB
//! passthrough", "brak kamery i mikrofonu", "read-only root") into a single
//! machine-checkable contract that `vm-controller` must honor and tests assert.

use crate::ids::{InstanceId, VmId};
use serde::{Deserialize, Serialize};

/// The role a VM plays in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmRole {
    /// The network gateway (firewall + tunnel). Has two NICs: one upstream to
    /// the host's NAT network, one downstream to the isolated browser network.
    Gateway,
    /// The browser workstation. Exactly one NIC, to the gateway only.
    Browser,
}

/// The GPU backend exposed to a VM. Physical passthrough is never an option
/// (spec §4 "Nie przekazywać fizycznej karty graficznej hosta").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum GpuBackend {
    /// `virtio-gpu` — normal mode.
    #[default]
    VirtioGpu,
    /// Pure software rendering — fallback / strict.
    Software,
}

/// A disk layer. Ephemeral sessions run on a throwaway qcow2 overlay backed by
/// a read-only base image; the overlay is destroyed at session end (spec §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLayer {
    /// Path to the read-only backing image (a signed base snapshot).
    pub backing_image: String,
    /// Path to the writable overlay (qcow2). For ephemeral VMs this lives on an
    /// encrypted/tmpfs-backed location and is shredded on destroy.
    pub overlay_path: String,
    /// Whether the overlay must be securely destroyed when the VM is torn down.
    pub destroy_on_close: bool,
    /// Whether the backing image is mounted read-only inside the guest.
    pub read_only_root: bool,
}

/// The host-isolation policy. Every field is a guarantee the controller must
/// uphold; `true` means "the risky feature is OFF / the safe default is ON".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationPolicy {
    /// No shared clipboard between host and guest.
    pub no_shared_clipboard: bool,
    /// No drag-and-drop channel.
    pub no_drag_and_drop: bool,
    /// No shared/host folders (9p/virtiofs/samba).
    pub no_shared_folders: bool,
    /// No automatic mounting of host disks.
    pub no_host_disk_automount: bool,
    /// No USB passthrough.
    pub no_usb_passthrough: bool,
    /// No PCI/GPU passthrough.
    pub no_pci_passthrough: bool,
    /// No camera or microphone exposed to the guest.
    pub no_camera_microphone: bool,
    /// No access to the host SSH agent.
    pub no_host_ssh_agent: bool,
    /// No guest tools that provide desktop integration.
    pub no_desktop_integration_tools: bool,
    /// Root filesystem is read-only inside the guest.
    pub read_only_root: bool,
    /// A locally-generated random instance id, unrelated to any host id.
    pub random_instance_id: bool,
    /// A fresh virtual NIC (new MAC) per instance.
    pub fresh_network_device: bool,
}

impl IsolationPolicy {
    /// The maximally-locked-down policy used for every Aegis VM. There is no
    /// weaker variant — these are invariants, not preferences.
    #[must_use]
    pub const fn hardened() -> Self {
        Self {
            no_shared_clipboard: true,
            no_drag_and_drop: true,
            no_shared_folders: true,
            no_host_disk_automount: true,
            no_usb_passthrough: true,
            no_pci_passthrough: true,
            no_camera_microphone: true,
            no_host_ssh_agent: true,
            no_desktop_integration_tools: true,
            read_only_root: true,
            random_instance_id: true,
            fresh_network_device: true,
        }
    }

    /// Returns the first violated guarantee, or `None` if fully hardened.
    #[must_use]
    pub fn validate(&self) -> Option<&'static str> {
        let checks: [(bool, &'static str); 12] = [
            (
                self.no_shared_clipboard,
                "shared clipboard must be disabled",
            ),
            (self.no_drag_and_drop, "drag-and-drop must be disabled"),
            (self.no_shared_folders, "shared folders must be disabled"),
            (
                self.no_host_disk_automount,
                "host disk automount must be disabled",
            ),
            (self.no_usb_passthrough, "USB passthrough must be disabled"),
            (
                self.no_pci_passthrough,
                "PCI/GPU passthrough must be disabled",
            ),
            (
                self.no_camera_microphone,
                "camera/microphone must be disabled",
            ),
            (
                self.no_host_ssh_agent,
                "host SSH agent forwarding must be disabled",
            ),
            (
                self.no_desktop_integration_tools,
                "desktop integration tools must be absent",
            ),
            (self.read_only_root, "root filesystem must be read-only"),
            (
                self.random_instance_id,
                "instance id must be locally randomized",
            ),
            (
                self.fresh_network_device,
                "a fresh virtual NIC must be used",
            ),
        ];
        checks.into_iter().find(|(ok, _)| !ok).map(|(_, msg)| msg)
    }

    /// Convenience: is this policy fully hardened?
    #[must_use]
    pub fn is_hardened(&self) -> bool {
        self.validate().is_none()
    }
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self::hardened()
    }
}

/// Static resource sizing for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmResources {
    /// Virtual CPUs.
    pub vcpus: u32,
    /// Memory in MiB.
    pub memory_mib: u32,
}

impl VmResources {
    /// Defaults for a gateway (small).
    #[must_use]
    pub const fn gateway() -> Self {
        Self {
            vcpus: 1,
            memory_mib: 512,
        }
    }
    /// Defaults for a browser workstation.
    #[must_use]
    pub const fn browser() -> Self {
        Self {
            vcpus: 2,
            memory_mib: 4096,
        }
    }
}

/// A request to provision a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmProvisionRequest {
    /// Locally-generated instance id, never derived from host state.
    pub instance_id: InstanceId,
    /// The VM's role.
    pub role: VmRole,
    /// Resource sizing.
    pub resources: VmResources,
    /// Disk layering.
    pub disk: DiskLayer,
    /// GPU backend.
    pub gpu: GpuBackend,
    /// Host-isolation policy (must be hardened).
    pub isolation: IsolationPolicy,
    /// Name of the isolated libvirt network the downstream NIC attaches to.
    pub isolated_network: String,
}

impl VmProvisionRequest {
    /// Validate the request against non-negotiable invariants before provisioning.
    ///
    /// # Errors
    /// Returns [`crate::Error::Isolation`] if any host-isolation guarantee is unmet.
    pub fn validate(&self) -> crate::Result<()> {
        if let Some(reason) = self.isolation.validate() {
            return Err(crate::Error::Isolation(reason.to_string()));
        }
        if self.role == VmRole::Browser && !self.disk.read_only_root {
            return Err(crate::Error::Isolation(
                "browser VM must have a read-only root filesystem".into(),
            ));
        }
        Ok(())
    }
}

/// Runtime state of a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmState {
    /// Defined but not started.
    Defined,
    /// Booting.
    Starting,
    /// Running.
    Running,
    /// Shutting down.
    Stopping,
    /// Stopped (still defined).
    Stopped,
    /// Destroyed and cleaned up (overlay shredded for ephemeral).
    Destroyed,
    /// In an error state.
    Failed,
}

impl VmState {
    /// Whether the VM is actively running.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// A handle to a provisioned VM returned by the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmHandle {
    /// The controller-assigned id.
    pub id: VmId,
    /// The instance id from the request.
    pub instance_id: InstanceId,
    /// The role.
    pub role: VmRole,
    /// The libvirt domain name (derived from the id slug; carries no host data).
    pub domain_name: String,
    /// Current state at the time the handle was produced.
    pub state: VmState,
}

/// The report returned after destroying a VM, proving cleanup happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestroyReport {
    /// The VM that was destroyed.
    pub id: VmId,
    /// Whether the writable overlay was securely removed.
    pub overlay_shredded: bool,
    /// Whether the libvirt domain definition was undefined.
    pub domain_undefined: bool,
}

impl DestroyReport {
    /// Whether the teardown left no writable residue (spec §14 disposable rule).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.overlay_shredded && self.domain_undefined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_policy_validates() {
        assert!(IsolationPolicy::hardened().is_hardened());
        assert!(IsolationPolicy::default().is_hardened());
    }

    #[test]
    fn any_weakening_is_rejected() {
        let mut p = IsolationPolicy::hardened();
        p.no_usb_passthrough = false;
        assert!(!p.is_hardened());
        assert!(p.validate().unwrap().contains("USB"));
    }

    #[test]
    fn browser_requires_readonly_root() {
        let req = VmProvisionRequest {
            instance_id: InstanceId::new(),
            role: VmRole::Browser,
            resources: VmResources::browser(),
            disk: DiskLayer {
                backing_image: "/img/browser-base.qcow2".into(),
                overlay_path: "/run/aegis/overlay.qcow2".into(),
                destroy_on_close: true,
                read_only_root: false, // <- violation
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: "aegis-net-abcd".into(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn destroy_report_clean_only_when_both() {
        let id = VmId::new();
        assert!(DestroyReport {
            id,
            overlay_shredded: true,
            domain_undefined: true
        }
        .is_clean());
        assert!(!DestroyReport {
            id,
            overlay_shredded: false,
            domain_undefined: true
        }
        .is_clean());
    }
}
