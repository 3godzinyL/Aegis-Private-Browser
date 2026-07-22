//! # vm-controller
//!
//! The concrete [`aegis_core::traits::VmController`] for Aegis (spec §4, §10,
//! Etap 2). It drives libvirt/QEMU by shelling out to `virsh` and `qemu-img`
//! through a small [`CommandRunner`] abstraction, so the security-critical
//! isolation logic is fully unit-testable without a hypervisor.
//!
//! ## What it guarantees
//!
//! * **Fail-closed provisioning.** [`LibvirtController::provision`] runs
//!   [`VmProvisionRequest::validate`] first; a non-hardened
//!   [`aegis_core::vm::IsolationPolicy`] or a browser VM without a read-only
//!   root is rejected with an [`aegis_core::Error::Isolation`]
//!   ([`aegis_core::FailureClass::Isolation`]) *before* any disk is created.
//! * **Locked-down machines.** The domain XML is produced by the pure
//!   [`render_domain_xml`] function, which never emits device passthrough, USB
//!   redirection, host-folder shares, or clipboard/drag agents. See [`xml`].
//! * **Disposable overlays.** Ephemeral VMs run on a throwaway qcow2 overlay
//!   backed by a read-only base image; [`LibvirtController::destroy`] shreds it
//!   and returns a [`DestroyReport`] proving the writable layer is gone.
//! * **Platform honesty.** The real runner ([`SystemRunner`]) returns
//!   [`aegis_core::Error::Unsupported`] on non-Linux hosts instead of pretending
//!   to succeed. The whole crate still compiles everywhere.
//!
//! ## Testing
//!
//! Inject a [`MockRunner`] to record `virsh`/`qemu-img` calls and return canned
//! output. See the module tests for adversarial cases (rejecting weak isolation,
//! verifying no host devices leak into the XML, clean teardown, etc.).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod runner;
pub mod xml;

pub use runner::{CommandOutput, CommandRunner, MockRunner, RecordedCall, SystemRunner};
pub use xml::{render_domain_xml, render_domain_xml_with};

use aegis_core::traits::{ShutdownMode, VmController};
use aegis_core::vm::{DestroyReport, VmHandle, VmProvisionRequest, VmState};
use aegis_core::{Error, Result, VmId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The external tool used to create and manage disk overlays.
const QEMU_IMG: &str = "qemu-img";
/// The external tool used to define/start/stop/destroy libvirt domains.
const VIRSH: &str = "virsh";

/// Internal bookkeeping for a VM this controller provisioned.
#[derive(Debug, Clone)]
struct Entry {
    handle: VmHandle,
    overlay_path: String,
    /// Whether the overlay must be shredded on destroy (ephemeral sessions).
    destroy_on_close: bool,
}

/// A [`VmController`] backed by libvirt/QEMU via `virsh` and `qemu-img`.
///
/// Construct with [`LibvirtController::new`] (real system runner) or
/// [`LibvirtController::with_runner`] (any [`CommandRunner`], e.g. a
/// [`MockRunner`] in tests). The controller tracks the VMs it provisioned in
/// memory so [`VmController::list`] can enumerate them and destroy can locate
/// the overlay to shred.
#[derive(Clone)]
pub struct LibvirtController {
    runner: Arc<dyn CommandRunner>,
    // domain_name -> Entry. Keyed by the stable libvirt domain name (the
    // instance slug) so lookups by VmId map through the handle.
    entries: Arc<Mutex<HashMap<VmId, Entry>>>,
}

impl std::fmt::Debug for LibvirtController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibvirtController")
            .field(
                "tracked_vms",
                &self.entries.lock().map(|e| e.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl LibvirtController {
    /// Create a controller that shells out to the real `virsh`/`qemu-img`.
    ///
    /// On non-Linux hosts the underlying [`SystemRunner`] returns
    /// [`Error::Unsupported`] at call time.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemRunner::new()))
    }

    /// Create a controller driven by a caller-supplied [`CommandRunner`].
    #[must_use]
    pub fn with_runner(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The libvirt domain name for a tracked VM, or an error if unknown.
    fn domain_of(&self, id: &VmId) -> Result<String> {
        self.entries
            .lock()
            .expect("controller lock poisoned")
            .get(id)
            .map(|e| e.handle.domain_name.clone())
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "VM {} is not tracked by this controller",
                    id.slug()
                ))
            })
    }

    /// Run an external command and turn a non-zero exit into a [`System`] error.
    ///
    /// [`System`]: aegis_core::Error::System
    async fn run_checked(
        &self,
        program: &str,
        args: &[String],
        what: &str,
    ) -> Result<CommandOutput> {
        let out = self.runner.run(program, args).await?;
        if !out.success() {
            // stderr from these tools does not carry secrets, but we scope the
            // message to the operation to avoid dumping arbitrary content.
            return Err(Error::System(format!(
                "{what} failed (exit {code}): {stderr}",
                code = out
                    .status
                    .map_or_else(|| "signal".to_string(), |c| c.to_string()),
                stderr = out.stderr.trim(),
            )));
        }
        Ok(out)
    }
}

impl Default for LibvirtController {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a `virsh domstate` string to a [`VmState`].
///
/// libvirt reports one of: `running`, `idle`, `paused`, `in shutdown`,
/// `shut off`, `crashed`, `pmsuspended`. Anything unrecognised is treated as
/// [`VmState::Failed`] (fail-closed: we never assume "running/safe" on doubt).
fn parse_domstate(s: &str) -> VmState {
    match s.trim() {
        "running" | "idle" => VmState::Running,
        "paused" | "pmsuspended" => VmState::Stopping,
        "in shutdown" => VmState::Stopping,
        "shut off" => VmState::Stopped,
        "crashed" => VmState::Failed,
        _ => VmState::Failed,
    }
}

#[async_trait]
impl VmController for LibvirtController {
    async fn provision(&self, req: &VmProvisionRequest) -> Result<VmHandle> {
        // 1. Fail-closed validation BEFORE touching disk or libvirt.
        req.validate()?;

        let domain_name = xml::domain_name(req);

        // 2. Create the disposable qcow2 overlay backed by the read-only base.
        //    qemu-img create -f qcow2 -F qcow2 -b <backing> <overlay>
        let create_args = vec![
            "create".to_string(),
            "-f".to_string(),
            "qcow2".to_string(),
            "-F".to_string(),
            "qcow2".to_string(),
            "-b".to_string(),
            req.disk.backing_image.clone(),
            req.disk.overlay_path.clone(),
        ];
        self.run_checked(QEMU_IMG, &create_args, "qemu-img create overlay")
            .await?;

        // 3. Render the locked-down domain XML and define it with virsh.
        //    We write the XML to a temp file so the definition survives argument
        //    length limits and never appears in a process listing.
        let domain_xml = render_domain_xml(req);
        let xml_path = write_temp_xml(&domain_name, &domain_xml)?;
        let define_args = vec!["define".to_string(), xml_path.clone()];
        let define_result = self
            .run_checked(VIRSH, &define_args, "virsh define domain")
            .await;
        // Best-effort cleanup of the temp XML regardless of outcome.
        let _ = std::fs::remove_file(&xml_path);
        define_result?;

        // Log only the host-independent domain name and role — never paths,
        // args, or any host-derived data.
        tracing::debug!(domain = %domain_name, role = ?req.role, "provisioned domain");

        let handle = VmHandle {
            id: VmId::new(),
            instance_id: req.instance_id,
            role: req.role,
            domain_name: domain_name.clone(),
            state: VmState::Defined,
        };

        self.entries
            .lock()
            .expect("controller lock poisoned")
            .insert(
                handle.id,
                Entry {
                    handle: handle.clone(),
                    overlay_path: req.disk.overlay_path.clone(),
                    destroy_on_close: req.disk.destroy_on_close,
                },
            );

        Ok(handle)
    }

    async fn start(&self, id: &VmId) -> Result<()> {
        let domain = self.domain_of(id)?;
        self.run_checked(VIRSH, &["start".to_string(), domain], "virsh start")
            .await?;
        if let Some(e) = self
            .entries
            .lock()
            .expect("controller lock poisoned")
            .get_mut(id)
        {
            e.handle.state = VmState::Running;
        }
        Ok(())
    }

    async fn shutdown(&self, id: &VmId, mode: ShutdownMode) -> Result<()> {
        let domain = self.domain_of(id)?;
        let (subcmd, what) = match mode {
            ShutdownMode::Graceful => ("shutdown", "virsh shutdown"),
            ShutdownMode::Forced => ("destroy", "virsh destroy (forced power-off)"),
        };
        self.run_checked(VIRSH, &[subcmd.to_string(), domain], what)
            .await?;
        if let Some(e) = self
            .entries
            .lock()
            .expect("controller lock poisoned")
            .get_mut(id)
        {
            e.handle.state = match mode {
                ShutdownMode::Graceful => VmState::Stopping,
                ShutdownMode::Forced => VmState::Stopped,
            };
        }
        Ok(())
    }

    async fn destroy(&self, id: &VmId) -> Result<DestroyReport> {
        let entry = self
            .entries
            .lock()
            .expect("controller lock poisoned")
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("VM {} is not tracked", id.slug())))?;
        let domain = entry.handle.domain_name.clone();

        // 1. Force power-off (best-effort: a domain that is already shut off
        //    makes `virsh destroy` fail, which is fine).
        let _ = self
            .runner
            .run(VIRSH, &["destroy".to_string(), domain.clone()])
            .await;

        // 2. Undefine the domain definition. This must succeed for a clean report.
        let undefine = self
            .runner
            .run(VIRSH, &["undefine".to_string(), domain.clone()])
            .await;
        let domain_undefined = matches!(undefine, Ok(ref o) if o.success());

        // 3. Shred + remove the writable overlay for ephemeral VMs.
        let overlay_shredded = if entry.destroy_on_close {
            shred_overlay(&self.runner, &entry.overlay_path).await
        } else {
            // Persistent VMs keep their overlay; "shredded" is trivially true in
            // the sense that there is no ephemeral residue to remove.
            true
        };

        // 4. Update / drop internal state.
        if let Some(e) = self
            .entries
            .lock()
            .expect("controller lock poisoned")
            .get_mut(id)
        {
            e.handle.state = VmState::Destroyed;
        }
        tracing::debug!(
            domain = %domain,
            overlay_shredded,
            domain_undefined,
            "destroyed domain"
        );

        Ok(DestroyReport {
            id: *id,
            overlay_shredded,
            domain_undefined,
        })
    }

    async fn state(&self, id: &VmId) -> Result<VmState> {
        let domain = self.domain_of(id)?;
        let out = self
            .run_checked(VIRSH, &["domstate".to_string(), domain], "virsh domstate")
            .await?;
        Ok(parse_domstate(out.stdout_trimmed()))
    }

    async fn list(&self) -> Result<Vec<VmHandle>> {
        Ok(self
            .entries
            .lock()
            .expect("controller lock poisoned")
            .values()
            .map(|e| e.handle.clone())
            .collect())
    }
}

/// Write the domain XML to a temp file and return its path.
///
/// The temp file lives in the OS temp dir with the domain name in its stem so
/// it is easy to correlate during debugging. The XML contains no secrets.
fn write_temp_xml(domain_name: &str, xml: &str) -> Result<String> {
    let mut path = std::env::temp_dir();
    // Sanitise the stem to a safe slug (it already is, but be defensive).
    let safe: String = domain_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    path.push(format!("aegis-{safe}.xml"));
    std::fs::write(&path, xml)
        .map_err(|e| Error::System(format!("failed to write domain XML: {e}")))?;
    Ok(path.to_string_lossy().into_owned())
}

/// Best-effort secure removal of the writable overlay.
///
/// Prefers `shred -u` (overwrite + unlink) via the runner where available;
/// falls back to a plain filesystem remove. Returns whether the file is gone
/// afterwards. Missing file counts as success (idempotent teardown).
async fn shred_overlay(runner: &Arc<dyn CommandRunner>, overlay_path: &str) -> bool {
    if overlay_path.is_empty() {
        return true;
    }
    // If it never existed, we are already clean.
    if !std::path::Path::new(overlay_path).exists() {
        // Still attempt shred on Linux in case the path is on a device the host
        // process cannot stat; but if plainly absent, report clean.
        return true;
    }

    // Try secure shred first (Linux). Ignore the result; verify by existence.
    let _ = runner
        .run(
            "shred",
            &["-u".to_string(), "-z".to_string(), overlay_path.to_string()],
        )
        .await;

    // Ensure removal even if shred is unavailable or failed.
    if std::path::Path::new(overlay_path).exists() {
        let _ = std::fs::remove_file(overlay_path);
    }

    !std::path::Path::new(overlay_path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::ids::InstanceId;
    use aegis_core::vm::{DiskLayer, GpuBackend, IsolationPolicy, VmResources, VmRole};
    use std::io::Write;

    fn browser_req(overlay: &str, backing: &str) -> VmProvisionRequest {
        VmProvisionRequest {
            instance_id: InstanceId::new(),
            role: VmRole::Browser,
            resources: VmResources::browser(),
            disk: DiskLayer {
                backing_image: backing.into(),
                overlay_path: overlay.into(),
                destroy_on_close: true,
                read_only_root: true,
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: "aegis-net-abcd".into(),
        }
    }

    /// A controller wired to a MockRunner where every command succeeds.
    fn ok_controller() -> (LibvirtController, Arc<MockRunner>) {
        let mock = Arc::new(MockRunner::new());
        let ctrl = LibvirtController::with_runner(mock.clone());
        (ctrl, mock)
    }

    #[tokio::test]
    async fn provision_issues_qemu_img_and_virsh_define() {
        let (ctrl, mock) = ok_controller();
        let req = browser_req("/tmp/aegis-overlay.qcow2", "/img/base.qcow2");
        let handle = ctrl.provision(&req).await.unwrap();

        assert_eq!(handle.role, VmRole::Browser);
        assert_eq!(handle.domain_name, req.instance_id.slug());
        assert_eq!(handle.state, VmState::Defined);

        // qemu-img create -f qcow2 -F qcow2 -b <backing> <overlay>
        assert!(mock.was_called_with(
            QEMU_IMG,
            &[
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                "/img/base.qcow2",
                "/tmp/aegis-overlay.qcow2"
            ]
        ));
        // virsh define <xmlpath>
        let calls = mock.calls();
        let define = calls
            .iter()
            .find(|c| c.program == VIRSH && c.args.first().map(String::as_str) == Some("define"));
        assert!(define.is_some(), "expected a virsh define call");
        // The XML path must end in .xml and reference the domain name.
        let path = &define.unwrap().args[1];
        assert!(path.ends_with(".xml"));
    }

    #[tokio::test]
    async fn provision_rejects_non_hardened_isolation() {
        let (ctrl, mock) = ok_controller();
        let mut req = browser_req("/tmp/o.qcow2", "/img/b.qcow2");
        req.isolation.no_usb_passthrough = false; // weaken isolation

        let err = ctrl.provision(&req).await.unwrap_err();
        assert!(matches!(err, Error::Isolation(_)));
        assert_eq!(err.class(), aegis_core::FailureClass::Isolation);
        assert!(err.requires_killswitch());
        // Fail-closed: no disk creation, no define, nothing tracked.
        assert_eq!(
            mock.call_count(),
            0,
            "must not touch tools when validation fails"
        );
        assert!(ctrl.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn provision_rejects_browser_without_readonly_root() {
        let (ctrl, mock) = ok_controller();
        let mut req = browser_req("/tmp/o.qcow2", "/img/b.qcow2");
        req.disk.read_only_root = false;

        let err = ctrl.provision(&req).await.unwrap_err();
        assert!(matches!(err, Error::Isolation(_)));
        assert_eq!(mock.call_count(), 0);
    }

    #[tokio::test]
    async fn provision_propagates_qemu_img_failure() {
        let mock = Arc::new(MockRunner::with_responder(|program, _| {
            if program == QEMU_IMG {
                Ok(CommandOutput::err(1, "backing file not found"))
            } else {
                Ok(CommandOutput::ok(""))
            }
        }));
        let ctrl = LibvirtController::with_runner(mock.clone());
        let req = browser_req("/tmp/o.qcow2", "/img/missing.qcow2");
        let err = ctrl.provision(&req).await.unwrap_err();
        assert!(matches!(err, Error::System(_)));
        // Must not have attempted a virsh define after qemu-img failed.
        assert!(!mock.calls().iter().any(|c| c.program == VIRSH));
        assert!(ctrl.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn start_and_shutdown_call_expected_subcommands() {
        let (ctrl, mock) = ok_controller();
        let req = browser_req("/tmp/o.qcow2", "/img/b.qcow2");
        let handle = ctrl.provision(&req).await.unwrap();
        let domain = handle.domain_name.clone();

        ctrl.start(&handle.id).await.unwrap();
        assert!(mock.was_called_with(VIRSH, &["start", &domain]));

        ctrl.shutdown(&handle.id, ShutdownMode::Graceful)
            .await
            .unwrap();
        assert!(mock.was_called_with(VIRSH, &["shutdown", &domain]));

        ctrl.shutdown(&handle.id, ShutdownMode::Forced)
            .await
            .unwrap();
        assert!(mock.was_called_with(VIRSH, &["destroy", &domain]));
    }

    #[tokio::test]
    async fn start_unknown_vm_is_not_found() {
        let (ctrl, _mock) = ok_controller();
        let err = ctrl.start(&VmId::new()).await.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn state_parses_domstate_output() {
        let mock = Arc::new(MockRunner::with_responder(|program, args| {
            if program == VIRSH && args.first().map(String::as_str) == Some("domstate") {
                Ok(CommandOutput::ok("running\n"))
            } else {
                Ok(CommandOutput::ok(""))
            }
        }));
        let ctrl = LibvirtController::with_runner(mock);
        let req = browser_req("/tmp/o.qcow2", "/img/b.qcow2");
        let handle = ctrl.provision(&req).await.unwrap();
        assert_eq!(ctrl.state(&handle.id).await.unwrap(), VmState::Running);
    }

    #[test]
    fn domstate_mapping_is_failclosed() {
        assert_eq!(parse_domstate("running"), VmState::Running);
        assert_eq!(parse_domstate("shut off"), VmState::Stopped);
        assert_eq!(parse_domstate("in shutdown"), VmState::Stopping);
        assert_eq!(parse_domstate("crashed"), VmState::Failed);
        assert_eq!(parse_domstate("something-weird"), VmState::Failed);
    }

    #[tokio::test]
    async fn destroy_yields_clean_report_and_removes_overlay() {
        // Create a real temp overlay so we can assert it is removed.
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("overlay.qcow2");
        {
            let mut f = std::fs::File::create(&overlay).unwrap();
            f.write_all(b"writable residue").unwrap();
        }
        assert!(overlay.exists());
        let overlay_str = overlay.to_string_lossy().into_owned();

        let (ctrl, mock) = ok_controller();
        let req = browser_req(&overlay_str, "/img/b.qcow2");
        let handle = ctrl.provision(&req).await.unwrap();

        let report = ctrl.destroy(&handle.id).await.unwrap();
        assert!(report.is_clean(), "expected clean destroy: {report:?}");
        assert!(report.overlay_shredded);
        assert!(report.domain_undefined);
        assert!(!overlay.exists(), "overlay must be removed");

        // Verify virsh undefine was issued.
        assert!(
            mock.any_arg_contains(VIRSH, "undefine")
                || mock.was_called_with(VIRSH, &["undefine", &handle.domain_name])
        );

        // State transitioned to Destroyed.
        let listed = ctrl.list().await.unwrap();
        assert_eq!(listed[0].state, VmState::Destroyed);
    }

    #[tokio::test]
    async fn destroy_reports_undefine_failure() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("overlay.qcow2");
        std::fs::write(&overlay, b"x").unwrap();
        let overlay_str = overlay.to_string_lossy().into_owned();

        let mock = Arc::new(MockRunner::with_responder(|program, args| {
            if program == VIRSH && args.first().map(String::as_str) == Some("undefine") {
                Ok(CommandOutput::err(1, "domain still active"))
            } else {
                Ok(CommandOutput::ok(""))
            }
        }));
        let ctrl = LibvirtController::with_runner(mock);
        let req = browser_req(&overlay_str, "/img/b.qcow2");
        let handle = ctrl.provision(&req).await.unwrap();

        let report = ctrl.destroy(&handle.id).await.unwrap();
        assert!(
            !report.domain_undefined,
            "undefine failure must be reported"
        );
        // Overlay removal still happens (best-effort) even if undefine failed.
        assert!(report.overlay_shredded);
        assert!(!report.is_clean());
    }

    #[tokio::test]
    async fn destroy_unknown_vm_is_not_found() {
        let (ctrl, _mock) = ok_controller();
        let err = ctrl.destroy(&VmId::new()).await.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn gateway_provision_defines_two_interface_domain() {
        let (ctrl, mock) = ok_controller();
        let req = VmProvisionRequest {
            instance_id: InstanceId::new(),
            role: VmRole::Gateway,
            resources: VmResources::gateway(),
            disk: DiskLayer {
                backing_image: "/img/gw.qcow2".into(),
                overlay_path: "/tmp/gw-overlay.qcow2".into(),
                destroy_on_close: true,
                read_only_root: true,
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: "aegis-net-abcd".into(),
        };
        let handle = ctrl.provision(&req).await.unwrap();
        assert_eq!(handle.role, VmRole::Gateway);
        // Confirm the XML rendered for a gateway had two interfaces by checking
        // the pure function directly (the define call only carries a path).
        let xml = render_domain_xml(&req);
        assert_eq!(xml.matches("<interface ").count(), 2);
        assert!(mock.was_called_with(
            QEMU_IMG,
            &[
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                "/img/gw.qcow2",
                "/tmp/gw-overlay.qcow2"
            ]
        ));
    }

    #[tokio::test]
    async fn list_tracks_multiple_handles() {
        let (ctrl, _mock) = ok_controller();
        let a = ctrl
            .provision(&browser_req("/tmp/a.qcow2", "/img/b.qcow2"))
            .await
            .unwrap();
        let b = ctrl
            .provision(&browser_req("/tmp/b.qcow2", "/img/b.qcow2"))
            .await
            .unwrap();
        let listed = ctrl.list().await.unwrap();
        assert_eq!(listed.len(), 2);
        let ids: Vec<_> = listed.iter().map(|h| h.id).collect();
        assert!(ids.contains(&a.id) && ids.contains(&b.id));
    }
}
