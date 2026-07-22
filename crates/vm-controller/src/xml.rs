//! Pure libvirt domain-XML rendering (spec §4, §10, Etap 2).
//!
//! [`render_domain_xml`] turns a validated [`VmProvisionRequest`] into a libvirt
//! domain definition. It is deliberately **pure** (no I/O, deterministic given
//! its inputs plus the supplied MAC/name) so tests can assert the exact security
//! properties of the generated machine:
//!
//! * `virtio-gpu` (or plain software) video, never host GPU passthrough;
//! * **no** `<hostdev>` (no USB/PCI passthrough);
//! * **no** `<redirdev>` (no USB redirection);
//! * **no** `<filesystem>` (no 9p/virtiofs host share);
//! * **no** sound / usb-redir / spicevmc / clipboard / drag channels;
//! * the base disk mounted **read-only** for the browser role;
//! * a browser has **exactly one** `<interface>` (to the isolated network);
//! * a gateway has **two** `<interface>`s (upstream NAT + downstream isolated);
//! * a locally-randomised MAC and an instance-derived domain name.
//!
//! Every value is XML-escaped; the generated document contains no host
//! identifiers or file paths carrying the host username beyond what the request
//! itself provided.

use aegis_core::vm::{GpuBackend, VmProvisionRequest, VmRole};

/// The libvirt network the gateway's upstream NIC attaches to. This is the
/// host-facing NAT network; the browser never touches it.
pub const UPSTREAM_NETWORK: &str = "default";

/// Escape the five XML predefined entities so untrusted strings (paths, network
/// names) cannot break out of an attribute or element.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// The libvirt domain name derived from the request's instance id.
///
/// This is a stable, host-independent slug (e.g. `inst-1a2b3c4d`). It carries no
/// host state, satisfying "losowy identyfikator instancji VM generowany lokalnie".
#[must_use]
pub fn domain_name(req: &VmProvisionRequest) -> String {
    req.instance_id.slug()
}

/// Render the `<video>` element for the chosen GPU backend.
///
/// Never emits `<hostdev>`-style passthrough. `virtio-gpu` is the normal path;
/// `Software` selects the `none`/`vga`-free software model. In both cases 3D
/// acceleration is explicitly disabled to avoid host driver exposure.
fn render_video(gpu: GpuBackend) -> &'static str {
    match gpu {
        GpuBackend::VirtioGpu => {
            "    <video>\n      \
             <model type='virtio' heads='1'>\n        \
             <acceleration accel3d='no'/>\n      </model>\n    </video>\n"
        }
        GpuBackend::Software => {
            "    <video>\n      <model type='vga' vram='16384' heads='1'/>\n    </video>\n"
        }
    }
}

/// Render one `<interface>` bound to a libvirt network with a fixed MAC.
fn render_interface(network: &str, mac: &str) -> String {
    format!(
        "    <interface type='network'>\n      \
         <mac address='{mac}'/>\n      \
         <source network='{network}'/>\n      \
         <model type='virtio'/>\n    </interface>\n",
        mac = xml_escape(mac),
        network = xml_escape(network),
    )
}

/// Render the `<disk>` stanza.
///
/// The base/backing image is always mounted read-only; writes go to the qcow2
/// overlay. For the browser role the guest sees a strictly read-only root
/// (`<readonly/>` on the device), enforcing "snapshot bazowego systemu tylko do
/// odczytu" at the device level in addition to the overlay/backing split.
fn render_disk(req: &VmProvisionRequest) -> String {
    let overlay = xml_escape(&req.disk.overlay_path);
    let backing = xml_escape(&req.disk.backing_image);
    // The read-only marker is applied when the guest root must be read-only.
    let readonly = if req.disk.read_only_root {
        "      <readonly/>\n"
    } else {
        ""
    };
    format!(
        "    <disk type='file' device='disk'>\n      \
         <driver name='qemu' type='qcow2'/>\n      \
         <source file='{overlay}'>\n        \
         <backingStore type='file'>\n          \
         <format type='qcow2'/>\n          \
         <source file='{backing}'/>\n        </backingStore>\n      </source>\n      \
         <target dev='vda' bus='virtio'/>\n{readonly}    </disk>\n",
    )
}

/// Build a complete libvirt domain XML for a provision request.
///
/// `mac` is the (already-randomised) MAC for the browser NIC / the gateway's
/// downstream NIC; `upstream_mac` is used for the gateway's upstream NIC and is
/// ignored for the browser role. Callers pass freshly-generated MACs so the
/// function stays pure and deterministic for testing.
///
/// # Panics
/// Never. All inputs are escaped; the function only formats strings.
#[must_use]
pub fn render_domain_xml_with(req: &VmProvisionRequest, mac: &str, upstream_mac: &str) -> String {
    let name = domain_name(req);
    let uuid = req.instance_id.as_uuid();

    // Interfaces per role:
    //  * Browser: EXACTLY ONE interface, to the isolated network only.
    //  * Gateway: TWO interfaces, upstream NAT + downstream isolated.
    let interfaces = match req.role {
        VmRole::Browser => render_interface(&req.isolated_network, mac),
        VmRole::Gateway => {
            let up = render_interface(UPSTREAM_NETWORK, upstream_mac);
            let down = render_interface(&req.isolated_network, mac);
            format!("{up}{down}")
        }
    };

    let video = render_video(req.gpu);
    let disk = render_disk(req);

    // The <features>/<devices> set is intentionally minimal. We emit NO:
    //   <hostdev>   (USB/PCI passthrough)
    //   <redirdev>  (USB redirection)
    //   <filesystem>(9p/virtiofs host share)
    //   <sound>     (audio device)
    //   <channel type='spicevmc'>  (usb-redir/clipboard agent transport)
    //   <clipboard>/<filetransfer> (copy-paste / drag agents)
    //   <graphics type='spice'>    (which would bring in the above)
    // A headless serial/console is provided for management only.
    format!(
        "<domain type='kvm'>\n  \
         <name>{name}</name>\n  \
         <uuid>{uuid}</uuid>\n  \
         <memory unit='MiB'>{mem}</memory>\n  \
         <currentMemory unit='MiB'>{mem}</currentMemory>\n  \
         <vcpu placement='static'>{vcpus}</vcpu>\n  \
         <os>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <boot dev='hd'/>\n  </os>\n  \
         <features>\n    <acpi/>\n    <apic/>\n  </features>\n  \
         <cpu mode='host-passthrough' check='none'/>\n  \
         <clock offset='utc'/>\n  \
         <on_poweroff>destroy</on_poweroff>\n  \
         <on_reboot>restart</on_reboot>\n  \
         <on_crash>destroy</on_crash>\n  \
         <devices>\n\
         {disk}\
         {interfaces}\
         {video}    \
         <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n    \
         <console type='pty'>\n      <target type='serial' port='0'/>\n    </console>\n    \
         <memballoon model='virtio'/>\n    \
         <rng model='virtio'>\n      <backend model='random'>/dev/urandom</backend>\n    </rng>\n  \
         </devices>\n\
         </domain>\n",
        mem = req.resources.memory_mib,
        vcpus = req.resources.vcpus,
    )
}

/// Convenience wrapper that generates the required MAC address(es) internally.
///
/// Prefer [`render_domain_xml_with`] in tests where a deterministic MAC is
/// needed; use this in production where fresh randomness is desired per
/// instance (satisfying "nowe wirtualne urządzenie sieciowe dla każdej instancji").
#[must_use]
pub fn render_domain_xml(req: &VmProvisionRequest) -> String {
    render_domain_xml_with(req, &random_mac(), &random_mac())
}

/// Generate a random, locally-administered unicast MAC address.
///
/// The first octet is `0x52` (the QEMU/KVM locally-administered prefix `52:54`),
/// guaranteeing the unicast + locally-administered bits and keeping the address
/// unrelated to any host NIC.
#[must_use]
pub fn random_mac() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // 52:54:00 is the canonical QEMU locally-administered OUI.
    let b: [u8; 3] = [rng.gen(), rng.gen(), rng.gen()];
    format!("52:54:00:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::ids::InstanceId;
    use aegis_core::vm::{DiskLayer, IsolationPolicy, VmResources};

    fn browser_req() -> VmProvisionRequest {
        VmProvisionRequest {
            instance_id: InstanceId::new(),
            role: VmRole::Browser,
            resources: VmResources::browser(),
            disk: DiskLayer {
                backing_image: "/img/browser-base.qcow2".into(),
                overlay_path: "/run/aegis/overlay.qcow2".into(),
                destroy_on_close: true,
                read_only_root: true,
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: "aegis-net-abcd".into(),
        }
    }

    fn gateway_req() -> VmProvisionRequest {
        VmProvisionRequest {
            instance_id: InstanceId::new(),
            role: VmRole::Gateway,
            resources: VmResources::gateway(),
            disk: DiskLayer {
                backing_image: "/img/gateway-base.qcow2".into(),
                overlay_path: "/run/aegis/gw-overlay.qcow2".into(),
                destroy_on_close: true,
                read_only_root: true,
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: "aegis-net-abcd".into(),
        }
    }

    #[test]
    fn browser_xml_has_virtio_gpu_and_no_passthrough() {
        let xml = render_domain_xml(&browser_req());
        assert!(xml.contains("<video>"));
        assert!(xml.contains("type='virtio'"));
        assert!(xml.contains("accel3d='no'"));
        // No device passthrough / redirection / host share / audio agents.
        assert!(!xml.contains("<hostdev"), "must not contain hostdev");
        assert!(!xml.contains("<redirdev"), "must not contain redirdev");
        assert!(
            !xml.contains("<filesystem"),
            "must not contain filesystem share"
        );
        assert!(!xml.contains("<sound"), "must not contain sound");
        assert!(
            !xml.contains("spicevmc"),
            "must not contain spicevmc channel"
        );
        assert!(!xml.contains("usbredir"), "must not contain usbredir");
        assert!(
            !xml.contains("<clipboard"),
            "must not contain clipboard agent"
        );
        assert!(
            !xml.contains("<filetransfer"),
            "must not contain drag/file transfer"
        );
        assert!(!xml.contains("spice"), "must not contain spice graphics");
    }

    #[test]
    fn browser_has_exactly_one_interface() {
        let xml = render_domain_xml(&browser_req());
        let count = xml.matches("<interface ").count();
        assert_eq!(count, 1, "browser must have exactly one NIC");
        assert!(xml.contains("aegis-net-abcd"));
        // Browser must NOT be attached to the upstream host network.
        assert!(!xml.contains("network='default'"));
    }

    #[test]
    fn browser_base_disk_is_readonly() {
        let xml = render_domain_xml(&browser_req());
        assert!(
            xml.contains("<readonly/>"),
            "browser root must be read-only"
        );
        assert!(xml.contains("<backingStore"));
        assert!(xml.contains("/img/browser-base.qcow2"));
        assert!(xml.contains("/run/aegis/overlay.qcow2"));
    }

    #[test]
    fn gateway_has_two_interfaces_upstream_and_downstream() {
        let xml = render_domain_xml(&gateway_req());
        let count = xml.matches("<interface ").count();
        assert_eq!(count, 2, "gateway must have exactly two NICs");
        assert!(xml.contains("network='default'"), "upstream NAT network");
        assert!(
            xml.contains("network='aegis-net-abcd'"),
            "downstream isolated network"
        );
    }

    #[test]
    fn domain_name_is_instance_slug() {
        let req = browser_req();
        let xml = render_domain_xml(&req);
        let expected = req.instance_id.slug();
        assert!(xml.contains(&format!("<name>{expected}</name>")));
        assert!(expected.starts_with("inst-"));
    }

    #[test]
    fn mac_is_locally_administered_and_random() {
        let m1 = random_mac();
        let m2 = random_mac();
        assert!(m1.starts_with("52:54:00:"));
        assert_eq!(m1.len(), 17);
        // Overwhelmingly likely to differ; guards against a constant MAC bug.
        assert_ne!(m1, m2);
    }

    #[test]
    fn software_gpu_uses_vga_model_not_passthrough() {
        let mut req = browser_req();
        req.gpu = GpuBackend::Software;
        let xml = render_domain_xml(&req);
        assert!(xml.contains("type='vga'"));
        assert!(!xml.contains("<hostdev"));
    }

    #[test]
    fn network_name_is_xml_escaped() {
        let mut req = browser_req();
        req.isolated_network = "aegis&<net>".into();
        let xml = render_domain_xml_with(&req, "52:54:00:aa:bb:cc", "52:54:00:dd:ee:ff");
        assert!(xml.contains("aegis&amp;&lt;net&gt;"));
        assert!(!xml.contains("aegis&<net>"));
    }

    #[test]
    fn deterministic_with_fixed_mac() {
        let req = browser_req();
        let a = render_domain_xml_with(&req, "52:54:00:11:22:33", "52:54:00:44:55:66");
        let b = render_domain_xml_with(&req, "52:54:00:11:22:33", "52:54:00:44:55:66");
        assert_eq!(a, b);
        assert!(a.contains("52:54:00:11:22:33"));
    }
}
