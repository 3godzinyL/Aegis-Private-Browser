//! Pure rendering functions: domain values → display strings.
//!
//! Everything here is deliberately side-effect-free so it can be unit-tested
//! WITHOUT a running daemon. Callers pass the `now` timestamp explicitly so age
//! rendering is deterministic in tests.
//!
//! The badge text always comes from [`aegis_core::preflight::ProtectionStatus::label`]
//! (one of "protection active" / "partial protection" / "unsafe configuration" /
//! "no protection"). We never print "100% anonymous" (spec §11, §16).

use aegis_core::config::{Enforcement, IsolationLevel};
use aegis_core::health::DiagnosticItem;
use aegis_core::preflight::{CheckOutcome, ConnectivityChecklist, ProtectionStatus};
use aegis_core::profile::Profile;
use aegis_core::session::SessionSummary;
use aegis_ipc::StatusDto;
use chrono::{DateTime, Duration, Utc};

/// The placeholder shown for an absent optional value.
const NONE: &str = "-";

/// Render a `chrono::Duration` as a compact human age (e.g. `3d 4h`, `12m`).
#[must_use]
pub fn human_age(age: Duration) -> String {
    // Clamp negatives (clock skew) to zero rather than printing "-1s".
    let secs = age.num_seconds().max(0);
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h {}m", mins % 60);
    }
    let days = hours / 24;
    format!("{days}d {}h", hours % 24)
}

/// Render an optional last-launched timestamp relative to `now`.
#[must_use]
fn last_run(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match last {
        Some(at) => format!("{} ago", human_age(now - at)),
        None => "never".to_string(),
    }
}

/// The one-word gateway/lock state shown in the profiles table.
///
/// A profile that currently holds the single-writer lock is `running`
/// (a session owns it); otherwise it is `idle`.
#[must_use]
fn gateway_state(profile: &Profile) -> &'static str {
    if profile.locked {
        "running"
    } else {
        "idle"
    }
}

/// The columns of the profiles table (spec §11), in order.
const PROFILE_HEADERS: [&str; 10] = [
    "NAME",
    "TYPE",
    "NET",
    "ISOLATION",
    "PROTECTION",
    "GATEWAY",
    "PUBLIC IP",
    "AGE",
    "SIZE",
    "LAST RUN",
];

/// The compact per-profile isolation cell for the table (`vm` / `host`), kept
/// short so the column stays narrow while `profile show` uses the full label.
#[must_use]
fn isolation_cell(level: IsolationLevel) -> &'static str {
    if level.is_full() {
        "vm"
    } else {
        "host"
    }
}

/// Build the row cells for a single profile (used by the table renderer and
/// tests that assert individual cells).
#[must_use]
pub fn profile_row(p: &Profile, now: DateTime<Utc>) -> [String; 10] {
    [
        p.spec.name.clone(),
        p.spec.kind.label().to_string(),
        p.spec.network.mode.label().to_string(),
        isolation_cell(p.spec.isolation).to_string(),
        p.spec.protection.label().to_string(),
        gateway_state(p).to_string(),
        NONE.to_string(), // public IP is a per-session observation, not a profile field
        human_age(p.age(now)),
        p.storage.human(),
        last_run(p.last_launched, now),
    ]
}

/// Render a list of profiles as an aligned table.
///
/// An empty list renders a friendly "no profiles" line instead of a bare header.
#[must_use]
pub fn profiles_table(profiles: &[Profile], now: DateTime<Utc>) -> String {
    if profiles.is_empty() {
        return "no profiles".to_string();
    }
    let rows: Vec<[String; 10]> = profiles.iter().map(|p| profile_row(p, now)).collect();
    render_table(&PROFILE_HEADERS, &rows)
}

/// Render one profile in detailed key/value form (for `profile show`).
#[must_use]
pub fn profile_detail(p: &Profile, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    let mut kv = |k: &str, v: String| {
        out.push_str(&format!("{k:<14}{v}\n"));
    };
    kv("id", p.id.to_string());
    kv("name", p.spec.name.clone());
    kv("type", p.spec.kind.label().to_string());
    kv("net", p.spec.network.mode.label().to_string());
    kv("isolation", p.spec.isolation.label().to_string());
    kv("protection", p.spec.protection.label().to_string());
    kv("dns", format!("{:?}", p.spec.network.dns.mode));
    kv("ipv6", format!("{:?}", p.spec.network.ipv6));
    kv("gateway", gateway_state(p).to_string());
    kv("age", human_age(p.age(now)));
    kv("size", p.storage.human());
    kv("created", p.created_at.to_rfc3339());
    kv("last run", last_run(p.last_launched, now));
    // trim the trailing newline
    out.trim_end().to_string()
}

/// The columns of the sessions table.
const SESSION_HEADERS: [&str; 4] = ["ID", "PROFILE", "STATE", "PROTECTION"];

/// Build the row cells for a session summary.
#[must_use]
pub fn session_row(s: &SessionSummary) -> [String; 4] {
    [
        s.id.to_string(),
        s.profile.to_string(),
        format!("{:?}", s.state).to_lowercase(),
        // The protection badge — always from the core label.
        s.protection.label().to_string(),
    ]
}

/// Render a list of session summaries as an aligned table, each with its badge.
#[must_use]
pub fn sessions_table(sessions: &[SessionSummary]) -> String {
    if sessions.is_empty() {
        return "no active sessions".to_string();
    }
    let rows: Vec<[String; 4]> = sessions.iter().map(session_row).collect();
    render_table(&SESSION_HEADERS, &rows)
}

/// The one-line badge for a protection status. Wraps the core label so tests and
/// call sites use a single source of truth (never "100% anonymous").
#[must_use]
pub fn protection_badge(status: ProtectionStatus) -> String {
    format!("[{}]", status.label())
}

/// Human label for a single check outcome.
#[must_use]
fn outcome_label(outcome: CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Pass => "pass",
        CheckOutcome::Fail => "FAIL",
        CheckOutcome::Skipped => "skip",
    }
}

/// Render the connectivity checklist plus its aggregate protection badge.
///
/// The header line is the badge derived from the checklist's aggregate status;
/// if any check fails, the badge reflects that (e.g. a DNS failure yields
/// "unsafe configuration") and the failing checks are listed with their detail.
#[must_use]
pub fn checklist_report(checklist: &ConnectivityChecklist) -> String {
    let status = checklist.status();
    let mut out = String::new();
    out.push_str(&format!("protection: {}\n", protection_badge(status)));

    // One line per check, in canonical order, with pass/FAIL/skip and detail.
    for id in aegis_core::preflight::CheckId::all() {
        match checklist.report(id) {
            Some(r) => {
                out.push_str(&format!(
                    "  [{:>4}] {}: {}\n",
                    outcome_label(r.outcome),
                    id,
                    r.detail
                ));
            }
            None => {
                out.push_str(&format!("  [{:>4}] {}: (no report)\n", "FAIL", id));
            }
        }
    }

    if let Some(obs) = &checklist.observed_ip {
        out.push_str(&format!(
            "  observed exit IP differs from host: {}\n",
            if obs.differs_from_host { "yes" } else { "NO" }
        ));
    }

    let failures = checklist.failures();
    if failures.is_empty() {
        out.push_str("all checks passed\n");
    } else {
        out.push_str("failing checks:");
        for f in &failures {
            out.push_str(&format!(" {f}"));
        }
        out.push('\n');
    }
    out.trim_end().to_string()
}

/// Render the diagnostics panel: the checklist report followed by the
/// per-subsystem [`DiagnosticItem`]s (spec §11).
#[must_use]
pub fn diagnostics_report(checklist: &ConnectivityChecklist, items: &[DiagnosticItem]) -> String {
    let mut out = checklist_report(checklist);
    out.push('\n');
    // Surface the observed public IP prominently if present.
    let observed = checklist
        .observed_ip
        .as_ref()
        .map_or(NONE.to_string(), |o| o.ip.clone());
    out.push_str(&format!("\npublic IP (from session): {observed}\n"));
    if items.is_empty() {
        out.push_str("no diagnostics items");
    } else {
        out.push_str("diagnostics:\n");
        let rows: Vec<[String; 3]> = items
            .iter()
            .map(|i| [i.key.clone(), i.level.label().to_string(), i.detail.clone()])
            .collect();
        out.push_str(&render_table(&["SUBSYSTEM", "LEVEL", "DETAIL"], &rows));
    }
    out.trim_end().to_string()
}

/// Render the doctor self-test checklist (pass/fail per check).
#[must_use]
pub fn doctor_report(checklist: &ConnectivityChecklist) -> String {
    let mut out = String::from("doctor self-test\n");
    out.push_str(&checklist_report(checklist));
    out.trim_end().to_string()
}

/// The one-line badge for an isolation level. Never claims full anonymity; the
/// reduced level is explicitly labelled `(reduced)` so the user is never misled.
#[must_use]
pub fn isolation_badge(level: IsolationLevel) -> String {
    format!("[{}]", level.label())
}

/// Render a boolean enforcement flag as `on`/`off`.
#[must_use]
fn on_off(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

/// Render an [`Enforcement`] policy as an aligned key/value block, including a
/// derived isolation-level badge.
#[must_use]
pub fn enforcement_report(e: &Enforcement) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "isolation      {}\n",
        isolation_badge(e.isolation_level())
    ));
    out.push_str(&format!(
        "vm-isolation   {}\n",
        on_off(e.require_vm_isolation)
    ));
    out.push_str(&format!("gateway        {}\n", on_off(e.require_gateway)));
    out.push_str(&format!(
        "host-browser   {}\n",
        on_off(e.allow_host_browser)
    ));
    out.trim_end().to_string()
}

/// Render a daemon [`StatusDto`]: platform, isolation badge, enforcement flags,
/// and host-browser availability/path. Never prints "100% anonymous".
#[must_use]
pub fn status_report(status: &StatusDto) -> String {
    let mut out = String::new();
    out.push_str(&format!("version        {}\n", status.version));
    out.push_str(&format!("platform       {}\n", status.platform));
    out.push_str(&format!(
        "isolation      {}\n",
        isolation_badge(status.isolation_level)
    ));
    out.push_str(&format!(
        "vm-isolation   {}\n",
        on_off(status.enforcement.require_vm_isolation)
    ));
    out.push_str(&format!(
        "gateway        {}\n",
        on_off(status.enforcement.require_gateway)
    ));
    out.push_str(&format!(
        "host-browser   {}\n",
        on_off(status.enforcement.allow_host_browser)
    ));
    let host = match (&status.host_browser_available, &status.host_browser_path) {
        (true, Some(p)) => format!("available ({p})"),
        (true, None) => "available".to_string(),
        (false, _) => "not found".to_string(),
    };
    out.push_str(&format!("host browser   {host}\n"));
    // If the effective isolation is reduced, state it plainly.
    if !status.isolation_level.is_full() {
        out.push_str(
            "note           reduced protection: the site runs on your real OS, only VM \
             isolation is dropped\n",
        );
    }
    out.trim_end().to_string()
}

/// Render a generic, left-aligned, space-padded table with a header row.
///
/// Column widths are the max cell width in each column; a two-space gutter
/// separates columns. Works for any fixed-width `[String; N]` rows.
fn render_table<const N: usize>(headers: &[&str; N], rows: &[[String; N]]) -> String {
    let mut widths = [0usize; N];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = h.chars().count();
    }
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    // header row (each header is a &str; convert to owned cell view)
    let header_cells: [String; N] = std::array::from_fn(|i| headers[i].to_string());
    push_padded_row(&mut out, &widths, &header_cells);
    // data rows
    for row in rows {
        push_padded_row(&mut out, &widths, row);
    }
    out.trim_end().to_string()
}

/// Push one padded row of owned cells, using `widths` for column alignment. The
/// final column is not right-padded (avoids trailing whitespace).
fn push_padded_row<const N: usize>(out: &mut String, widths: &[usize; N], row: &[String; N]) {
    for (i, cell) in row.iter().enumerate() {
        out.push_str(cell);
        if i + 1 != N {
            let pad = widths[i].saturating_sub(cell.chars().count());
            out.push_str(&" ".repeat(pad + 2));
        }
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::fingerprint::ProtectionLevel;
    use aegis_core::health::HealthLevel;
    use aegis_core::ids::{ProfileId, SessionId};
    use aegis_core::network::{NetworkConfig, NetworkMode, ProxyConfig, ProxyProtocol};
    use aegis_core::preflight::{CheckId, CheckReport, IpObservation};
    use aegis_core::profile::{ProfileSpec, ProfileType, StorageUsage};
    use aegis_core::session::SessionState;

    fn tor_strict_profile(now: DateTime<Utc>) -> Profile {
        let mut spec = ProfileSpec::ephemeral("research");
        spec.kind = ProfileType::Persistent;
        spec.protection = ProtectionLevel::Strict;
        // default network is Tor
        Profile {
            id: ProfileId::new(),
            spec,
            created_at: now - Duration::hours(50),
            last_launched: Some(now - Duration::minutes(30)),
            storage: StorageUsage {
                bytes: 5 * 1024 * 1024,
            },
            locked: true,
        }
    }

    fn all_pass() -> Vec<CheckReport> {
        CheckId::all()
            .into_iter()
            .map(|id| CheckReport::pass(id, "ok"))
            .collect()
    }

    #[test]
    fn human_age_buckets() {
        assert_eq!(human_age(Duration::seconds(5)), "5s");
        assert_eq!(human_age(Duration::seconds(90)), "1m");
        assert_eq!(human_age(Duration::minutes(90)), "1h 30m");
        assert_eq!(human_age(Duration::hours(50)), "2d 2h");
        // negative clamps to 0s
        assert_eq!(human_age(Duration::seconds(-10)), "0s");
    }

    #[test]
    fn tor_strict_profile_row_renders_correctly() {
        let now = Utc::now();
        let p = tor_strict_profile(now);
        let row = profile_row(&p, now);
        assert_eq!(row[1], "persistent");
        assert_eq!(row[2], "Tor");
        assert_eq!(row[3], "vm"); // default full-VM isolation
        assert_eq!(row[4], "Strict");
        assert_eq!(row[5], "running"); // locked
        assert_eq!(row[8], "5.0 MiB");
        assert!(row[9].ends_with("ago"));
    }

    #[test]
    fn proxy_balanced_profile_row() {
        let now = Utc::now();
        let mut spec = ProfileSpec::ephemeral("proxied");
        spec.network = NetworkConfig::from_mode(NetworkMode::Proxy(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "10.0.0.1".into(),
            port: 1080,
            credentials_ref: None,
            remote_dns: true,
        }));
        let p = Profile {
            id: ProfileId::new(),
            spec,
            created_at: now,
            last_launched: None,
            storage: StorageUsage::default(),
            locked: false,
        };
        let row = profile_row(&p, now);
        assert_eq!(row[2], "Proxy");
        assert_eq!(row[3], "vm");
        assert_eq!(row[4], "Balanced");
        assert_eq!(row[5], "idle");
        assert_eq!(row[9], "never");
    }

    #[test]
    fn profiles_table_has_header_and_aligns() {
        let now = Utc::now();
        let p = tor_strict_profile(now);
        let table = profiles_table(std::slice::from_ref(&p), now);
        assert!(table.contains("NAME"));
        assert!(table.contains("PROTECTION"));
        assert!(table.contains("research"));
        assert!(table.contains("Strict"));
        // header row + one data row
        assert_eq!(table.lines().count(), 2);
    }

    #[test]
    fn empty_profiles_table_is_friendly() {
        assert_eq!(profiles_table(&[], Utc::now()), "no profiles");
    }

    #[test]
    fn profile_detail_lists_fields() {
        let now = Utc::now();
        let p = tor_strict_profile(now);
        let detail = profile_detail(&p, now);
        assert!(detail.contains("name"));
        assert!(detail.contains("research"));
        assert!(detail.contains("Strict"));
        assert!(detail.contains("Tor"));
        // The per-profile isolation level is surfaced.
        assert!(detail.contains("isolation"));
        assert!(detail.contains("full VM isolation"));
    }

    #[test]
    fn profile_row_and_detail_reflect_host_isolation() {
        let now = Utc::now();
        let mut spec = ProfileSpec::ephemeral("host");
        spec.isolation = IsolationLevel::HostProcess;
        let p = Profile {
            id: ProfileId::new(),
            spec,
            created_at: now,
            last_launched: None,
            storage: StorageUsage::default(),
            locked: false,
        };
        // Table cell is the compact "host".
        let row = profile_row(&p, now);
        assert_eq!(row[3], "host");
        // Detail shows the full reduced label.
        let detail = profile_detail(&p, now);
        assert!(detail.contains("host process (reduced)"));
        assert!(!detail.to_lowercase().contains("anonymous"));
    }

    #[test]
    fn profiles_table_has_isolation_column() {
        let now = Utc::now();
        let p = tor_strict_profile(now);
        let table = profiles_table(std::slice::from_ref(&p), now);
        assert!(table.contains("ISOLATION"));
    }

    #[test]
    fn checklist_all_pass_renders_active_badge() {
        let cl = ConnectivityChecklist::new(all_pass());
        let out = checklist_report(&cl);
        assert!(out.contains("protection active"));
        assert!(out.contains("all checks passed"));
        assert!(!out.to_lowercase().contains("100% anonymous"));
    }

    #[test]
    fn checklist_dns_failure_renders_unsafe_and_lists_failing_check() {
        let mut reports = all_pass();
        for r in &mut reports {
            if r.id == CheckId::DnsRouteVerified {
                *r = CheckReport::fail(CheckId::DnsRouteVerified, "leak: plaintext DNS observed");
            }
        }
        let cl = ConnectivityChecklist::new(reports);
        let out = checklist_report(&cl);
        // The aggregate badge must be the unsafe label.
        assert!(
            out.contains("unsafe configuration"),
            "expected unsafe badge in:\n{out}"
        );
        // The failing check is listed by id and detail.
        assert!(out.contains("dns_route_verified"));
        assert!(out.contains("leak: plaintext DNS observed"));
        assert!(out.contains("FAIL"));
    }

    #[test]
    fn checklist_no_gateway_renders_no_protection() {
        let mut reports = all_pass();
        for r in &mut reports {
            if r.id == CheckId::GatewayReady {
                *r = CheckReport::fail(CheckId::GatewayReady, "gateway unreachable");
            }
        }
        let cl = ConnectivityChecklist::new(reports);
        let out = checklist_report(&cl);
        assert!(out.contains("no protection"));
    }

    #[test]
    fn diagnostics_report_includes_items_and_ip() {
        let mut cl = ConnectivityChecklist::new(all_pass());
        cl.observed_ip = Some(IpObservation {
            ip: "198.51.100.9".into(),
            via_tunnel: true,
            differs_from_host: true,
        });
        let items = vec![
            DiagnosticItem::new("dns", HealthLevel::Ok, "verified via Tor DNSPort"),
            DiagnosticItem::new("ipv6", HealthLevel::Ok, "blocked at gateway"),
            DiagnosticItem::new("kill_switch", HealthLevel::Ok, "armed"),
        ];
        let out = diagnostics_report(&cl, &items);
        assert!(out.contains("198.51.100.9"));
        assert!(out.contains("SUBSYSTEM"));
        assert!(out.contains("dns"));
        assert!(out.contains("kill_switch"));
        assert!(out.contains("protection active"));
    }

    #[test]
    fn sessions_table_shows_badges() {
        let sessions = vec![
            SessionSummary {
                id: SessionId::new(),
                profile: ProfileId::new(),
                state: SessionState::Browsing,
                protection: ProtectionStatus::Active,
                public_ip: Some("198.51.100.1".into()),
            },
            SessionSummary {
                id: SessionId::new(),
                profile: ProfileId::new(),
                state: SessionState::Failed,
                protection: ProtectionStatus::Unsafe,
                public_ip: None,
            },
        ];
        let out = sessions_table(&sessions);
        assert!(out.contains("PROTECTION"));
        assert!(out.contains("protection active"));
        assert!(out.contains("unsafe configuration"));
        assert!(out.contains("browsing"));
        assert!(out.contains("failed"));
    }

    #[test]
    fn empty_sessions_table_is_friendly() {
        assert_eq!(sessions_table(&[]), "no active sessions");
    }

    #[test]
    fn protection_badge_never_claims_anonymity() {
        for status in [
            ProtectionStatus::Active,
            ProtectionStatus::Partial,
            ProtectionStatus::Unsafe,
            ProtectionStatus::None,
        ] {
            let b = protection_badge(status);
            assert!(!b.to_lowercase().contains("anonymous"));
            assert!(!b.contains("100%"));
        }
    }

    #[test]
    fn doctor_report_renders_checklist() {
        let cl = ConnectivityChecklist::new(all_pass());
        let out = doctor_report(&cl);
        assert!(out.contains("doctor self-test"));
        assert!(out.contains("protection active"));
    }

    #[test]
    fn isolation_badge_labels_full_and_reduced() {
        assert!(isolation_badge(IsolationLevel::FullVm).contains("full VM isolation"));
        let reduced = isolation_badge(IsolationLevel::HostProcess);
        assert!(reduced.contains("reduced"));
        assert!(!reduced.to_lowercase().contains("anonymous"));
        assert!(!reduced.contains("100%"));
    }

    #[test]
    fn enforcement_report_shows_flags_and_badge() {
        let secure = enforcement_report(&Enforcement::secure());
        assert!(secure.contains("full VM isolation"));
        assert!(secure.contains("vm-isolation   on"));
        assert!(secure.contains("host-browser   off"));

        let host = enforcement_report(&Enforcement::host_browser());
        assert!(host.contains("reduced"));
        assert!(host.contains("vm-isolation   off"));
        assert!(host.contains("host-browser   on"));
    }

    #[test]
    fn status_report_full_vm_has_no_reduced_note() {
        let status = StatusDto {
            version: "0.1.0".into(),
            platform: "linux".into(),
            isolation_level: IsolationLevel::FullVm,
            enforcement: Enforcement::secure(),
            host_browser_available: false,
            host_browser_path: None,
        };
        let out = status_report(&status);
        assert!(out.contains("platform       linux"));
        assert!(out.contains("full VM isolation"));
        assert!(out.contains("host browser   not found"));
        assert!(!out.contains("reduced protection"));
        assert!(!out.to_lowercase().contains("anonymous"));
    }

    #[test]
    fn status_report_host_process_states_reduced_and_path() {
        let status = StatusDto {
            version: "0.1.0".into(),
            platform: "windows".into(),
            isolation_level: IsolationLevel::HostProcess,
            enforcement: Enforcement::host_browser(),
            host_browser_available: true,
            host_browser_path: Some(r"C:\chrome.exe".into()),
        };
        let out = status_report(&status);
        assert!(out.contains("platform       windows"));
        assert!(out.contains("reduced"));
        assert!(out.contains("reduced protection: the site runs on your real OS"));
        assert!(out.contains(r"available (C:\chrome.exe)"));
    }
}
