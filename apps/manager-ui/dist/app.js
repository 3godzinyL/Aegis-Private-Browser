// Aegis Private Browser — manager UI frontend.
//
// A static, bundler-free app. It invokes the Rust #[tauri::command] handlers via
// window.__TAURI__ and renders the profiles view + diagnostics panel + advanced
// enforcement controls.
//
// Design notes:
//  * The protection badge uses EXACTLY the four labels returned by the backend
//    (which come verbatim from aegis_core::preflight::ProtectionStatus::label):
//    "protection active" / "partial protection" / "unsafe configuration" /
//    "no protection". The frontend never invents its own wording and never
//    displays "100% anonymous" or "undetectable" (spec §11, §16). The Polish
//    badge translations are honest, one-to-one renderings of those four states
//    and NEVER add a "w pełni anonimowy" ("fully anonymous") claim.
//  * All backend errors surface in the banner; nothing silently falls back.
//  * i18n: a small dictionary (en/pl) + a t(key) helper. The chosen language is
//    persisted to localStorage; default is English (the repo/GitHub is English).

"use strict";

// --- Tauri invoke shim (v2) -------------------------------------------------
// window.__TAURI__.core.invoke is the v2 entry point. We resolve it lazily so a
// helpful message shows if the page is opened outside the Tauri shell.
function tauriInvoke(cmd, args) {
  const t = window.__TAURI__;
  const invoke =
    (t && t.core && t.core.invoke) || (t && t.invoke) || null;
  if (!invoke) {
    return Promise.reject(
      new Error("Tauri API unavailable (open this app through the Aegis manager, not a browser)")
    );
  }
  return invoke(cmd, args);
}

// ============================================================ i18n layer
// The dictionary covers EVERY visible string. `en` is the source of truth;
// missing pl keys fall back to en (and finally to the raw key).
const I18N = {
  en: {
    // top bar / chrome
    app_title: "Aegis Private Browser",
    tagline: "Disposable, isolated browsing environments",
    btn_doctor: "Run doctor",
    btn_refresh: "Refresh",
    btn_new_session: "New Private Session",
    notice:
      "Stronger protection can reduce site compatibility. Aegis reduces linkability and hides your host IP through an isolated gateway — it does not make you anonymous by default. Review the diagnostics panel before you rely on a session.",
    footer_note: "Aegis never claims to make you fully anonymous or undetectable.",
    daemon_unknown: "Daemon: unknown",
    daemon_prefix: "Daemon: ",
    daemon_connected: "connected",
    daemon_unreachable: "unreachable",

    // profiles panel
    profiles_title: "Profiles",
    btn_new_profile: "+ New profile",

    // ---- unified "New Private Session" create modal ----
    create_title: "New Private Session",
    create_sub: "Configure a fresh, isolated browsing profile. Sensible, safe defaults are pre-selected.",
    create_foot_hint: 'Stronger protection can reduce site compatibility. Aegis is not "100% anonymous".',
    btn_create_start: "Create & start",
    btn_create_only: "Create only",

    // tabs
    tab_setup: "Setup",
    tab_preview: "Preview",

    // (1) platform (sets isolation)
    sec_platform: "Where should it run?",
    sec_platform_note: "Where the browser actually runs. This sets your isolation.",
    opt_iso_full: "Linux — full VM isolation",
    opt_iso_full_tag: "max protection",
    opt_iso_full_desc: "Runs in a dedicated VM behind a gateway. Strongest protection. Needs Linux/KVM.",
    opt_iso_host: "Windows / macOS — host browser",
    opt_iso_host_tag: "reduced protection",
    opt_iso_host_desc: "Runs your host browser through Tor/proxy. Reduced protection. Some options are unavailable.",
    iso_host_note:
      "Host mode: the site runs on your real operating system. Only your IP is hidden (via Tor/proxy) and your fingerprint is normalized — you are NOT in an isolated VM. This is weaker protection, not anonymity.",

    // (2) safety tiers (aegis-core SafetyPreset)
    sec_safety: "How safe do you want to be?",
    sec_safety_note: "One click sets protection + fingerprint. Fine-tune in Advanced.",
    tier_compatibility: "Compatibility",
    tier_compatibility_desc: "Loosest — best site compatibility, still hides your host.",
    tier_balanced: "Balanced",
    tier_balanced_desc: "Recommended — most sites work, strong unlinkability.",
    tier_strict: "Strict",
    tier_strict_desc: "Stronger — more uniform fingerprint, some sites break.",
    tier_paranoid: "Paranoid",
    tier_paranoid_desc: "Tightest — maximum uniformity, expect breakage.",

    // (3) name
    sec_name: "Give it a name (optional)",
    sec_name_note: "A label just for you. Not sent to any website. Blank = auto-named.",
    field_name: "Name",
    field_name_ph: "Session 1",

    // (4) live summary — plain-language "what will happen" line.
    // {browser}, {os}, {network} and {protection} are substituted at runtime.
    summary_vm: "➜ Will open {browser} in an isolated Linux VM via {network} — protection: {protection}.",
    summary_host: "➜ Will open {browser} on {os} through {network} — protection: {protection}.",
    summary_os_windows: "Windows",
    summary_net_tor: "Tor",
    summary_net_socks5: "a SOCKS5 proxy",
    summary_net_http: "an HTTP proxy",
    summary_net_vpn: "a VPN",

    // type (moved into Advanced)
    sec_type: "Type",
    sec_type_note: "Whether anything is kept between sessions.",
    field_type: "Type",
    opt_ephemeral: "Ephemeral (leaves nothing behind)",
    opt_ephemeral_desc: "Destroyed at close. Diagnostics show whether disposal was runtime-verified.",
    opt_persistent: "Persistent (encryption required)",
    opt_persistent_desc: "Re-openable. Aegis must verify the encrypted volume before claiming encryption.",

    // (d) advanced
    sec_advanced: "Advanced (fine-tune on top of the preset)",
    sec_browser: "Browser engine",
    sec_browser_note: "Which engine renders the pages.",
    opt_chromium: "Chromium",
    opt_chromium_desc: "Hardened Chromium. Best site compatibility.",
    opt_firefox: "Firefox / Tor Browser",
    opt_firefox_desc: "Gecko engine with a uniform Tor-Browser user-agent.",
    sec_fingerprint: "Fingerprint (override the preset)",
    sec_fingerprint_note: "Each switch overrides the preset for this profile only.",
    fp_webgl: "WebGL",
    fp_webgl_virtual: "Virtual backend",
    fp_webgl_restricted: "Restricted",
    fp_webgl_disabled: "Disabled",
    fp_webgpu: "WebGPU",
    fp_canvas: "Limit Canvas readback",
    fp_letterbox: "Letterboxing",
    fp_cores: "CPU cores (0 = real)",
    fp_timezone: "Timezone",
    fp_timezone_ph: "UTC",
    fp_language: "Language",
    fp_language_ph: "en-US",
    fp_hint: "Non-negotiable rules still apply: device APIs stay blocked and WebGPU stays off in Strict/Paranoid.",

    // network
    sec_network: "Network",
    sec_network_note: "How this profile reaches the internet.",
    field_network: "Network",
    opt_tor: "Tor",
    opt_tor_desc: "Routes through the Tor network. Strongest IP hiding.",
    opt_socks5: "SOCKS5 proxy",
    opt_socks5_desc: "Your own SOCKS5 server. DNS resolved remotely.",
    opt_http: "HTTP proxy",
    opt_http_desc: "An HTTP CONNECT proxy. DNS resolved remotely.",
    opt_vpn: "VPN",
    opt_vpn_desc: "Configured via the CLI (needs endpoint + stored credentials).",
    tag_full_vm_only: "full-VM only",
    field_bridges: "Bridges (optional)",
    field_bridges_ph: "obfs4 1.2.3.4:443 CERT ...",
    field_bridges_hint: "One bridge line per row. Leave empty to connect to Tor directly.",
    field_proxy_host: "Host",
    field_proxy_host_ph: "127.0.0.1",
    field_proxy_port: "Port",
    field_proxy_port_ph: "1080",
    field_proxy_creds: "Credentials (optional)",
    field_proxy_creds_ph: "user:pass",
    field_proxy_creds_hint: "Stored as a reference in secure storage — the password is never logged.",
    err_proxy_host: "Enter a proxy host and port.",
    vpn_note:
      "VPN needs an endpoint and stored credentials, so it is set up through the CLI/config. In host mode, use Tor or a proxy instead.",
    vpn_disabled_host: "VPN is unavailable in host mode — use Tor or a proxy.",

    // ---- Preview tab (aegis-core ProfileSpec::preview) ----
    preview_intro: "Configured target values for this profile. After launch, runtime diagnostics distinguish configured values from measured and verified values.",
    pv_browser: "Browser",
    pv_user_agent: "User-Agent",
    pv_user_agent_note: "Representative — the real engine version is used at runtime.",
    pv_isolation: "Isolation",
    pv_network: "Network",
    pv_protection: "Protection",
    pv_timezone: "Timezone",
    pv_language: "Language",
    pv_cores: "CPU cores",
    pv_webgl: "WebGL",
    pv_webgpu: "WebGPU",
    pv_canvas: "Canvas",
    pv_letterbox: "Letterboxing",
    pv_timer: "Timer precision",
    pv_device_apis: "Device APIs blocked",
    pv_media: "Media devices limited",
    pv_battery: "Battery / Sensors off",
    pv_cores_real: "real (virtual) count",
    pv_on: "on",
    pv_off: "off",
    pv_yes: "yes",
    pv_no: "no",
    preview_error: "Fix the setup to see the preview: ",

    btn_create_profile: "Create profile",
    btn_cancel: "Cancel",

    // table headers
    th_name: "Name",
    th_type: "Type",
    th_network: "Network",
    th_protection: "Protection",
    th_gateway: "Gateway",
    th_public_ip: "Public IP",
    th_age: "Age",
    th_size: "Size",
    th_last_run: "Last run",
    th_actions: "Actions",
    loading_profiles: "Loading profiles…",
    no_profiles: "No profiles yet. Create one to get started.",
    could_not_load_profiles: "Could not load profiles.",

    // profile pills / values
    kind_ephemeral: "ephemeral",
    kind_persistent: "persistent",
    gw_running: "running",
    gw_idle: "idle",
    never: "never",

    // row actions
    btn_start: "Start",
    btn_starting: "Starting…",
    btn_delete: "Delete",

    // diagnostics panel
    diagnostics_title: "Diagnostics",
    no_active_session: "No active session",
    select_session: "Select a session…",
    evidence_legend: "Evidence:",
    evidence_configured: "configured",
    evidence_measured: "measured",
    evidence_verified: "verified",
    evidence_unknown: "unknown",
    session_security: "Session security",
    diag_public_ip: "Public IP (from session)",
    diag_isolation: "Isolation",
    diag_engine: "Browser engine",
    diag_cohort: "Cohort profile",
    diag_protection_level: "Protection level",
    diag_gateway: "Gateway",
    diag_tunnel: "Tunnel",
    diag_dns: "DNS",
    diag_ipv6: "IPv6",
    diag_webrtc: "WebRTC",
    diag_devices: "Available devices",
    diag_render: "Render mode",
    diag_persistence: "Profile persistence",
    diag_killswitch: "Kill-switch activity",
    diag_browser_process: "Browser process",
    diag_storage: "Storage encryption",
    what_sites_see: "What websites can see",
    what_sites_see_intro: "Configured values are targets. Only measured or verified values came back from the running browser environment.",
    site_public_ip: "Public IP",
    site_user_agent: "User-Agent",
    site_viewport: "Screen / viewport",
    site_timezone: "Timezone",
    site_language: "Language / locale",
    site_cpu: "CPU",
    site_media: "Media devices",
    preflight_checks: "Preflight checks",
    subsystem_details: "Subsystem details",
    no_details: "No details.",
    no_additional_details: "No additional subsystem details.",
    select_session_checks: "Select a session to view its preflight checks.",
    no_preflight_checks: "No preflight checks reported.",
    doctor_daemon_only: "Doctor reports the daemon-level checklist only.",
    not_observed: "not observed",
    no_session_selected: "No active session selected.",
    browsing_permitted: "Browsing permitted.",
    browsing_blocked: "Browsing is blocked in this state (fail-closed).",
    doctor_selftest: "Daemon self-test (doctor).",

    // protection badges — the exact four states (honest wording only)
    prot_active: "protection active",
    prot_partial: "partial protection",
    prot_unsafe: "unsafe configuration",
    prot_none: "no protection",

    // banners / messages
    session_started: "Session started",
    profile_deleted: "Profile \"{name}\" deleted.",
    profile_created: "Profile \"{name}\" created.",
    confirm_delete: "Delete profile \"{name}\"? Its data will be shredded and cannot be recovered.",
    create_profile_first: "Create a profile first, then start a private session.",
    doctor_completed: "Doctor completed: ",

    // advanced section
    advanced_title: "Advanced",
    btn_refresh_status: "Refresh status",
    adv_platform: "Platform",
    adv_version: "Daemon version",
    adv_isolation: "Isolation level",
    iso_unknown: "unknown",
    iso_full: "full VM isolation",
    iso_host: "host process (reduced)",
    enforcement_title: "Containment enforcement",
    tg_require_vm: "Require VM isolation",
    tg_require_vm_hint: "Browser runs in a dedicated VM.",
    tg_require_gateway: "Require gateway VM",
    tg_require_gateway_hint: "Network path runs through a dedicated gateway VM.",
    tg_allow_host: "Allow host browser (Windows mode)",
    tg_allow_host_hint: "Run the browser directly on the host through a proxy/Tor.",
    adv_note:
      "Full VM isolation is the secure default. Relaxing it trades protection for the ability to run without a hypervisor.",
    reduced_warning:
      "Reduced protection: the site runs on your real operating system. Only your IP is hidden (via Tor/proxy) and your fingerprint is normalized — you are NOT running in an isolated VM. This is weaker than the full model and is not anonymity.",
    enforcement_updated: "Enforcement updated.",
    host_browser_unavailable:
      "No host browser was found; host-browser mode will not start until one is installed.",
  },
  pl: {
    // top bar / chrome
    app_title: "Aegis Private Browser",
    tagline: "Jednorazowe, izolowane środowiska przeglądania",
    btn_doctor: "Uruchom diagnostykę",
    btn_refresh: "Odśwież",
    btn_new_session: "Nowa sesja prywatna",
    notice:
      "Silniejsza ochrona może pogorszyć zgodność ze stronami. Aegis ogranicza możliwość łączenia śladów i ukrywa Twój adres IP hosta poprzez izolowaną bramę — nie czyni Cię anonimowym domyślnie. Przejrzyj panel diagnostyczny, zanim zaufasz sesji.",
    footer_note: "Aegis nigdy nie twierdzi, że czyni Cię w pełni anonimowym lub niewykrywalnym.",
    daemon_unknown: "Demon: nieznany",
    daemon_prefix: "Demon: ",
    daemon_connected: "połączony",
    daemon_unreachable: "nieosiągalny",

    // profiles panel
    profiles_title: "Profile",
    btn_new_profile: "+ Nowy profil",

    // ---- ujednolicone okno "Nowa sesja prywatna" ----
    create_title: "Nowa sesja prywatna",
    create_sub: "Skonfiguruj świeży, izolowany profil przeglądania. Rozsądne, bezpieczne ustawienia są już wybrane.",
    create_foot_hint: 'Silniejsza ochrona może pogorszyć zgodność ze stronami. Aegis nie jest „100% anonimowy”.',
    btn_create_start: "Utwórz i uruchom",
    btn_create_only: "Tylko utwórz",

    // karty
    tab_setup: "Konfiguracja",
    tab_preview: "Podgląd",

    // (1) platforma (ustawia izolację)
    sec_platform: "Gdzie ma działać?",
    sec_platform_note: "Gdzie faktycznie działa przeglądarka. To ustawia Twoją izolację.",
    opt_iso_full: "Linux — pełna izolacja VM",
    opt_iso_full_tag: "maksymalna ochrona",
    opt_iso_full_desc: "Działa w dedykowanej maszynie wirtualnej za bramą. Najsilniejsza ochrona. Wymaga Linux/KVM.",
    opt_iso_host: "Windows / macOS — przeglądarka hosta",
    opt_iso_host_tag: "ograniczona ochrona",
    opt_iso_host_desc: "Uruchamia przeglądarkę hosta przez Tor/proxy. Ograniczona ochrona. Niektóre opcje są niedostępne.",
    iso_host_note:
      "Tryb hosta: strona działa w Twoim prawdziwym systemie operacyjnym. Ukrywany jest tylko Twój adres IP (przez Tor/proxy), a odcisk przeglądarki jest normalizowany — NIE działasz w izolowanej maszynie wirtualnej. To słabsza ochrona, nie anonimowość.",

    // (2) poziomy bezpieczeństwa (aegis-core SafetyPreset)
    sec_safety: "Jak bezpiecznie chcesz działać?",
    sec_safety_note: "Jedno kliknięcie ustawia ochronę + odcisk. Dostrój w Zaawansowanych.",
    tier_compatibility: "Zgodność",
    tier_compatibility_desc: "Najluźniejszy — najlepsza zgodność stron, nadal ukrywa hosta.",
    tier_balanced: "Zrównoważony",
    tier_balanced_desc: "Zalecany — większość stron działa, silna nierozróżnialność.",
    tier_strict: "Ścisły",
    tier_strict_desc: "Silniejszy — bardziej jednolity odcisk, część stron działa gorzej.",
    tier_paranoid: "Paranoiczny",
    tier_paranoid_desc: "Najściślejszy — maksymalna jednolitość, spodziewaj się problemów.",

    // (3) nazwa
    sec_name: "Nadaj nazwę (opcjonalnie)",
    sec_name_note: "Etykieta tylko dla Ciebie. Nie jest wysyłana do żadnej strony. Puste = nazwa automatyczna.",
    field_name: "Nazwa",
    field_name_ph: "Sesja 1",

    // (4) podsumowanie na żywo — zdanie „co się stanie”.
    summary_vm: "➜ Otworzy {browser} w izolowanej maszynie wirtualnej Linux przez {network} — ochrona: {protection}.",
    summary_host: "➜ Otworzy {browser} na {os} przez {network} — ochrona: {protection}.",
    summary_os_windows: "Windows",
    summary_net_tor: "Tor",
    summary_net_socks5: "proxy SOCKS5",
    summary_net_http: "proxy HTTP",
    summary_net_vpn: "VPN",

    // typ (przeniesiony do Zaawansowanych)
    sec_type: "Typ",
    sec_type_note: "Czy cokolwiek jest zachowywane między sesjami.",
    field_type: "Typ",
    opt_ephemeral: "Jednorazowy (nie zostawia śladów)",
    opt_ephemeral_desc: "Niszczony przy zamknięciu. Diagnostyka pokazuje, czy usunięcie potwierdzono w runtime.",
    opt_persistent: "Trwały (wymagane szyfrowanie)",
    opt_persistent_desc: "Można otworzyć ponownie. Aegis musi zweryfikować wolumen, zanim nazwie go szyfrowanym.",

    // (d) zaawansowane
    sec_advanced: "Zaawansowane (dostrajanie na wierzchu ustawienia)",
    sec_browser: "Silnik przeglądarki",
    sec_browser_note: "Który silnik renderuje strony.",
    opt_chromium: "Chromium",
    opt_chromium_desc: "Wzmocniony Chromium. Najlepsza zgodność ze stronami.",
    opt_firefox: "Firefox / Tor Browser",
    opt_firefox_desc: "Silnik Gecko z jednolitym user-agentem Tor Browser.",
    sec_fingerprint: "Odcisk (nadpisz ustawienie)",
    sec_fingerprint_note: "Każdy przełącznik nadpisuje ustawienie tylko dla tego profilu.",
    fp_webgl: "WebGL",
    fp_webgl_virtual: "Wirtualny backend",
    fp_webgl_restricted: "Ograniczony",
    fp_webgl_disabled: "Wyłączony",
    fp_webgpu: "WebGPU",
    fp_canvas: "Ogranicz odczyt Canvas",
    fp_letterbox: "Marginesy okna",
    fp_cores: "Rdzenie CPU (0 = prawdziwe)",
    fp_timezone: "Strefa czasowa",
    fp_timezone_ph: "UTC",
    fp_language: "Język",
    fp_language_ph: "en-US",
    fp_hint: "Zasady nienaruszalne nadal obowiązują: API urządzeń pozostają zablokowane, a WebGPU wyłączone w trybie Ścisły/Paranoiczny.",

    // sieć
    sec_network: "Sieć",
    sec_network_note: "Jak ten profil łączy się z internetem.",
    field_network: "Sieć",
    opt_tor: "Tor",
    opt_tor_desc: "Kieruje ruch przez sieć Tor. Najsilniejsze ukrywanie IP.",
    opt_socks5: "Proxy SOCKS5",
    opt_socks5_desc: "Twój własny serwer SOCKS5. DNS rozwiązywany zdalnie.",
    opt_http: "Proxy HTTP",
    opt_http_desc: "Proxy HTTP CONNECT. DNS rozwiązywany zdalnie.",
    opt_vpn: "VPN",
    opt_vpn_desc: "Konfigurowany przez CLI (wymaga punktu końcowego + zapisanych poświadczeń).",
    tag_full_vm_only: "tylko pełna VM",
    field_bridges: "Mostki (opcjonalnie)",
    field_bridges_ph: "obfs4 1.2.3.4:443 CERT ...",
    field_bridges_hint: "Jeden mostek w wierszu. Zostaw puste, aby połączyć się z Torem bezpośrednio.",
    field_proxy_host: "Host",
    field_proxy_host_ph: "127.0.0.1",
    field_proxy_port: "Port",
    field_proxy_port_ph: "1080",
    field_proxy_creds: "Poświadczenia (opcjonalnie)",
    field_proxy_creds_ph: "użytkownik:hasło",
    field_proxy_creds_hint: "Przechowywane jako odwołanie w bezpiecznym magazynie — hasło nigdy nie jest logowane.",
    err_proxy_host: "Podaj host i port proxy.",
    vpn_note:
      "VPN wymaga punktu końcowego i zapisanych poświadczeń, więc konfiguruje się go przez CLI/config. W trybie hosta użyj Tora lub proxy.",
    vpn_disabled_host: "VPN jest niedostępny w trybie hosta — użyj Tora lub proxy.",

    // ---- karta Podgląd (aegis-core ProfileSpec::preview) ----
    preview_intro: "Docelowe wartości skonfigurowane dla profilu. Po uruchomieniu diagnostyka odróżnia konfigurację od pomiaru i weryfikacji.",
    pv_browser: "Przeglądarka",
    pv_user_agent: "User-Agent",
    pv_user_agent_note: "Reprezentatywny — w czasie działania używana jest prawdziwa wersja silnika.",
    pv_isolation: "Izolacja",
    pv_network: "Sieć",
    pv_protection: "Ochrona",
    pv_timezone: "Strefa czasowa",
    pv_language: "Język",
    pv_cores: "Rdzenie CPU",
    pv_webgl: "WebGL",
    pv_webgpu: "WebGPU",
    pv_canvas: "Canvas",
    pv_letterbox: "Marginesy okna",
    pv_timer: "Precyzja timera",
    pv_device_apis: "API urządzeń zablokowane",
    pv_media: "Urządzenia multimedialne ograniczone",
    pv_battery: "Bateria / Czujniki wyłączone",
    pv_cores_real: "prawdziwa (wirtualna) liczba",
    pv_on: "wł.",
    pv_off: "wył.",
    pv_yes: "tak",
    pv_no: "nie",
    preview_error: "Popraw konfigurację, aby zobaczyć podgląd: ",

    btn_create_profile: "Utwórz profil",
    btn_cancel: "Anuluj",

    // table headers
    th_name: "Nazwa",
    th_type: "Typ",
    th_network: "Sieć",
    th_protection: "Ochrona",
    th_gateway: "Brama",
    th_public_ip: "Publiczny IP",
    th_age: "Wiek",
    th_size: "Rozmiar",
    th_last_run: "Ostatnie uruchomienie",
    th_actions: "Akcje",
    loading_profiles: "Ładowanie profili…",
    no_profiles: "Brak profili. Utwórz jeden, aby zacząć.",
    could_not_load_profiles: "Nie udało się załadować profili.",

    // profile pills / values
    kind_ephemeral: "jednorazowy",
    kind_persistent: "trwały",
    gw_running: "uruchomiona",
    gw_idle: "bezczynna",
    never: "nigdy",

    // row actions
    btn_start: "Uruchom",
    btn_starting: "Uruchamianie…",
    btn_delete: "Usuń",

    // diagnostics panel
    diagnostics_title: "Diagnostyka",
    no_active_session: "Brak aktywnej sesji",
    select_session: "Wybierz sesję…",
    evidence_legend: "Dowód:",
    evidence_configured: "skonfigurowane",
    evidence_measured: "zmierzone",
    evidence_verified: "zweryfikowane",
    evidence_unknown: "nieznane",
    session_security: "Bezpieczeństwo sesji",
    diag_public_ip: "Publiczny IP (z sesji)",
    diag_isolation: "Izolacja",
    diag_engine: "Silnik przeglądarki",
    diag_cohort: "Profil kohortowy",
    diag_protection_level: "Poziom ochrony",
    diag_gateway: "Brama",
    diag_tunnel: "Tunel",
    diag_dns: "DNS",
    diag_ipv6: "IPv6",
    diag_webrtc: "WebRTC",
    diag_devices: "Dostępne urządzenia",
    diag_render: "Tryb renderowania",
    diag_persistence: "Trwałość profilu",
    diag_killswitch: "Aktywność wyłącznika awaryjnego",
    diag_browser_process: "Proces przeglądarki",
    diag_storage: "Szyfrowanie danych",
    what_sites_see: "Co widzą strony internetowe",
    what_sites_see_intro: "Wartości skonfigurowane są celami. Tylko wartości zmierzone lub zweryfikowane wróciły z działającego środowiska przeglądarki.",
    site_public_ip: "Publiczny IP",
    site_user_agent: "User-Agent",
    site_viewport: "Ekran / viewport",
    site_timezone: "Strefa czasowa",
    site_language: "Język / locale",
    site_cpu: "CPU",
    site_media: "Urządzenia multimedialne",
    preflight_checks: "Testy wstępne",
    subsystem_details: "Szczegóły podsystemów",
    no_details: "Brak szczegółów.",
    no_additional_details: "Brak dodatkowych szczegółów podsystemów.",
    select_session_checks: "Wybierz sesję, aby zobaczyć jej testy wstępne.",
    no_preflight_checks: "Nie zgłoszono żadnych testów wstępnych.",
    doctor_daemon_only: "Diagnostyka pokazuje tylko listę kontrolną na poziomie demona.",
    not_observed: "nie zaobserwowano",
    no_session_selected: "Nie wybrano aktywnej sesji.",
    browsing_permitted: "Przeglądanie dozwolone.",
    browsing_blocked: "Przeglądanie jest zablokowane w tym stanie (bezpieczne domyślnie).",
    doctor_selftest: "Autotest demona (diagnostyka).",

    // protection badges — honest one-to-one translations, NO "w pełni anonimowy"
    prot_active: "ochrona aktywna",
    prot_partial: "ochrona częściowa",
    prot_unsafe: "konfiguracja niebezpieczna",
    prot_none: "brak ochrony",

    // banners / messages
    session_started: "Sesja uruchomiona",
    profile_deleted: "Profil \"{name}\" usunięty.",
    profile_created: "Profil \"{name}\" utworzony.",
    confirm_delete: "Usunąć profil \"{name}\"? Jego dane zostaną zniszczone i nie będzie można ich odzyskać.",
    create_profile_first: "Najpierw utwórz profil, a następnie uruchom sesję prywatną.",
    doctor_completed: "Diagnostyka zakończona: ",

    // advanced section
    advanced_title: "Zaawansowane",
    btn_refresh_status: "Odśwież status",
    adv_platform: "Platforma",
    adv_version: "Wersja demona",
    adv_isolation: "Poziom izolacji",
    iso_unknown: "nieznany",
    iso_full: "pełna izolacja VM",
    iso_host: "proces hosta (ograniczona)",
    enforcement_title: "Wymuszanie izolacji",
    tg_require_vm: "Wymagaj izolacji VM",
    tg_require_vm_hint: "Przeglądarka działa w dedykowanej maszynie wirtualnej.",
    tg_require_gateway: "Wymagaj bramy VM",
    tg_require_gateway_hint: "Ruch sieciowy przechodzi przez dedykowaną bramę VM.",
    tg_allow_host: "Zezwól na przeglądarkę hosta (tryb Windows)",
    tg_allow_host_hint: "Uruchom przeglądarkę bezpośrednio na hoście przez proxy/Tor.",
    adv_note:
      "Pełna izolacja VM to bezpieczne ustawienie domyślne. Jej osłabienie wymienia ochronę na możliwość działania bez hipernadzorcy.",
    reduced_warning:
      "Ograniczona ochrona: strona działa w Twoim prawdziwym systemie operacyjnym. Ukrywany jest tylko Twój adres IP (przez Tor/proxy), a odcisk przeglądarki jest normalizowany — NIE działasz w izolowanej maszynie wirtualnej. To słabsze niż pełny model i nie jest anonimowością.",
    enforcement_updated: "Zaktualizowano wymuszanie izolacji.",
    host_browser_unavailable:
      "Nie znaleziono przeglądarki hosta; tryb przeglądarki hosta nie uruchomi się, dopóki nie zostanie zainstalowana.",
  },
};

let LANG = "en";

/** Translate a key for the current language, with {placeholder} substitution. */
function t(key, vars) {
  const table = I18N[LANG] || I18N.en;
  let s = table[key];
  if (s == null) s = I18N.en[key];
  if (s == null) s = key;
  if (vars) {
    for (const k of Object.keys(vars)) {
      s = s.split("{" + k + "}").join(String(vars[k]));
    }
  }
  return s;
}

/** Apply translations to every [data-i18n] element in the document. */
function applyI18n() {
  document.documentElement.setAttribute("lang", LANG);
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.getAttribute("data-i18n");
    const attr = node.getAttribute("data-i18n-attr");
    if (attr) {
      node.setAttribute(attr, t(key));
    } else {
      node.textContent = t(key);
    }
  });
  // Reflect the active language button.
  document.querySelectorAll(".lang-btn").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-lang") === LANG);
  });
}

/** Switch language live, persist the choice, and re-render dynamic content. */
function setLang(lang) {
  if (lang !== "en" && lang !== "pl") lang = "en";
  LANG = lang;
  try {
    localStorage.setItem("aegis.lang", lang);
  } catch (_e) {
    /* localStorage may be unavailable; language still applies for this run. */
  }
  applyI18n();
  // Re-render anything whose text is produced in JS rather than static HTML.
  refreshAll();
  renderStatus(LAST_STATUS);
  // The live create-modal summary is JS-generated, so re-translate it too.
  updateSummary();
}

function initLang() {
  let saved = null;
  try {
    saved = localStorage.getItem("aegis.lang");
  } catch (_e) {
    saved = null;
  }
  LANG = saved === "pl" ? "pl" : "en"; // default English.
}

// --- small DOM helpers ------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

let bannerTimer = null;
function showBanner(message, kind) {
  const b = $("#banner");
  b.textContent = message;
  b.className = "banner" + (kind === "ok" ? " ok" : "");
  if (bannerTimer) clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => b.classList.add("hidden"), kind === "ok" ? 4000 : 8000);
}
function clearBanner() {
  $("#banner").classList.add("hidden");
}

function setDaemon(up, labelKey) {
  const s = $("#daemon-status");
  s.textContent = t("daemon_prefix") + t(labelKey);
  s.className = "daemon-status " + (up ? "up" : "down");
}

// ============================================================ Profiles view
function pill(text, extraClass) {
  const p = el("span", "pill" + (extraClass ? " " + extraClass : ""), text);
  return p;
}

function fmtTs(iso) {
  if (!iso) return t("never");
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

// Localize the coarse tokens that come back from the backend for display.
function kindLabel(kind) {
  return kind === "persistent" ? t("kind_persistent") : t("kind_ephemeral");
}
function gatewayLabel(state) {
  return state === "running" ? t("gw_running") : t("gw_idle");
}

function renderProfiles(profiles) {
  const body = $("#profiles-body");
  body.innerHTML = "";
  if (!profiles || profiles.length === 0) {
    const tr = el("tr", "empty-row");
    tr.appendChild(Object.assign(el("td"), { colSpan: 10, textContent: t("no_profiles") }));
    body.appendChild(tr);
    return;
  }
  for (const p of profiles) {
    const tr = el("tr");
    tr.appendChild(cell(p.name));

    const tdKind = el("td");
    tdKind.appendChild(pill(kindLabel(p.kind)));
    tr.appendChild(tdKind);

    const tdNet = el("td");
    tdNet.appendChild(pill(p.network_mode, p.network_mode === "Tor" ? "pill-tor" : ""));
    tr.appendChild(tdNet);

    const tdProt = el("td");
    tdProt.appendChild(pill(p.protection_level, p.protection_level === "Strict" ? "pill-strict" : ""));
    tr.appendChild(tdProt);

    const tdGw = el("td");
    tdGw.appendChild(pill(gatewayLabel(p.gateway_state), p.gateway_state === "running" ? "pill-running" : "pill-idle"));
    tr.appendChild(tdGw);

    tr.appendChild(cell(p.public_ip || "—", "mono"));
    tr.appendChild(cell(p.age));
    tr.appendChild(cell(p.size_on_disk));
    tr.appendChild(cell(fmtTs(p.last_run)));

    const tdActions = el("td", "cell-actions");
    const startBtn = el("button", "btn btn-secondary btn-mini", t("btn_start"));
    startBtn.addEventListener("click", () => startSessionFor(p.id, startBtn));
    const delBtn = el("button", "btn btn-danger btn-mini", t("btn_delete"));
    delBtn.addEventListener("click", () => deleteProfile(p.id, p.name, delBtn));
    tdActions.appendChild(startBtn);
    tdActions.appendChild(delBtn);
    tr.appendChild(tdActions);

    body.appendChild(tr);
  }
}

function cell(text, cls) {
  const td = el("td", cls);
  td.textContent = text;
  return td;
}

async function loadProfiles() {
  try {
    const profiles = await tauriInvoke("list_profiles");
    renderProfiles(profiles);
    setDaemon(true, "daemon_connected");
    clearBanner();
  } catch (e) {
    setDaemon(false, "daemon_unreachable");
    const body = $("#profiles-body");
    body.innerHTML = "";
    const tr = el("tr", "empty-row");
    tr.appendChild(Object.assign(el("td"), { colSpan: 10, textContent: t("could_not_load_profiles") }));
    body.appendChild(tr);
    showBanner(String(e.message || e));
  }
}

async function deleteProfile(id, name, btn) {
  if (!window.confirm(t("confirm_delete", { name }))) return;
  btn.disabled = true;
  try {
    await tauriInvoke("delete_profile", { id });
    showBanner(t("profile_deleted", { name }), "ok");
    await refreshAll();
  } catch (e) {
    showBanner(String(e.message || e));
  } finally {
    btn.disabled = false;
  }
}

// --- create-profile modal ---------------------------------------------------
// The two-tab "New Private Session" flow. Tab 1 (Setup) walks top-to-bottom:
// platform → name/type → four one-click safety tiers → an expandable Advanced
// section that fine-tunes on top of the chosen preset. Tab 2 (Preview) shows
// the configured target values, computed by the backend from ProfileSpec::preview.
// The create-args -> ProfileSpec mapping itself lives entirely in Rust.

/** The current value of a radio group by its `name` attribute. */
function radioValue(name) {
  const checked = document.querySelector(`input[name="${name}"]:checked`);
  return checked ? checked.value : null;
}

// The four one-click safety tiers, mirroring aegis-core SafetyPreset. Each maps
// to the coarse protection level sent to the backend and to the fingerprint
// defaults used to SEED the Advanced switches so they show the preset's baseline
// before the user overrides anything. These mirror FingerprintPolicy::{...} in
// aegis-core (kept honest — device APIs are always blocked; WebGPU always off).
const SAFETY_PRESETS = {
  compatibility: {
    protection: "balanced",
    fp: { webgl: "virtual-backend", webgpu: false, canvas: false, letterbox: false, cores: 8, timezone: "UTC", language: "en-US" },
  },
  balanced: {
    protection: "balanced",
    fp: { webgl: "virtual-backend", webgpu: false, canvas: false, letterbox: false, cores: 4, timezone: "UTC", language: "en-US" },
  },
  strict: {
    protection: "strict",
    fp: { webgl: "disabled", webgpu: false, canvas: true, letterbox: true, cores: 2, timezone: "UTC", language: "en-US" },
  },
  paranoid: {
    protection: "strict",
    fp: { webgl: "disabled", webgpu: false, canvas: true, letterbox: true, cores: 2, timezone: "UTC", language: "en-US" },
  },
};

// Whether the Advanced fingerprint switches have been touched by the user. Until
// then, picking a safety tier re-seeds them from the preset baseline.
let FP_DIRTY = false;
// Debounce handle for the live preview.
let PREVIEW_TIMER = null;

/** Seed the Advanced fingerprint switches from a safety preset's baseline. */
function seedFingerprintFromPreset(presetKey) {
  const p = SAFETY_PRESETS[presetKey] || SAFETY_PRESETS.balanced;
  const fp = p.fp;
  $("#cf-fp-webgl").value = fp.webgl;
  $("#cf-fp-webgpu").checked = fp.webgpu;
  $("#cf-fp-canvas").checked = fp.canvas;
  $("#cf-fp-letterbox").checked = fp.letterbox;
  $("#cf-fp-cores").value = String(fp.cores);
  $("#cf-fp-timezone").value = fp.timezone;
  $("#cf-fp-language").value = fp.language;
}

/** Switch between the Setup and Preview tabs. */
function selectTab(tab) {
  const isSetup = tab !== "preview";
  $("#pane-setup").classList.toggle("hidden", !isSetup);
  $("#pane-preview").classList.toggle("hidden", isSetup);
  $("#tab-setup").classList.toggle("active", isSetup);
  $("#tab-preview").classList.toggle("active", !isSetup);
  $("#tab-setup").setAttribute("aria-selected", String(isSetup));
  $("#tab-preview").setAttribute("aria-selected", String(!isSetup));
  if (!isSetup) updatePreview();
}

/** Open the create modal, resetting it to safe defaults. */
function openCreateModal() {
  const form = $("#create-form");
  form.reset();
  // reset() restores the HTML `checked` defaults; sync conditional UI to them.
  FP_DIRTY = false;
  seedFingerprintFromPreset(radioValue("safety") || "balanced");
  $("#cf-adv-body").classList.add("hidden");
  $("#cf-adv-toggle").setAttribute("aria-expanded", "false");
  selectTab("setup");
  syncCreateForm();
  $("#cf-proxy-error").classList.add("hidden");
  $("#create-modal").classList.remove("hidden");
  $("#cf-name").focus();
}

/** Close the create modal. */
function closeCreateModal() {
  $("#create-modal").classList.add("hidden");
}

/** Toggle the collapsible Advanced section. */
function toggleAdvanced() {
  const body = $("#cf-adv-body");
  const nowHidden = body.classList.toggle("hidden");
  $("#cf-adv-toggle").setAttribute("aria-expanded", String(!nowHidden));
}

/** Reflect the current network + platform choices in the conditional UI. */
function syncCreateForm() {
  const net = radioValue("network_mode") || "tor";
  const isolation = radioValue("isolation") || "full-vm";
  const hostMode = isolation === "host-process";

  // Platform: show the honest reduced-protection note in host mode.
  $("#cf-iso-note").classList.toggle("hidden", !hostMode);

  // VPN is full-VM only: disable/grey it in host mode, with a tooltip. If it was
  // selected, fall back to Tor so we never submit an invalid combination.
  const vpnLabel = $("#cf-network-vpn");
  const vpnInput = vpnLabel.querySelector('input[name="network_mode"]');
  vpnInput.disabled = hostMode;
  vpnLabel.classList.toggle("choice-disabled", hostMode);
  vpnLabel.title = hostMode ? t("vpn_disabled_host") : "";
  let effectiveNet = net;
  if (hostMode && net === "vpn") {
    const torInput = document.querySelector('input[name="network_mode"][value="tor"]');
    if (torInput) torInput.checked = true;
    effectiveNet = "tor";
  }

  // Network sub-fields appear conditionally on the chosen mode.
  const isProxy = effectiveNet === "socks5" || effectiveNet === "http";
  $("#cf-tor-fields").classList.toggle("hidden", effectiveNet !== "tor");
  $("#cf-proxy-fields").classList.toggle("hidden", !isProxy);
  $("#cf-vpn-note").classList.toggle("hidden", effectiveNet !== "vpn");

  // Keep the live "what will happen" summary in step with every choice.
  updateSummary();
}

// The four safety tiers collapse onto the two coarse protection labels the
// daemon uses; the summary shows the *tier* name the user actually clicked.
const TIER_LABEL_KEY = {
  compatibility: "tier_compatibility",
  balanced: "tier_balanced",
  strict: "tier_strict",
  paranoid: "tier_paranoid",
};
const NET_LABEL_KEY = {
  tor: "summary_net_tor",
  socks5: "summary_net_socks5",
  http: "summary_net_http",
  vpn: "summary_net_vpn",
};

/** Recompute the live plain-language "what will happen" summary line.
 *  Everything is derived from the current selection so it can never drift from
 *  what the button will actually do. */
function updateSummary() {
  const box = $("#cf-summary");
  if (!box) return;
  const isolation = radioValue("isolation") || "full-vm";
  const hostMode = isolation === "host-process";
  const browser = radioValue("browser") === "firefox" ? "Firefox" : "Chromium";
  const net = radioValue("network_mode") || "tor";
  const network = t(NET_LABEL_KEY[net] || "summary_net_tor");
  const protection = t(TIER_LABEL_KEY[radioValue("safety") || "balanced"]);
  const key = hostMode ? "summary_host" : "summary_vm";
  box.textContent = t(key, {
    browser,
    os: t("summary_os_windows"),
    network,
    protection,
  });
}

/** React to a safety-tier pick: set protection + (re-)seed the fingerprint. */
function onSafetyChange() {
  const tier = radioValue("safety") || "balanced";
  // Only re-seed the switches if the user hasn't manually customized them yet;
  // otherwise picking a tier would silently clobber their overrides.
  if (!FP_DIRTY) seedFingerprintFromPreset(tier);
  updateSummary();
  schedulePreview();
}

/** Mark the fingerprint switches as user-touched and refresh the preview. */
function onFingerprintChange() {
  FP_DIRTY = true;
  schedulePreview();
}

/** Generate a friendly default name so a blank field never blocks the user. */
function autoName() {
  // A short, human timestamp keeps names unique without exposing anything.
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `Session ${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
}

/** The effective name: the typed value, or an auto-generated one when blank. */
function effectiveName() {
  return $("#cf-name").value.trim() || autoName();
}

/** Gather the modal inputs into the create-args DTO the backend expects. */
function collectCreateArgs() {
  const port = $("#cf-proxy-port").value.trim();
  const tier = radioValue("safety") || "balanced";
  const preset = SAFETY_PRESETS[tier] || SAFETY_PRESETS.balanced;
  const coresRaw = $("#cf-fp-cores").value.trim();
  const cores = coresRaw === "" ? 0 : Number(coresRaw);
  return {
    // Never send an empty name: auto-generate one so creation is always one click.
    name: effectiveName(),
    kind: radioValue("kind"),
    isolation: radioValue("isolation"),
    network_mode: radioValue("network_mode"),
    bridges: $("#cf-bridges").value,
    proxy_host: $("#cf-proxy-host").value.trim() || null,
    proxy_port: port ? Number(port) : null,
    proxy_credentials: $("#cf-proxy-creds").value.trim() || null,
    // The four tiers collapse onto the coarse protection level the daemon uses.
    protection: preset.protection,
    browser: radioValue("browser"),
    // The Advanced panel builds a full fingerprint override on top of the preset.
    fingerprint: {
      webgl: $("#cf-fp-webgl").value,
      webgpu_enabled: $("#cf-fp-webgpu").checked,
      canvas: $("#cf-fp-canvas").checked ? "limited" : "passthrough",
      letterbox: $("#cf-fp-letterbox").checked,
      hardware_concurrency: Number.isFinite(cores) ? cores : 0,
      timezone: $("#cf-fp-timezone").value.trim() || null,
      language: $("#cf-fp-language").value.trim() || null,
    },
  };
}

// --- live preview (Tab 2) ---------------------------------------------------
// Computed by the backend from ProfileSpec::preview() so it stays aligned with
// the configured policy. Runtime evidence is shown only in Diagnostics.

function schedulePreview() {
  if (PREVIEW_TIMER) clearTimeout(PREVIEW_TIMER);
  PREVIEW_TIMER = setTimeout(updatePreview, 160);
}

function yesNo(b) { return b ? t("pv_yes") : t("pv_no"); }
function onOff(b) { return b ? t("pv_on") : t("pv_off"); }

/** Render a ProfilePreview into the Preview pane. */
function renderPreview(p) {
  $("#cf-preview-error").classList.add("hidden");
  $("#cf-preview-grid").classList.remove("hidden");
  $("#pv-browser").textContent = p.browser === "firefox" ? "Firefox/Mullvad" : "Chromium";
  $("#pv-user-agent").textContent = p.user_agent;
  $("#pv-isolation").textContent = p.isolation_label;
  $("#pv-network").textContent = p.network;
  $("#pv-protection").textContent = p.protection === "strict" ? t("tier_strict") : t("tier_balanced");
  $("#pv-timezone").textContent = p.timezone;
  $("#pv-language").textContent = p.language;
  $("#pv-cores").textContent =
    p.hardware_concurrency == null ? t("pv_cores_real") : String(p.hardware_concurrency);
  $("#pv-webgl").textContent = p.webgl;
  $("#pv-webgpu").textContent = onOff(p.webgpu_enabled);
  $("#pv-canvas").textContent = p.canvas;
  $("#pv-letterbox").textContent = onOff(p.letterbox);
  $("#pv-timer").textContent = `${p.timer_coarsening_us} µs`;
  $("#pv-device-apis").textContent = yesNo(p.device_apis_blocked);
  $("#pv-media").textContent = yesNo(p.limit_media_devices);
  $("#pv-battery-sensors").textContent = onOff(p.battery_disabled && p.sensors_disabled);
}

/** Fetch and render the live preview for the current form state. */
async function updatePreview() {
  const args = collectCreateArgs();
  try {
    const p = await tauriInvoke("preview_profile", { args });
    renderPreview(p);
  } catch (e) {
    // Show the (secret-free) reason inline; the preview cannot be computed for an
    // incomplete/invalid setup (e.g. a proxy without a host) — fail-closed.
    const box = $("#cf-preview-error");
    box.textContent = t("preview_error") + String(e.message || e);
    box.classList.remove("hidden");
    $("#cf-preview-grid").classList.add("hidden");
  }
}

/** Lightweight inline validation before we bother the backend.
 *  The name is never validated here: a blank field is auto-named in
 *  collectCreateArgs so the user is never blocked. Only the proxy sub-fields,
 *  which the daemon would reject anyway, are checked up front. */
function validateCreateForm(args) {
  let ok = true;
  const proxyErr = $("#cf-proxy-error");
  const isProxy = args.network_mode === "socks5" || args.network_mode === "http";
  if (isProxy && (!args.proxy_host || !args.proxy_port)) {
    proxyErr.classList.remove("hidden");
    ok = false;
  } else {
    proxyErr.classList.add("hidden");
  }
  return ok;
}

/** Ensure the offending field is visible before we point the user at it. */
function revealSetupFor(args) {
  // Always bring the Setup tab forward for inline errors.
  selectTab("setup");
  // The proxy fields live inside the collapsible Advanced section.
  const isProxy = args.network_mode === "socks5" || args.network_mode === "http";
  if (isProxy) {
    $("#cf-adv-body").classList.remove("hidden");
    $("#cf-adv-toggle").setAttribute("aria-expanded", "true");
  }
}

// The primary button (form `submit`) = "Create & start": it creates the profile
// AND immediately starts a session so the browser actually launches. The
// secondary "Create only" button passes startAfter = false.
async function createProfile(ev, startAfter) {
  if (ev) ev.preventDefault();
  const args = collectCreateArgs();
  if (!validateCreateForm(args)) {
    revealSetupFor(args);
    return;
  }
  const buttons = ["#btn-create", "#btn-create-start"].map($);
  buttons.forEach((b) => b && (b.disabled = true));
  try {
    // 1) Create the profile from the current selection.
    const p = await tauriInvoke("create_profile", { args });
    showBanner(t("profile_created", { name: p.name }), "ok");
    closeCreateModal();
    $("#create-form").reset();
    await refreshAll();
    // 2) On "Create & start", immediately start a session for the new profile id
    //    so the browser launches — one click, no extra step.
    if (startAfter) {
      await startSessionFor(p.id, null);
    }
  } catch (e) {
    // Never swallow: surface the backend message in the existing banner.
    showBanner(String(e.message || e));
  } finally {
    buttons.forEach((b) => b && (b.disabled = false));
  }
}

async function startSessionFor(profileId, btn) {
  if (btn) { btn.disabled = true; btn.textContent = t("btn_starting"); }
  try {
    const s = await tauriInvoke("start_session", { profileId });
    showBanner(`${t("session_started")} (${localizeProtection(s.protection_status, s.protection_label)}).`, s.is_safe ? "ok" : undefined);
    await refreshAll();
    // Focus the new session in the diagnostics panel.
    $("#session-select").value = s.id;
    await loadDiagnostics(s.id);
  } catch (e) {
    showBanner(String(e.message || e));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = t("btn_start"); }
  }
}

async function newPrivateSession() {
  // Convenience: start a session for the first available profile, else open the
  // unified create modal so the user can configure a fresh one.
  try {
    const profiles = await tauriInvoke("list_profiles");
    if (!profiles || profiles.length === 0) {
      showBanner(t("create_profile_first"));
      openCreateModal();
      return;
    }
    const target = profiles.find((p) => p.gateway_state !== "running") || profiles[0];
    await startSessionFor(target.id, null);
  } catch (e) {
    showBanner(String(e.message || e));
  }
}

// ============================================================ Diagnostics
const BADGE_CLASS = {
  active: "badge-active",
  partial: "badge-partial",
  unsafe: "badge-unsafe",
  none: "badge-none",
};

// Map the machine protection token onto a localized, honest label. The backend
// label is used only as a fallback so the frontend never invents wording.
const PROT_KEY = {
  active: "prot_active",
  partial: "prot_partial",
  unsafe: "prot_unsafe",
  none: "prot_none",
};
function localizeProtection(statusToken, fallbackLabel) {
  const key = PROT_KEY[statusToken];
  return key ? t(key) : (fallbackLabel || t("prot_none"));
}

function setBadge(statusToken, label, meta) {
  const badge = $("#protection-badge");
  badge.className = "protection-badge " + (BADGE_CLASS[statusToken] || "badge-none");
  $("#protection-label").textContent = localizeProtection(statusToken, label);
  $("#badge-meta").textContent = meta || "";
}

function levelClass(level) {
  return "diag-val lvl-" + (level || "unknown");
}

const DIAG_VALUE_IDS = [
  "#diag-public-ip", "#diag-isolation", "#diag-engine", "#diag-cohort",
  "#diag-protection-level", "#diag-gateway", "#diag-tunnel", "#diag-dns",
  "#diag-ipv6", "#diag-webrtc", "#diag-killswitch", "#diag-browser-process",
  "#diag-devices", "#diag-render", "#diag-persistence", "#diag-storage",
  "#site-public-ip", "#site-user-agent", "#site-viewport", "#site-timezone",
  "#site-language", "#site-cpu", "#site-webgl", "#site-webgpu",
  "#site-canvas", "#site-media",
];

function evidenceToken(value) {
  return ["configured", "measured", "verified"].includes(value) ? value : "unknown";
}

function setDiagnosticNode(node, item) {
  const evidence = evidenceToken(item && item.evidence);
  const level = (item && item.level) || "unknown";
  const isMono = node.classList.contains("mono");
  node.textContent = (item && (item.detail || item.level)) || "—";
  node.className = levelClass(level) + (isMono ? " mono" : "");

  const card = node.closest(".diag-card");
  const badge = card && card.querySelector(".evidence-badge");
  if (badge) {
    badge.className = "evidence-badge evidence-" + evidence;
    badge.textContent = t("evidence_" + evidence);
  }
}

function clearDiagnosticNodes() {
  DIAG_VALUE_IDS.forEach((id) => setDiagnosticNode($(id), null));
}

// Map the daemon's diagnostic items (keyed by subsystem) onto the fixed cards.
// Unknown keys are appended to the subsystem-details list.
function applyItems(items) {
  const byKey = {};
  for (const it of items || []) byKey[it.key] = it;

  const cardFor = (id, keys) => {
    const node = $(id);
    let found = null;
    for (const k of keys) { if (byKey[k]) { found = byKey[k]; break; } }
    setDiagnosticNode(node, found);
    return found ? found.key : null;
  };

  const used = new Set();
  const mark = (k) => { if (k) used.add(k); };
  mark(cardFor("#diag-public-ip", ["site_public_ip"]));
  mark(cardFor("#diag-isolation", ["isolation"]));
  mark(cardFor("#diag-engine", ["browser_engine"]));
  mark(cardFor("#diag-cohort", ["cohort_profile"]));
  mark(cardFor("#diag-protection-level", ["protection_level"]));
  mark(cardFor("#diag-gateway", ["gateway", "gateway_ready"]));
  mark(cardFor("#diag-tunnel", ["tunnel", "tunnel_ready"]));
  mark(cardFor("#diag-dns", ["dns", "dns_route", "dns_status"]));
  mark(cardFor("#diag-ipv6", ["ipv6", "ipv6_status"]));
  mark(cardFor("#diag-webrtc", ["webrtc", "webrtc_status"]));
  mark(cardFor("#diag-devices", ["devices", "available_devices", "device_apis"]));
  mark(cardFor("#diag-render", ["render_mode", "render", "webgl", "rendering"]));
  mark(cardFor("#diag-persistence", ["persistence", "profile_persistence", "profile"]));
  mark(cardFor("#diag-killswitch", ["kill_switch", "killswitch", "kill-switch"]));
  mark(cardFor("#diag-browser-process", ["browser_process"]));
  mark(cardFor("#diag-storage", ["storage_encryption"]));

  mark(cardFor("#site-public-ip", ["site_public_ip"]));
  mark(cardFor("#site-user-agent", ["site_user_agent"]));
  mark(cardFor("#site-viewport", ["site_viewport"]));
  mark(cardFor("#site-timezone", ["site_timezone"]));
  mark(cardFor("#site-language", ["site_language"]));
  mark(cardFor("#site-cpu", ["site_cpu"]));
  mark(cardFor("#site-webgl", ["site_webgl"]));
  mark(cardFor("#site-webgpu", ["site_webgpu"]));
  mark(cardFor("#site-canvas", ["site_canvas"]));
  mark(cardFor("#site-media", ["site_media_devices"]));

  // Remaining items go into the details list.
  const list = $("#items-list");
  list.innerHTML = "";
  const extras = (items || []).filter((it) => !used.has(it.key));
  if (extras.length === 0) {
    list.appendChild(el("li", "check-empty", t("no_additional_details")));
    return;
  }
  for (const it of extras) {
    const li = el("li", "item-row");
    li.appendChild(el("span", "item-key", it.key));
    const evidence = evidenceToken(it.evidence);
    const d = el("span", "item-detail " + ("lvl-" + it.level), `${t("evidence_" + evidence)} · ${it.level} — ${it.detail}`);
    li.appendChild(d);
    list.appendChild(li);
  }
}

function renderChecks(checks) {
  const ul = $("#checklist");
  ul.innerHTML = "";
  if (!checks || checks.length === 0) {
    ul.appendChild(el("li", "check-empty", t("no_preflight_checks")));
    return;
  }
  for (const c of checks) {
    const cls = c.passed ? "check-pass" : c.outcome === "skipped" ? "check-skip" : "check-fail";
    const icon = c.passed ? "✓" : c.outcome === "skipped" ? "•" : "✕";
    const li = el("li", "check " + cls);
    li.appendChild(el("span", "check-icon", icon));
    li.appendChild(el("span", "check-name", c.id));
    const evidence = evidenceToken(c.evidence);
    li.appendChild(el("span", "evidence-badge evidence-" + evidence, t("evidence_" + evidence)));
    li.appendChild(el("span", "check-detail", c.detail));
    ul.appendChild(li);
  }
}

// Track the last diagnostics/doctor render so a language switch can re-render.
let LAST_DIAG = null; // { kind: 'session'|'doctor'|'none', data }

function resetDiagnostics() {
  LAST_DIAG = { kind: "none" };
  setBadge("none", t("prot_none"), t("no_session_selected"));
  clearDiagnosticNodes();
  $("#checklist").innerHTML = "";
  $("#checklist").appendChild(el("li", "check-empty", t("select_session_checks")));
  $("#items-list").innerHTML = "";
  $("#items-list").appendChild(el("li", "check-empty", t("no_details")));
}

async function loadDiagnostics(sessionId) {
  if (!sessionId) { resetDiagnostics(); return; }
  try {
    const d = await tauriInvoke("get_diagnostics", { sessionId });
    LAST_DIAG = { kind: "session", data: d };
    setBadge(
      d.protection_status,
      d.protection_label,
      d.permits_browsing ? t("browsing_permitted") : t("browsing_blocked")
    );
    applyItems(d.items);
    // Compatibility with an older daemon that returns the observation but no
    // structured `site_public_ip` item.
    if (d.public_ip && !(d.items || []).some((it) => it.key === "site_public_ip")) {
      const fallback = { detail: d.public_ip, level: "unknown", evidence: "measured" };
      setDiagnosticNode($("#diag-public-ip"), fallback);
      setDiagnosticNode($("#site-public-ip"), fallback);
    }
    renderChecks(d.checks);
  } catch (e) {
    resetDiagnostics();
    showBanner(String(e.message || e));
  }
}

async function loadSessions() {
  let sessions = [];
  try {
    sessions = await tauriInvoke("list_sessions");
  } catch (e) {
    // Non-fatal for the whole page; profiles may still render.
    sessions = [];
  }
  const sel = $("#session-select");
  const prev = sel.value;
  sel.innerHTML = "";
  if (!sessions || sessions.length === 0) {
    sel.appendChild(Object.assign(el("option"), { value: "", textContent: t("no_active_session") }));
    sel.value = "";
    resetDiagnostics();
    return;
  }
  sel.appendChild(Object.assign(el("option"), { value: "", textContent: t("select_session") }));
  for (const s of sessions) {
    const label = `${s.id.slice(0, 8)} · ${s.state} · ${localizeProtection(s.protection_status, s.protection_label)}`;
    sel.appendChild(Object.assign(el("option"), { value: s.id, textContent: label }));
  }
  // Keep the previous selection if it still exists, else pick the first.
  const stillThere = sessions.some((s) => s.id === prev);
  sel.value = stillThere ? prev : sessions[0].id;
  await loadDiagnostics(sel.value);
}

async function runDoctor() {
  try {
    const d = await tauriInvoke("doctor");
    LAST_DIAG = { kind: "doctor", data: d };
    setBadge(d.protection_status, d.protection_label, t("doctor_selftest"));
    clearDiagnosticNodes();
    renderChecks(d.checks);
    $("#items-list").innerHTML = "";
    $("#items-list").appendChild(el("li", "check-empty", t("doctor_daemon_only")));
    showBanner(t("doctor_completed") + localizeProtection(d.protection_status, d.protection_label), d.protection_status === "active" ? "ok" : undefined);
    setDaemon(true, "daemon_connected");
  } catch (e) {
    setDaemon(false, "daemon_unreachable");
    showBanner(String(e.message || e));
  }
}

// ============================================================ Advanced section
// The last status snapshot so a language switch can re-render the badge/warning.
let LAST_STATUS = null;
// Guard so programmatic checkbox updates don't re-fire set_enforcement.
let SUPPRESS_TOGGLE = false;

const ISO_BADGE_CLASS = {
  "full-vm": "iso-full",
  "host-process": "iso-host",
};
const ISO_LABEL_KEY = {
  "full-vm": "iso_full",
  "host-process": "iso_host",
};

function renderStatus(status) {
  if (!status) {
    // Unknown/not-yet-loaded state.
    $("#adv-platform").textContent = "—";
    $("#adv-version").textContent = "—";
    const badge = $("#isolation-badge");
    badge.className = "isolation-badge iso-unknown";
    badge.textContent = t("iso_unknown");
    $("#reduced-warning").classList.add("hidden");
    return;
  }
  $("#adv-platform").textContent = status.platform || "—";
  $("#adv-version").textContent = status.version || "—";

  const badge = $("#isolation-badge");
  badge.className = "isolation-badge " + (ISO_BADGE_CLASS[status.isolation_status] || "iso-unknown");
  const labelKey = ISO_LABEL_KEY[status.isolation_status];
  badge.textContent = labelKey ? t(labelKey) : t("iso_unknown");

  // Reflect the three toggles without re-triggering set_enforcement.
  SUPPRESS_TOGGLE = true;
  $("#tg-vm").checked = !!status.enforcement.require_vm_isolation;
  $("#tg-gateway").checked = !!status.enforcement.require_gateway;
  $("#tg-host-browser").checked = !!status.enforcement.allow_host_browser;
  SUPPRESS_TOGGLE = false;

  // Reduced-protection warning whenever full isolation is NOT in force.
  const warn = $("#reduced-warning");
  if (status.is_full_isolation) {
    warn.classList.add("hidden");
    warn.textContent = "";
  } else {
    warn.classList.remove("hidden");
    let text = t("reduced_warning");
    if (status.enforcement.allow_host_browser && !status.host_browser_available) {
      text += " " + t("host_browser_unavailable");
    }
    warn.textContent = text;
  }
}

async function loadStatus() {
  try {
    const status = await tauriInvoke("get_status");
    LAST_STATUS = status;
    renderStatus(status);
    setDaemon(true, "daemon_connected");
  } catch (e) {
    // Advanced is best-effort; do not clobber the whole page.
    LAST_STATUS = null;
    renderStatus(null);
    showBanner(String(e.message || e));
  }
}

async function applyEnforcement() {
  if (SUPPRESS_TOGGLE) return;
  const enforcement = {
    require_vm_isolation: $("#tg-vm").checked,
    require_gateway: $("#tg-gateway").checked,
    allow_host_browser: $("#tg-host-browser").checked,
  };
  // Disable toggles during the round trip so rapid clicks can't race.
  const toggles = ["#tg-vm", "#tg-gateway", "#tg-host-browser"].map($);
  toggles.forEach((n) => (n.disabled = true));
  try {
    const applied = await tauriInvoke("set_enforcement", { enforcement });
    // Re-fetch the full status so the isolation badge/warning reflect the
    // daemon's canonical result (it may normalize the policy).
    LAST_STATUS = await tauriInvoke("get_status");
    renderStatus(LAST_STATUS);
    showBanner(t("enforcement_updated"), LAST_STATUS && LAST_STATUS.is_full_isolation ? "ok" : undefined);
    void applied;
  } catch (e) {
    // Restore the toggles to the last known-good state on failure.
    renderStatus(LAST_STATUS);
    showBanner(String(e.message || e));
  } finally {
    toggles.forEach((n) => (n.disabled = false));
  }
}

// ============================================================ orchestration
async function refreshAll() {
  await loadProfiles();
  await loadSessions();
  await loadStatus();
}

function wireEvents() {
  $("#btn-refresh").addEventListener("click", refreshAll);
  $("#btn-doctor").addEventListener("click", runDoctor);
  $("#btn-new-session").addEventListener("click", newPrivateSession);

  // Create-profile modal open/close.
  $("#btn-toggle-create").addEventListener("click", openCreateModal);
  $("#btn-cancel-create").addEventListener("click", closeCreateModal);
  $("#btn-close-create").addEventListener("click", closeCreateModal);
  // Click on the dimmed backdrop (but not the panel) closes the modal.
  $("#create-modal").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeCreateModal();
  });
  // Esc closes it too.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("#create-modal").classList.contains("hidden")) {
      closeCreateModal();
    }
  });

  // Submit (the big primary button) = create AND start; the secondary
  // "Create only" button just creates the profile.
  $("#create-form").addEventListener("submit", (e) => createProfile(e, true));
  $("#btn-create").addEventListener("click", () => createProfile(null, false));

  // Tab strip: Setup / Preview.
  $("#tab-setup").addEventListener("click", () => selectTab("setup"));
  $("#tab-preview").addEventListener("click", () => selectTab("preview"));

  // Collapsible Advanced section.
  $("#cf-adv-toggle").addEventListener("click", toggleAdvanced);

  // Live conditional UI: any network or platform change re-syncs the sub-fields
  // and refreshes the preview.
  document
    .querySelectorAll('#cf-network input[name="network_mode"], #cf-isolation input[name="isolation"]')
    .forEach((r) =>
      r.addEventListener("change", () => {
        syncCreateForm();
        schedulePreview();
      })
    );

  // Safety tiers drive protection + the fingerprint baseline.
  document
    .querySelectorAll('#cf-safety input[name="safety"]')
    .forEach((r) => r.addEventListener("change", onSafetyChange));

  // Browser engine change refreshes the summary line and the (user-agent) preview.
  document
    .querySelectorAll('#cf-browser input[name="browser"]')
    .forEach((r) => r.addEventListener("change", () => { updateSummary(); schedulePreview(); }));

  // Individual fingerprint switches build a custom override on top of the preset.
  ["#cf-fp-webgl", "#cf-fp-webgpu", "#cf-fp-canvas", "#cf-fp-letterbox", "#cf-fp-cores", "#cf-fp-timezone", "#cf-fp-language"]
    .forEach((id) => {
      const node = $(id);
      node.addEventListener("change", onFingerprintChange);
      node.addEventListener("input", onFingerprintChange);
    });

  // Name/type and proxy sub-fields also affect the preview.
  $("#cf-name").addEventListener("input", schedulePreview);
  document
    .querySelectorAll('#cf-kind input[name="kind"]')
    .forEach((r) => r.addEventListener("change", schedulePreview));
  ["#cf-bridges", "#cf-proxy-host", "#cf-proxy-port", "#cf-proxy-creds"]
    .forEach((id) => $(id).addEventListener("input", schedulePreview));

  $("#session-select").addEventListener("change", (e) => loadDiagnostics(e.target.value));

  // Language switcher.
  $("#lang-en").addEventListener("click", () => setLang("en"));
  $("#lang-pl").addEventListener("click", () => setLang("pl"));

  // Advanced section.
  $("#btn-refresh-status").addEventListener("click", loadStatus);
  $("#tg-vm").addEventListener("change", applyEnforcement);
  $("#tg-gateway").addEventListener("change", applyEnforcement);
  $("#tg-host-browser").addEventListener("change", applyEnforcement);
}

window.addEventListener("DOMContentLoaded", () => {
  initLang();
  applyI18n();
  wireEvents();
  // Seed the Advanced fingerprint switches from the default (Balanced) tier so
  // the create-args carry a coherent override baseline even before the modal opens.
  seedFingerprintFromPreset(radioValue("safety") || "balanced");
  syncCreateForm();
  resetDiagnostics();
  renderStatus(null);
  refreshAll();
});
