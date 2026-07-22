# Networks & proxies — getting a working, reliable route

Every Aegis session reaches the Internet through **exactly one** route. If that route isn't genuinely
working, the six-check preflight fails and the browser gets **no** Internet (fail-closed, by design). This
guide shows you how to get a reliable route so preflight passes **every time**.

It's ordered from most-recommended to least:

1. **[Tor](#1-tor--recommended-default)** — free, reliable, the recommended default.
2. **[SOCKS5 / HTTP proxy](#2-socks5--http-proxy)** — a provider's or your own.
3. **[VPN](#3-vpn-full-vm-mode)** — full-VM mode only; the Gateway VM routes it.

> [!IMPORTANT]
> None of these make you "undetectable." Aegis provides **unlinkability to the host** — a site can still
> tell it's talking to *some* browser environment; it just can't easily tie that to your real computer.
> Read [`limitations.md`](limitations.md).

---

## How Aegis uses the route (two postures)

- **Full VM mode (default):** the **Gateway VM** owns the tunnel. You pick the mode per profile
  (`--net tor|vpn|proxy`); the gateway routes Tor/VPN/proxy for the Browser VM behind a default-deny
  firewall + kill switch. Setup for the gateway itself is in [`INSTALL-linux.md`](INSTALL-linux.md).
- **Host-browser mode (reduced):** the browser runs on the **host**, routed through a **host-side**
  Tor/proxy. Here the endpoint is chosen from the profile's network mode and can be overridden with the
  `AEGIS_HOST_PROXY` environment variable. VPN is **not** supported in host mode — use Tor or a proxy.

The examples below cover both: the profile's `--net` field, and the host-side daemon that consumes it.

---

## 1. Tor — recommended default

Free, well-maintained, and the strongest at hiding your public IP. Aegis defaults new profiles to Tor.
The only catch: some sites block Tor exit nodes (a compatibility tradeoff, not a leak).

Aegis's host-mode default is `socks5h://127.0.0.1:9050` (note the **`h`** — it means *DNS is resolved
by the proxy*, so your DNS never leaks locally). You just need a Tor SOCKS proxy listening there.

### Windows

**Option A — Tor Browser (easiest).** Its bundled Tor exposes a SOCKS proxy on **`127.0.0.1:9150`**.

1. Install the Tor Browser from **<https://www.torproject.org/download/>**.
2. Launch it and let it connect (leave it running — it hosts the SOCKS proxy).
3. Point Aegis at port **9150**:
   ```sh
   # PowerShell
   $env:AEGIS_HOST_PROXY = "socks5h://127.0.0.1:9150"
   # cmd.exe
   set AEGIS_HOST_PROXY=socks5h://127.0.0.1:9150
   ```

**Option B — Tor Expert Bundle (headless, no browser).** Exposes SOCKS on **`127.0.0.1:9050`**.

1. Download the **Tor Expert Bundle** from **<https://www.torproject.org/download/tor/>**.
2. Extract it and run `tor.exe` (from `Tor\tor.exe`). Leave it running.
3. Port `9050` is Aegis's default, so **no override needed**. (To be explicit:
   `set AEGIS_HOST_PROXY=socks5h://127.0.0.1:9050`.)

### Linux

**Option A — system Tor daemon (recommended, `127.0.0.1:9050`).**

```sh
sudo apt-get update
sudo apt-get install -y tor
sudo systemctl enable --now tor
systemctl status tor --no-pager        # confirm it's active

# Confirm the SOCKS port is listening:
ss -ltnp | grep 9050 || sudo ss -ltnp | grep 9050
```

Port `9050` is Aegis's default — nothing else to set. In **full VM mode** the Gateway VM already runs Tor
internally (`DNSPort 5353`, `TransPort 9040`), so you just create a Tor profile; see below.

**Option B — Tor Browser on Linux (`127.0.0.1:9150`).** If you'd rather use the Tor Browser bundle:

```sh
export AEGIS_HOST_PROXY="socks5h://127.0.0.1:9150"
```

### Create a Tor profile

```sh
# Tor is the default --net, so this is a Tor profile:
aegis profile create --name tor-session --kind ephemeral --net tor --protection balanced

# In a censored network, add one or more bridge lines (repeatable) to use Tor bridges:
aegis profile create --name tor-bridged --kind ephemeral --net tor \
      --tor-bridge "obfs4 1.2.3.4:443 <FINGERPRINT> cert=<CERT> iat-mode=0" \
      --protection balanced

aegis session start <profile-id>
```

---

## 2. SOCKS5 / HTTP proxy

Use this to plug in a paid provider's proxy, a proxy you run yourself (e.g. an SSH `-D` tunnel or a
Shadowsocks/Dante server), or a corporate egress proxy. Aegis accepts **SOCKS5** and **HTTP CONNECT**.

> [!IMPORTANT]
> A proxy is only acceptable once Aegis confirms **DNS and the required protocols actually traverse it**.
> A proxy that can't carry DNS remotely will fail the `dns_route_verified` preflight check and be
> rejected — that's intentional. Prefer **SOCKS5h** (proxy-side DNS) over plain SOCKS5.

### Put it into a profile (CLI / UI)

```sh
# --net proxy REQUIRES --proxy-host and --proxy-port (you get a friendly error otherwise).
# SOCKS5 (default, supports remote DNS via SOCKS5h):
aegis profile create --name work-proxy --kind ephemeral --net proxy \
      --proxy-kind socks5 --proxy-host proxy.example.net --proxy-port 1080 \
      --protection balanced

# HTTP CONNECT tunnel instead:
aegis profile create --name http-proxy --kind ephemeral --net proxy \
      --proxy-kind http --proxy-host 10.0.0.9 --proxy-port 3128 --protection balanced
```

The proxy fields (mirroring `aegis_core::network::ProxyConfig`):

| CLI flag | Values / example | Notes |
|----------|------------------|-------|
| **`--proxy-kind`** | `socks5` (default) or `http` (HTTP CONNECT) | Prefer SOCKS5 (`socks5h` semantics) so DNS is resolved remotely. |
| **`--proxy-host`** | `proxy.example.net` / `10.0.0.8` | Your provider's or your own proxy host. **Required** for `--net proxy`. |
| **`--proxy-port`** | e.g. `1080` (SOCKS) / `3128` (HTTP) | Whatever the proxy listens on. **Required** for `--net proxy`. |
| **credentials** | username/password (optional) | Stored as a **`CredentialRef`** into secure storage — Aegis never writes proxy passwords in plaintext. |

You can also pick the run posture with **`--isolation vm`** (default, full VM) or **`--isolation host`**
(reduced host-process mode). Note: `--isolation host` supports Tor or a SOCKS5/HTTP proxy, **not** a VPN.

In the **UI**, the profile editor exposes the same fields (type · isolation · network · protection); pick
**Network → Proxy** and fill kind/host/port/credentials.

### Host-browser mode override

In reduced host-browser mode, the daemon builds the host proxy endpoint from the profile's proxy config
(`socks5h://host:port` for SOCKS5, `http://host:port` for HTTP CONNECT). You can also force a specific
endpoint for a run:

```sh
# Windows (PowerShell)
$env:AEGIS_HOST_PROXY = "socks5h://proxy.example.net:1080"
# Linux / macOS
export AEGIS_HOST_PROXY="socks5h://proxy.example.net:1080"
```

### Roll your own quickly (SSH SOCKS proxy)

If you have SSH access to a server you trust, that server can be your proxy in seconds:

```sh
# Opens a local SOCKS5 proxy on 127.0.0.1:1080 tunneled to your-server.
ssh -D 127.0.0.1:1080 -N -C you@your-server.example.net
# Then set the proxy fields to protocol=socks5, host=127.0.0.1, port=1080
# (or: export AEGIS_HOST_PROXY="socks5h://127.0.0.1:1080")
```

---

## 3. VPN (full-VM mode)

VPN mode is **full-VM only** — the **Gateway VM** brings up the VPN tunnel and routes all Browser-VM
traffic through it behind the default-deny firewall + kill switch. (Host-browser mode does **not** support
VPN; use Tor or a proxy there.)

Honest tradeoffs:

- ✅ Better site compatibility than Tor (fewer blocks).
- ⚠️ The VPN **operator sees your entry address** — they know *where you connect from*, though not your host
  hardware or profile. Pick a provider you're willing to trust with that.
- ⚠️ A VPN is **not** anonymity. It moves trust from your ISP to the VPN operator.

```sh
# VPN needs full VM isolation (the default). --isolation host with --net vpn is rejected.
aegis profile create --name vpn-session --kind ephemeral --net vpn \
      --isolation vm --protection balanced
```

VPN credentials are held as a secure **`CredentialRef`**, never stored in plaintext. Configure the
gateway's VPN backend as part of the full VM setup in [`INSTALL-linux.md`](INSTALL-linux.md).

---

## ⛔ A strong warning about free public proxy lists

**Do not** paste random proxies from free "public proxy list" sites into Aegis. They are, in practice:

- **Unreliable** — they appear and vanish constantly, so preflight will pass one minute and fail the next.
- **Often malicious** — many free open proxies are run to **intercept, log, or tamper with traffic**
  (including injecting content), which is the *opposite* of what Aegis is for.
- **Frequently leaky** — many can't carry DNS remotely, so they fail `dns_route_verified` anyway.

For a reliable, honest setup use **Tor** (free), a **proxy you run yourself** (SSH `-D`, your own server),
or a **reputable paid provider** you're willing to trust. Aegis's fail-closed design will reject a broken
proxy rather than leak — but a *malicious* proxy you deliberately chose is a trust problem no firewall can
fix.

---

## ✅ Verify it works

Run through this checklist before you trust a session:

1. **The proxy is actually listening.**
   ```sh
   # Linux (Tor default):
   ss -ltnp | grep -E '9050|9150|1080' || sudo ss -ltnp | grep -E '9050|9150|1080'
   ```
   ```powershell
   # Windows:
   netstat -ano | findstr "9150 9050 1080"
   ```
2. **The route carries traffic + DNS.** Quick smoke test through the proxy (Tor example):
   ```sh
   # 'h' in socks5h = DNS resolved by the proxy (no local DNS leak).
   curl -x socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip
   # For a generic proxy: curl -x socks5h://HOST:PORT https://api.ipify.org
   ```
   You should get back an IP that is **not** your real one.
3. **Aegis preflight passes.** Ask the daemon to self-test, then start a session and read diagnostics:
   ```sh
   aegis doctor
   aegis session start <profile-id>
   aegis diagnostics <session-id>
   ```
   Confirm the six checks are green: `gateway_ready`, `tunnel_ready`, `dns_route_verified`,
   `public_ip_observed`, `webrtc_policy_loaded`, `ipv6_policy_verified`. Only an **all-pass**
   (`ProtectionStatus::Active`) lets the browser reach the Internet.
4. **The public IP isn't yours.** In diagnostics, the *visible public IP* must differ from your real IP,
   and DNS/IPv6/WebRTC must all read as contained.
5. **The kill switch holds.** If you stop the tunnel (e.g. `sudo systemctl stop tor`), the session must
   lose connectivity — it must **never** fall back to a direct connection.

If any check is red, the route isn't ready. That's the system working as intended: **no leak before
compatibility.**

---

### See also

- [`INSTALL-linux.md`](INSTALL-linux.md) — full VM setup (Gateway VM owns the tunnel).
- [`privacy-model.md`](privacy-model.md) — why Tor/VPN/proxy are explicit tradeoffs.
- [`threat-model.md`](threat-model.md) — what each network operator can and cannot see.
- [`limitations.md`](limitations.md) — the honest boundaries (no "undetectable").
