<h1 align="center">webrecon</h1>

<p align="center">
  <b>Attack-surface reconnaissance in one CLI.</b><br>
  Discovery → enumeration → fingerprinting → intel → CVE — from a domain, IP, ASN, or CIDR.
</p>

<p align="center">
  <a href="#install"><img alt="Rust 1.75+" src="https://img.shields.io/badge/rust-1.75%2B-orange"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <a href="#status"><img alt="Status" src="https://img.shields.io/badge/status-active-brightgreen"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey">
</p>

---

## Why webrecon

Every recon workflow ends up as a shell script that duct-tapes `subfinder → naabu → httpx → shodan → nuclei` together with `jq` and `xargs`. **webrecon collapses that pipeline into a single binary** with a stable JSON schema across every stage, sensible defaults, and no glue code.

<table>
<tr><th align="left">Replaces</th><th align="left">With</th></tr>
<tr><td><code>whois</code>, <code>whodig</code></td><td><code>webrecon whois</code> (RDAP)</td></tr>
<tr><td><code>subfinder</code>, <code>amass -passive</code>, <code>puredns</code></td><td><code>webrecon subs --active</code></td></tr>
<tr><td><code>naabu</code>, <code>masscan</code> (small ranges), <code>nmap -sT</code></td><td><code>webrecon alive --full-scan</code></td></tr>
<tr><td><code>httpx</code>, <code>wappalyzer-cli</code></td><td><code>webrecon http</code></td></tr>
<tr><td><code>shodan-cli</code>, <code>censys-cli</code></td><td><code>webrecon shodan</code> / <code>censys</code></td></tr>
<tr><td><code>bgpview.io</code>, <code>bgp.he.net</code> lookups</td><td><code>webrecon asn --search</code></td></tr>
</table>

---

## The pipeline

```
    asn ─┐                                      ┌──►  scan   ──►  cve
         ├──►  cidr  ──►  alive  ──►  http  ────┤
   subs ─┘   (live IPs)  (services)  (TLS+tech) └──►  ipinfo / shodan / vt
```

Every stage is a standalone command **and** chained by `recon` or `alive --full-scan --probe`. Missing API keys skip their stage — nothing errors.

---

## Install

```bash
git clone https://github.com/saiyan566/webrecon
cd webrecon
cargo build --release
sudo ln -s "$PWD/target/release/webrecon" /usr/local/bin/webrecon
```

Requires Rust 1.75+. On Debian/Kali also `apt install libssl-dev pkg-config`.

---

## Quick start

```bash
# One shot: domain to actionable findings
webrecon recon example.com --scan --cve

# CIDR → live hosts → all 65535 ports → HTTP fingerprint on survivors
webrecon alive 185.136.69.0/24 --full-scan --probe

# Every ASN registered to an org (bgp.he.net + peeringdb)
webrecon asn --search google

# Passive + active subdomain enum
webrecon subs target.com --active --concurrency 200

# HTTP fingerprint with TLS SAN extraction (works even when server 403's)
webrecon http 1.2.3.4:8443
```

Every command supports `--json` for jq-friendly output:

```bash
webrecon alive 10.0.0.0/24 --json | jq -r '.alive[].ip' | xargs webrecon http
```

---

## Commands

### Discovery

| Command | What it does |
|---|---|
| `whois <domain\|ip>` | RDAP lookup — registrar, dates, abuse contact, allocation |
| `asn <target> [--search\|--deep]` | ASN by IP/domain, org-name search across bgp.he.net + PeeringDB, or deep sub-to-ASN sweep |
| `cidr <ASN>` | Announced IPv4 + IPv6 prefixes from RIPEstat |
| `subs <domain> [--active]` | Passive sources (crt.sh, OTX, HackerTarget, VT, Censys) + optional DNS brute force |
| `alive <cidr> [--full-scan --probe]` | Live-host sweep → optional full port scan → optional HTTP/TLS fingerprint |

### Enumeration

| Command | What it does |
|---|---|
| `scan <target> [--top N\|--ports SPEC]` | TCP connect scan with banner grab (host, IP, or CIDR) |
| `http <targets…>` | HTTP fingerprint — status, redirects, tech, CDN, TLS subject/issuer/SAN |

### Analysis

| Command | What it does |
|---|---|
| `cve id <CVE-ID>` | NVD lookup |
| `cve search <product> <version>` | Vulners → NVD keyword search |
| `cve scan <target>` | Scan → fingerprint banners → match CVEs per service |
| `recon <target> [--scan --cve]` | Full pipeline chain |

### Intel & Reputation

| Command | Source | Purpose |
|---|---|---|
| `ipinfo <ip>` | IPinfo + GreyNoise + AbuseIPDB (parallel) | Who / intent / history |
| `shodan <ip>` | Shodan | Passive host facts — no packets sent |
| `censys <ip>` | Censys | Services + AS + location |
| `vt <indicator>` | VirusTotal v3 | Reputation for IP / domain / hash |
| `pulsedive <indicator>` | Pulsedive | Risk score + threat tags |
| `intelx <selector>` | IntelligenceX | Leak / dark-web selector search |
| `github <user>` | GitHub API | Profile + public repos |

### Meta

| Command | What it does |
|---|---|
| `config` | Show which API keys resolved (masked) and from where |

Run `webrecon <command> --help` for detailed flags, tuning advice, and examples on each one.

---

## Configuration

Config file:

```bash
mkdir -p ~/.config/webrecon
cp configs/default.toml ~/.config/webrecon/config.toml
${EDITOR:-vi} ~/.config/webrecon/config.toml
webrecon config     # verify which keys resolved
```

Every key is optional. Modules whose key is unset skip silently — no errors, no prompts. Environment variables override the file:

```
WEBRECON_SHODAN         WEBRECON_IPINFO        WEBRECON_ABUSEIPDB
WEBRECON_GREYNOISE      WEBRECON_VIRUSTOTAL    WEBRECON_CENSYS
WEBRECON_PULSEDIVE      WEBRECON_INTELX        WEBRECON_GITHUB
WEBRECON_VULNERS        WEBRECON_NVD           WEBRECON_OTX
```

Rate limits without keys:

| Source | Unauthenticated | Authenticated |
|---|---|---|
| NVD | 5 req / 30 s | 50 req / 30 s |
| GitHub | 60 req / hr | 5000 req / hr |
| Shodan | – | account tier |
| Censys | – | Personal Access Token (Bearer) |
| bgp.he.net, PeeringDB, RIPEstat, crt.sh, Cymru, RDAP | ∞ | – |

---

## Global flags

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Machine-readable output on every command |
| `--no-color` | auto | Strip ANSI colors (auto-off when stdout is a pipe) |
| `--timeout N` | 15 | Per-HTTP-request timeout, seconds |
| `-v, --verbose` | off | Per-source diagnostics + skipped-reason logging |

---

## Architecture

```
crates/
├── webrecon-cli          binary — clap, colored UI, command wiring
├── webrecon-core         shared types (Target, Finding, errors)
├── webrecon-whois        RDAP + Cymru + RIPEstat + ASN search
├── webrecon-subdomains   passive sources + DNS brute force
├── webrecon-portscan     TCP connect scan + banner grab
├── webrecon-http         httpx-style prober + TLS SAN grabbing
├── webrecon-cve          NVD + Vulners fingerprint matcher
├── webrecon-ipintel      IPinfo + GreyNoise + AbuseIPDB
└── webrecon-intel        Shodan / Censys / VT / Pulsedive / IntelX / GitHub
```

Rust workspace, single binary output. No runtime dependencies, no plugins, no Docker.

---

## Status

| Area | State |
|---|---|
| Workspace, CLI, colored UI | done |
| WHOIS (RDAP), ASN (Cymru, bgp.he.net, PeeringDB), CIDR (RIPEstat) | done |
| Subdomain enum — passive + active DNS brute | done |
| Port scanning — top-100 / top-1000 / custom / full 65535 | done |
| `alive` CIDR sweep + `--full-scan` + `--probe` chain | done |
| HTTP fingerprinting — 30+ tech, CDN detection, TLS SAN | done |
| CVE lookup — NVD + Vulners, scan→fingerprint→CVE chain | done |
| IP intel — IPinfo + GreyNoise + AbuseIPDB parallel | done |
| Third-party intel — Shodan, Censys, VT, Pulsedive, IntelX, GitHub | done |
| Unified `recon` pipeline | done |
| SYN scan (raw sockets, root) | planned |
| Persistence + `diff` between runs | planned |
| Nuclei-style vulnerability templates | planned |
| IPv6 across all commands | planned |

---

## Contributing

Issues and PRs welcome. Every new stage should:

- Live in its own crate under `crates/`.
- Skip cleanly when its API key is absent (never error).
- Support `--json` with a stable schema.
- Ship with `long_help` on every flag containing at least one example.

---

## License

MIT — see [LICENSE](LICENSE).
