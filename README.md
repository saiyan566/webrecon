# webrecon

Personal recon toolkit — one CLI for whois, ASN, CIDR, subdomains, port scanning, and CVE lookup. Built in **Rust** (core + CLI) with **Go** modules planned for later phases. Cross-platform: Linux (primary), macOS, Windows.

> Goal: never need to juggle nmap + whois + subfinder + amass again.

---

## Status

| Phase | Scope                                       | Status |
|-------|---------------------------------------------|--------|
| 0     | Workspace scaffold, CLI, colored UI         | ✅ done |
| 1     | `whois` (RDAP), `asn` (Cymru), `cidr` (RIPEstat) | ✅ done |
| 2     | `subs` — subdomain enum (passive crt.sh/OTX/HackerTarget + active brute force) | ✅ done |
| 3     | `scan` — TCP connect port scanner + banner grab (top-100 / top-1000 / custom) | ✅ done |
| 3.5   | SYN scan (raw sockets, root)                | ⏳ planned |
| 4     | `cve` — NVD lookup by ID, keyword search, or scan→fingerprint→CVE chain | ✅ done |
| 5a    | Config + keys (`~/.config/webrecon/config.toml` + `WEBRECON_*` env) | ✅ done |
| 5b    | `ipinfo` — unified IP intel (IPinfo + GreyNoise + AbuseIPDB in parallel) | ✅ done |
| 5c    | `subs` boost: VirusTotal + Censys cert sources | ✅ done |
| 5d    | `cve` upgrade: Vulners preferred, NVD with API key | ✅ done |
| 5e+   | Shodan / VT / Pulsedive / IntelX / Censys host + unified `recon` | ⏳ planned |

---

## Install

Requires Rust 1.75+.

```bash
git clone https://github.com/saiyan566/webrecon
cd webrecon
cargo build --release
# Binary at: target/release/webrecon
```

Symlink it into your `$PATH`:

```bash
sudo ln -s "$PWD/target/release/webrecon" /usr/local/bin/webrecon
```

---

## Usage

```bash
webrecon whois example.com
webrecon whois 1.1.1.1
webrecon whois example.com --json

webrecon asn 8.8.8.8           # IP -> ASN
webrecon asn example.com       # resolves, then ASN per IP
webrecon asn AS15169           # ASN -> AS name

webrecon cidr AS15169          # announced prefixes (v4 + v6)

webrecon subs example.com                 # passive only
webrecon subs example.com --active        # + brute force with embedded wordlist
webrecon subs example.com --active --wordlist /path/to/list.txt --concurrency 100
webrecon subs example.com --no-passive --active   # active only

webrecon scan scanme.nmap.org              # top-100 ports, banner grab
webrecon scan 1.1.1.1 --top 1000           # top-1000 ports
webrecon scan target.com --ports 22,80,443,8000-8100
webrecon scan 10.0.0.0/28 --no-banner --concurrency 1000

webrecon cve id CVE-2021-44228                     # single CVE lookup
webrecon cve search nginx 1.18.0 --limit 10        # keyword search by product+version
webrecon cve scan scanme.nmap.org                  # scan, fingerprint banners, fetch CVEs per service
```

> **NVD rate limit:** 5 requests / 30s without a key, 50 / 30s with one. `cve scan` walks services serially.

---

## Configuration

Copy [configs/default.toml](configs/default.toml) to `~/.config/webrecon/config.toml` and fill in the keys you have. All keys are optional — modules that need a missing key say so.

```bash
mkdir -p ~/.config/webrecon
cp configs/default.toml ~/.config/webrecon/config.toml
${EDITOR:-vi} ~/.config/webrecon/config.toml
webrecon config            # shows which keys are loaded
```

Environment variables override the file:

```
WEBRECON_SHODAN, WEBRECON_IPINFO, WEBRECON_PULSEDIVE, WEBRECON_VULNERS,
WEBRECON_INTELX, WEBRECON_GREYNOISE, WEBRECON_VIRUSTOTAL, WEBRECON_OTX,
WEBRECON_NVD, WEBRECON_ABUSEIPDB, WEBRECON_CENSYS_ID, WEBRECON_CENSYS_SECRET
```

### IP enrichment

`webrecon ipinfo <ip>` runs **IPinfo + GreyNoise + AbuseIPDB** in parallel and shows a single report. Any source whose key is missing is skipped (not an error).

- **IPinfo** — *who/where:* geo, ASN, ISP, org, hosting/VPN/Tor flags
- **GreyNoise** — *intent:* mass-scanning noise vs targeted; benign infra (RIOT)
- **AbuseIPDB** — *history:* crowdsourced abuse score + recent reports

```bash
webrecon ipinfo 8.8.8.8
webrecon ipinfo 185.220.100.255 --max-age 30   # narrow abuse report window
webrecon ipinfo 1.1.1.1 --json
```

### Global flags

| Flag           | Default | Meaning                          |
|----------------|---------|----------------------------------|
| `--json`       | off     | Emit raw JSON instead of pretty  |
| `--no-color`   | off     | Disable ANSI colors              |
| `--timeout N`  | 15      | Per-request timeout (seconds)    |
| `-v, --verbose`| off     | Verbose logging                  |

---

## Architecture

```
webrecon-cli       binary: clap subcommands, colored output
  └─ webrecon-core shared types (Target, Finding, errors)
  └─ webrecon-whois RDAP + Cymru + RIPEstat
```

Later phases add `webrecon-subdomains`, `webrecon-portscan`, `webrecon-cve`. Go modules will live under `go/modules/` and be invoked as subprocesses for clean boundaries.

---

## Data sources (Phase 1)

- **RDAP** — `https://rdap.org/` (no key, modern whois)
- **Team Cymru** — DNS-based IP→ASN (`origin.asn.cymru.com`, no key)
- **RIPEstat** — `https://stat.ripe.net/data/announced-prefixes/` (no key)

No API keys required for Phase 1.

---

## License

MIT — see [LICENSE](LICENSE).
