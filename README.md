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
| 3     | Port scanner (TCP connect + SYN) + banners  | ⏳ planned |
| 4     | CVE lookup (NVD / CIRCL)                    | ⏳ planned |
| 5     | HTTP fingerprinting + unified `recon` pipeline | ⏳ planned |

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
