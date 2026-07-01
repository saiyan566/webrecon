mod ui;
mod commands;

use clap::{Parser, Subcommand};

const ABOUT: &str = "Attack-surface recon in one CLI — discovery, enumeration, intel, CVE.";

const LONG_ABOUT: &str = "\
webrecon — attack-surface reconnaissance in a single, colored CLI.

  A composable pipeline that goes from a domain / IP / ASN / CIDR down to
  live services, fingerprinted tech, and matched CVEs — while pulling in
  Shodan, Censys, VirusTotal, GreyNoise, IPinfo, AbuseIPDB, Pulsedive,
  IntelX, and GitHub for external intelligence.

THE PIPELINE

     asn  ─┐                                   ┌─►  scan   ──►  cve
           ├─►  cidr  ──►  alive  ──►  http  ──┤
    subs  ─┘   (live IPs)  (services)  (TLS,   └─►  ipinfo / shodan / vt
                                        tech)

  Every stage has a standalone command AND is chained by `recon` or
  `alive --full-scan --probe`. Missing API keys skip their stage — never
  error.

QUICK START

  webrecon recon example.com --scan --cve
      one shot: whois → asn → cidr → subs → ipinfo → shodan → vt → scan → cve

  webrecon alive 1.2.3.0/24 --full-scan --probe
      discovery sweep → full port scan → HTTP + TLS fingerprint on survivors

  webrecon asn --search google
      every ASN registered to \"google\" (bgp.he.net + peeringdb)

  webrecon subs target.com --active
      passive sources + wordlist DNS brute force

CONFIGURATION

  Config file:  ~/.config/webrecon/config.toml
  Template:     configs/default.toml

  Every key is optional. Modules whose key is unset are skipped silently.
  Environment variables override the file:

    WEBRECON_SHODAN         WEBRECON_IPINFO        WEBRECON_ABUSEIPDB
    WEBRECON_GREYNOISE      WEBRECON_VIRUSTOTAL    WEBRECON_CENSYS
    WEBRECON_PULSEDIVE      WEBRECON_INTELX        WEBRECON_GITHUB
    WEBRECON_VULNERS        WEBRECON_NVD           WEBRECON_OTX

  Run  webrecon config  to see which keys resolved (values are masked).

TIP
  Every subcommand supports --json for jq-friendly output, and every flag
  documented in this help has a longer explanation under its own `--help`.
";

const AFTER_HELP: &str = "\
Subcommand help:  webrecon <command> --help
Config diagnosis: webrecon config
Report issues:    https://github.com/saiyan566/webrecon";

#[derive(Parser, Debug)]
#[command(
    name = "webrecon",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP,
    disable_version_flag = false,
    max_term_width = 100,
)]
struct Cli {
    #[arg(long, global = true, help = "Emit JSON instead of pretty output", long_help = "\
Emit one JSON object (or array) on stdout instead of the colored human
report. Shape is stable across commands — pipe to jq, save to a file,
or feed into another `webrecon` invocation.

EXAMPLES
  webrecon subs example.com --json | jq -r '.subdomains[]'
  webrecon alive 10.0.0.0/24 --json > sweep.json
  webrecon asn --search google --json | jq '.asns[].asn'")]
    json: bool,

    #[arg(long, global = true, help = "Disable ANSI colors", long_help = "\
Strip ANSI color codes from output. Colors are already auto-disabled when
stdout is not a TTY (i.e. when you pipe into a file or another command),
so this flag is only needed for terminals that render escape codes
literally, or when writing scripts against the human output.")]
    no_color: bool,

    #[arg(long, global = true, default_value_t = 15, help = "Per-request HTTP timeout in seconds",
        long_help = "\
Per-HTTP-request timeout in seconds. Applies to every outbound HTTP call
in every intel / API-backed command (Shodan, VirusTotal, GitHub, ...).
Does NOT apply to raw TCP scans — those have their own --connect-timeout.

Raise for slow upstreams: crt.sh with a huge domain, IntelX (which polls
until results are ready), or any endpoint behind a Tor gateway.

EXAMPLES
  --timeout 5      fail-fast (CI / bulk enum)
  --timeout 15     default
  --timeout 60     crt.sh, IntelX
  --timeout 120    very slow upstreams over VPN")]
    timeout: u64,

    #[arg(short, long, global = true, help = "Verbose logging", long_help = "\
Prints extra diagnostics: which sources were tried, which were skipped
(and why), per-source response counts, and network errors that were
silently swallowed. Useful when a command returns fewer results than
expected.")]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum CveAction {
    /// Look up a single CVE by ID (e.g. CVE-2021-44228)
    #[command(long_about = "\
Fetch one CVE by its identifier from the NVD REST API v2.0.
Shows CVSS score, severity, publish date, description, and reference URLs.

EXAMPLES
  webrecon cve id CVE-2021-44228     # Log4Shell
  webrecon cve id CVE-2014-0160      # Heartbleed
")]
    Id { id: String },
    /// Keyword search by product (and optional version)
    #[command(long_about = "\
Keyword search against NVD (or Vulners when a `vulners` key is configured and
a version is provided). Vulners returns higher-quality matches because it
understands software identifiers directly.

EXAMPLES
  webrecon cve search nginx 1.18.0 --limit 10
  webrecon cve search openssh 8.2
  webrecon cve search log4j
")]
    Search {
        /// Product name (e.g. nginx, apache, openssh)
        product: String,
        /// Optional version string — enables Vulners exact-match
        version: Option<String>,
        /// Max results to return
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Scan host → fingerprint banners → query CVEs per service
    #[command(long_about = "\
End-to-end pipeline: connect-scan top ports, grab banners, parse them into
product+version, and query CVEs for each detected service. Prefers Vulners
when key+version are both available; falls back to NVD.

EXAMPLES
  webrecon cve scan scanme.nmap.org
  webrecon cve scan target.com --top 1000 --limit 10
")]
    Scan {
        target: String,
        #[arg(long, long_help = "Port spec, e.g. \"80,443,8000-8100\". Overrides --top.")]
        ports: Option<String>,
        #[arg(long, default_value_t = 100, long_help = "Use the nmap top-N list (100 or 1000). Ignored if --ports is set.")]
        top: u16,
        #[arg(long, default_value_t = 500)]
        concurrency: usize,
        #[arg(long, default_value_t = 1500, long_help = "Per-port TCP connect timeout (milliseconds).")]
        connect_timeout: u64,
        #[arg(long, default_value_t = 5, long_help = "CVEs to show per detected service.")]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
enum Cmd {
    // ─── DISCOVERY ─────────────────────────────────────────────
    /// RDAP / whois lookup for a domain or IP
    #[command(long_about = "\
Resolves WHOIS data via RDAP (https://rdap.org). For domains: registrar,
nameservers, registrant org, abuse contact, important dates. For IPs:
allocation org, CIDR, country, abuse contact.

EXAMPLES
  webrecon whois example.com
  webrecon whois 1.1.1.1 --json
")]
    #[command(help_heading = "Discovery")]
    Whois { target: String },

    /// ASN info — ASN/IP/domain lookup, org search, or deep subdomain sweep
    #[command(long_about = "\
Resolve ASNs three ways:

  default      ASN / IP / domain → Team Cymru DNS lookup
                 - \"AS15169\" or \"15169\"  → AS name
                 - \"8.8.8.8\"               → owning ASN + prefix + country
                 - \"cloudflare.com\"        → A/AAAA → ASN per IP

  --search     Treat <target> as an org / keyword and search public registries
               (PeeringDB primary, RIPEstat fallback). Returns every ASN whose
               name matches. Best way to find every ASN a large org owns.
               Tip: pass a short brand (\"nvidia\"), not a domain (\"nvidia.com\").

  --deep       Enumerate passive subdomains for <target>, resolve each, and
               aggregate every unique ASN observed. Reveals every cloud/CDN/
               own-infra provider the domain touches (often 5–20 ASNs for a
               big org).

EXAMPLES
  webrecon asn 8.8.8.8
  webrecon asn AS15169
  webrecon asn cloudflare.com
  webrecon asn nvidia --search             # all NVIDIA-owned ASNs
  webrecon asn nvidia.com --deep           # every ASN their subdomains touch
")]
    #[command(help_heading = "Discovery")]
    Asn {
        target: String,
        /// Org/keyword search via BGPView (treat target as a query term)
        #[arg(long)]
        search: bool,
        /// Enumerate subdomains, resolve each, aggregate unique ASNs
        #[arg(long)]
        deep: bool,
        /// Concurrent DNS resolutions in --deep mode
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
    },

    /// Announced CIDR prefixes for an ASN (RIPEstat)
    #[command(long_about = "\
Lists all currently announced IPv4 + IPv6 prefixes for an ASN, sourced from
RIPEstat. Useful for finding the full address space an organization owns.

EXAMPLES
  webrecon cidr AS15169       # Google
  webrecon cidr 13335 --json  # Cloudflare
")]
    #[command(help_heading = "Discovery")]
    Cidr { target: String },

    /// Enumerate subdomains (passive + optional active brute force)
    #[command(long_about = "\
Subdomain enumeration with multiple sources merged and deduped.

PASSIVE SOURCES (always tried, no key needed unless noted)
  * crt.sh           certificate transparency
  * AlienVault OTX   passive DNS  (key recommended to avoid rate limits)
  * HackerTarget     passive DNS  (free tier rate-limited)
  * VirusTotal v3    (needs `virustotal` key)
  * Censys certs     (needs `censys` key)

ACTIVE
  --active     enables DNS brute force against an embedded wordlist (~270 entries).
               Use --wordlist for a custom list (one entry per line). DNS lookups
               are concurrent — tune with --concurrency.

EXAMPLES
  webrecon subs example.com
  webrecon subs target.com --active
  webrecon subs target.com --active --wordlist big.txt --concurrency 200
  webrecon subs target.com --no-passive --active     # active only
")]
    #[command(help_heading = "Discovery")]
    Subs {
        /// Apex domain (e.g. example.com)
        target: String,
        #[arg(long, long_help = "\
Skip all passive sources (crt.sh, AlienVault OTX, HackerTarget, ...) and
run active-only. Fastest way to test if your active brute-force is doing
anything on top of what passive already finds.

EXAMPLE
  webrecon subs example.com --no-passive --active")]
        no_passive: bool,
        #[arg(long, long_help = "\
Enable DNS brute-force from a wordlist (default: embedded list of ~5000
common labels). Each entry N is resolved as `N.example.com`; hits are
kept only when they resolve to at least one A/AAAA.

Passive + active are additive — use both for max coverage:
  webrecon subs example.com --active

EXAMPLES
  webrecon subs example.com --active
  webrecon subs example.com --active --wordlist ~/lists/all.txt --concurrency 200")]
        active: bool,
        #[arg(long, long_help = "\
Path to a custom wordlist for --active. One label per line; blank lines
and lines starting with `#` are ignored. Typical sources:

  SecLists       Discovery/DNS/subdomains-top1million-5000.txt
  Assetnote      best-dns-wordlist.txt (~9M entries — huge)
  n0kovo         dns_wordlist.txt

Bigger list = more coverage AND more traffic to the target's authoritative
NS. Respect rate limits — many public DNS resolvers throttle above ~200 qps.

EXAMPLE
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")]
        wordlist: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 50, long_help = "\
Concurrent DNS resolutions during --active. Bounded by your resolver's
QPS ceiling more than by your host.

EXAMPLES
  --concurrency 20     public DNS, be polite
  --concurrency 100    local unbound / dnsmasq
  --concurrency 500    dedicated resolver pool")]
        concurrency: usize,
    },

    /// CVE lookup — by ID, keyword search, or scan→fingerprint→CVE
    #[command(long_about = "\
CVE intelligence with three modes:

  id     Fetch one CVE by ID (NVD).
  search Keyword search by product/version (Vulners preferred, NVD fallback).
  scan   TCP scan + banner grab + fingerprint + CVE per service.

Run `webrecon cve <action> --help` for action-specific flags.
")]
    #[command(help_heading = "Analysis")]
    Cve {
        #[command(subcommand)]
        action: CveAction,
    },

    /// TCP connect port scan (host/IP/CIDR) with optional banner grab
    #[command(long_about = "\
Async TCP connect scan via tokio. Does NOT need root. Supports single host,
IP, or small CIDR ranges (capped by --max-hosts to avoid runaway scans).

PORTS
  --ports \"80,443,8000-8100\"   custom spec, overrides --top
  --top 100  | --top 1000       use nmap's top-N list (default 100)

BANNER GRAB
  Open ports get a 2.5s banner read (HTTP GET / for known web ports, raw read
  for the rest). Disable with --no-banner.

EXAMPLES
  webrecon scan scanme.nmap.org
  webrecon scan 1.1.1.1 --top 1000
  webrecon scan target.com --ports 22,80,443
  webrecon scan 10.0.0.0/28 --no-banner --concurrency 1000
")]
    #[command(help_heading = "Enumeration")]
    Scan {
        /// host, IP, or CIDR (e.g. example.com / 1.2.3.4 / 10.0.0.0/28)
        target: String,
        #[arg(long, long_help = "\
Explicit port spec — takes precedence over --top. Supports mixed lists
and ranges.

EXAMPLES
  --ports 22,80,443                          three ports
  --ports 1-1024                             privileged range
  --ports 80,443,3000-3010,8000-8100         mixed
  --ports 1-65535                            everything (slow)")]
        ports: Option<String>,
        #[arg(long, default_value_t = 100, long_help = "\
Use nmap's `--top-ports N` list. Only 100 and 1000 supported.
The top-1000 list covers ~93% of services seen on the internet; top-100
covers ~78%. Ignored when --ports is given.

EXAMPLES
  --top 100     fastest, catches web + ssh + rdp + common DBs
  --top 1000    thorough, still ~10× faster than full 65535")]
        top: u16,
        #[arg(long, default_value_t = 500, long_help = "\
Concurrent connect attempts on this host. Bounded by target's SYN-flood
protection more than your host.

EXAMPLES
  --concurrency 100     stealthier, WAF-friendly
  --concurrency 500     default, balanced
  --concurrency 5000    aggressive, needs `ulimit -n 8192`")]
        concurrency: usize,
        #[arg(long, default_value_t = 1500, long_help = "\
Per-port TCP connect timeout (ms). Since you already know this host is
reachable, closed/filtered ports normally return quickly — this just
caps how long silent-drop ports burn.

EXAMPLES
  --connect-timeout 800     nearby, low-latency
  --connect-timeout 3000    cross-continent or CDN edge")]
        connect_timeout: u64,
        #[arg(long, long_help = "\
Skip service banner grab on open ports. ~2× faster on hosts with many
open ports, but you lose version strings — meaning `webrecon cve` after
this will have nothing to fingerprint from.

EXAMPLE
  webrecon scan 1.2.3.4 --top 1000 --no-banner")]
        no_banner: bool,
        #[arg(long, default_value_t = 256, long_help = "\
Refuses to scan a CIDR bigger than this. Different from the sweep's cap
because a scan multiplies by port count — 256 hosts × 1000 ports is
already 256k connects.

EXAMPLE
  webrecon scan 10.0.0.0/22 --top 100 --max-hosts 1500")]
        max_hosts: usize,
    },

    /// Live-host discovery across a CIDR (fast TCP probe to common ports)
    #[command(long_about = "\
Feed a CIDR (or single IP) and get back only the hosts that respond on at
least one of the probe ports. Much faster than a full port scan because
each IP gets only a few quick TCP attempts.

DEFAULTS
  --probe-ports 80,443,22,8080,3389   widely-listening ports
  --connect-timeout 500ms             aggressive — bump for slow networks
  --concurrency 1000                  raise on fast links + small CIDRs
  --max-hosts 65536                   cap CIDR expansion (= /16)

EXAMPLES
  webrecon alive 10.0.0.0/24
  webrecon alive 198.51.100.0/22 --probe-ports 22,80,443,8443
  webrecon alive 1.2.3.0/29 --connect-timeout 1500
  webrecon alive 192.168.1.0/24 --json | jq '.alive[].ip'

Pipe the output into `webrecon scan` for full enumeration of the alive ones:
  webrecon alive 10.0.0.0/24 --json | jq -r '.alive[].ip' | xargs -I{} webrecon scan {} --top 1000
")]
    #[command(help_heading = "Discovery")]
    Alive {
        /// CIDR (e.g. 10.0.0.0/24) or single IP
        target: String,
        #[arg(long, default_value = "80,443,22,25,53,445,3389,8080,8443", long_help = "\
Comma-separated list of TCP ports used for liveness detection. Any single
successful connect marks the host alive; the sweep does NOT enumerate all
open ports — that's what --full-scan is for.

Trade-offs:
  • Fewer ports  → faster, misses hosts that only listen elsewhere
  • More ports   → slower, catches mail servers / SMB / DB hosts

EXAMPLES
  --probe-ports 443                              only https
  --probe-ports 80,443,22                        web + ssh
  --probe-ports 1-1024                           full privileged range
  --probe-ports 80,443,22,25,110,143,445,3389   default (broad)")]
        probe_ports: String,
        #[arg(long, default_value_t = 1200, long_help = "\
Per-port TCP connect timeout in milliseconds. Raise on high-latency links
(satellite, cross-continent) or when residential ISPs silently drop SYN.

Trade-offs:
  • 300–500ms   LAN / same-region cloud, fast but drops slow hosts
  • 1200ms      default — safe for most public internet
  • 2500–4000ms residential / behind-NAT / far-away targets

EXAMPLE
  --connect-timeout 2500       when a /24 returns 0 alive on default")]
        connect_timeout: u64,
        #[arg(long, default_value_t = 1000, long_help = "\
Max concurrent TCP connects across the whole sweep. Higher = faster on a
big CIDR but you'll hit kernel fd limits (`ulimit -n`) and NAT conntrack
saturation past ~5000 on a laptop.

RULE OF THUMB
  254 hosts × 9 ports = 2286 connects.
  At concurrency 1000 the sweep drains in ~3 waves (≈ 3 × timeout).

EXAMPLES
  --concurrency 500     safer on flaky links / oversubscribed VPN
  --concurrency 3000    aggressive; needs `ulimit -n 8192`")]
        concurrency: usize,
        #[arg(long, default_value_t = 65536, long_help = "\
Refuses to expand a CIDR beyond this many hosts. Safety valve so a typo'd
/8 doesn't produce 16M targets.

Common sizes:
  /24 =    254   /22 = 1022   /20 =  4094
  /16 = 65534    /14 = 262142

EXAMPLE
  webrecon alive 10.0.0.0/14 --max-hosts 300000")]
        max_hosts: usize,
        #[arg(long, long_help = "\
After discovery, run a full TCP port scan on every alive host. Cost scales
with the ALIVE count × --scan-ports width, not the CIDR size — so a /16
with 20 live hosts is very cheap; a /16 with 5000 live hosts is not.

Prints a worst-case ETA before starting; real elapsed is usually 20–40%
of that because closed ports return RST instantly.

EXAMPLE
  webrecon alive 185.136.69.0/24 --full-scan
  webrecon alive 10.0.0.0/16 --full-scan --scan-ports 80,443,22")]
        full_scan: bool,
        #[arg(long, default_value = "1-65535", long_help = "\
Port spec for the --full-scan phase (ignored otherwise). Supports lists
and ranges, mixed freely.

EXAMPLES
  --scan-ports 1-65535             every port (slowest, most complete)
  --scan-ports 1-1024              privileged range only
  --scan-ports 80,443,8080,8443    web-only, fastest
  --scan-ports 1-1024,3306,5432,6379,9200,27017  common + DBs")]
        scan_ports: String,
        #[arg(long, default_value_t = 2000, long_help = "\
Concurrent TCP connects PER HOST during the --full-scan phase. Applied
per host because a full scan on one host is already 65k connects; batching
across hosts would starve any single host.

EXAMPLES
  --scan-concurrency 500    slow/careful (WAF-friendly)
  --scan-concurrency 5000   fast, needs high fd limit")]
        scan_concurrency: usize,
        #[arg(long, default_value_t = 800, long_help = "\
Per-port TCP connect timeout during --full-scan (ms). Lower than the
discovery timeout because at this stage you already KNOW the host is up,
so closed/filtered ports should reject quickly.

EXAMPLE
  --scan-timeout 500       when scanning a fast, nearby target")]
        scan_timeout: u64,
        #[arg(long, long_help = "\
Skip service banner grab in the --full-scan phase. Speeds the scan up by
~2× on hosts with many open ports; you lose the version strings that
would feed `webrecon cve`.

EXAMPLE
  webrecon alive 1.2.3.0/24 --full-scan --no-banner   # fastest possible")]
        no_banner: bool,
        #[arg(long, long_help = "\
After --full-scan, run HTTP fingerprint on every open port on every alive
host. The prober auto-detects HTTP vs HTTPS by port; non-web ports simply
time out and are silently dropped.

For each responding endpoint you get status, redirect chain, server,
X-Powered-By, CDN, ~30 tech fingerprints, page title, and (for HTTPS)
the TLS cert subject / issuer / SAN list — even when the HTTP request
itself 403s (the SAN list is often your route to real hostnames behind
a shared IP).

EXAMPLE
  webrecon alive 185.136.69.0/24 --full-scan --probe --scan-ports 80,443,8080,8443")]
        probe: bool,
    },

    /// Full IP intel: IPinfo + GreyNoise + AbuseIPDB in parallel
    #[command(long_about = "\
Concurrent triple-lookup for a single IP:

  IPinfo     — who/where: geo, ASN, ISP, org, hosting/VPN/Tor flags
  GreyNoise  — intent: mass-scanning noise vs targeted; benign infra (RIOT)
  AbuseIPDB  — history: crowdsourced abuse score + recent reports

Sources whose key is missing are skipped, not errored.

EXAMPLES
  webrecon ipinfo 8.8.8.8
  webrecon ipinfo 185.220.100.255 --max-age 30
  webrecon ipinfo 1.1.1.1 --json
")]
    #[command(help_heading = "Intel & Reputation")]
    Ipinfo {
        ip: String,
        #[arg(long, default_value_t = 90, long_help = "AbuseIPDB report-window in days (max 365).")]
        max_age: u32,
    },

    /// Shodan host lookup — open ports, banners, vulns (no packets sent)
    #[command(long_about = "\
Pulls Shodan's cached scan record for an IP: open ports, service banners,
known vulnerabilities, ASN/geo. Completely passive — Shodan already scanned.

Requires `shodan` key.

EXAMPLES
  webrecon shodan 1.1.1.1
")]
    #[command(help_heading = "Intel & Reputation")]
    Shodan { ip: String },

    /// Censys host lookup — services + autonomous system + location
    #[command(long_about = "\
Like Shodan but Censys. Returns the indexed host record: services, AS, OS,
location. Often complements Shodan with different visibility.

Requires `censys` key (Personal Access Token, Bearer auth).
")]
    #[command(help_heading = "Intel & Reputation")]
    Censys { ip: String },

    /// VirusTotal v3 reputation for IP / domain / file hash
    #[command(long_about = "\
Auto-routes by indicator kind:
  IP        → /ip_addresses/{ip}
  Domain    → /domains/{domain}
  MD5/SHA1/SHA256 → /files/{hash}

Requires `virustotal` key.

EXAMPLES
  webrecon vt example.com
  webrecon vt 1.1.1.1
  webrecon vt 44d88612fea8a8f36de82e1278abb02f
")]
    #[command(help_heading = "Intel & Reputation")]
    Vt { indicator: String },

    /// Pulsedive risk score + threat tags for an indicator
    #[command(long_about = "\
Pulsedive enrichment for an IP / domain / URL: risk score, threat
categorization, attribution to feeds.

Requires `pulsedive` key.
")]
    #[command(help_heading = "Intel & Reputation")]
    Pulsedive { indicator: String },

    /// IntelligenceX search by selector (email, domain, btc, hash, URL, …)
    #[command(long_about = "\
Searches IntelligenceX's archive of breaches, leaks, and dark-web data. The
search runs in two steps (POST + poll) — this command waits up to ~12s.

Requires `intelx` key.

EXAMPLES
  webrecon intelx user@example.com
  webrecon intelx example.com --limit 50
  webrecon intelx 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa     # btc address
")]
    #[command(help_heading = "Intel & Reputation")]
    Intelx {
        term: String,
        #[arg(long, default_value_t = 20, long_help = "Max records to fetch (capped at 100).")]
        limit: usize,
    },

    /// GitHub recon — user/org profile + public repos
    #[command(long_about = "\
Inspects a GitHub user or organization via the public REST API. Returns the
profile (login, bio, location, blog, public_repos, followers, ...) and a list
of recent repos with language, stars, forks, last push date, description.

Works without a key (60 req/hr); set `github` (PAT) to raise to 5000 req/hr.

EXAMPLES
  webrecon github torvalds
  webrecon github anthropics --repos 50
  webrecon github saiyan566 --json
")]
    #[command(help_heading = "Intel & Reputation")]
    Github {
        /// GitHub username or org name
        user: String,
        #[arg(long, default_value_t = 30, long_help = "Number of repos to fetch (1–100).")]
        repos: usize,
    },

    /// Unified recon: chains whois + asn + cidr + subs + ipinfo + shodan + vt
    #[command(long_about = "\
One command, every stage. Resolves the target to (apex domain, primary IP),
then runs each module sequentially with live spinners. Missing API keys
auto-skip those modules.

STAGES (in order)
  1. WHOIS / RDAP
  2. ASN (Cymru)
  3. CIDR (RIPEstat)
  4. Subdomains — passive sources only (use `webrecon subs` for active)
  5. IPinfo + GreyNoise + AbuseIPDB (parallel)
  6. Shodan host
  7. VirusTotal
  8. [opt] TCP scan with banners       (--scan)
  9. [opt] CVE lookup per service      (--cve, implies --scan)

EXAMPLES
  webrecon recon example.com
  webrecon recon example.com --scan --cve
  webrecon recon 1.1.1.1 --no-vt --no-shodan
  webrecon recon target.com --json > report.json
")]
    #[command(help_heading = "Analysis")]
    Recon {
        target: String,
        #[arg(long, long_help = "Also TCP-scan the resolved IP using the top-N port list.")]
        scan: bool,
        #[arg(long, long_help = "Run CVE lookup per fingerprinted service (implies --scan).")]
        cve: bool,
        #[arg(long, long_help = "Skip passive subdomain enumeration.")]
        no_subs: bool,
        #[arg(long, long_help = "Skip Shodan host lookup.")]
        no_shodan: bool,
        #[arg(long, long_help = "Skip VirusTotal lookup.")]
        no_vt: bool,
        #[arg(long, long_help = "Skip IPinfo / GreyNoise / AbuseIPDB triple.")]
        no_ipinfo: bool,
        #[arg(long, default_value_t = 100, long_help = "Top-N ports for --scan (100 or 1000).")]
        top: u16,
    },

    /// HTTP fingerprint: status, title, server, tech, CDN, redirects
    #[command(long_about = "\
Probes hosts/URLs over HTTPS then HTTP (first responder wins). For each
live endpoint returns: status, final URL after redirects, response time,
Server header, X-Powered-By, CDN (from headers), title, and a small
tech-fingerprint set (nginx, WordPress, Grafana, Jenkins, Next.js, ...).

Bare hosts get both schemes tried; host:port picks a scheme by port
convention (443/8443 → https, 80/8080/8000/8888/3000 → http, else both).

EXAMPLES
  webrecon http example.com
  webrecon http 1.2.3.4:8443 example.com https://internal.corp:9000
  webrecon http --list hosts.txt --concurrency 200
  webrecon alive 10.0.0.0/24 --json | jq -r '.alive[].ip' | xargs webrecon http
")]
    #[command(help_heading = "Enumeration")]
    Http {
        /// Hosts, host:port, or URLs. Multiple allowed.
        targets: Vec<String>,
        #[arg(long, long_help = "\
Read targets from a file, one per line. Blank lines and lines starting
with `#` are ignored. Combines with any targets given on the CLI.

Accepted forms per line:
  example.com
  1.2.3.4
  1.2.3.4:8443
  https://internal.corp:9000/health

EXAMPLES
  webrecon http --list subs.txt
  webrecon subs example.com --json | jq -r '.subdomains[]' > subs.txt \\
    && webrecon http --list subs.txt --concurrency 200")]
        list: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 50, long_help = "\
Number of endpoints probed in parallel. Each probe does at most 2 TCP
connects (HTTPS then HTTP fallback) plus a TLS handshake, so 50 = ~150
sockets briefly open.

EXAMPLES
  --concurrency 20    friendly to WAFs / rate-limited targets
  --concurrency 200   bulk enum after `webrecon subs`
  --concurrency 500   throwaway VPS; needs `ulimit -n 4096`")]
        concurrency: usize,
        #[arg(long, default_value_t = 10000, long_help = "\
Per-target timeout in milliseconds. Covers TCP connect + TLS handshake
+ HTTP round-trip. Raise for CDN-fronted or overseas hosts.

EXAMPLES
  --timeout-ms 3000    fast fail (only strong signals)
  --timeout-ms 10000   default — safe for CDN edges
  --timeout-ms 30000   internal networks over VPN with high jitter")]
        timeout_ms: u64,
        #[arg(long, long_help = "\
Disable redirect following. By default up to 5 redirects are followed
and the `redirect_chain` field lists each hop.

Use this when you want to see the raw 3xx response (Location header,
status code) instead of the final destination — e.g. to catch open
redirects or SSO handoff URLs.

EXAMPLE
  webrecon http login.corp.com --no-follow")]
        no_follow: bool,
        #[arg(long, long_help = "\
Try plain HTTP first, then HTTPS. Default order is HTTPS-first because
it yields more info (cert SAN, TLS version) and modern hosts default to
TLS. Flip this only when scanning a range known to be HTTP-only (legacy
appliances, embedded devices, IoT).

EXAMPLE
  webrecon http --prefer-http 192.168.1.0/24    # LAN of printers/cams")]
        prefer_http: bool,
    },

    /// Show resolved config: which keys are loaded and from where
    #[command(long_about = "\
Prints the resolved config: the config file path it looked at, and for each
known key whether it's loaded (with the first/last 3 characters shown) or
unset. Run after editing ~/.config/webrecon/config.toml to verify the file
parsed and the right keys were picked up.
")]
    #[command(help_heading = "Meta")]
    Config,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    ui::init(cli.no_color);

    if !cli.json {
        ui::banner();
    }

    let result = match &cli.cmd {
        Cmd::Whois { target } => commands::whois::run(target, cli.timeout, cli.json).await,
        Cmd::Asn { target, search, deep, concurrency } => {
            commands::asn::run(target, *search, *deep, *concurrency, cli.timeout, cli.json).await
        }
        Cmd::Cidr { target } => commands::cidr::run(target, cli.timeout, cli.json).await,
        Cmd::Subs { target, no_passive, active, wordlist, concurrency } => {
            commands::subs::run(target, *no_passive, *active, wordlist.as_deref(), *concurrency, cli.timeout, cli.json).await
        }
        Cmd::Scan { target, ports, top, concurrency, connect_timeout, no_banner, max_hosts } => {
            commands::scan::run(target, ports.as_deref(), *top, *concurrency, *connect_timeout, *no_banner, *max_hosts, cli.json).await
        }
        Cmd::Cve { action } => commands::cve::run(action, cli.timeout, cli.json).await,
        Cmd::Alive { target, probe_ports, connect_timeout, concurrency, max_hosts, full_scan, scan_ports, scan_concurrency, scan_timeout, no_banner, probe } => {
            commands::alive::run(
                target, probe_ports, *connect_timeout, *concurrency, *max_hosts,
                *full_scan, scan_ports, *scan_concurrency, *scan_timeout, *no_banner, *probe,
                cli.json,
            ).await
        }
        Cmd::Ipinfo { ip, max_age } => commands::ipintel::run(ip, *max_age, cli.timeout, cli.json).await,
        Cmd::Shodan { ip } => commands::intel::shodan(ip, cli.timeout, cli.json).await,
        Cmd::Censys { ip } => commands::intel::censys(ip, cli.timeout, cli.json).await,
        Cmd::Vt { indicator } => commands::intel::vt(indicator, cli.timeout, cli.json).await,
        Cmd::Pulsedive { indicator } => commands::intel::pulsedive(indicator, cli.timeout, cli.json).await,
        Cmd::Intelx { term, limit } => commands::intel::intelx(term, *limit, cli.timeout, cli.json).await,
        Cmd::Github { user, repos } => commands::intel::github(user, *repos, cli.timeout, cli.json).await,
        Cmd::Recon { target, scan, cve, no_subs, no_shodan, no_vt, no_ipinfo, top } => {
            commands::recon::run(target, *scan || *cve, *cve, *no_subs, *no_shodan, *no_vt, *no_ipinfo, *top, cli.timeout, cli.json).await
        }
        Cmd::Http { targets, list, concurrency, timeout_ms, no_follow, prefer_http } => {
            commands::http::run(targets, list.as_deref(), *concurrency, *timeout_ms, *no_follow, *prefer_http, cli.json).await
        }
        Cmd::Config => commands::config_show::run(cli.json),
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
