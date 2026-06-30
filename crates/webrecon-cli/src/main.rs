mod ui;
mod commands;

use clap::{Parser, Subcommand};

const LONG_ABOUT: &str = "\
webrecon — a personal recon toolkit that bundles WHOIS / ASN / CIDR lookups,
subdomain enumeration, port scanning, CVE matching, IP reputation, and intel
sources (Shodan, VirusTotal, Pulsedive, IntelX, Censys, GitHub) into a single
colored CLI.

CONFIGURATION
  Copy `configs/default.toml` to `~/.config/webrecon/config.toml` and fill in
  any API keys you have. Modules that need a missing key are skipped, not
  errored. Env vars override the file:

    WEBRECON_SHODAN, WEBRECON_IPINFO, WEBRECON_PULSEDIVE, WEBRECON_VULNERS,
    WEBRECON_INTELX, WEBRECON_GREYNOISE, WEBRECON_VIRUSTOTAL, WEBRECON_OTX,
    WEBRECON_NVD, WEBRECON_ABUSEIPDB, WEBRECON_CENSYS, WEBRECON_GITHUB

  Run `webrecon config` to see which keys are loaded (masked).

GLOBAL FLAGS
  --json          machine-readable output for every command
  --no-color      strip ANSI colors (auto-off when stdout isn't a TTY)
  --timeout N     per-request HTTP timeout (seconds, default 15)
  -v, --verbose   verbose logging

EXAMPLES
  webrecon recon example.com --scan --cve   # full pipeline
  webrecon subs target.com --active         # subdomain enum + brute force
  webrecon scan 10.0.0.0/28 --top 1000      # CIDR-wide port scan
  webrecon cve scan target.com              # scan → fingerprint → CVE
  webrecon ipinfo 1.1.1.1                   # IPinfo + GreyNoise + AbuseIPDB
  webrecon github torvalds --repos 50

Each subcommand has its own `--help` with detailed flags and examples.
";

#[derive(Parser, Debug)]
#[command(
    name = "webrecon",
    version,
    about = "Personal recon toolkit — whois, subs, scan, CVE, intel — one CLI",
    long_about = LONG_ABOUT,
)]
struct Cli {
    /// Emit JSON instead of pretty output
    #[arg(long, global = true, long_help = "Emit one JSON object/array on stdout instead of the colored human report. Stable shape across commands — pipe to jq, save to a file, etc.")]
    json: bool,

    /// Disable ANSI colors
    #[arg(long, global = true, long_help = "Strip ANSI color codes from output. Color is auto-disabled when stdout is not a TTY (e.g. piping into a file or another command), so you rarely need this explicitly.")]
    no_color: bool,

    /// Per-request HTTP timeout in seconds
    #[arg(long, global = true, default_value_t = 15, long_help = "Per-HTTP-request timeout in seconds. Increase for slow upstreams (e.g. `--timeout 60` for crt.sh on large domains, or for IntelX which polls results).")]
    timeout: u64,

    /// Verbose logging
    #[arg(short, long, global = true)]
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
    /// RDAP / whois lookup for a domain or IP
    #[command(long_about = "\
Resolves WHOIS data via RDAP (https://rdap.org). For domains: registrar,
nameservers, registrant org, abuse contact, important dates. For IPs:
allocation org, CIDR, country, abuse contact.

EXAMPLES
  webrecon whois example.com
  webrecon whois 1.1.1.1 --json
")]
    Whois { target: String },

    /// ASN info for an ASN, IP, or domain
    #[command(long_about = "\
Resolves an ASN from a Team Cymru DNS lookup. Accepts:
  - ASN: \"AS15169\" or \"15169\" → returns AS name
  - IP:  \"8.8.8.8\"            → returns owning ASN + prefix + country
  - Domain: \"example.com\"     → resolves A/AAAA, then ASN per IP

EXAMPLES
  webrecon asn 8.8.8.8
  webrecon asn AS15169
  webrecon asn cloudflare.com
")]
    Asn { target: String },

    /// Announced CIDR prefixes for an ASN (RIPEstat)
    #[command(long_about = "\
Lists all currently announced IPv4 + IPv6 prefixes for an ASN, sourced from
RIPEstat. Useful for finding the full address space an organization owns.

EXAMPLES
  webrecon cidr AS15169       # Google
  webrecon cidr 13335 --json  # Cloudflare
")]
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
    Subs {
        /// Apex domain (e.g. example.com)
        target: String,
        /// Disable passive sources
        #[arg(long)]
        no_passive: bool,
        /// Enable active DNS brute force
        #[arg(long)]
        active: bool,
        /// Custom wordlist (one entry per line). Defaults to embedded list.
        #[arg(long)]
        wordlist: Option<std::path::PathBuf>,
        /// Concurrent DNS resolutions
        #[arg(long, default_value_t = 50)]
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
    Scan {
        /// host, IP, or CIDR (e.g. example.com / 1.2.3.4 / 10.0.0.0/28)
        target: String,
        #[arg(long, long_help = "Port spec, e.g. \"22,80,443,8000-8100\". Overrides --top.")]
        ports: Option<String>,
        #[arg(long, default_value_t = 100, long_help = "Use nmap top-N list (100 or 1000). Ignored when --ports is given.")]
        top: u16,
        #[arg(long, default_value_t = 500, long_help = "Concurrent TCP connect attempts.")]
        concurrency: usize,
        #[arg(long, default_value_t = 1500, long_help = "Per-port connect timeout in milliseconds.")]
        connect_timeout: u64,
        #[arg(long, long_help = "Skip banner grab on open ports (faster, less info).")]
        no_banner: bool,
        #[arg(long, default_value_t = 256, long_help = "Reject a CIDR that expands to more than this many hosts.")]
        max_hosts: usize,
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
    Shodan { ip: String },

    /// Censys host lookup — services + autonomous system + location
    #[command(long_about = "\
Like Shodan but Censys. Returns the indexed host record: services, AS, OS,
location. Often complements Shodan with different visibility.

Requires `censys` key (Personal Access Token, Bearer auth).
")]
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
    Vt { indicator: String },

    /// Pulsedive risk score + threat tags for an indicator
    #[command(long_about = "\
Pulsedive enrichment for an IP / domain / URL: risk score, threat
categorization, attribution to feeds.

Requires `pulsedive` key.
")]
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

    /// Show resolved config: which keys are loaded and from where
    #[command(long_about = "\
Prints the resolved config: the config file path it looked at, and for each
known key whether it's loaded (with the first/last 3 characters shown) or
unset. Run after editing ~/.config/webrecon/config.toml to verify the file
parsed and the right keys were picked up.
")]
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
        Cmd::Asn { target } => commands::asn::run(target, cli.timeout, cli.json).await,
        Cmd::Cidr { target } => commands::cidr::run(target, cli.timeout, cli.json).await,
        Cmd::Subs { target, no_passive, active, wordlist, concurrency } => {
            commands::subs::run(target, *no_passive, *active, wordlist.as_deref(), *concurrency, cli.timeout, cli.json).await
        }
        Cmd::Scan { target, ports, top, concurrency, connect_timeout, no_banner, max_hosts } => {
            commands::scan::run(target, ports.as_deref(), *top, *concurrency, *connect_timeout, *no_banner, *max_hosts, cli.json).await
        }
        Cmd::Cve { action } => commands::cve::run(action, cli.timeout, cli.json).await,
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
        Cmd::Config => commands::config_show::run(cli.json),
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
