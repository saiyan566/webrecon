mod ui;
mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "webrecon", version, about = "Personal recon toolkit", long_about = None)]
struct Cli {
    /// Emit JSON instead of pretty output
    #[arg(long, global = true)]
    json: bool,
    /// Disable ANSI colors
    #[arg(long, global = true)]
    no_color: bool,
    /// Per-request timeout in seconds
    #[arg(long, global = true, default_value_t = 15)]
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
    Id { id: String },
    /// Keyword search by product (and optional version)
    Search {
        product: String,
        version: Option<String>,
        /// Max results to fetch
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Scan host → fingerprint banners → query CVEs per service
    Scan {
        target: String,
        #[arg(long)]
        ports: Option<String>,
        #[arg(long, default_value_t = 100)]
        top: u16,
        #[arg(long, default_value_t = 500)]
        concurrency: usize,
        #[arg(long, default_value_t = 1500)]
        connect_timeout: u64,
        /// CVEs to show per fingerprinted service
        #[arg(long, default_value_t = 5)]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// RDAP / whois lookup for a domain or IP
    Whois { target: String },
    /// ASN info for an ASN, IP, or domain (resolves first)
    Asn { target: String },
    /// Announced CIDR prefixes for an ASN
    Cidr { target: String },
    /// CVE lookup — by ID, keyword search, or chained scan→fingerprint→CVE
    Cve {
        #[command(subcommand)]
        action: CveAction,
    },
    /// Full IP intel: IPinfo (geo/ASN) + GreyNoise (noise) + AbuseIPDB (reputation) in parallel
    Ipinfo {
        ip: String,
        /// AbuseIPDB report window in days
        #[arg(long, default_value_t = 90)]
        max_age: u32,
    },
    /// Show resolved config: where keys are loaded from and which are present
    Config,
    /// TCP connect port scan (host/IP/CIDR) with optional banner grab
    Scan {
        /// host, IP, or CIDR (e.g. example.com / 1.2.3.4 / 10.0.0.0/28)
        target: String,
        /// Port spec: "80,443,8000-8100". Overrides --top.
        #[arg(long)]
        ports: Option<String>,
        /// Use top-N nmap ports (100 or 1000). Ignored if --ports given.
        #[arg(long, default_value_t = 100)]
        top: u16,
        /// Concurrent connect attempts per host
        #[arg(long, default_value_t = 500)]
        concurrency: usize,
        /// Per-port connect timeout (ms)
        #[arg(long, default_value_t = 1500)]
        connect_timeout: u64,
        /// Skip banner grab on open ports
        #[arg(long)]
        no_banner: bool,
        /// Max hosts to expand from a CIDR
        #[arg(long, default_value_t = 256)]
        max_hosts: usize,
    },
    /// Enumerate subdomains (passive + optional active brute force)
    Subs {
        /// Apex domain (e.g. example.com)
        target: String,
        /// Disable passive sources (crt.sh / OTX / HackerTarget)
        #[arg(long)]
        no_passive: bool,
        /// Enable active DNS brute force
        #[arg(long)]
        active: bool,
        /// Custom wordlist path (one entry per line). Defaults to embedded list.
        #[arg(long)]
        wordlist: Option<std::path::PathBuf>,
        /// Concurrent DNS resolutions for active brute force
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
    },
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
        Cmd::Config => commands::config_show::run(cli.json),
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
