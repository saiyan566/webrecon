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
enum Cmd {
    /// RDAP / whois lookup for a domain or IP
    Whois { target: String },
    /// ASN info for an ASN, IP, or domain (resolves first)
    Asn { target: String },
    /// Announced CIDR prefixes for an ASN
    Cidr { target: String },
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
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
