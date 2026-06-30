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
    };

    if let Err(e) = result {
        ui::error(&format!("{e}"));
        std::process::exit(1);
    }
}
