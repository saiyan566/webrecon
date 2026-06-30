pub mod shodan;
pub mod vt;
pub mod pulsedive;
pub mod intelx;

use reqwest::Client;
use std::time::Duration;

pub fn http_client(timeout_secs: u64) -> Client {
    Client::builder()
        .user_agent(concat!("webrecon/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("failed to build http client")
}

/// Classify a free-form indicator for routing to the right VT/Pulsedive endpoint.
pub fn indicator_kind(s: &str) -> &'static str {
    let s = s.trim();
    if s.parse::<std::net::IpAddr>().is_ok() { return "ip"; }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) { return "sha256"; }
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) { return "sha1"; }
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) { return "md5"; }
    if s.contains('.') { return "domain"; }
    "unknown"
}
