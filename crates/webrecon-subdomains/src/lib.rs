pub mod passive;
pub mod active;

use reqwest::Client;
use std::collections::BTreeMap;
use std::time::Duration;

pub fn http_client(timeout_secs: u64) -> Client {
    Client::builder()
        .user_agent(concat!("webrecon/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("failed to build http client")
}

/// Default embedded wordlist (used when no --wordlist is given).
pub const DEFAULT_WORDLIST: &str = include_str!("../data/wordlist.txt");

/// Normalize and dedupe a domain set per apex.
pub fn dedupe(apex: &str, hosts: impl IntoIterator<Item = String>) -> Vec<String> {
    let apex = apex.trim_start_matches('.').to_lowercase();
    let mut set: BTreeMap<String, ()> = BTreeMap::new();
    for h in hosts {
        let mut h = h.trim().trim_end_matches('.').to_lowercase();
        if h.starts_with("*.") {
            h = h[2..].to_string();
        }
        if h.is_empty() { continue; }
        if h == apex || h.ends_with(&format!(".{}", apex)) {
            set.insert(h, ());
        }
    }
    set.into_keys().collect()
}
