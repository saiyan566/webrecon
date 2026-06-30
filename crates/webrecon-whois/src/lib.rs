pub mod rdap;
pub mod cymru;
pub mod ripestat;

use reqwest::Client;
use std::time::Duration;

pub fn http_client(timeout_secs: u64) -> Client {
    Client::builder()
        .user_agent(concat!("webrecon/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("failed to build http client")
}
