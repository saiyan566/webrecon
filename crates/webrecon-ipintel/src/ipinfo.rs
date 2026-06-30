use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

pub async fn lookup(client: &Client, key: &str, ip: &str) -> Result<Value> {
    let url = format!("https://ipinfo.io/{}/json?token={}", ip, key);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("ipinfo {} -> {}", ip, resp.status())));
    }
    resp.json::<Value>().await.map_err(|e| WebreconError::Parse(e.to_string()))
}
