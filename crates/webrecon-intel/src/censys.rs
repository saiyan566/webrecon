use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

pub async fn host(client: &Client, token: &str, ip: &str) -> Result<Value> {
    let url = format!("https://search.censys.io/api/v2/hosts/{}", ip);
    let resp = client.get(&url)
        .bearer_auth(token)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if resp.status().as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("censys: {ip} not indexed")));
    }
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("censys -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(v.pointer("/result").cloned().unwrap_or(v))
}
