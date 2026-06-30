use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

/// Community endpoint (works with the community key). Returns noise/riot classification.
pub async fn lookup(client: &Client, key: &str, ip: &str) -> Result<Value> {
    let url = format!("https://api.greynoise.io/v3/community/{}", ip);
    let resp = client.get(&url)
        .header("key", key)
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("greynoise: {} not seen", ip)));
    }
    if !status.is_success() {
        return Err(WebreconError::Network(format!("greynoise {} -> {}", ip, status)));
    }
    resp.json::<Value>().await.map_err(|e| WebreconError::Parse(e.to_string()))
}
