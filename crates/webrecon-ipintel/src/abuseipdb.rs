use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

pub async fn lookup(client: &Client, key: &str, ip: &str, max_age_days: u32) -> Result<Value> {
    let url = format!(
        "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays={}&verbose",
        ip, max_age_days
    );
    let resp = client.get(&url)
        .header("Key", key)
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("abuseipdb {} -> {}", ip, resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(v.get("data").cloned().unwrap_or(v))
}
