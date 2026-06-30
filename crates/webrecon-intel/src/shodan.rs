use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

pub async fn host(client: &Client, key: &str, ip: &str) -> Result<Value> {
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, key);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if resp.status().as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("shodan: {ip} not indexed")));
    }
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("shodan -> {}", resp.status())));
    }
    resp.json::<Value>().await.map_err(|e| WebreconError::Parse(e.to_string()))
}
