use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

pub async fn info(client: &Client, key: &str, indicator: &str) -> Result<Value> {
    let url = format!(
        "https://pulsedive.com/api/info.php?indicator={}&pretty=0&key={}",
        urlencode(indicator), key
    );
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("pulsedive -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        return Err(WebreconError::NotFound(format!("pulsedive: {err}")));
    }
    Ok(v)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
