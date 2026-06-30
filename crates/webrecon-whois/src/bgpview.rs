use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

/// Free-text search across ASN names, descriptions, prefixes. No key needed.
pub async fn search(client: &Client, query: &str) -> Result<Value> {
    let url = format!("https://api.bgpview.io/search?query_term={}", urlencode(query));
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("bgpview -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let data = v.get("data").cloned().unwrap_or(v);
    Ok(data)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
