use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

/// Free-text search across ASN names, descriptions, prefixes. No key needed.
pub async fn search(client: &Client, query: &str) -> Result<Value> {
    let url = format!("https://api.bgpview.io/search?query_term={}", urlencode(query));
    let resp = client.get(&url)
        .header("Accept", "application/json")
        .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        .send().await
        .map_err(|e| WebreconError::Network(format!("bgpview connect failed ({e}) — try: curl -v '{url}'")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(WebreconError::Network(format!("bgpview -> {status}")));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    if v.get("status").and_then(|s| s.as_str()) == Some("error") {
        let msg = v.pointer("/status_message").and_then(|s| s.as_str()).unwrap_or("unknown");
        return Err(WebreconError::Network(format!("bgpview: {msg}")));
    }
    Ok(v.get("data").cloned().unwrap_or(v))
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
