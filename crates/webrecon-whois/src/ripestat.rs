use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Finding, Result, WebreconError};

pub async fn announced_prefixes(client: &Client, asn: u32) -> Result<Finding> {
    let url = format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}",
        asn
    );
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::NotFound(format!("ripestat AS{} -> {}", asn, resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let prefixes: Vec<String> = body
        .pointer("/data/prefixes")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|p| p.get("prefix").and_then(|s| s.as_str()).map(|s| s.to_string()))
            .collect())
        .unwrap_or_default();
    let v4 = prefixes.iter().filter(|p| !p.contains(':')).count();
    let v6 = prefixes.iter().filter(|p| p.contains(':')).count();
    Ok(Finding::new("cidr.ripestat", &format!("AS{}", asn), serde_json::json!({
        "asn": asn,
        "ipv4_count": v4,
        "ipv6_count": v6,
        "prefixes": prefixes,
    })))
}
