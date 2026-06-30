use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

use crate::indicator_kind;

pub async fn lookup(client: &Client, key: &str, indicator: &str) -> Result<Value> {
    let kind = indicator_kind(indicator);
    let path = match kind {
        "ip" => format!("ip_addresses/{indicator}"),
        "domain" => format!("domains/{indicator}"),
        "sha256" | "sha1" | "md5" => format!("files/{indicator}"),
        _ => return Err(WebreconError::InvalidTarget(format!("vt: unknown indicator {indicator}"))),
    };
    let url = format!("https://www.virustotal.com/api/v3/{path}");
    let resp = client.get(&url)
        .header("x-apikey", key)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("vt: {indicator} unknown")));
    }
    if !status.is_success() {
        return Err(WebreconError::Network(format!("vt -> {}", status)));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(v.get("data").cloned().unwrap_or(v))
}
