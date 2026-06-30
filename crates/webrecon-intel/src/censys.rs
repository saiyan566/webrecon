use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

/// Auth helper: if the configured key contains `:`, treat as legacy `api_id:api_secret`
/// (Basic auth). Otherwise use it as a Personal Access Token (Bearer).
pub fn apply_auth(req: RequestBuilder, key: &str) -> RequestBuilder {
    match key.split_once(':') {
        Some((id, secret)) if !id.is_empty() && !secret.is_empty() => req.basic_auth(id, Some(secret)),
        _ => req.bearer_auth(key),
    }
}

pub async fn host(client: &Client, key: &str, ip: &str) -> Result<Value> {
    let url = format!("https://search.censys.io/api/v2/hosts/{}", ip);
    let resp = apply_auth(client.get(&url), key)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if resp.status().as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("censys: {ip} not indexed")));
    }
    if resp.status().as_u16() == 401 {
        return Err(WebreconError::Network("censys 401 — check your key (paste 'id:secret' for legacy keys, or PAT for new)".into()));
    }
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("censys -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(v.pointer("/result").cloned().unwrap_or(v))
}
