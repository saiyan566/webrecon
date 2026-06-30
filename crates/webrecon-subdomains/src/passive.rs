use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

#[derive(Debug, Clone)]
pub struct SourceResult {
    pub source: &'static str,
    pub hosts: Vec<String>,
    pub error: Option<String>,
}

impl SourceResult {
    fn ok(source: &'static str, hosts: Vec<String>) -> Self {
        Self { source, hosts, error: None }
    }
    fn err(source: &'static str, e: impl ToString) -> Self {
        Self { source, hosts: Vec::new(), error: Some(e.to_string()) }
    }
}

pub async fn run_all(client: &Client, domain: &str) -> Vec<SourceResult> {
    let (crtsh, otx, ht) = tokio::join!(
        crtsh(client, domain),
        otx(client, domain),
        hackertarget(client, domain),
    );
    vec![
        unpack(crtsh, "crt.sh"),
        unpack(otx, "otx.alienvault"),
        unpack(ht, "hackertarget"),
    ]
}

fn unpack(r: Result<Vec<String>>, source: &'static str) -> SourceResult {
    match r {
        Ok(v) => SourceResult::ok(source, v),
        Err(e) => SourceResult::err(source, e),
    }
}

pub async fn crtsh(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("crt.sh -> {}", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let arr = body.as_array().ok_or_else(|| WebreconError::Parse("crt.sh: not an array".into()))?;
    let mut out = Vec::with_capacity(arr.len() * 2);
    for entry in arr {
        if let Some(s) = entry.get("name_value").and_then(|v| v.as_str()) {
            for line in s.split('\n') {
                out.push(line.to_string());
            }
        }
        if let Some(s) = entry.get("common_name").and_then(|v| v.as_str()) {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

pub async fn otx(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("otx -> {}", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let arr = body.pointer("/passive_dns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WebreconError::Parse("otx: missing passive_dns".into()))?;
    Ok(arr.iter()
        .filter_map(|e| e.get("hostname").and_then(|v| v.as_str()).map(String::from))
        .collect())
}

pub async fn hackertarget(client: &Client, domain: &str) -> Result<Vec<String>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("hackertarget -> {}", resp.status())));
    }
    let text = resp.text().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    if text.contains("API count exceeded") || text.starts_with("error") {
        return Err(WebreconError::Network(format!("hackertarget: {}", text.trim())));
    }
    Ok(text.lines()
        .filter_map(|l| l.split(',').next())
        .map(|s| s.to_string())
        .collect())
}
