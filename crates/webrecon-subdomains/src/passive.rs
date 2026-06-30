use base64::Engine;
use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Keys, Result, WebreconError};

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

pub async fn run_all(client: &Client, domain: &str, keys: &Keys) -> Vec<SourceResult> {
    let (crtsh_r, otx_r, ht_r, vt_r, censys_r) = tokio::join!(
        crtsh(client, domain),
        otx(client, domain, keys.otx.as_deref()),
        hackertarget(client, domain),
        async {
            match keys.virustotal.as_deref() {
                Some(k) => virustotal(client, k, domain).await,
                None => Err(WebreconError::NotFound("no virustotal key".into())),
            }
        },
        async {
            match (keys.censys_api_id.as_deref(), keys.censys_api_secret.as_deref()) {
                (Some(id), Some(secret)) => censys_certs(client, id, secret, domain).await,
                _ => Err(WebreconError::NotFound("no censys keys".into())),
            }
        },
    );
    vec![
        unpack(crtsh_r, "crt.sh"),
        unpack(otx_r, "otx.alienvault"),
        unpack(ht_r, "hackertarget"),
        unpack(vt_r, "virustotal"),
        unpack(censys_r, "censys.certs"),
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

pub async fn otx(client: &Client, domain: &str, key: Option<&str>) -> Result<Vec<String>> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let mut req = client.get(&url);
    if let Some(k) = key { req = req.header("X-OTX-API-KEY", k); }
    let resp = req.send().await
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

pub async fn virustotal(client: &Client, key: &str, domain: &str) -> Result<Vec<String>> {
    let mut url = format!(
        "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40",
        domain
    );
    let mut out: Vec<String> = Vec::new();
    let mut pages = 0;
    loop {
        let resp = client.get(&url)
            .header("x-apikey", key)
            .send().await
            .map_err(|e| WebreconError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(WebreconError::Network(format!("virustotal -> {}", resp.status())));
        }
        let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
        if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                    out.push(id.to_string());
                }
            }
        }
        pages += 1;
        let next = body.pointer("/links/next").and_then(|v| v.as_str()).map(String::from);
        match next {
            Some(n) if pages < 5 => { url = n; }
            _ => break,
        }
    }
    Ok(out)
}

pub async fn censys_certs(client: &Client, id: &str, secret: &str, domain: &str) -> Result<Vec<String>> {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", id, secret));
    let body = serde_json::json!({
        "q": format!("names: {}", domain),
        "per_page": 100,
    });
    let resp = client.post("https://search.censys.io/api/v2/certificates/search")
        .header("Authorization", format!("Basic {}", token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("censys -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let hits = v.pointer("/result/hits").and_then(|h| h.as_array())
        .ok_or_else(|| WebreconError::Parse("censys: no hits".into()))?;
    let mut out = Vec::new();
    for hit in hits {
        if let Some(names) = hit.get("names").and_then(|v| v.as_array()) {
            for n in names {
                if let Some(s) = n.as_str() { out.push(s.to_string()); }
            }
        }
    }
    Ok(out)
}
