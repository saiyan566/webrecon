use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Keys, Result, WebreconError};

#[derive(Debug, Clone)]
pub struct SourceResult {
    pub source: &'static str,
    pub hosts: Vec<String>,
    /// Short human-friendly status. None = OK. Some("no key") = clean skip.
    /// Some("http 503") / Some("timeout") / ... = real failure, kept short.
    pub error: Option<String>,
    /// True when the source was skipped intentionally (missing key), not a real failure.
    pub skipped: bool,
}

impl SourceResult {
    fn ok(source: &'static str, hosts: Vec<String>) -> Self {
        Self { source, hosts, error: None, skipped: false }
    }
    fn err(source: &'static str, e: impl ToString) -> Self {
        let raw = e.to_string();
        let (short, skipped) = classify_error(&raw);
        Self { source, hosts: Vec::new(), error: Some(short), skipped }
    }
}

fn classify_error(raw: &str) -> (String, bool) {
    let low = raw.to_ascii_lowercase();
    if low.starts_with("no ") && low.ends_with(" key") {
        return ("no key".into(), true);
    }
    // Extract HTTP status if present ("... -> 401 Unauthorized", "... 503 ...").
    if let Some(pos) = raw.find(" -> ") {
        let tail: String = raw[pos + 4..].chars().take(30).collect();
        return (tail.trim().to_string(), false);
    }
    if low.contains("timed out") || low.contains("timeout") {
        return ("timeout".into(), false);
    }
    if low.contains("dns error") || low.contains("failed to lookup") {
        return ("dns error".into(), false);
    }
    if low.contains("connection") {
        return ("connection refused".into(), false);
    }
    // Fallback: truncate whatever we got.
    let s: String = raw.chars().take(60).collect();
    (s, false)
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
            match keys.censys.as_deref() {
                Some(token) => censys_certs(client, token, domain).await,
                None => Err(WebreconError::NotFound("no censys key".into())),
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
    // crt.sh 503s under load; retry with backoff on 5xx / transient network errors.
    let backoff_ms = [0u64, 800, 2500];
    let mut last_err: Option<WebreconError> = None;
    let mut resp_opt: Option<reqwest::Response> = None;
    for delay in backoff_ms {
        if delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(delay)).await; }
        match client.get(&url).send().await {
            Ok(r) => {
                let s = r.status();
                if s.is_success() { resp_opt = Some(r); break; }
                let retryable = s.as_u16() >= 500 || s.as_u16() == 429;
                last_err = Some(WebreconError::Network(format!("crt.sh -> {}", s)));
                if !retryable { break; }
            }
            Err(e) => { last_err = Some(WebreconError::Network(e.to_string())); }
        }
    }
    let resp = match resp_opt {
        Some(r) => r,
        None => return Err(last_err.unwrap_or_else(|| WebreconError::Network("crt.sh: unreachable".into()))),
    };
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

pub async fn censys_certs(client: &Client, key: &str, domain: &str) -> Result<Vec<String>> {
    let body = serde_json::json!({
        "q": format!("names: {}", domain),
        "per_page": 100,
    });
    let req = client.post("https://search.censys.io/api/v2/certificates/search")
        .header("Content-Type", "application/json")
        .json(&body);
    let req = match key.split_once(':') {
        Some((id, secret)) if !id.is_empty() && !secret.is_empty() => req.basic_auth(id, Some(secret)),
        _ => req.bearer_auth(key),
    };
    let resp = req.send().await
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
