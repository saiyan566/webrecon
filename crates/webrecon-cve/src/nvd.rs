use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Debug, Clone, Serialize)]
pub struct CveSummary {
    pub id: String,
    pub cvss: Option<f64>,
    pub severity: Option<String>,
    pub published: Option<String>,
    pub description: String,
    pub references: Vec<String>,
}

pub async fn fetch_by_id(client: &Client, key: Option<&str>, id: &str) -> Result<CveSummary> {
    let url = format!("{}?cveId={}", NVD_BASE, id);
    let body = http_get_json(client, key, &url).await?;
    let vulns = body.get("vulnerabilities").and_then(|v| v.as_array())
        .ok_or_else(|| WebreconError::Parse("nvd: no vulnerabilities".into()))?;
    let first = vulns.first()
        .ok_or_else(|| WebreconError::NotFound(format!("{id} not found")))?;
    let cve = first.get("cve").ok_or_else(|| WebreconError::Parse("nvd: missing cve".into()))?;
    Ok(parse_cve(cve))
}

pub async fn search(client: &Client, key: Option<&str>, product: &str, version: Option<&str>, limit: usize) -> Result<Vec<CveSummary>> {
    let mut q = product.to_string();
    if let Some(v) = version { q.push(' '); q.push_str(v); }
    let url = format!(
        "{}?keywordSearch={}&resultsPerPage={}",
        NVD_BASE,
        urlencode(&q),
        limit.min(2000),
    );
    let body = http_get_json(client, key, &url).await?;
    let vulns = body.get("vulnerabilities").and_then(|v| v.as_array())
        .ok_or_else(|| WebreconError::Parse("nvd: no vulnerabilities".into()))?;
    let mut out: Vec<CveSummary> = vulns.iter()
        .filter_map(|v| v.get("cve").map(parse_cve))
        .collect();
    out.sort_by(|a, b| b.cvss.unwrap_or(0.0).partial_cmp(&a.cvss.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
    Ok(out)
}

async fn http_get_json(client: &Client, key: Option<&str>, url: &str) -> Result<Value> {
    let mut req = client.get(url);
    if let Some(k) = key { req = req.header("apiKey", k); }
    let resp = req.send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(WebreconError::Network(format!("nvd {} -> {}", url, status)));
    }
    resp.json::<Value>().await.map_err(|e| WebreconError::Parse(e.to_string()))
}

fn parse_cve(cve: &Value) -> CveSummary {
    let id = cve.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let published = cve.get("published").and_then(|v| v.as_str()).map(String::from);
    let description = cve.pointer("/descriptions/0/value")
        .and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (cvss, severity) = extract_cvss(cve);
    let references = cve.pointer("/references")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
            .take(5).collect())
        .unwrap_or_default();
    CveSummary { id, cvss, severity, published, description, references }
}

fn extract_cvss(cve: &Value) -> (Option<f64>, Option<String>) {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let pointer = format!("/metrics/{}/0", key);
        if let Some(m) = cve.pointer(&pointer) {
            let score = m.pointer("/cvssData/baseScore").and_then(|v| v.as_f64());
            let sev = m.pointer("/cvssData/baseSeverity")
                .or_else(|| m.get("baseSeverity"))
                .and_then(|v| v.as_str()).map(String::from);
            if score.is_some() { return (score, sev); }
        }
    }
    (None, None)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
