use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

use crate::nvd::CveSummary;

/// Vulners "Audit by software" endpoint — feed product + version, get matching CVEs.
/// Docs: https://vulners.com/docs/api_reference/burp_api/#software-audit
pub async fn audit_software(
    client: &Client,
    key: &str,
    software: &str,
    version: &str,
) -> Result<Vec<CveSummary>> {
    let body = serde_json::json!({
        "software": software,
        "version": version,
        "type": "software",
        "apiKey": key,
    });
    let resp = client.post("https://vulners.com/api/v3/burp/software/")
        .json(&body)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("vulners -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    if v.get("result").and_then(|x| x.as_str()) == Some("error") {
        let msg = v.pointer("/data/error").and_then(|s| s.as_str()).unwrap_or("unknown");
        return Err(WebreconError::Network(format!("vulners: {}", msg)));
    }
    let arr = v.pointer("/data/search").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let mut out: Vec<CveSummary> = arr.iter()
        .filter_map(|item| {
            let src = item.get("_source")?;
            let id = src.get("id").and_then(|v| v.as_str())?.to_string();
            if !id.starts_with("CVE-") { return None; }
            let cvss = src.pointer("/cvss/score").and_then(|v| v.as_f64())
                .or_else(|| src.pointer("/cvss3/cvssV3/baseScore").and_then(|v| v.as_f64()));
            let severity = cvss.map(|s| severity_band(s));
            let published = src.get("published").and_then(|v| v.as_str()).map(String::from);
            let description = src.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let references = src.get("references").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|r| r.as_str().map(String::from)).take(5).collect())
                .unwrap_or_default();
            Some(CveSummary { id, cvss, severity, published, description, references })
        })
        .collect();
    out.sort_by(|a, b| b.cvss.unwrap_or(0.0).partial_cmp(&a.cvss.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
    Ok(out)
}

fn severity_band(score: f64) -> String {
    let s = if score >= 9.0 { "CRITICAL" }
    else if score >= 7.0 { "HIGH" }
    else if score >= 4.0 { "MEDIUM" }
    else if score > 0.0 { "LOW" }
    else { "NONE" };
    s.into()
}
