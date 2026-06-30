use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;
use webrecon_core::{Result, WebreconError};

const BASE: &str = "https://2.intelx.io";

/// Two-step search: POST to start, then poll for results.
/// Returns the records array from the final result page.
pub async fn search(client: &Client, key: &str, term: &str, max_results: usize) -> Result<Value> {
    let start = serde_json::json!({
        "term": term,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": max_results.min(100),
        "timeout": 0,
        "datefrom": "",
        "dateto": "",
        "sort": 4,
        "media": 0,
        "terminate": [],
    });
    let resp = client.post(format!("{}/intelligent/search", BASE))
        .header("x-key", key)
        .json(&start)
        .send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("intelx search -> {}", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let id = body.get("id").and_then(|v| v.as_str())
        .ok_or_else(|| WebreconError::Parse("intelx: no search id".into()))?
        .to_string();
    let status = body.get("status").and_then(|v| v.as_i64()).unwrap_or(-1);
    if status == 1 {
        return Err(WebreconError::InvalidTarget("intelx: invalid term".into()));
    }

    // Poll up to ~12s for results (status 0 = ready, 3 = no more, 1 = error).
    for _ in 0..6 {
        let url = format!("{}/intelligent/search/result?id={}&limit={}", BASE, id, max_results.min(100));
        let r = client.get(&url)
            .header("x-key", key)
            .send().await
            .map_err(|e| WebreconError::Network(e.to_string()))?;
        if !r.status().is_success() {
            return Err(WebreconError::Network(format!("intelx result -> {}", r.status())));
        }
        let v: Value = r.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
        let st = v.get("status").and_then(|x| x.as_i64()).unwrap_or(-1);
        let records = v.get("records").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        if st == 0 || st == 3 || !records.is_empty() {
            return Ok(serde_json::json!({
                "id": id,
                "status": st,
                "count": records.len(),
                "records": records,
            }));
        }
        sleep(Duration::from_millis(2000)).await;
    }
    Err(WebreconError::Network("intelx: poll timed out".into()))
}
