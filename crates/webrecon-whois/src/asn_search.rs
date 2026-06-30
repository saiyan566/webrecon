use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

#[derive(Debug, Clone, Serialize)]
pub struct AsnHit {
    pub asn: u32,
    pub name: String,
    pub description: String,
    pub country: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub query: String,
    pub source: &'static str,
    pub asns: Vec<AsnHit>,
}

/// Try PeeringDB first (clean JSON, no key). Fall back to RIPEstat searchcomplete
/// if PeeringDB returns nothing.
pub async fn search(client: &Client, query: &str) -> Result<SearchResult> {
    let mut peering = peeringdb(client, query).await.unwrap_or_default();
    if !peering.is_empty() {
        peering.sort_by_key(|h| h.asn);
        return Ok(SearchResult { query: query.into(), source: "peeringdb", asns: peering });
    }

    let mut ripe = ripestat(client, query).await?;
    ripe.sort_by_key(|h| h.asn);
    Ok(SearchResult { query: query.into(), source: "ripestat", asns: ripe })
}

/// PeeringDB — searches the network table by `name__contains` (also matches AKAs).
pub async fn peeringdb(client: &Client, query: &str) -> Result<Vec<AsnHit>> {
    let url = format!("https://www.peeringdb.com/api/net?name__contains={}", urlencode(query));
    let resp = client.get(&url)
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| WebreconError::Network(format!("peeringdb: {e}")))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("peeringdb -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let arr = v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    Ok(arr.into_iter().filter_map(|n| {
        let asn = n.get("asn").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        if asn == 0 { return None; }
        Some(AsnHit {
            asn,
            name: n.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            description: n.get("aka").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            country: n.pointer("/org/country").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            source: "peeringdb",
        })
    }).collect())
}

/// RIPEstat searchcomplete — autocomplete-style across RIRs.
pub async fn ripestat(client: &Client, query: &str) -> Result<Vec<AsnHit>> {
    let url = format!("https://stat.ripe.net/data/searchcomplete/data.json?resource={}", urlencode(query));
    let resp = client.get(&url)
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| WebreconError::Network(format!("ripestat: {e}")))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("ripestat -> {}", resp.status())));
    }
    let v: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let cats = v.pointer("/data/categories").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for c in cats {
        let cat_name = c.get("category").and_then(|x| x.as_str()).unwrap_or("");
        if !cat_name.to_lowercase().contains("asn") { continue; }
        if let Some(items) = c.get("suggestions").and_then(|s| s.as_array()) {
            for it in items {
                let val = it.get("value").and_then(|x| x.as_str()).unwrap_or("");
                let asn_n: u32 = val.strip_prefix("AS").or_else(|| val.strip_prefix("as"))
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
                if asn_n == 0 { continue; }
                out.push(AsnHit {
                    asn: asn_n,
                    name: it.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    description: String::new(),
                    country: String::new(),
                    source: "ripestat",
                });
            }
        }
    }
    Ok(out)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
