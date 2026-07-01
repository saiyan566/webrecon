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

/// Merge results from bgp.he.net (broadest org index) + PeeringDB (peering nets).
/// Fall back to RIPEstat autocomplete if both are empty.
pub async fn search(client: &Client, query: &str) -> Result<SearchResult> {
    let he = bgp_he(client, query).await.unwrap_or_default();
    let peering = peeringdb(client, query).await.unwrap_or_default();

    let mut merged: std::collections::BTreeMap<u32, AsnHit> = std::collections::BTreeMap::new();
    for h in he.into_iter().chain(peering.into_iter()) {
        merged.entry(h.asn).and_modify(|e| {
            if e.country.is_empty() && !h.country.is_empty() { e.country = h.country.clone(); }
            if e.name.is_empty() && !h.name.is_empty() { e.name = h.name.clone(); }
        }).or_insert(h);
    }

    if !merged.is_empty() {
        let asns: Vec<AsnHit> = merged.into_values().collect();
        return Ok(SearchResult { query: query.into(), source: "bgp.he.net+peeringdb", asns });
    }

    let mut ripe = ripestat(client, query).await?;
    ripe.sort_by_key(|h| h.asn);
    Ok(SearchResult { query: query.into(), source: "ripestat", asns: ripe })
}

/// bgp.he.net — HTML scrape of the org search table. Broadest org→ASN index
/// available without an API key; returns every ASN whose registered org name
/// contains the query.
pub async fn bgp_he(client: &Client, query: &str) -> Result<Vec<AsnHit>> {
    let url = format!(
        "https://bgp.he.net/search?search%5Bsearch%5D={}&commit=Search",
        urlencode(query)
    );
    let resp = client.get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        .header("Accept", "text/html")
        .send().await
        .map_err(|e| WebreconError::Network(format!("bgp.he.net: {e}")))?;
    if !resp.status().is_success() {
        return Err(WebreconError::Network(format!("bgp.he.net -> {}", resp.status())));
    }
    let body = resp.text().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    let mut out = Vec::new();
    // Rows look like: <tr>...<a href="/AS15169">AS15169</a></td><td>ASN</td><td>Google LLC</td>...
    // Extract by walking each <a href="/ASN"> and the following "ASN" cell's org text.
    let mut i = 0;
    while let Some(pos) = body[i..].find("<a href=\"/AS") {
        let start = i + pos + "<a href=\"/AS".len();
        let end = match body[start..].find('"') { Some(e) => start + e, None => break };
        let asn_str = &body[start..end];
        i = end;
        let asn_n: u32 = match asn_str.parse() { Ok(n) => n, Err(_) => continue };
        // Only match rows in the search results table: the next cell is "<td>ASN</td>".
        let after = &body[end..];
        let Some(td_asn) = after.find("<td>ASN</td>") else { continue };
        // Extract next <td>...</td> after that — the org name.
        let post = &after[td_asn + "<td>ASN</td>".len()..];
        let Some(td_start) = post.find("<td>") else { continue };
        let org_area = &post[td_start + 4..];
        let Some(td_end) = org_area.find("</td>") else { continue };
        let raw = &org_area[..td_end];
        let name = strip_tags(raw).trim().to_string();
        if name.is_empty() { continue; }
        out.push(AsnHit {
            asn: asn_n,
            name,
            description: String::new(),
            country: String::new(),
            source: "bgp.he.net",
        });
    }
    Ok(out)
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
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
