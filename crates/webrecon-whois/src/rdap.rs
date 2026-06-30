use reqwest::Client;
use serde_json::Value;
use webrecon_core::{Finding, Result, WebreconError};

pub async fn lookup_domain(client: &Client, domain: &str) -> Result<Finding> {
    let url = format!("https://rdap.org/domain/{}", domain);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::NotFound(format!("RDAP {} -> {}", domain, resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(Finding::new("whois.rdap.domain", domain, summarize_domain(&body)))
}

pub async fn lookup_ip(client: &Client, ip: &str) -> Result<Finding> {
    let url = format!("https://rdap.org/ip/{}", ip);
    let resp = client.get(&url).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(WebreconError::NotFound(format!("RDAP {} -> {}", ip, resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| WebreconError::Parse(e.to_string()))?;
    Ok(Finding::new("whois.rdap.ip", ip, summarize_ip(&body)))
}

fn summarize_domain(body: &Value) -> Value {
    let handle = body.get("handle").cloned().unwrap_or(Value::Null);
    let ldh = body.get("ldhName").cloned().unwrap_or(Value::Null);
    let status = body.get("status").cloned().unwrap_or(Value::Null);
    let nameservers: Vec<String> = body.get("nameservers")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|ns| ns.get("ldhName").and_then(|s| s.as_str()).map(|s| s.to_string()))
            .collect())
        .unwrap_or_default();
    let mut registrar = Value::Null;
    let mut abuse = Value::Null;
    if let Some(ents) = body.get("entities").and_then(|v| v.as_array()) {
        for e in ents {
            let roles: Vec<String> = e.get("roles").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if roles.iter().any(|r| r == "registrar") {
                if let Some(name) = vcard_name(e) { registrar = Value::String(name); }
            }
            if roles.iter().any(|r| r == "abuse") {
                if let Some(email) = vcard_email(e) { abuse = Value::String(email); }
            }
        }
    }
    let mut events = serde_json::Map::new();
    if let Some(evs) = body.get("events").and_then(|v| v.as_array()) {
        for ev in evs {
            if let (Some(action), Some(date)) = (
                ev.get("eventAction").and_then(|v| v.as_str()),
                ev.get("eventDate").and_then(|v| v.as_str()),
            ) {
                events.insert(action.into(), Value::String(date.into()));
            }
        }
    }
    serde_json::json!({
        "handle": handle,
        "domain": ldh,
        "status": status,
        "registrar": registrar,
        "abuse_email": abuse,
        "nameservers": nameservers,
        "events": events,
    })
}

fn summarize_ip(body: &Value) -> Value {
    let handle = body.get("handle").cloned().unwrap_or(Value::Null);
    let name = body.get("name").cloned().unwrap_or(Value::Null);
    let country = body.get("country").cloned().unwrap_or(Value::Null);
    let start = body.get("startAddress").cloned().unwrap_or(Value::Null);
    let end = body.get("endAddress").cloned().unwrap_or(Value::Null);
    let cidr = body.get("cidr0_cidrs").cloned().unwrap_or(Value::Null);
    let mut org = Value::Null;
    let mut abuse = Value::Null;
    if let Some(ents) = body.get("entities").and_then(|v| v.as_array()) {
        for e in ents {
            let roles: Vec<String> = e.get("roles").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if roles.iter().any(|r| r == "registrant" || r == "administrative") {
                if let Some(n) = vcard_name(e) { org = Value::String(n); }
            }
            if roles.iter().any(|r| r == "abuse") {
                if let Some(em) = vcard_email(e) { abuse = Value::String(em); }
            }
        }
    }
    serde_json::json!({
        "handle": handle,
        "name": name,
        "org": org,
        "country": country,
        "start_address": start,
        "end_address": end,
        "cidr": cidr,
        "abuse_email": abuse,
    })
}

fn vcard_name(entity: &Value) -> Option<String> {
    let arr = entity.get("vcardArray")?.as_array()?;
    let items = arr.get(1)?.as_array()?;
    for item in items {
        let parts = item.as_array()?;
        if parts.get(0)?.as_str()? == "fn" {
            return parts.get(3)?.as_str().map(String::from);
        }
    }
    None
}

fn vcard_email(entity: &Value) -> Option<String> {
    let arr = entity.get("vcardArray")?.as_array()?;
    let items = arr.get(1)?.as_array()?;
    for item in items {
        let parts = item.as_array()?;
        if parts.get(0)?.as_str()? == "email" {
            return parts.get(3)?.as_str().map(String::from);
        }
    }
    None
}
