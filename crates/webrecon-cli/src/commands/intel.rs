use crate::ui;
use anyhow::Result;
use webrecon_core::Config;
use webrecon_intel::{http_client, shodan as shodan_mod, vt as vt_mod, pulsedive as pulse_mod, intelx as ix_mod, censys as censys_mod, indicator_kind};

fn require_key(opt: Option<&str>, name: &str) -> Result<String> {
    opt.map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing {name} key — set keys.{} in ~/.config/webrecon/config.toml or WEBRECON_{} env var", name.to_lowercase(), name.to_uppercase()))
}

pub async fn shodan(ip: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.shodan.as_deref(), "shodan")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("shodan host {ip}"))) } else { None };
    let v = shodan_mod::host(&client, &key, ip).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }

    ui::section(&format!("Shodan — {ip}"));
    for key in ["ip_str","org","isp","asn","country_name","city","os","hostnames","domains","last_update","tags"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    if let Some(ports) = v.get("ports").and_then(|p| p.as_array()) {
        let list: Vec<String> = ports.iter().filter_map(|p| p.as_u64().map(|n| n.to_string())).collect();
        ui::kv("ports", &list.join(", "));
    }
    if let Some(vulns) = v.get("vulns") {
        let s = ui::json_str(vulns);
        if !s.is_empty() { ui::kv("vulns", &s); }
    }
    if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
        ui::section("Services");
        for svc in data {
            let port = svc.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
            let product = svc.get("product").and_then(|p| p.as_str()).unwrap_or("");
            let version = svc.get("version").and_then(|p| p.as_str()).unwrap_or("");
            let banner: String = svc.get("data").and_then(|b| b.as_str()).unwrap_or("").lines().next().unwrap_or("").chars().take(140).collect();
            ui::list_item(&format!("{:>5}/tcp  {} {}  {}", port, product, version, banner));
        }
    }
    Ok(())
}

pub async fn censys(ip: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let id = require_key(cfg.keys.censys_api_id.as_deref(), "censys_api_id")?;
    let secret = require_key(cfg.keys.censys_api_secret.as_deref(), "censys_api_secret")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("censys host {ip}"))) } else { None };
    let v = censys_mod::host(&client, &id, &secret, ip).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }

    ui::section(&format!("Censys — {ip}"));
    for key in ["ip","last_updated_at","location","autonomous_system","dns","operating_system"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    if let Some(services) = v.get("services").and_then(|s| s.as_array()) {
        ui::section("Services");
        for svc in services {
            let port = svc.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
            let name = svc.get("service_name").and_then(|n| n.as_str()).unwrap_or("?");
            let proto = svc.get("transport_protocol").and_then(|p| p.as_str()).unwrap_or("");
            let product = svc.pointer("/software/0/product").and_then(|p| p.as_str()).unwrap_or("");
            let version = svc.pointer("/software/0/version").and_then(|p| p.as_str()).unwrap_or("");
            ui::list_item(&format!("{:>5}/{}  {}  {} {}", port, proto, name, product, version));
        }
    }
    Ok(())
}

pub async fn vt(indicator: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.virustotal.as_deref(), "virustotal")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("VirusTotal {indicator}"))) } else { None };
    let v = vt_mod::lookup(&client, &key, indicator).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }

    let kind = indicator_kind(indicator);
    ui::section(&format!("VirusTotal — {indicator} ({kind})"));
    let attrs = v.get("attributes").unwrap_or(&v);
    if let Some(stats) = attrs.get("last_analysis_stats") {
        ui::kv("analysis_stats", &ui::json_str(stats));
    }
    for key in ["reputation","whois","registrar","country","asn","as_owner","tld","creation_date","last_modification_date","tags","categories","last_dns_records_date","jarm","total_votes"] {
        if let Some(val) = attrs.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    if let Some(records) = attrs.get("last_dns_records").and_then(|r| r.as_array()) {
        if !records.is_empty() {
            ui::section("DNS records");
            for r in records.iter().take(10) {
                let t = r.get("type").and_then(|x| x.as_str()).unwrap_or("?");
                let val = r.get("value").and_then(|x| x.as_str()).unwrap_or("");
                ui::list_item(&format!("{t:<6} {val}"));
            }
        }
    }
    Ok(())
}

pub async fn pulsedive(indicator: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.pulsedive.as_deref(), "pulsedive")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("Pulsedive {indicator}"))) } else { None };
    let v = pulse_mod::info(&client, &key, indicator).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }

    ui::section(&format!("Pulsedive — {indicator}"));
    for key in ["iid","indicator","type","risk","risk_recommended","manualrisk","stamp_added","stamp_updated","stamp_seen","stamp_retired","submissions"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    if let Some(threats) = v.get("threats").and_then(|t| t.as_array()) {
        if !threats.is_empty() {
            ui::section("Threats");
            for t in threats.iter().take(10) {
                let name = t.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                let cat = t.get("category").and_then(|x| x.as_str()).unwrap_or("");
                ui::list_item(&format!("{name}  [{cat}]"));
            }
        }
    }
    if let Some(feeds) = v.get("feeds").and_then(|f| f.as_array()) {
        if !feeds.is_empty() {
            ui::section("Feeds");
            for f in feeds.iter().take(10) {
                let name = f.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                let org  = f.get("organization").and_then(|x| x.as_str()).unwrap_or("");
                ui::list_item(&format!("{name}  [{org}]"));
            }
        }
    }
    Ok(())
}

pub async fn intelx(term: &str, limit: usize, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.intelx.as_deref(), "intelx")?;
    let client = http_client(timeout.max(30));
    let pb = if !as_json { Some(ui::spinner(&format!("IntelX search {term}"))) } else { None };
    let v = ix_mod::search(&client, &key, term, limit).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }

    ui::section(&format!("IntelX — {term}"));
    ui::kv("count", &ui::json_str(v.get("count").unwrap_or(&serde_json::Value::Null)));
    if let Some(records) = v.get("records").and_then(|r| r.as_array()) {
        ui::section("Records");
        for r in records.iter().take(limit) {
            let name = r.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let date = r.get("date").and_then(|x| x.as_str()).unwrap_or("");
            let bucket = r.get("bucket").and_then(|x| x.as_str()).unwrap_or("");
            let media = r.get("mediah").and_then(|x| x.as_str()).unwrap_or("");
            ui::list_item(&format!("{date}  [{bucket:<14}] {media:<18} {name}"));
        }
    }
    Ok(())
}
