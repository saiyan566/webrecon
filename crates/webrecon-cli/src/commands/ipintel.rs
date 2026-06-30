use crate::ui;
use anyhow::Result;
use webrecon_core::Config;
use webrecon_ipintel::{http_client, ipinfo as ipinfo_mod, greynoise as gn_mod, abuseipdb as abuse_mod};

fn require_key(opt: Option<&str>, name: &str) -> Result<String> {
    opt.map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing {name} key — set keys.{} in ~/.config/webrecon/config.toml or WEBRECON_{} env var", name.to_lowercase(), name.to_uppercase()))
}

pub async fn ipinfo(ip: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.ipinfo.as_deref(), "ipinfo")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("ipinfo {ip}"))) } else { None };
    let v = ipinfo_mod::lookup(&client, &key, ip).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }
    ui::section(&format!("IPinfo — {ip}"));
    for key in ["ip","hostname","city","region","country","loc","org","postal","timezone","asn","company","privacy","abuse","domains"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    Ok(())
}

pub async fn greynoise(ip: &str, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.greynoise.as_deref(), "greynoise")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("greynoise {ip}"))) } else { None };
    let v = gn_mod::lookup(&client, &key, ip).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }
    ui::section(&format!("GreyNoise — {ip}"));
    for key in ["ip","noise","riot","classification","name","link","last_seen","message"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    Ok(())
}

pub async fn abuseipdb(ip: &str, max_age: u32, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let key = require_key(cfg.keys.abuseipdb.as_deref(), "abuseipdb")?;
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("abuseipdb {ip}"))) } else { None };
    let v = abuse_mod::lookup(&client, &key, ip, max_age).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    if as_json { ui::print_json(&v); return Ok(()); }
    ui::section(&format!("AbuseIPDB — {ip}"));
    for key in ["ipAddress","isPublic","ipVersion","isWhitelisted","abuseConfidenceScore","countryCode","usageType","isp","domain","hostnames","totalReports","numDistinctUsers","lastReportedAt"] {
        if let Some(val) = v.get(key) {
            ui::kv(key, &ui::json_str(val));
        }
    }
    if let Some(reports) = v.get("reports").and_then(|r| r.as_array()) {
        if !reports.is_empty() {
            ui::section("Recent reports");
            for r in reports.iter().take(5) {
                if let Some(c) = r.get("comment").and_then(|x| x.as_str()) {
                    let line: String = c.chars().take(160).collect();
                    ui::list_item(&line);
                }
            }
        }
    }
    Ok(())
}
