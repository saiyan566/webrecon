use crate::ui;
use anyhow::Result;
use serde_json::Value;
use webrecon_core::Config;
use webrecon_ipintel::{abuseipdb as abuse_mod, greynoise as gn_mod, http_client, ipinfo as ipinfo_mod};

#[derive(Debug)]
enum Outcome {
    Hit(Value),
    Missing,           // no API key configured
    Err(String),       // network/parse error
}

pub async fn run(ip: &str, max_age: u32, timeout: u64, as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let client = http_client(timeout);

    let pb = if !as_json {
        Some(ui::spinner(&format!("ipinfo + greynoise + abuseipdb for {ip}")))
    } else { None };

    let (ipinfo_o, greynoise_o, abuse_o) = tokio::join!(
        async {
            match cfg.keys.ipinfo.as_deref() {
                None => Outcome::Missing,
                Some(k) => match ipinfo_mod::lookup(&client, k, ip).await {
                    Ok(v) => Outcome::Hit(v),
                    Err(e) => Outcome::Err(e.to_string()),
                },
            }
        },
        async {
            match cfg.keys.greynoise.as_deref() {
                None => Outcome::Missing,
                Some(k) => match gn_mod::lookup(&client, k, ip).await {
                    Ok(v) => Outcome::Hit(v),
                    Err(e) => Outcome::Err(e.to_string()),
                },
            }
        },
        async {
            match cfg.keys.abuseipdb.as_deref() {
                None => Outcome::Missing,
                Some(k) => match abuse_mod::lookup(&client, k, ip, max_age).await {
                    Ok(v) => Outcome::Hit(v),
                    Err(e) => Outcome::Err(e.to_string()),
                },
            }
        },
    );

    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&serde_json::json!({
            "ip": ip,
            "ipinfo":    outcome_to_json(&ipinfo_o),
            "greynoise": outcome_to_json(&greynoise_o),
            "abuseipdb": outcome_to_json(&abuse_o),
        }));
        return Ok(());
    }

    render_ipinfo(&ipinfo_o);
    render_greynoise(&greynoise_o);
    render_abuseipdb(&abuse_o);
    Ok(())
}

fn outcome_to_json(o: &Outcome) -> Value {
    match o {
        Outcome::Hit(v) => v.clone(),
        Outcome::Missing => serde_json::json!({"status": "no_key"}),
        Outcome::Err(e) => serde_json::json!({"status": "error", "error": e}),
    }
}

fn render_ipinfo(o: &Outcome) {
    ui::section("IPinfo");
    match o {
        Outcome::Missing => ui::info("no ipinfo key configured (skipped)"),
        Outcome::Err(e) => ui::error(e),
        Outcome::Hit(v) => {
            for key in ["ip","hostname","city","region","country","loc","org","postal","timezone","asn","company","privacy","abuse","domains"] {
                if let Some(val) = v.get(key) {
                    ui::kv(key, &ui::json_str(val));
                }
            }
        }
    }
}

fn render_greynoise(o: &Outcome) {
    ui::section("GreyNoise");
    match o {
        Outcome::Missing => ui::info("no greynoise key configured (skipped)"),
        Outcome::Err(e) => ui::error(e),
        Outcome::Hit(v) => {
            for key in ["ip","noise","riot","classification","name","link","last_seen","message"] {
                if let Some(val) = v.get(key) {
                    ui::kv(key, &ui::json_str(val));
                }
            }
        }
    }
}

fn render_abuseipdb(o: &Outcome) {
    ui::section("AbuseIPDB");
    match o {
        Outcome::Missing => ui::info("no abuseipdb key configured (skipped)"),
        Outcome::Err(e) => ui::error(e),
        Outcome::Hit(v) => {
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
        }
    }
}
