use crate::ui;
use anyhow::Result;
use webrecon_core::{config::config_path, Config};

pub fn run(as_json: bool) -> Result<()> {
    let cfg = Config::load();
    let path = config_path().map(|p| p.display().to_string()).unwrap_or_else(|| "<unknown>".into());

    let entries: Vec<(&str, Option<&String>)> = vec![
        ("shodan", cfg.keys.shodan.as_ref()),
        ("ipinfo", cfg.keys.ipinfo.as_ref()),
        ("pulsedive", cfg.keys.pulsedive.as_ref()),
        ("vulners", cfg.keys.vulners.as_ref()),
        ("intelx", cfg.keys.intelx.as_ref()),
        ("greynoise", cfg.keys.greynoise.as_ref()),
        ("virustotal", cfg.keys.virustotal.as_ref()),
        ("otx", cfg.keys.otx.as_ref()),
        ("nvd", cfg.keys.nvd.as_ref()),
        ("abuseipdb", cfg.keys.abuseipdb.as_ref()),
        ("censys_api_id", cfg.keys.censys_api_id.as_ref()),
        ("censys_api_secret", cfg.keys.censys_api_secret.as_ref()),
    ];

    if as_json {
        let json = serde_json::json!({
            "config_path": path,
            "keys": entries.iter().map(|(k,v)| (*k, v.map(|s| mask(s)).unwrap_or_else(|| "<unset>".into()))).collect::<std::collections::BTreeMap<_,_>>(),
        });
        ui::print_json(&json);
        return Ok(());
    }
    ui::section("Config");
    ui::kv("config_path", &path);
    ui::section("Keys");
    for (k, v) in entries {
        let val = match v {
            Some(s) => mask(s),
            None => "<unset>".into(),
        };
        ui::kv(k, &val);
    }
    Ok(())
}

fn mask(s: &str) -> String {
    if s.len() <= 6 { "set".into() } else { format!("set ({}…{})", &s[..3], &s[s.len()-3..]) }
}
