use crate::ui;
use anyhow::Result;
use webrecon_core::Target;
use webrecon_whois::{http_client, rdap};

pub async fn run(target: &str, timeout: u64, as_json: bool) -> Result<()> {
    let t = Target::parse(target)?;
    let client = http_client(timeout);

    let pb = if !as_json { Some(ui::spinner(&format!("RDAP lookup for {}", target))) } else { None };

    let finding = match &t {
        Target::Domain(d) => rdap::lookup_domain(&client, d).await?,
        Target::Ip(ip) => rdap::lookup_ip(&client, &ip.to_string()).await?,
        Target::Cidr(c) => {
            let ip = c.split('/').next().unwrap_or(c);
            rdap::lookup_ip(&client, ip).await?
        }
        Target::Asn(n) => {
            anyhow::bail!("whois on ASN not supported; try `webrecon asn {}` or `webrecon cidr {}`", n, n);
        }
    };

    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&serde_json::to_value(&finding)?);
        return Ok(());
    }

    ui::section(&format!("WHOIS / RDAP — {}", target));
    let d = &finding.data;
    for key in ["handle","domain","name","org","country","registrar","abuse_email","start_address","end_address","status"] {
        if let Some(v) = d.get(key) {
            ui::kv(key, &ui::json_str(v));
        }
    }
    if let Some(events) = d.get("events").and_then(|v| v.as_object()) {
        if !events.is_empty() {
            ui::section("Events");
            for (k, v) in events {
                ui::kv(k, &ui::json_str(v));
            }
        }
    }
    if let Some(ns) = d.get("nameservers").and_then(|v| v.as_array()) {
        if !ns.is_empty() {
            ui::section("Nameservers");
            for n in ns {
                if let Some(s) = n.as_str() { ui::list_item(s); }
            }
        }
    }
    Ok(())
}
