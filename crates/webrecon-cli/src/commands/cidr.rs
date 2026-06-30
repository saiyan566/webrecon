use crate::ui;
use anyhow::Result;
use webrecon_core::Target;
use webrecon_whois::{http_client, ripestat};

pub async fn run(target: &str, timeout: u64, as_json: bool) -> Result<()> {
    let t = Target::parse(target)?;
    let asn = match t {
        Target::Asn(n) => n,
        _ => anyhow::bail!("cidr requires an ASN (e.g. AS15169 or 15169)"),
    };
    let client = http_client(timeout);
    let pb = if !as_json { Some(ui::spinner(&format!("RIPEstat announced prefixes for AS{asn}"))) } else { None };
    let finding = ripestat::announced_prefixes(&client, asn).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&serde_json::to_value(&finding)?);
        return Ok(());
    }

    ui::section(&format!("CIDR — AS{asn}"));
    if let Some(v) = finding.data.get("ipv4_count") { ui::kv("ipv4_count", &ui::json_str(v)); }
    if let Some(v) = finding.data.get("ipv6_count") { ui::kv("ipv6_count", &ui::json_str(v)); }
    if let Some(arr) = finding.data.get("prefixes").and_then(|v| v.as_array()) {
        ui::section("Prefixes");
        for p in arr {
            if let Some(s) = p.as_str() { ui::list_item(s); }
        }
    }
    Ok(())
}
