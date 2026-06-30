use crate::ui;
use anyhow::Result;
use std::net::IpAddr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use webrecon_core::{Target, Finding};
use webrecon_whois::cymru;

pub async fn run(target: &str, _timeout: u64, as_json: bool) -> Result<()> {
    let t = Target::parse(target)?;
    let pb = if !as_json { Some(ui::spinner(&format!("ASN lookup for {}", target))) } else { None };

    let findings: Vec<Finding> = match &t {
        Target::Ip(ip) => vec![cymru::lookup_ip(*ip).await?],
        Target::Domain(d) => {
            let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            let resp = r.lookup_ip(d.as_str()).await
                .map_err(|e| anyhow::anyhow!("DNS resolve failed: {e}"))?;
            let ips: Vec<IpAddr> = resp.iter().collect();
            if ips.is_empty() { anyhow::bail!("no IPs resolved for {d}"); }
            let mut out = Vec::new();
            for ip in ips {
                if let Ok(f) = cymru::lookup_ip(ip).await { out.push(f); }
            }
            out
        }
        Target::Asn(n) => {
            let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            let name = cymru::lookup_asn_name(&r, *n).await.unwrap_or_default();
            vec![Finding::new("asn.cymru", &format!("AS{n}"), serde_json::json!({
                "asn": n, "as_name": name,
            }))]
        }
        Target::Cidr(c) => {
            let ip_str = c.split('/').next().unwrap_or(c);
            let ip: IpAddr = ip_str.parse()?;
            vec![cymru::lookup_ip(ip).await?]
        }
    };

    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&serde_json::to_value(&findings)?);
        return Ok(());
    }

    for f in &findings {
        ui::section(&format!("ASN — {}", f.target));
        for key in ["asn","as_name","prefix","country","registry","allocated"] {
            if let Some(v) = f.data.get(key) {
                ui::kv(key, &ui::json_str(v));
            }
        }
    }
    Ok(())
}
