use crate::ui;
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use webrecon_core::{Config, Finding, Target};
use webrecon_whois::{bgpview, cymru, http_client};
use webrecon_subdomains::{dedupe, http_client as subs_client, passive as sub_passive};

pub async fn run(
    target: &str,
    do_search: bool,
    do_deep: bool,
    concurrency: usize,
    timeout: u64,
    as_json: bool,
) -> Result<()> {
    if do_search {
        return bgpview_search(target, timeout, as_json).await;
    }
    if do_deep {
        return deep_sweep(target, concurrency, timeout, as_json).await;
    }
    classic(target, as_json).await
}

async fn classic(target: &str, as_json: bool) -> Result<()> {
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

async fn bgpview_search(query: &str, timeout: u64, as_json: bool) -> Result<()> {
    let client = http_client(timeout.max(30));
    let pb = if !as_json { Some(ui::spinner(&format!("BGPView search: {query}"))) } else { None };
    let data = bgpview::search(&client, query).await?;
    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&data);
        return Ok(());
    }

    let asns = data.get("asns").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let v4 = data.get("ipv4_prefixes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let v6 = data.get("ipv6_prefixes").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    ui::section(&format!("BGPView search — \"{query}\""));
    ui::kv("asns_matched", &asns.len().to_string());
    ui::kv("ipv4_prefixes_matched", &v4.len().to_string());
    ui::kv("ipv6_prefixes_matched", &v6.len().to_string());

    if !asns.is_empty() {
        ui::section("ASNs");
        for a in asns.iter().take(50) {
            let n = a.get("asn").and_then(|x| x.as_u64()).unwrap_or(0);
            let name = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let desc = a.get("description").and_then(|x| x.as_str()).unwrap_or("");
            let cc = a.get("country_code").and_then(|x| x.as_str()).unwrap_or("");
            ui::list_item(&format!("AS{:<8} [{:<2}] {:<30} {}", n, cc, name, desc));
        }
        if asns.len() > 50 {
            ui::info(&format!("(+{} more ASNs in --json)", asns.len() - 50));
        }
    }
    if !v4.is_empty() {
        ui::section("Sample IPv4 prefixes");
        for p in v4.iter().take(15) {
            let pfx = p.get("prefix").and_then(|x| x.as_str()).unwrap_or("");
            let name = p.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let asn = p.get("parent_asn").and_then(|x| x.as_u64());
            let asn_s = asn.map(|n| format!("AS{n}")).unwrap_or_default();
            ui::list_item(&format!("{:<22} {:<10} {}", pfx, asn_s, name));
        }
    }
    Ok(())
}

async fn deep_sweep(target: &str, concurrency: usize, timeout: u64, as_json: bool) -> Result<()> {
    let domain = match Target::parse(target) {
        Ok(Target::Domain(d)) => d,
        Ok(_) => anyhow::bail!("--deep needs a domain (e.g. google.com), not an IP/ASN/CIDR"),
        Err(_) => anyhow::bail!("--deep needs a full domain like 'google.com', not just '{target}'. Add the TLD."),
    };
    let cfg = Config::load();

    // 1) Subdomain passive enum
    let pb = if !as_json { Some(ui::spinner(&format!("passive subs for {}", domain))) } else { None };
    let http = subs_client(timeout.max(60));
    let results = sub_passive::run_all(&http, &domain, &cfg.keys).await;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    let mut hosts: Vec<String> = results.iter().flat_map(|r| r.hosts.clone()).collect();
    hosts.push(domain.clone());
    let hosts = dedupe(&domain, hosts);

    if !as_json {
        ui::info(&format!("collected {} subdomains; resolving + ASN mapping", hosts.len()));
    }

    // 2) Concurrent DNS resolve
    let resolver = Arc::new(TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = FuturesUnordered::new();
    for h in &hosts {
        let resolver = resolver.clone();
        let sem = sem.clone();
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let r = resolver.lookup_ip(h.as_str()).await.ok()?;
            let ips: Vec<IpAddr> = r.iter().collect();
            if ips.is_empty() { None } else { Some((h, ips)) }
        }));
    }
    let mut all_ips: BTreeMap<IpAddr, Vec<String>> = BTreeMap::new();
    while let Some(r) = tasks.next().await {
        if let Ok(Some((h, ips))) = r {
            for ip in ips { all_ips.entry(ip).or_default().push(h.clone()); }
        }
    }

    if !as_json {
        ui::info(&format!("resolved {} unique IPs; querying Cymru", all_ips.len()));
    }

    // 3) Cymru ASN lookup per IP (concurrent)
    let sem = Arc::new(Semaphore::new(20)); // be polite to Cymru DNS
    let mut tasks = FuturesUnordered::new();
    for ip in all_ips.keys().copied() {
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            cymru::lookup_ip(ip).await.ok().map(|f| (ip, f.data))
        }));
    }

    #[derive(Default, Clone)]
    struct AsnAgg { name: String, country: String, ips: Vec<IpAddr> }
    let mut by_asn: BTreeMap<u64, AsnAgg> = BTreeMap::new();

    while let Some(r) = tasks.next().await {
        if let Ok(Some((ip, data))) = r {
            let n = data.get("asn").and_then(|v| v.as_u64()).unwrap_or(0);
            if n == 0 { continue; }
            let entry = by_asn.entry(n).or_default();
            if entry.name.is_empty() {
                entry.name = data.get("as_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                entry.country = data.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string();
            }
            entry.ips.push(ip);
        }
    }

    if as_json {
        ui::print_json(&serde_json::json!({
            "domain": domain,
            "subdomain_count": hosts.len(),
            "unique_ips": all_ips.len(),
            "asns": by_asn.iter().map(|(n, a)| serde_json::json!({
                "asn": n, "as_name": a.name, "country": a.country, "ip_count": a.ips.len(),
                "ips": a.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    ui::section(&format!("Deep ASN sweep — {}", domain));
    ui::kv("subdomains_seen", &hosts.len().to_string());
    ui::kv("unique_ips", &all_ips.len().to_string());
    ui::kv("unique_asns", &by_asn.len().to_string());

    ui::section("ASNs (sorted by IP count)");
    let mut rows: Vec<(u64, AsnAgg)> = by_asn.into_iter().collect();
    rows.sort_by(|a, b| b.1.ips.len().cmp(&a.1.ips.len()));
    for (n, a) in &rows {
        ui::list_item(&format!(
            "AS{:<8} [{:<2}] {:<3} IPs  {}",
            n, a.country, a.ips.len(), a.name
        ));
    }
    Ok(())
}
