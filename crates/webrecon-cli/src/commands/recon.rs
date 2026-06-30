use crate::ui;
use anyhow::Result;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use webrecon_core::{Config, Target};
use webrecon_whois::{http_client as whois_client, rdap, cymru, ripestat};
use webrecon_subdomains::{passive as sub_passive, dedupe, http_client as subs_client};
use webrecon_intel::{http_client as intel_client, shodan as shodan_mod, vt as vt_mod};
use webrecon_ipintel::{http_client as ip_client, ipinfo as ipinfo_mod, greynoise as gn_mod, abuseipdb as abuse_mod};
use webrecon_portscan::{scan::{scan_host, ScanOpts}, ports::TOP_100, ports::TOP_1000};
use webrecon_cve::{http_client as cve_client, nvd, vulners, fingerprint};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    target: &str,
    do_scan: bool,
    do_cve: bool,
    no_subs: bool,
    no_shodan: bool,
    no_vt: bool,
    no_ipinfo: bool,
    top: u16,
    timeout: u64,
    as_json: bool,
) -> Result<()> {
    let t = Target::parse(target)?;
    let cfg = Config::load();
    let mut report = serde_json::Map::new();
    report.insert("target".into(), Value::String(target.into()));

    if !as_json { banner_header(target); }

    // Resolve to (apex_domain_or_none, primary_ip)
    let (apex, primary_ip) = resolve(&t).await?;
    if !as_json {
        ui::section("Target");
        if let Some(d) = &apex { ui::kv("domain", d); }
        ui::kv("primary_ip", &primary_ip.to_string());
    }
    report.insert("primary_ip".into(), Value::String(primary_ip.to_string()));
    if let Some(d) = &apex { report.insert("apex".into(), Value::String(d.clone())); }

    // ── WHOIS / RDAP ───────────────────────────────────────────────
    let whois_http = whois_client(timeout);
    let whois_val: Value = if let Some(d) = &apex {
        spin_or_silent(as_json, &format!("whois {d}"), async {
            rdap::lookup_domain(&whois_http, d).await
        }).await.map(|f| f.data).unwrap_or(Value::Null)
    } else {
        spin_or_silent(as_json, &format!("whois {primary_ip}"), async {
            rdap::lookup_ip(&whois_http, &primary_ip.to_string()).await
        }).await.map(|f| f.data).unwrap_or(Value::Null)
    };
    render_section_kv(as_json, "WHOIS / RDAP", &whois_val, &["handle","domain","registrar","org","country","abuse_email"]);
    report.insert("whois".into(), whois_val);

    // ── ASN + CIDR ─────────────────────────────────────────────────
    let asn_finding = spin_or_silent(as_json, &format!("asn {primary_ip}"), async {
        cymru::lookup_ip(primary_ip).await
    }).await;
    let asn_num: Option<u32> = asn_finding.as_ref()
        .and_then(|f| f.data.get("asn").and_then(|v| v.as_u64()).map(|n| n as u32));
    let asn_val = asn_finding.map(|f| f.data).unwrap_or(Value::Null);
    render_section_kv(as_json, "ASN", &asn_val, &["asn","as_name","prefix","country","registry"]);
    report.insert("asn".into(), asn_val);

    if let Some(n) = asn_num {
        let cidr = spin_or_silent(as_json, &format!("cidr AS{n}"), async {
            ripestat::announced_prefixes(&whois_http, n).await
        }).await.map(|f| f.data).unwrap_or(Value::Null);
        if !as_json {
            ui::section(&format!("CIDR — AS{n}"));
            if let Some(c) = cidr.get("ipv4_count") { ui::kv("ipv4_count", &ui::json_str(c)); }
            if let Some(c) = cidr.get("ipv6_count") { ui::kv("ipv6_count", &ui::json_str(c)); }
            if let Some(arr) = cidr.get("prefixes").and_then(|v| v.as_array()) {
                let preview: Vec<&str> = arr.iter().take(10).filter_map(|p| p.as_str()).collect();
                if !preview.is_empty() {
                    ui::section(&format!("Prefixes (first {} of {})", preview.len(), arr.len()));
                    for p in preview { ui::list_item(p); }
                    if arr.len() > 10 {
                        ui::info(&format!("(+{} more, use `webrecon cidr AS{}` for full list)", arr.len() - 10, n));
                    }
                }
            }
        }
        report.insert("cidr".into(), cidr);
    }

    // ── Subdomains (passive only — fast) ───────────────────────────
    if !no_subs {
        if let Some(d) = &apex {
            let subs_http = subs_client(timeout.max(60));
            let pb = if !as_json { Some(ui::spinner(&format!("subdomains {d}"))) } else { None };
            let results = sub_passive::run_all(&subs_http, d, &cfg.keys).await;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            let all: Vec<String> = results.iter().flat_map(|r| r.hosts.clone()).collect();
            let merged = dedupe(d, all);
            if !as_json {
                ui::section(&format!("Subdomains — {d}"));
                ui::kv("total_unique", &merged.len().to_string());
                for r in &results {
                    let line = match &r.error {
                        Some(e) => format!("{} (err: {})", r.hosts.len(), e),
                        None => r.hosts.len().to_string(),
                    };
                    ui::kv(r.source, &line);
                }
                let preview = merged.iter().take(20).cloned().collect::<Vec<_>>();
                if !preview.is_empty() {
                    ui::section("First 20 hosts");
                    for h in preview { ui::list_item(&h); }
                    if merged.len() > 20 { ui::info(&format!("(+{} more, use `webrecon subs {}` for full list)", merged.len() - 20, d)); }
                }
            }
            report.insert("subdomains".into(), json!({
                "total_unique": merged.len(),
                "hosts": merged,
                "sources": results.iter().map(|r| json!({"source": r.source, "count": r.hosts.len(), "error": r.error})).collect::<Vec<_>>(),
            }));
        } else if !as_json {
            ui::info("subdomains skipped: target is not a domain");
        }
    }

    // ── IPinfo + GreyNoise + AbuseIPDB (parallel) ──────────────────
    if !no_ipinfo {
        let ip_http = ip_client(timeout);
        let ip_str = primary_ip.to_string();
        let pb = if !as_json { Some(ui::spinner(&format!("ipinfo+greynoise+abuseipdb {ip_str}"))) } else { None };
        let (info_r, gn_r, ab_r) = tokio::join!(
            async {
                match cfg.keys.ipinfo.as_deref() {
                    Some(k) => ipinfo_mod::lookup(&ip_http, k, &ip_str).await.ok(),
                    None => None,
                }
            },
            async {
                match cfg.keys.greynoise.as_deref() {
                    Some(k) => gn_mod::lookup(&ip_http, k, &ip_str).await.ok(),
                    None => None,
                }
            },
            async {
                match cfg.keys.abuseipdb.as_deref() {
                    Some(k) => abuse_mod::lookup(&ip_http, k, &ip_str, 90).await.ok(),
                    None => None,
                }
            },
        );
        if let Some(pb) = pb { pb.finish_and_clear(); }
        if let Some(v) = &info_r { render_section_kv(as_json, "IPinfo", v, &["ip","hostname","city","country","org","asn"]); }
        if let Some(v) = &gn_r { render_section_kv(as_json, "GreyNoise", v, &["ip","noise","riot","classification","name","last_seen"]); }
        if let Some(v) = &ab_r { render_section_kv(as_json, "AbuseIPDB", v, &["abuseConfidenceScore","totalReports","lastReportedAt","isp","usageType","countryCode"]); }
        report.insert("ip_intel".into(), json!({
            "ipinfo": info_r, "greynoise": gn_r, "abuseipdb": ab_r,
        }));
    }

    // ── Shodan ─────────────────────────────────────────────────────
    if !no_shodan {
        let intel_http = intel_client(timeout);
        if let Some(k) = cfg.keys.shodan.as_deref() {
            let pb = if !as_json { Some(ui::spinner(&format!("shodan {primary_ip}"))) } else { None };
            let v = shodan_mod::host(&intel_http, k, &primary_ip.to_string()).await.ok();
            if let Some(pb) = pb { pb.finish_and_clear(); }
            if let Some(v) = &v {
                if !as_json {
                    ui::section("Shodan");
                    for key in ["org","isp","asn","country_name","city","os","tags"] {
                        if let Some(val) = v.get(key) { ui::kv(key, &ui::json_str(val)); }
                    }
                    if let Some(ports) = v.get("ports").and_then(|p| p.as_array()) {
                        let list: Vec<String> = ports.iter().filter_map(|p| p.as_u64().map(|n| n.to_string())).collect();
                        ui::kv("ports", &list.join(", "));
                    }
                    if let Some(vulns) = v.get("vulns") {
                        let s = ui::json_str(vulns);
                        if !s.is_empty() { ui::kv("vulns", &s); }
                    }
                }
                report.insert("shodan".into(), v.clone());
            } else if !as_json { ui::info("shodan: no data"); }
        } else if !as_json { ui::info("shodan skipped: no key"); }
    }

    // ── VirusTotal (target itself) ─────────────────────────────────
    if !no_vt {
        if let Some(k) = cfg.keys.virustotal.as_deref() {
            let intel_http = intel_client(timeout);
            let indicator = apex.clone().unwrap_or_else(|| primary_ip.to_string());
            let pb = if !as_json { Some(ui::spinner(&format!("virustotal {indicator}"))) } else { None };
            let v = vt_mod::lookup(&intel_http, k, &indicator).await.ok();
            if let Some(pb) = pb { pb.finish_and_clear(); }
            if let Some(v) = &v {
                if !as_json {
                    ui::section("VirusTotal");
                    let attrs = v.get("attributes").unwrap_or(v);
                    if let Some(stats) = attrs.get("last_analysis_stats") { ui::kv("analysis_stats", &ui::json_str(stats)); }
                    for key in ["reputation","registrar","country","asn","as_owner","tags"] {
                        if let Some(val) = attrs.get(key) { ui::kv(key, &ui::json_str(val)); }
                    }
                }
                report.insert("virustotal".into(), v.clone());
            }
        } else if !as_json { ui::info("virustotal skipped: no key"); }
    }

    // ── Scan + CVE (opt-in) ────────────────────────────────────────
    if do_scan {
        let ports: Vec<u16> = match top {
            100 => TOP_100.to_vec(),
            1000 => TOP_1000.to_vec(),
            _ => TOP_100.to_vec(),
        };
        let opts = ScanOpts {
            concurrency: 500,
            connect_timeout: Duration::from_millis(1500),
            do_banner: true,
        };
        let host_label = apex.clone().unwrap_or_else(|| primary_ip.to_string());
        let pb = if !as_json { Some(ui::spinner(&format!("scan {host_label}"))) } else { None };
        let open = scan_host(&host_label, primary_ip, &ports, &opts).await;
        if let Some(pb) = pb { pb.finish_and_clear(); }

        if !as_json {
            ui::section(&format!("Scan — {host_label} ({primary_ip})"));
            ui::kv("open_ports", &open.len().to_string());
            for p in &open {
                let svc = p.service.as_deref().unwrap_or("?");
                let banner = p.banner.as_deref().unwrap_or("");
                ui::list_item(&format!("{:>5}/tcp  {}  {}", p.port, svc, banner));
            }
        }
        report.insert("scan".into(), serde_json::to_value(&open).unwrap_or(Value::Null));

        if do_cve {
            let cve_http = cve_client(timeout.max(30));
            let mut findings: Vec<Value> = Vec::new();
            for p in &open {
                let banner = match &p.banner { Some(b) => b, None => continue };
                let fp = match fingerprint::parse(banner) { Some(f) => f, None => continue };
                let label = format!("{} {}", fp.product, fp.version.clone().unwrap_or_default());
                let pb2 = if !as_json { Some(ui::spinner(&format!("cve {label}"))) } else { None };
                let cves = if let (Some(vk), Some(ver)) = (cfg.keys.vulners.as_deref(), fp.version.as_deref()) {
                    vulners::audit_software(&cve_http, vk, &fp.product, ver).await
                        .map(|mut x| { x.truncate(5); x }).unwrap_or_default()
                } else {
                    nvd::search(&cve_http, cfg.keys.nvd.as_deref(), &fp.product, fp.version.as_deref(), 5).await.unwrap_or_default()
                };
                if let Some(pb2) = pb2 { pb2.finish_and_clear(); }

                if !as_json {
                    ui::section(&format!("CVEs — {}/tcp {}", p.port, label));
                    for c in &cves {
                        let sev = c.severity.clone().unwrap_or_else(|| "?".into());
                        let score = c.cvss.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "-".into());
                        let desc: String = c.description.chars().take(120).collect();
                        ui::list_item(&format!("{:<16} [{}|{:<7}] {}", c.id, score, sev, desc));
                    }
                }
                findings.push(json!({
                    "port": p.port,
                    "fingerprint": fp,
                    "cves": cves,
                }));
            }
            report.insert("cve".into(), Value::Array(findings));
        }
    }

    if as_json {
        ui::print_json(&Value::Object(report));
    }
    Ok(())
}

async fn resolve(t: &Target) -> Result<(Option<String>, IpAddr)> {
    match t {
        Target::Ip(ip) => Ok((None, *ip)),
        Target::Domain(d) => {
            let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            let resp = r.lookup_ip(d.as_str()).await
                .map_err(|e| anyhow::anyhow!("DNS resolve failed: {e}"))?;
            let ip = resp.iter().next()
                .ok_or_else(|| anyhow::anyhow!("no IPs for {d}"))?;
            Ok((Some(d.clone()), ip))
        }
        Target::Cidr(_) => anyhow::bail!("recon does not accept CIDR; pick one IP"),
        Target::Asn(_) => anyhow::bail!("recon does not accept ASN; use `webrecon cidr` instead"),
    }
}

async fn spin_or_silent<F, T>(as_json: bool, label: &str, fut: F) -> Option<T>
where F: std::future::Future<Output = webrecon_core::Result<T>>,
{
    let pb = if !as_json { Some(ui::spinner(label)) } else { None };
    let r = fut.await;
    if let Some(pb) = pb { pb.finish_and_clear(); }
    r.ok()
}

fn render_section_kv(as_json: bool, title: &str, v: &Value, keys: &[&str]) {
    if as_json { return; }
    ui::section(title);
    for k in keys {
        if let Some(val) = v.get(*k) {
            ui::kv(k, &ui::json_str(val));
        }
    }
}

fn banner_header(target: &str) {
    ui::section(&format!("Recon — {target}"));
}
