use crate::ui;
use crate::CveAction;
use anyhow::Result;
use std::time::Duration;
use webrecon_core::Config;
use webrecon_cve::{http_client, nvd, vulners, fingerprint};
use webrecon_portscan::{resolve_targets, scan::{scan_host, ScanOpts}, ports::{parse_spec, TOP_100, TOP_1000}};

pub async fn run(action: &CveAction, timeout: u64, as_json: bool) -> Result<()> {
    let client = http_client(timeout.max(30));
    let cfg = Config::load();
    let nvd_key = cfg.keys.nvd.as_deref();
    let vulners_key = cfg.keys.vulners.as_deref();

    match action {
        CveAction::Id { id } => {
            let pb = if !as_json { Some(ui::spinner(&format!("NVD lookup {id}"))) } else { None };
            let cve = nvd::fetch_by_id(&client, nvd_key, id).await?;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            if as_json { ui::print_json(&serde_json::to_value(&cve)?); return Ok(()); }
            render_one(&cve);
        }
        CveAction::Search { product, version, limit } => {
            let label = format!("{} {}", product, version.clone().unwrap_or_default());
            let pb = if !as_json { Some(ui::spinner(&format!("CVE search {label}"))) } else { None };

            let (source, cves) = lookup_cves(&client, vulners_key, nvd_key, product, version.as_deref(), *limit).await;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            let cves = cves?;

            if as_json {
                ui::print_json(&serde_json::json!({
                    "source": source, "product": product, "version": version,
                    "results": cves,
                }));
                return Ok(());
            }
            ui::section(&format!("CVE search — {label}"));
            ui::kv("source", source);
            ui::kv("results", &cves.len().to_string());
            for c in &cves { render_summary_line(c); }
        }
        CveAction::Scan { target, ports, top, concurrency, connect_timeout, limit } => {
            let port_list = if let Some(spec) = ports {
                parse_spec(spec)?
            } else {
                match top {
                    100 => TOP_100.to_vec(),
                    1000 => TOP_1000.to_vec(),
                    n => anyhow::bail!("--top must be 100 or 1000 (got {n})"),
                }
            };
            let targets = resolve_targets(target, 64).await?;
            let opts = ScanOpts {
                concurrency: *concurrency,
                connect_timeout: Duration::from_millis(*connect_timeout),
                do_banner: true,
            };

            let mut report: Vec<serde_json::Value> = Vec::new();
            for t in &targets {
                let pb = if !as_json { Some(ui::spinner(&format!("scanning {}", t.host))) } else { None };
                let open = scan_host(&t.host, t.ip, &port_list, &opts).await;
                if let Some(pb) = pb { pb.finish_and_clear(); }

                if !as_json {
                    ui::section(&format!("Scan — {} ({})", t.host, t.ip));
                    ui::kv("open_ports", &open.len().to_string());
                }

                let mut services = Vec::new();
                for p in &open {
                    let banner = match &p.banner { Some(b) => b, None => continue };
                    let fp = match fingerprint::parse(banner) { Some(f) => f, None => continue };
                    let label = format!("{} {}", fp.product, fp.version.clone().unwrap_or_default());
                    let pb2 = if !as_json { Some(ui::spinner(&format!("CVE lookup {label}"))) } else { None };
                    let (source, cves) = lookup_cves(&client, vulners_key, nvd_key, &fp.product, fp.version.as_deref(), *limit).await;
                    let cves = cves.unwrap_or_default();
                    if let Some(pb2) = pb2 { pb2.finish_and_clear(); }

                    if !as_json {
                        ui::section(&format!("{}/tcp  {}", p.port, label));
                        ui::kv("banner", banner);
                        ui::kv("source", source);
                        ui::kv("cves", &cves.len().to_string());
                        for c in &cves { render_summary_line(c); }
                    }

                    services.push(serde_json::json!({
                        "port": p.port,
                        "service": p.service,
                        "fingerprint": fp,
                        "cve_source": source,
                        "cves": cves,
                    }));
                }
                report.push(serde_json::json!({
                    "host": t.host,
                    "ip": t.ip.to_string(),
                    "services": services,
                }));
            }

            if as_json {
                ui::print_json(&serde_json::json!({
                    "target": target,
                    "report": report,
                }));
            }
        }
    }
    Ok(())
}

/// Prefer Vulners (when key present and product+version known); fall back to NVD keyword search.
async fn lookup_cves(
    client: &reqwest::Client,
    vulners_key: Option<&str>,
    nvd_key: Option<&str>,
    product: &str,
    version: Option<&str>,
    limit: usize,
) -> (&'static str, Result<Vec<nvd::CveSummary>>) {
    if let (Some(vk), Some(v)) = (vulners_key, version) {
        let r = vulners::audit_software(client, vk, product, v).await
            .map(|mut x| { x.truncate(limit); x })
            .map_err(|e| anyhow::anyhow!(e));
        return ("vulners", r);
    }
    let r = nvd::search(client, nvd_key, product, version, limit).await
        .map_err(|e| anyhow::anyhow!(e));
    ("nvd", r)
}

fn render_one(c: &nvd::CveSummary) {
    ui::section(&format!("CVE — {}", c.id));
    if let Some(s) = c.cvss { ui::kv("cvss", &format!("{:.1}", s)); }
    if let Some(s) = &c.severity { ui::kv("severity", s); }
    if let Some(p) = &c.published { ui::kv("published", p); }
    ui::kv("description", &c.description);
    if !c.references.is_empty() {
        ui::section("References");
        for r in &c.references { ui::list_item(r); }
    }
}

fn render_summary_line(c: &nvd::CveSummary) {
    let sev = c.severity.clone().unwrap_or_else(|| "?".into());
    let score = c.cvss.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "-".into());
    let desc: String = c.description.chars().take(120).collect();
    ui::list_item(&format!("{:<16} [{}|{:<7}] {}", c.id, score, sev, desc));
}
