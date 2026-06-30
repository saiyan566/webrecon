use crate::ui;
use crate::CveAction;
use anyhow::Result;
use std::time::Duration;
use webrecon_cve::{http_client, nvd, fingerprint};
use webrecon_portscan::{resolve_targets, scan::{scan_host, ScanOpts}, ports::{parse_spec, TOP_100, TOP_1000}};

pub async fn run(action: &CveAction, timeout: u64, as_json: bool) -> Result<()> {
    let client = http_client(timeout.max(30));

    match action {
        CveAction::Id { id } => {
            let pb = if !as_json { Some(ui::spinner(&format!("NVD lookup {id}"))) } else { None };
            let cve = nvd::fetch_by_id(&client, id).await?;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            if as_json { ui::print_json(&serde_json::to_value(&cve)?); return Ok(()); }
            render_one(&cve);
        }
        CveAction::Search { product, version, limit } => {
            let pb = if !as_json {
                Some(ui::spinner(&format!("NVD search {product} {}", version.clone().unwrap_or_default())))
            } else { None };
            let cves = nvd::search(&client, product, version.as_deref(), *limit).await?;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            if as_json { ui::print_json(&serde_json::to_value(&cves)?); return Ok(()); }
            ui::section(&format!("CVE search — {} {}", product, version.clone().unwrap_or_default()));
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
                    let pb2 = if !as_json {
                        Some(ui::spinner(&format!("CVE lookup {} {}", fp.product, fp.version.clone().unwrap_or_default())))
                    } else { None };
                    let cves = nvd::search(&client, &fp.product, fp.version.as_deref(), *limit)
                        .await.unwrap_or_default();
                    if let Some(pb2) = pb2 { pb2.finish_and_clear(); }

                    if !as_json {
                        ui::section(&format!("{}/tcp  {} {}", p.port, fp.product, fp.version.clone().unwrap_or_default()));
                        ui::kv("banner", banner);
                        ui::kv("cves", &cves.len().to_string());
                        for c in &cves { render_summary_line(c); }
                    }

                    services.push(serde_json::json!({
                        "port": p.port,
                        "service": p.service,
                        "fingerprint": fp,
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
