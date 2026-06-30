use crate::ui;
use anyhow::Result;
use std::time::Duration;
use webrecon_portscan::{resolve_targets, scan::{scan_host, ScanOpts}, ports::{parse_spec, TOP_100, TOP_1000}};

pub async fn run(
    target: &str,
    ports_spec: Option<&str>,
    top: u16,
    concurrency: usize,
    connect_timeout_ms: u64,
    no_banner: bool,
    max_hosts: usize,
    as_json: bool,
) -> Result<()> {
    let ports: Vec<u16> = if let Some(spec) = ports_spec {
        parse_spec(spec)?
    } else {
        match top {
            100 => TOP_100.to_vec(),
            1000 => TOP_1000.to_vec(),
            n => anyhow::bail!("--top must be 100 or 1000 (got {n}); use --ports for custom"),
        }
    };

    let targets = resolve_targets(target, max_hosts).await?;
    if !as_json {
        ui::info(&format!("scanning {} host(s) × {} ports", targets.len(), ports.len()));
    }

    let opts = ScanOpts {
        concurrency,
        connect_timeout: Duration::from_millis(connect_timeout_ms),
        do_banner: !no_banner,
    };

    let mut all_results = Vec::new();
    for t in &targets {
        let pb = if !as_json {
            Some(ui::spinner(&format!("scanning {} ({})", t.host, t.ip)))
        } else { None };
        let open = scan_host(&t.host, t.ip, &ports, &opts).await;
        if let Some(pb) = pb { pb.finish_and_clear(); }
        all_results.push((t.clone(), open));
    }

    if as_json {
        let out = serde_json::json!({
            "target": target,
            "ports_scanned": ports.len(),
            "results": all_results.iter().map(|(t, ports)| serde_json::json!({
                "host": t.host,
                "ip": t.ip.to_string(),
                "open": ports,
            })).collect::<Vec<_>>(),
        });
        ui::print_json(&out);
        return Ok(());
    }

    for (t, open) in &all_results {
        ui::section(&format!("Scan — {} ({})", t.host, t.ip));
        ui::kv("open_ports", &open.len().to_string());
        if open.is_empty() { continue; }
        for p in open {
            let svc = p.service.as_deref().unwrap_or("?");
            let mut line = format!("{:>5}/tcp  {}", p.port, svc);
            if let Some(b) = &p.banner {
                line.push_str(&format!("  {}", b));
            }
            ui::list_item(&line);
        }
    }

    Ok(())
}
