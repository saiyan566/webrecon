use crate::ui;
use anyhow::Result;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use webrecon_portscan::scan::{discover_alive, scan_host, ScanOpts};
use webrecon_portscan::ports::parse_spec;
use webrecon_http::{probe_many, ProbeOpts};

pub async fn run(
    target: &str,
    probe_ports_spec: &str,
    connect_timeout_ms: u64,
    concurrency: usize,
    max_hosts: usize,
    full_scan: bool,
    scan_ports_spec: &str,
    scan_concurrency: usize,
    scan_timeout_ms: u64,
    no_banner: bool,
    do_http_probe: bool,
    as_json: bool,
) -> Result<()> {
    let probe_ports = parse_spec(probe_ports_spec)?;
    let ips = expand(target, max_hosts)?;

    if !as_json {
        ui::info(&format!(
            "probing {} host(s) on {} port(s) — timeout {}ms, concurrency {}",
            ips.len(), probe_ports.len(), connect_timeout_ms, concurrency
        ));
    }

    let pb = if !as_json {
        Some(ui::spinner(&format!("alive sweep — {} IPs", ips.len())))
    } else { None };

    let started = std::time::Instant::now();
    let alive = discover_alive(
        ips.clone(),
        probe_ports.clone(),
        concurrency,
        Duration::from_millis(connect_timeout_ms),
    ).await;
    let elapsed = started.elapsed();

    if let Some(pb) = pb { pb.finish_and_clear(); }

    // Optional phase 2: full port scan against every alive host.
    let full_results = if full_scan && !alive.is_empty() {
        let scan_ports = parse_spec(scan_ports_spec)?;
        if !as_json {
            ui::info(&format!(
                "full scan — {} host(s) × {} port(s), concurrency {}, timeout {}ms  (~{})",
                alive.len(), scan_ports.len(), scan_concurrency, scan_timeout_ms,
                eta_hint(alive.len(), scan_ports.len(), scan_concurrency, scan_timeout_ms)
            ));
        }
        let opts = ScanOpts {
            concurrency: scan_concurrency,
            connect_timeout: Duration::from_millis(scan_timeout_ms),
            do_banner: !no_banner,
        };
        let mut out = Vec::new();
        for (ip, _) in &alive {
            let pb = if !as_json {
                Some(ui::spinner(&format!("scanning {} ({} ports)", ip, scan_ports.len())))
            } else { None };
            let open = scan_host(&ip.to_string(), *ip, &scan_ports, &opts).await;
            if let Some(pb) = pb { pb.finish_and_clear(); }
            out.push((*ip, open));
        }
        Some(out)
    } else { None };

    if as_json {
        ui::print_json(&serde_json::json!({
            "target": target,
            "probed": ips.len(),
            "alive_count": alive.len(),
            "elapsed_ms": elapsed.as_millis(),
            "alive": alive.iter().map(|(ip, ports)| serde_json::json!({
                "ip": ip.to_string(),
                "ports": ports,
            })).collect::<Vec<_>>(),
            "full_scan": full_results.as_ref().map(|rs| rs.iter().map(|(ip, open)| serde_json::json!({
                "ip": ip.to_string(),
                "open": open,
            })).collect::<Vec<_>>()),
        }));
        return Ok(());
    }

    ui::section(&format!("Alive sweep — {target}"));
    ui::kv("probed", &ips.len().to_string());
    ui::kv("alive", &alive.len().to_string());
    ui::kv("elapsed", &format!("{:.2}s", elapsed.as_secs_f64()));
    if !alive.is_empty() {
        ui::section("Live hosts");
        for (ip, ports) in &alive {
            let plist: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            ui::list_item(&format!("{:<16}  [{}]", ip.to_string(), plist.join(",")));
        }
    } else {
        ui::info("no hosts responded on any probe port. Common causes:");
        ui::list_item("range is residential/firewalled ISP space (inbound SYN dropped) — try a known hosting CIDR like 34.190.208.0/24");
        ui::list_item("timeout too tight — retry with --connect-timeout 2500");
        ui::list_item("services on non-default ports — retry with --probe-ports 80,443,22,25,53,110,143,445,993,995,1723,3306,3389,5432,5900,8080,8443");
        ui::list_item("egress from your host is blocked (corporate/VPN filter) — test connectivity: `curl -v https://1.1.1.1`");
    }

    if let Some(rs) = &full_results {
        ui::section("Full scan — alive hosts");
        for (ip, open) in rs {
            ui::kv(&ip.to_string(), &format!("{} open", open.len()));
            for p in open {
                let svc = p.service.as_deref().unwrap_or("?");
                let mut line = format!("  {:>5}/tcp  {}", p.port, svc);
                if let Some(b) = &p.banner { line.push_str(&format!("  {}", b)); }
                ui::list_item(&line);
            }
        }
    }

    // Optional phase 3: HTTP fingerprint every open port on every alive host.
    if do_http_probe {
        let source_ports: Vec<(IpAddr, u16)> = match &full_results {
            Some(rs) => rs.iter().flat_map(|(ip, open)| open.iter().map(move |p| (*ip, p.port))).collect(),
            None => alive.iter().flat_map(|(ip, ports)| ports.iter().map(move |p| (*ip, *p))).collect(),
        };
        if !source_ports.is_empty() {
            let inputs: Vec<String> = source_ports.iter().map(|(ip, p)| format!("{}:{}", ip, p)).collect();
            if !as_json {
                ui::info(&format!("http probe — {} endpoint(s)", inputs.len()));
            }
            let http_opts = ProbeOpts { timeout: Duration::from_secs(8), ..Default::default() };
            let http_results = probe_many(inputs, 100, http_opts).await;
            if !as_json {
                ui::section("HTTP fingerprint");
                ui::kv("responded", &http_results.len().to_string());
                for r in &http_results {
                    let title = r.title.clone().unwrap_or_default();
                    let cdn = r.cdn.clone().map(|c| format!(" cdn={c}")).unwrap_or_default();
                    let server = r.server.clone().map(|s| format!(" server={s}")).unwrap_or_default();
                    let tech = if r.tech.is_empty() { String::new() } else { format!(" tech=[{}]", r.tech.join(",")) };
                    let title_s = if title.is_empty() { String::new() } else {
                        let t: String = title.chars().take(70).collect();
                        format!(" — {t}")
                    };
                    ui::list_item(&format!("{:<3} {}{}{}{}{}", r.status, r.url, server, cdn, tech, title_s));
                }
            }
        }
    }
    Ok(())
}

fn eta_hint(hosts: usize, ports: usize, concurrency: usize, timeout_ms: u64) -> String {
    let per_host_ms = (ports.max(1) as u64 * timeout_ms) / concurrency.max(1) as u64;
    let total_s = (hosts as u64 * per_host_ms) / 1000;
    if total_s < 60 { format!("~{}s worst-case", total_s) }
    else if total_s < 3600 { format!("~{}m worst-case", total_s / 60) }
    else { format!("~{:.1}h worst-case", total_s as f64 / 3600.0) }
}

fn expand(target: &str, max_hosts: usize) -> Result<Vec<IpAddr>> {
    if target.contains('/') {
        let net = ipnet::IpNet::from_str(target)
            .map_err(|e| anyhow::anyhow!("bad CIDR {target}: {e}"))?;
        let hosts: Vec<IpAddr> = net.hosts().take(max_hosts + 1).collect();
        if hosts.len() > max_hosts {
            anyhow::bail!("CIDR expands to >{} hosts; raise --max-hosts or narrow the range", max_hosts);
        }
        return Ok(hosts);
    }
    let ip = IpAddr::from_str(target).map_err(|e| anyhow::anyhow!("not an IP/CIDR: {e}"))?;
    Ok(vec![ip])
}
