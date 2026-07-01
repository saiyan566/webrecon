use crate::ui;
use anyhow::Result;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use webrecon_portscan::scan::discover_alive;
use webrecon_portscan::ports::parse_spec;

pub async fn run(
    target: &str,
    probe_ports_spec: &str,
    connect_timeout_ms: u64,
    concurrency: usize,
    max_hosts: usize,
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
    Ok(())
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
