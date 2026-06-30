pub mod ports;
pub mod scan;
pub mod banner;

use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use webrecon_core::{Result, WebreconError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedTarget {
    pub host: String,   // original input (host or ip text)
    pub ip: IpAddr,
}

/// Expand input into resolved targets.
/// - "1.2.3.4" → [Ip]
/// - "example.com" → all resolved A/AAAA, with original host preserved
/// - "10.0.0.0/24" → every host in the subnet
pub async fn resolve_targets(input: &str, max_hosts: usize) -> Result<Vec<ResolvedTarget>> {
    if let Some((_, _)) = input.split_once('/') {
        let net = ipnet::IpNet::from_str(input)
            .map_err(|e| WebreconError::Parse(format!("bad CIDR: {e}")))?;
        let hosts: Vec<IpAddr> = net.hosts().take(max_hosts + 1).collect();
        if hosts.len() > max_hosts {
            return Err(WebreconError::InvalidTarget(format!(
                "CIDR expands to >{} hosts; narrow the range or raise --max-hosts", max_hosts
            )));
        }
        return Ok(hosts.into_iter()
            .map(|ip| ResolvedTarget { host: ip.to_string(), ip })
            .collect());
    }
    if let Ok(ip) = IpAddr::from_str(input) {
        return Ok(vec![ResolvedTarget { host: input.to_string(), ip }]);
    }
    let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let resp = r.lookup_ip(input).await
        .map_err(|e| WebreconError::Network(format!("DNS resolve {input}: {e}")))?;
    let ips: Vec<IpAddr> = resp.iter().collect();
    if ips.is_empty() {
        return Err(WebreconError::NotFound(format!("no IPs for {input}")));
    }
    Ok(ips.into_iter()
        .map(|ip| ResolvedTarget { host: input.to_string(), ip })
        .collect())
}
