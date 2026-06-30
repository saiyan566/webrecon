use std::net::IpAddr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use webrecon_core::{Finding, Result, WebreconError};

#[derive(Debug, Clone)]
pub struct AsnRecord {
    pub asn: u32,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
    pub as_name: String,
}

fn resolver() -> Result<TokioAsyncResolver> {
    Ok(TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()))
}

pub async fn lookup_ip(ip: IpAddr) -> Result<Finding> {
    let r = resolver()?;
    let query = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6.octets().iter()
                .flat_map(|b| [format!("{:x}", b >> 4), format!("{:x}", b & 0xf)])
                .collect::<Vec<_>>().into_iter().rev()
                .collect::<Vec<_>>().join(".");
            format!("{}.origin6.asn.cymru.com.", nibbles)
        }
    };
    let txt = r.txt_lookup(query).await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    let first = txt.iter().next()
        .ok_or_else(|| WebreconError::NotFound(format!("no ASN record for {}", ip)))?;
    let raw: String = first.iter()
        .map(|d| String::from_utf8_lossy(d).into_owned())
        .collect::<Vec<_>>().join("");
    let parts: Vec<&str> = raw.split('|').map(|s| s.trim()).collect();
    if parts.len() < 5 {
        return Err(WebreconError::Parse(format!("bad cymru txt: {raw}")));
    }
    let asn: u32 = parts[0].split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
    let prefix = parts[1].to_string();
    let country = parts[2].to_string();
    let registry = parts[3].to_string();
    let allocated = parts[4].to_string();

    let as_name = lookup_asn_name(&r, asn).await.unwrap_or_default();

    let rec = AsnRecord { asn, prefix, country, registry, allocated, as_name };
    Ok(Finding::new("asn.cymru", &ip.to_string(), serde_json::json!({
        "asn": rec.asn,
        "prefix": rec.prefix,
        "country": rec.country,
        "registry": rec.registry,
        "allocated": rec.allocated,
        "as_name": rec.as_name,
    })))
}

pub async fn lookup_asn_name(r: &TokioAsyncResolver, asn: u32) -> Option<String> {
    let q = format!("AS{}.asn.cymru.com.", asn);
    let txt = r.txt_lookup(q).await.ok()?;
    let rec = txt.iter().next()?;
    let raw: String = rec.iter().map(|d| String::from_utf8_lossy(d).into_owned()).collect::<Vec<_>>().join("");
    let parts: Vec<&str> = raw.split('|').map(|s| s.trim()).collect();
    parts.get(4).map(|s| s.to_string())
}
