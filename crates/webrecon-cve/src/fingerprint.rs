/// Lightweight banner fingerprinting → (product, optional version).
/// Designed for the small set of common services webrecon's scanner can grab.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Fingerprint {
    pub product: String,
    pub version: Option<String>,
    pub raw: String,
}

pub fn parse(banner: &str) -> Option<Fingerprint> {
    let raw = banner.trim().to_string();
    if raw.is_empty() { return None; }

    // SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    if let Some(rest) = raw.strip_prefix("SSH-").or_else(|| raw.strip_prefix("ssh-")) {
        // skip protocol version up to '-'
        if let Some(idx) = rest.find('-') {
            let banner = &rest[idx + 1..];
            if let Some((prod, ver)) = split_underscore(banner) {
                return Some(Fingerprint { product: prod, version: Some(ver), raw });
            }
            return Some(Fingerprint { product: banner.split_whitespace().next().unwrap_or(banner).to_lowercase(), version: None, raw });
        }
    }

    // HTTP-style: extract Server header value from `Server: <X>` if present.
    if let Some(server) = extract_server(&raw) {
        return from_server(&server, &raw);
    }

    // Try first whitespace-separated token e.g. "ProFTPD 1.3.5e"
    if let Some(fp) = split_space(&raw) {
        return Some(Fingerprint { product: fp.0, version: Some(fp.1), raw });
    }

    None
}

fn extract_server(raw: &str) -> Option<String> {
    if let Some(idx) = raw.to_lowercase().find("server:") {
        let tail = &raw[idx + "server:".len()..];
        let end = tail.find('|').unwrap_or(tail.len());
        return Some(tail[..end].trim().to_string());
    }
    None
}

fn from_server(server: &str, raw: &str) -> Option<Fingerprint> {
    let server = server.trim();
    // "Apache/2.4.41" or "nginx/1.18.0" or "Microsoft-IIS/10.0"
    if let Some((prod, ver)) = server.split_once('/') {
        let product = normalize_product(prod);
        let version = ver.split_whitespace().next().unwrap_or(ver).to_string();
        return Some(Fingerprint { product, version: Some(version), raw: raw.into() });
    }
    Some(Fingerprint { product: normalize_product(server), version: None, raw: raw.into() })
}

fn split_underscore(s: &str) -> Option<(String, String)> {
    let s = s.split_whitespace().next()?;
    let (a, b) = s.split_once('_')?;
    Some((a.to_lowercase(), b.to_string()))
}

fn split_space(s: &str) -> Option<(String, String)> {
    let mut it = s.split_whitespace();
    let prod = it.next()?.to_lowercase();
    let ver = it.next()?.to_string();
    if ver.chars().next()?.is_ascii_digit() {
        Some((prod, ver))
    } else {
        None
    }
}

fn normalize_product(s: &str) -> String {
    let s = s.to_lowercase();
    if s.contains("microsoft-iis") || s == "iis" { return "iis".into(); }
    if s.contains("apache") { return "apache".into(); }
    if s.contains("nginx") { return "nginx".into(); }
    if s.contains("openssh") { return "openssh".into(); }
    if s.contains("lighttpd") { return "lighttpd".into(); }
    if s.contains("caddy") { return "caddy".into(); }
    if s.contains("envoy") { return "envoy".into(); }
    s
}
