use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebreconError {
    #[error("network error: {0}")]
    Network(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WebreconError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Target {
    Domain(String),
    Ip(IpAddr),
    Cidr(String),
    Asn(u32),
}

impl Target {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(WebreconError::InvalidTarget("empty".into()));
        }
        // ASN: "AS15169" or "15169"
        let asn_candidate = s.strip_prefix("AS").or_else(|| s.strip_prefix("as")).unwrap_or(s);
        if !s.contains('.') && !s.contains(':') {
            if let Ok(n) = asn_candidate.parse::<u32>() {
                return Ok(Target::Asn(n));
            }
        }
        // CIDR
        if s.contains('/') {
            if ipnet::IpNet::from_str(s).is_ok() {
                return Ok(Target::Cidr(s.to_string()));
            }
        }
        // IP
        if let Ok(ip) = IpAddr::from_str(s) {
            return Ok(Target::Ip(ip));
        }
        // Domain (loose check)
        if s.contains('.') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
            return Ok(Target::Domain(s.to_lowercase()));
        }
        Err(WebreconError::InvalidTarget(s.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub module: String,
    pub target: String,
    pub data: serde_json::Value,
}

impl Finding {
    pub fn new(module: &str, target: &str, data: serde_json::Value) -> Self {
        Self { module: module.into(), target: target.into(), data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_targets() {
        assert!(matches!(Target::parse("example.com").unwrap(), Target::Domain(_)));
        assert!(matches!(Target::parse("1.1.1.1").unwrap(), Target::Ip(_)));
        assert!(matches!(Target::parse("AS15169").unwrap(), Target::Asn(15169)));
        assert!(matches!(Target::parse("15169").unwrap(), Target::Asn(15169)));
        assert!(matches!(Target::parse("10.0.0.0/8").unwrap(), Target::Cidr(_)));
    }
}
