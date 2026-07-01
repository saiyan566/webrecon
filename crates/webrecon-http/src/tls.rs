//! TLS peer-certificate inspection. Grabs subject / issuer / SAN list / validity
//! window from whatever cert the endpoint presents — cert validity is *not*
//! enforced (recon accepts self-signed, expired, and CN mismatches).
//!
//! Rationale: the biggest single blind spot in probing IPs (vs hostnames) is
//! that most services behind SNI return 403 to raw IPs. The cert SAN list is
//! exactly the missing hostname list, so we grab it before the HTTP request.

use native_tls::TlsConnector as NativeConnector;
use serde::Serialize;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector as AsyncTlsConnector;
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub sni_used: String,
}

/// Handshake, capture peer cert, parse subject/issuer/SAN/validity.
///
/// `sni` is what we advertise in the ClientHello. Passing the target hostname
/// yields the vhost's cert; passing an IP yields the server's *default* cert,
/// which is often more informative for recon (it leaks internal hostnames).
pub async fn fetch(sni: &str, connect_host: &str, port: u16, budget: Duration) -> Option<TlsInfo> {
    let native = NativeConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_sni(true)
        .build()
        .ok()?;
    let connector = AsyncTlsConnector::from(native);

    let addr = format!("{connect_host}:{port}");
    let tcp = timeout(budget, TcpStream::connect(&addr)).await.ok()?.ok()?;
    let stream = timeout(budget, connector.connect(sni, tcp)).await.ok()?.ok()?;
    let cert = stream.get_ref().peer_certificate().ok()??;
    let der = cert.to_der().ok()?;
    parse_der(&der, sni)
}

fn parse_der(der: &[u8], sni: &str) -> Option<TlsInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for g in &san.general_names {
                if let GeneralName::DNSName(d) = g {
                    sans.push(d.to_string());
                }
            }
        }
    }
    sans.sort();
    sans.dedup();
    Some(TlsInfo {
        subject,
        issuer,
        sans,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        sni_used: sni.to_string(),
    })
}
