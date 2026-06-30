use futures::stream::{FuturesUnordered, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::banner;
use crate::ports::service_name;

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenPort {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub service: Option<String>,
    pub banner: Option<String>,
}

pub struct ScanOpts {
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub do_banner: bool,
}

pub async fn scan_host(
    host: &str,
    ip: IpAddr,
    ports: &[u16],
    opts: &ScanOpts,
) -> Vec<OpenPort> {
    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = FuturesUnordered::new();

    for &port in ports {
        let sem = sem.clone();
        let host_s = host.to_string();
        let ip_s = ip.to_string();
        let to = opts.connect_timeout;
        let grab_banner = opts.do_banner;
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let addr = format!("{}:{}", ip_s, port);
            match timeout(to, TcpStream::connect(&addr)).await {
                Ok(Ok(_stream)) => {
                    let banner = if grab_banner {
                        banner::grab(&ip_s, port).await
                    } else { None };
                    Some(OpenPort {
                        host: host_s,
                        ip: ip_s,
                        port,
                        service: service_name(port).map(String::from),
                        banner,
                    })
                }
                _ => None,
            }
        }));
    }

    let mut out = Vec::new();
    while let Some(r) = tasks.next().await {
        if let Ok(Some(op)) = r { out.push(op); }
    }
    out.sort_by_key(|p| p.port);
    out
}
