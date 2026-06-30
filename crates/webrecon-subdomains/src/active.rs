use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use tokio::sync::Semaphore;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

#[derive(Debug, Clone)]
pub struct ResolvedHost {
    pub host: String,
    pub ips: Vec<String>,
}

pub fn build_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(3);
    opts.attempts = 1;
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

pub async fn brute_force(
    domain: &str,
    words: &[&str],
    concurrency: usize,
) -> Vec<ResolvedHost> {
    let resolver = Arc::new(build_resolver());
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = FuturesUnordered::new();

    for w in words {
        let w = w.trim();
        if w.is_empty() || w.starts_with('#') { continue; }
        let host = format!("{}.{}", w, domain);
        let resolver = resolver.clone();
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let lookup = resolver.lookup_ip(host.as_str()).await.ok()?;
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            if ips.is_empty() { return None; }
            Some(ResolvedHost { host, ips })
        }));
    }

    let mut out = Vec::new();
    while let Some(r) = tasks.next().await {
        if let Ok(Some(rh)) = r {
            out.push(rh);
        }
    }
    out.sort_by(|a, b| a.host.cmp(&b.host));
    out
}
