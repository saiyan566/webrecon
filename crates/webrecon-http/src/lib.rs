//! HTTP fingerprinting layer. Modeled on ProjectDiscovery's httpx:
//! probe an endpoint over HTTPS-then-HTTP, follow redirects, capture status,
//! title, server, and a small tech-fingerprint set from headers + body.
//!
//! Kept intentionally small — extend `TECH_PATTERNS` to broaden coverage.

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::redirect::Policy;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub mod tls;
pub use tls::TlsInfo;

#[derive(Debug, Clone, Serialize)]
pub struct HttpProbe {
    pub input: String,
    pub url: String,
    pub scheme: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub title: Option<String>,
    pub tech: Vec<String>,
    pub cdn: Option<String>,
    pub redirect_chain: Vec<String>,
    pub elapsed_ms: u128,
    pub tls: Option<TlsInfo>,
}

#[derive(Debug, Clone)]
pub struct ProbeOpts {
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub user_agent: String,
    pub prefer_https: bool,
}

impl Default for ProbeOpts {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            follow_redirects: true,
            max_redirects: 5,
            user_agent: "Mozilla/5.0 (compatible; webrecon/0.1)".into(),
            prefer_https: true,
        }
    }
}

/// Probe a single input. `input` can be a bare host (`example.com`),
/// host:port, or a full URL. Returns the first scheme that responded.
pub async fn probe(input: &str, opts: &ProbeOpts) -> Option<HttpProbe> {
    let candidates = expand_schemes(input, opts.prefer_https);
    for url in candidates {
        if let Some(p) = probe_url(input, &url, opts).await {
            return Some(p);
        }
    }
    None
}

/// Probe many inputs concurrently.
pub async fn probe_many(inputs: Vec<String>, concurrency: usize, opts: ProbeOpts) -> Vec<HttpProbe> {
    let opts = Arc::new(opts);
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = FuturesUnordered::new();
    for inp in inputs {
        let sem = sem.clone();
        let opts = opts.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            probe(&inp, &opts).await
        }));
    }
    let mut out = Vec::new();
    while let Some(r) = tasks.next().await {
        if let Ok(Some(p)) = r { out.push(p); }
    }
    out.sort_by(|a, b| a.input.cmp(&b.input));
    out
}

fn expand_schemes(input: &str, prefer_https: bool) -> Vec<String> {
    if input.starts_with("http://") || input.starts_with("https://") {
        return vec![input.to_string()];
    }
    // host or host:port
    let (host, explicit_port) = match input.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p.to_string())),
        _ => (input, None),
    };
    let host = host.trim_end_matches('/');
    let mut out = Vec::new();
    let (a, b) = if prefer_https { ("https", "http") } else { ("http", "https") };
    match &explicit_port {
        Some(p) => {
            // If port maps to a well-known scheme, only try that one.
            match p.as_str() {
                "443" | "8443" => out.push(format!("https://{}:{}", host, p)),
                "80" | "8080" | "8000" | "8888" | "3000" => out.push(format!("http://{}:{}", host, p)),
                _ => {
                    out.push(format!("{}://{}:{}", a, host, p));
                    out.push(format!("{}://{}:{}", b, host, p));
                }
            }
        }
        None => {
            out.push(format!("{}://{}", a, host));
            out.push(format!("{}://{}", b, host));
        }
    }
    out
}

async fn probe_url(input: &str, url: &str, opts: &ProbeOpts) -> Option<HttpProbe> {
    // Grab TLS info first for https so we still return SAN/subject even if the
    // HTTP request fails (403 default vhost, TLS-only services, ...).
    let tls = if url.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str()?.to_string();
            let port = parsed.port().unwrap_or(443);
            tls::fetch(&host, &host, port, opts.timeout).await
        } else { None }
    } else { None };

    let policy = if opts.follow_redirects {
        Policy::limited(opts.max_redirects)
    } else {
        Policy::none()
    };
    let client = reqwest::Client::builder()
        .redirect(policy)
        .timeout(opts.timeout)
        .danger_accept_invalid_certs(true) // recon: don't stop on bad certs
        .user_agent(&opts.user_agent)
        .build()
        .ok()?;

    let started = std::time::Instant::now();
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => {
            // HTTP failed but TLS may have succeeded — SAN list alone is valuable.
            if let Some(t) = tls {
                return Some(HttpProbe {
                    input: input.to_string(),
                    url: url.to_string(),
                    scheme: "https".into(),
                    status: 0,
                    content_type: None,
                    content_length: None,
                    server: None,
                    powered_by: None,
                    title: None,
                    tech: vec![],
                    cdn: None,
                    redirect_chain: vec![url.into()],
                    elapsed_ms: started.elapsed().as_millis(),
                    tls: Some(t),
                });
            }
            return None;
        }
    };
    let final_url = resp.url().to_string();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let server = headers.get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok()).map(String::from);
    let powered_by = headers.get("x-powered-by")
        .and_then(|v| v.to_str().ok()).map(String::from);
    let content_type = headers.get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()).map(String::from);
    let content_length = headers.get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok());
    let cdn = detect_cdn(&headers);

    let body_bytes = resp.bytes().await.ok()?;
    let elapsed = started.elapsed().as_millis();
    let body_str = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(65536)]);
    let title = extract_title(&body_str);
    let tech = detect_tech(&headers, &body_str);

    Some(HttpProbe {
        input: input.to_string(),
        url: final_url.clone(),
        scheme: if final_url.starts_with("https") { "https".into() } else { "http".into() },
        status,
        content_type,
        content_length: content_length.or_else(|| Some(body_bytes.len() as u64)),
        server,
        powered_by,
        title,
        tech,
        cdn,
        redirect_chain: if final_url != url { vec![url.into(), final_url] } else { vec![url.into()] },
        elapsed_ms: elapsed,
        tls,
    })
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title>")? + gt;
    let raw = body.get(gt..end)?.trim();
    if raw.is_empty() { return None; }
    Some(html_unescape(raw).chars().take(160).collect())
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", "\"").replace("&#39;", "'").replace("&nbsp;", " ")
}

/// Header-based CDN detection — the fast, reliable subset.
fn detect_cdn(h: &reqwest::header::HeaderMap) -> Option<String> {
    if h.contains_key("cf-ray") || h.get("server").and_then(|v| v.to_str().ok()).map_or(false, |s| s.eq_ignore_ascii_case("cloudflare")) {
        return Some("Cloudflare".into());
    }
    if h.contains_key("x-amz-cf-id") || h.contains_key("x-amz-cf-pop") { return Some("CloudFront".into()); }
    if h.contains_key("x-fastly-request-id") || h.get("server").and_then(|v| v.to_str().ok()).map_or(false, |s| s.contains("Fastly")) { return Some("Fastly".into()); }
    if h.contains_key("x-akamai-request-id") || h.contains_key("akamai-grn") { return Some("Akamai".into()); }
    if h.get("server").and_then(|v| v.to_str().ok()).map_or(false, |s| s.starts_with("AkamaiGHost")) { return Some("Akamai".into()); }
    if h.contains_key("x-vercel-id") { return Some("Vercel".into()); }
    if h.contains_key("x-nf-request-id") { return Some("Netlify".into()); }
    if h.contains_key("x-github-request-id") { return Some("GitHub Pages".into()); }
    if h.contains_key("x-served-by") && h.get("x-served-by").and_then(|v| v.to_str().ok()).map_or(false, |s| s.contains("cache-")) {
        return Some("Fastly/Varnish".into());
    }
    None
}

/// Header + body fingerprints. Cheap regex-free contains checks.
fn detect_tech(h: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let hdr = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    let server = hdr("server").to_lowercase();
    let powered = hdr("x-powered-by").to_lowercase();
    let cookies = hdr("set-cookie").to_lowercase();
    let body_l = body.to_ascii_lowercase();

    let checks: &[(&str, &dyn Fn(&str, &str, &str, &str) -> bool)] = &[
        ("nginx",       &|s,_,_,_| s.contains("nginx")),
        ("Apache",      &|s,_,_,_| s.contains("apache")),
        ("IIS",         &|s,_,_,_| s.contains("microsoft-iis")),
        ("LiteSpeed",   &|s,_,_,_| s.contains("litespeed")),
        ("Caddy",       &|s,_,_,_| s.contains("caddy")),
        ("Tomcat",      &|s,_,_,_| s.contains("tomcat") || s.contains("coyote")),
        ("PHP",         &|_,p,_,_| p.contains("php")),
        ("ASP.NET",     &|_,p,_,_| p.contains("asp.net")),
        ("Express",     &|_,p,_,_| p.contains("express")),
        ("WordPress",   &|_,_,_,b| b.contains("wp-content") || b.contains("/wp-includes/")),
        ("Drupal",      &|_,_,_,b| b.contains("drupal.settings") || b.contains("/sites/default/files")),
        ("Joomla",      &|_,_,_,b| b.contains("/media/jui/") || b.contains("joomla!")),
        ("Grafana",     &|_,_,_,b| b.contains("<title>grafana") || b.contains("grafana_session")),
        ("Kibana",      &|_,_,_,b| b.contains("kbn-name") || b.contains("kibana")),
        ("Jenkins",     &|_,_,c,b| c.contains("jsessionid") && b.contains("jenkins")),
        ("GitLab",      &|_,_,_,b| b.contains("gitlab-static") || b.contains("<meta content=\"gitlab")),
        ("Jira",        &|_,_,_,b| b.contains("jira.webresources") || b.contains("com.atlassian.jira")),
        ("Confluence",  &|_,_,_,b| b.contains("confluence") && b.contains("atlassian")),
        ("phpMyAdmin",  &|_,_,_,b| b.contains("phpmyadmin")),
        ("Next.js",     &|_,_,_,b| b.contains("__next_data__") || b.contains("/_next/static/")),
        ("Nuxt",        &|_,_,_,b| b.contains("__nuxt") || b.contains("/_nuxt/")),
        ("React",       &|_,_,_,b| b.contains("data-reactroot") || b.contains("react-dom")),
        ("Vue.js",      &|_,_,_,b| b.contains("data-v-") || b.contains("vue.js")),
        ("Angular",     &|_,_,_,b| b.contains("ng-version=") || b.contains("ng-app")),
        ("Django",      &|_,_,c,_| c.contains("csrftoken") || c.contains("sessionid=")),
        ("Laravel",     &|_,_,c,_| c.contains("laravel_session") || c.contains("xsrf-token")),
        ("Rails",       &|_,_,c,_| c.contains("_rails_") || c.contains("_session_id=")),
        ("Kubernetes Dashboard", &|_,_,_,b| b.contains("kubernetes dashboard")),
        ("Prometheus",  &|_,_,_,b| b.contains("<title>prometheus")),
        ("Elastic",     &|_,_,_,b| b.contains("elasticsearch") || b.contains("\"cluster_name\"")),
        ("Swagger",     &|_,_,_,b| b.contains("swagger-ui")),
        ("MinIO",       &|_,_,_,b| b.contains("minio")),
        ("Portainer",   &|_,_,_,b| b.contains("portainer")),
    ];
    for (name, f) in checks {
        if f(&server, &powered, &cookies, &body_l) {
            out.push((*name).to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}
