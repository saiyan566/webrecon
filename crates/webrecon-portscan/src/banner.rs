use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const READ_LIMIT: usize = 1024;
const BANNER_TIMEOUT: Duration = Duration::from_millis(2500);

/// Best-effort banner grab. Returns a short, single-line UTF-8 banner if any.
pub async fn grab(host: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = timeout(BANNER_TIMEOUT, TcpStream::connect(&addr)).await.ok()?.ok()?;

    let is_http = matches!(port, 80 | 81 | 591 | 2080 | 2480 | 3000 | 4567 | 5000 | 5104 | 5800 | 8000 | 8008 | 8009 | 8080 | 8081 | 8088 | 8090 | 8888 | 9000 | 9080 | 9090 | 9200 | 9981);
    if is_http {
        let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: webrecon\r\nConnection: close\r\n\r\n", host);
        let _ = timeout(BANNER_TIMEOUT, stream.write_all(req.as_bytes())).await;
    }

    let mut buf = vec![0u8; READ_LIMIT];
    let n = timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 { return None; }
    buf.truncate(n);

    let text = String::from_utf8_lossy(&buf);
    if is_http {
        return Some(http_summary(&text));
    }
    let first_line = text.lines().next().unwrap_or("").trim().to_string();
    if first_line.is_empty() { return None; }
    Some(truncate(&first_line, 160))
}

fn http_summary(raw: &str) -> String {
    let mut server = None;
    let mut status_line = String::new();
    for (i, line) in raw.lines().enumerate() {
        if i == 0 { status_line = line.trim().to_string(); }
        if let Some(v) = line.strip_prefix("Server:").or_else(|| line.strip_prefix("server:")) {
            server = Some(v.trim().to_string());
        }
        if line.is_empty() { break; }
    }
    let mut parts = Vec::new();
    if !status_line.is_empty() { parts.push(status_line); }
    if let Some(s) = server { parts.push(format!("Server: {s}")); }
    truncate(&parts.join(" | "), 200)
}

fn truncate(s: &str, n: usize) -> String {
    let cleaned: String = s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= n {
        cleaned
    } else {
        let head: String = cleaned.chars().take(n).collect();
        format!("{}…", head)
    }
}
