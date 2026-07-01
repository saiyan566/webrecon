use crate::ui;
use anyhow::Result;
use std::path::Path;
use std::time::Duration;
use webrecon_http::{probe_many, ProbeOpts};

pub async fn run(
    targets: &[String],
    from_file: Option<&Path>,
    concurrency: usize,
    timeout_ms: u64,
    no_follow: bool,
    prefer_http: bool,
    as_json: bool,
) -> Result<()> {
    let mut inputs: Vec<String> = targets.iter().cloned().collect();
    if let Some(path) = from_file {
        let raw = std::fs::read_to_string(path)?;
        for line in raw.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') { continue; }
            inputs.push(t.to_string());
        }
    }
    if inputs.is_empty() {
        anyhow::bail!("no targets — pass hosts on the CLI or use --list <file>");
    }
    inputs.sort();
    inputs.dedup();

    let opts = ProbeOpts {
        timeout: Duration::from_millis(timeout_ms),
        follow_redirects: !no_follow,
        prefer_https: !prefer_http,
        ..Default::default()
    };

    if !as_json {
        ui::info(&format!(
            "probing {} target(s) — concurrency {}, timeout {}ms, {}redirects",
            inputs.len(), concurrency, timeout_ms,
            if no_follow { "no " } else { "" }
        ));
    }
    let pb = if !as_json { Some(ui::spinner("http probe")) } else { None };
    let results = probe_many(inputs.clone(), concurrency, opts).await;
    if let Some(pb) = pb { pb.finish_and_clear(); }

    if as_json {
        ui::print_json(&serde_json::json!({
            "probed": inputs.len(),
            "responded": results.len(),
            "results": results,
        }));
        return Ok(());
    }

    ui::section("HTTP probe");
    ui::kv("probed", &inputs.len().to_string());
    ui::kv("responded", &results.len().to_string());
    if results.is_empty() {
        ui::info("no targets responded on HTTP/HTTPS.");
        return Ok(());
    }
    ui::section("Live endpoints");
    for r in &results {
        let title = r.title.clone().unwrap_or_default();
        let cdn = r.cdn.clone().map(|c| format!(" cdn={c}")).unwrap_or_default();
        let server = r.server.clone().map(|s| format!(" server={s}")).unwrap_or_default();
        let tech = if r.tech.is_empty() { String::new() } else { format!(" tech=[{}]", r.tech.join(",")) };
        let title_s = if title.is_empty() { String::new() } else { format!(" — {}", truncate(&title, 80)) };
        let status_s = if r.status == 0 { "TLS".to_string() } else { r.status.to_string() };
        ui::list_item(&format!(
            "{:<3} {} ({}ms){}{}{}{}",
            status_s, r.url, r.elapsed_ms, server, cdn, tech, title_s
        ));
        if let Some(t) = &r.tls {
            ui::list_item(&format!("     subject: {}", truncate(&t.subject, 100)));
            ui::list_item(&format!("     issuer:  {}", truncate(&t.issuer, 100)));
            if !t.sans.is_empty() {
                let sans_line = if t.sans.len() <= 6 { t.sans.join(", ") } else { format!("{}, … (+{} more)", t.sans[..6].join(", "), t.sans.len() - 6) };
                ui::list_item(&format!("     sans:    {}", sans_line));
            }
            ui::list_item(&format!("     valid:   {} → {}", t.not_before, t.not_after));
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}
