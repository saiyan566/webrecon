use crate::ui;
use anyhow::Result;
use std::path::Path;
use webrecon_core::{Config, Target};
use webrecon_subdomains::{active, passive, dedupe, http_client, DEFAULT_WORDLIST};

pub async fn run(
    target: &str,
    no_passive: bool,
    do_active: bool,
    wordlist_path: Option<&Path>,
    concurrency: usize,
    timeout: u64,
    as_json: bool,
) -> Result<()> {
    let t = Target::parse(target)?;
    let apex = match t {
        Target::Domain(d) => d,
        _ => anyhow::bail!("subs requires a domain (e.g. example.com)"),
    };

    let mut per_source: Vec<(String, usize, Option<String>)> = Vec::new();
    let mut all_hosts: Vec<String> = Vec::new();

    if !no_passive {
        let pb = if !as_json { Some(ui::spinner(&format!("passive enum for {}", apex))) } else { None };
        let client = http_client(timeout);
        let cfg = Config::load();
        let results = passive::run_all(&client, &apex, &cfg.keys).await;
        if let Some(pb) = pb { pb.finish_and_clear(); }
        for r in results {
            per_source.push((r.source.to_string(), r.hosts.len(), r.error.clone()));
            all_hosts.extend(r.hosts);
        }
    }

    let passive_hosts = dedupe(&apex, all_hosts.clone());

    let mut active_resolved: Vec<active::ResolvedHost> = Vec::new();
    if do_active {
        let pb = if !as_json { Some(ui::spinner(&format!("active brute force for {}", apex))) } else { None };
        let wordlist_owned: String = match wordlist_path {
            Some(p) => std::fs::read_to_string(p)?,
            None => DEFAULT_WORDLIST.to_string(),
        };
        let words: Vec<&str> = wordlist_owned.lines().collect();
        active_resolved = active::brute_force(&apex, &words, concurrency).await;
        if let Some(pb) = pb { pb.finish_and_clear(); }
        let active_hosts: Vec<String> = active_resolved.iter().map(|r| r.host.clone()).collect();
        per_source.push(("brute-force".into(), active_hosts.len(), None));
        all_hosts.extend(active_hosts);
    }

    let merged = dedupe(&apex, all_hosts);

    if as_json {
        let out = serde_json::json!({
            "target": apex,
            "sources": per_source.iter().map(|(s,c,e)| serde_json::json!({
                "source": s, "count": c, "error": e
            })).collect::<Vec<_>>(),
            "subdomains": merged,
            "resolved": active_resolved.iter().map(|r| serde_json::json!({
                "host": r.host, "ips": r.ips,
            })).collect::<Vec<_>>(),
        });
        ui::print_json(&out);
        return Ok(());
    }

    ui::section(&format!("Subdomains — {}", apex));
    ui::kv("passive_hosts", &passive_hosts.len().to_string());
    ui::kv("active_hosts", &active_resolved.len().to_string());
    ui::kv("total_unique", &merged.len().to_string());

    ui::section("Sources");
    for (s, c, e) in &per_source {
        let label = format!("{}", s);
        if let Some(err) = e {
            ui::kv(&label, &format!("{} (err: {})", c, err));
        } else {
            ui::kv(&label, &c.to_string());
        }
    }

    if !merged.is_empty() {
        ui::section("Hosts");
        for h in &merged {
            ui::list_item(h);
        }
    }

    if !active_resolved.is_empty() {
        ui::section("Resolved (active)");
        for r in &active_resolved {
            ui::list_item(&format!("{} → {}", r.host, r.ips.join(", ")));
        }
    }

    Ok(())
}
