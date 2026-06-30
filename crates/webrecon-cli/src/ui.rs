use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::{OwoColorize, Stream, Style, set_override};
use serde_json::Value;
use std::time::Duration;

pub fn init(no_color: bool) {
    if no_color {
        set_override(false);
    }
}

pub fn banner() {
    let art = r#"
                _
 __      _____| |__  _ __ ___  ___ ___  _ __
 \ \ /\ / / _ \ '_ \| '__/ _ \/ __/ _ \| '_ \
  \ V  V /  __/ |_) | | |  __/ (_| (_) | | | |
   \_/\_/ \___|_.__/|_|  \___|\___\___/|_| |_|
"#;
    eprintln!("{}", art.if_supports_color(Stream::Stderr, |s| s.bright_cyan()));
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  {} {}\n",
        "personal recon toolkit".if_supports_color(Stream::Stderr, |s| s.bright_white()),
        version.if_supports_color(Stream::Stderr, |s| s.style(Style::new().dimmed())),
    );
}

pub fn section(title: &str) {
    println!();
    println!("{} {}",
        "▸".if_supports_color(Stream::Stdout, |s| s.bright_magenta()),
        title.if_supports_color(Stream::Stdout, |s| s.style(Style::new().bright_white().bold())),
    );
    println!("{}", "─".repeat(60).if_supports_color(Stream::Stdout, |s| s.bright_black()));
}

pub fn kv(key: &str, value: &str) {
    if value.is_empty() || value == "null" {
        return;
    }
    let label = format!("{}:", key);
    println!("  {:<16} {}",
        label.if_supports_color(Stream::Stdout, |s| s.bright_cyan()),
        value,
    );
}

pub fn list_item(value: &str) {
    println!("  {} {}",
        "•".if_supports_color(Stream::Stdout, |s| s.bright_yellow()),
        value,
    );
}

pub fn info(msg: &str) {
    eprintln!("{} {}",
        "[i]".if_supports_color(Stream::Stderr, |s| s.bright_blue()),
        msg,
    );
}

pub fn error(msg: &str) {
    eprintln!("{} {}",
        "[!]".if_supports_color(Stream::Stderr, |s| s.style(Style::new().bright_red().bold())),
        msg,
    );
}

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]),
    );
    pb.set_message(msg.to_string());
    pb
}

pub fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
}

pub fn json_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(arr) => arr.iter()
            .map(|x| match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}
