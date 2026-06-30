use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub keys: Keys,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Keys {
    pub shodan: Option<String>,
    pub ipinfo: Option<String>,
    pub pulsedive: Option<String>,
    pub vulners: Option<String>,
    pub intelx: Option<String>,
    pub greynoise: Option<String>,
    pub virustotal: Option<String>,
    pub otx: Option<String>,
    pub nvd: Option<String>,
    pub abuseipdb: Option<String>,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
}

impl Config {
    /// Load from `~/.config/webrecon/config.toml`, then apply `WEBRECON_*` env overrides.
    /// Missing file is fine — returns defaults.
    pub fn load() -> Self {
        let mut cfg: Config = config_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default();
        cfg.apply_env();
        cfg
    }

    fn apply_env(&mut self) {
        fn pick(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        }
        if let Some(v) = pick("WEBRECON_SHODAN")        { self.keys.shodan = Some(v); }
        if let Some(v) = pick("WEBRECON_IPINFO")        { self.keys.ipinfo = Some(v); }
        if let Some(v) = pick("WEBRECON_PULSEDIVE")     { self.keys.pulsedive = Some(v); }
        if let Some(v) = pick("WEBRECON_VULNERS")       { self.keys.vulners = Some(v); }
        if let Some(v) = pick("WEBRECON_INTELX")        { self.keys.intelx = Some(v); }
        if let Some(v) = pick("WEBRECON_GREYNOISE")     { self.keys.greynoise = Some(v); }
        if let Some(v) = pick("WEBRECON_VIRUSTOTAL")    { self.keys.virustotal = Some(v); }
        if let Some(v) = pick("WEBRECON_OTX")           { self.keys.otx = Some(v); }
        if let Some(v) = pick("WEBRECON_NVD")           { self.keys.nvd = Some(v); }
        if let Some(v) = pick("WEBRECON_ABUSEIPDB")     { self.keys.abuseipdb = Some(v); }
        if let Some(v) = pick("WEBRECON_CENSYS_ID")     { self.keys.censys_api_id = Some(v); }
        if let Some(v) = pick("WEBRECON_CENSYS_SECRET") { self.keys.censys_api_secret = Some(v); }
    }
}

pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("webrecon").join("config.toml"))
}
