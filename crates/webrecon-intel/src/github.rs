use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use webrecon_core::{Result, WebreconError};

const API: &str = "https://api.github.com";

fn authed(req: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    let mut r = req
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(t) = token { r = r.bearer_auth(t); }
    r
}

async fn get_json(client: &Client, token: Option<&str>, url: &str) -> Result<Value> {
    let resp = authed(client.get(url), token).send().await
        .map_err(|e| WebreconError::Network(e.to_string()))?;
    let status = resp.status();
    if status.as_u16() == 404 {
        return Err(WebreconError::NotFound(format!("github 404 {url}")));
    }
    if status.as_u16() == 403 {
        return Err(WebreconError::Network("github 403 (rate limited — add a token)".into()));
    }
    if !status.is_success() {
        return Err(WebreconError::Network(format!("github -> {status}")));
    }
    resp.json::<Value>().await.map_err(|e| WebreconError::Parse(e.to_string()))
}

pub async fn user(client: &Client, token: Option<&str>, name: &str) -> Result<Value> {
    get_json(client, token, &format!("{API}/users/{name}")).await
}

pub async fn repos(client: &Client, token: Option<&str>, name: &str, limit: usize) -> Result<Vec<Value>> {
    let per = limit.min(100).max(1);
    let url = format!("{API}/users/{name}/repos?per_page={per}&sort=updated");
    let v = get_json(client, token, &url).await?;
    Ok(v.as_array().cloned().unwrap_or_default())
}
