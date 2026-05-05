#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

#[derive(Clone, Default)]
pub struct ReverseProxy {
    routes: Arc<RwLock<HashMap<String, String>>>,
}

impl ReverseProxy {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_route(&self, path: &str, upstream: &str) {
        let mut routes = self.routes.write().await;
        routes.insert(path.to_string(), upstream.to_string());
    }

    pub async fn get_upstream(&self, path: &str) -> Option<String> {
        let routes = self.routes.read().await;
        routes
            .iter()
            .filter(|(k, _)| path.starts_with(*k))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, v)| v.clone())
    }
}

#[allow(dead_code)]
pub async fn proxy_request(
    uri: axum::http::Uri,
    upstream: String,
) -> Result<axum::response::Response<axum::body::Body>, Box<dyn std::error::Error + Send + Sync>> {
    use axum::{body::Body, response::Response};

    debug!("Proxying request to: {}", upstream);

    let upstream_uri = format!(
        "{}{}",
        upstream,
        uri.path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_default()
    );

    let client = reqwest::Client::new();
    let res = client.get(&upstream_uri).send().await?;

    let status = axum::http::StatusCode::from_u16(res.status().as_u16())?;
    let body = res.bytes().await?;

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;

    Ok(response)
}
