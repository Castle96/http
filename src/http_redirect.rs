use axum::{extract::Host, http::Uri, response::Redirect, routing::get, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

pub async fn start_http_redirect_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    let listener = TcpListener::bind(addr).await?;
    info!("HTTP redirect server listening on http://{}", addr);

    let app = Router::new().route("/", get(handle_redirect));

    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_redirect(Host(host): Host, uri: Uri) -> Redirect {
    let https_uri = format!("https://{}{}", host, uri);
    Redirect::permanent(&https_uri)
}
