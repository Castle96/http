use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::Path,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use hyper::server::conn::http1;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio::time::timeout;
use tower::util::ServiceExt;
use tracing::{error, info, warn};

mod acme;
mod cert_manager;
mod http_redirect;
mod proxy;
mod tls;

use acme::LetsEncryptConfig;
use anyhow::Result;
use cert_manager::CertificateManager;
use tls::TlsConfig;
use tokio_rustls::TlsAcceptor;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

fn load_config() -> Result<Config> {
    dotenv::dotenv().ok();

    let domain =
        std::env::var("DOMAIN").map_err(|_| anyhow::anyhow!("DOMAIN not set in environment"))?;
    let email =
        std::env::var("EMAIL").map_err(|_| anyhow::anyhow!("EMAIL not set in environment"))?;
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "certs/".to_string());
    let use_staging = std::env::var("USE_STAGING")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "443".to_string())
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid PORT value"))?;

    Ok(Config {
        domain,
        email,
        cert_dir,
        use_staging,
        host,
        port,
    })
}

struct Config {
    domain: String,
    email: String,
    cert_dir: String,
    use_staging: bool,
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = load_config()?;

    info!("Starting HTTP server for domain: {}", config.domain);

    let le_config = LetsEncryptConfig::new(
        config.domain.clone(),
        config.email,
        &config.cert_dir,
        config.use_staging,
    );

    let tls_config = TlsConfig::load_from_le_config(&le_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {}", e))?;
    let initial_acceptor = Arc::new(
        tls_config
            .create_acceptor()
            .map_err(|e| anyhow::anyhow!("Failed to create acceptor: {}", e))?,
    );

    let shared_acceptor: Arc<RwLock<Arc<TlsAcceptor>>> =
        Arc::new(RwLock::new(initial_acceptor.clone()));

    let (shutdown_tx, _) = broadcast::channel(1);

    let cert_manager = CertificateManager::new(le_config.clone(), shared_acceptor.clone());
    let cert_manager_handle = tokio::spawn(async move {
        if let Err(e) = cert_manager.start_renewal_loop().await {
            error!("Certificate manager loop failed: {}", e);
        }
    });

    let http_redirect_handle = tokio::spawn(async {
        if let Err(e) = http_redirect::start_http_redirect_server().await {
            error!("HTTP redirect server failed: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let app = create_router();

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS server listening on https://{}", addr);

    let mut shutdown_rx = shutdown_tx.subscribe();

    tokio::select! {
        result = async {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown signal received, stopping listener");
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((socket, peer_addr)) => {
                                let shared_acceptor = shared_acceptor.clone();
                                let app = app.clone();
                                let shutdown_tx = shutdown_tx.clone();

                                tokio::spawn(async move {
                                    let _ = shutdown_tx;
                                    if let Err(e) = handle_connection(socket, peer_addr, shared_acceptor, app).await {
                                        error!("Connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        } => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
    }

    info!("Stopping new connections, waiting for existing to drain...");

    let _ = shutdown_tx.send(());

    match timeout(SHUTDOWN_TIMEOUT, async {
        cert_manager_handle.abort();
        http_redirect_handle.abort();
    })
    .await
    {
        Ok(_) => info!("Background tasks stopped"),
        Err(_) => warn!("Shutdown timeout, forcing exit"),
    }

    info!("Server shutdown complete");
    Ok(())
}

async fn handle_connection(
    socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    shared_acceptor: Arc<RwLock<Arc<TlsAcceptor>>>,
    app: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = {
        let guard = shared_acceptor.read().await;
        guard.clone()
    };

    let tls_stream = timeout(Duration::from_secs(10), acceptor.accept(socket))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timeout"))??;

    info!("TLS connection established from {}", peer_addr);

    let io = hyper_util::rt::TokioIo::new(tls_stream);

    let hyper_service = hyper::service::service_fn(move |req| {
        let app = app.clone();
        async move {
            match app.oneshot(req).await {
                Ok(resp) => Ok::<_, std::convert::Infallible>(resp.into_response()),
                Err(_) => Ok::<_, std::convert::Infallible>(
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
                ),
            }
        }
    });

    timeout(
        Duration::from_secs(60),
        http1::Builder::new().serve_connection(io, hyper_service),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    Ok(())
}

fn create_router() -> Router {
    Router::new()
        .route("/", get(handler_root))
        .route("/health", get(handler_health))
        .route("/health/cert", get(handler_cert_health))
        .route(
            "/.well-known/acme-challenge/:token",
            get(handle_acme_challenge),
        )
}

async fn handler_root() -> Html<&'static str> {
    Html("<h1>Welcome to Rust HTTPS Server with Let's Encrypt!</h1>")
}

async fn handler_health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn handler_cert_health() -> impl IntoResponse {
    use chrono::Utc;

    let cert_dir = std::path::Path::new("certs/");
    let metadata_path = cert_dir.join("cert_metadata.json");

    match std::fs::read_to_string(&metadata_path) {
        Ok(content) => match serde_json::from_str::<acme::CertificateMetadata>(&content) {
            Ok(metadata) => {
                let now = Utc::now();
                let days_until_expiry = (metadata.expires_at - now).num_days();
                let status = if days_until_expiry > 30 {
                    "healthy"
                } else if days_until_expiry > 7 {
                    "renewing_soon"
                } else {
                    "critical"
                };

                let body = serde_json::json!({
                    "status": status,
                    "domain": metadata.domain,
                    "expires_at": metadata.expires_at,
                    "days_until_expiry": days_until_expiry,
                });

                Json(body).into_response()
            }
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to parse metadata",
            )
                .into_response(),
        },
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "No certificate found").into_response(),
    }
}

async fn handle_acme_challenge(Path(token): Path<String>) -> Result<String, StatusCode> {
    let cert_dir = std::path::Path::new("certs/");
    let challenge_file = cert_dir
        .join(".well-known")
        .join("acme-challenge")
        .join(&token);

    match std::fs::read_to_string(&challenge_file) {
        Ok(content) => Ok(content),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}
