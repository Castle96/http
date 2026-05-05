use crate::acme::LetsEncryptConfig;
use crate::tls::TlsConfig;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub struct CertificateManager {
    config: LetsEncryptConfig,
    shared_acceptor: Arc<RwLock<Arc<TlsAcceptor>>>,
}

impl CertificateManager {
    pub fn new(config: LetsEncryptConfig, shared_acceptor: Arc<RwLock<Arc<TlsAcceptor>>>) -> Self {
        Self {
            config,
            shared_acceptor,
        }
    }

    /// Start the certificate renewal loop (checks daily) and hot-swaps the acceptor on success.
    pub async fn start_renewal_loop(&self) -> Result<()> {
        loop {
            match self.check_and_renew().await {
                Ok(renewed) => {
                    if renewed {
                        info!("Certificate successfully provisioned/renewed and acceptor updated");
                    } else {
                        info!("Certificate is still valid; no renewal needed");
                    }
                }
                Err(e) => {
                    error!("Certificate renewal check failed: {:?}", e);
                }
            }

            // Check daily
            sleep(Duration::from_secs(86400)).await;
        }
    }

    /// Check if renewal is needed and perform it. If provisioning succeeds, reload TLS acceptor.
    async fn check_and_renew(&self) -> Result<bool> {
        match self.config.load_metadata() {
            Some(metadata) => {
                if self.config.needs_renewal(&metadata) {
                    warn!(
                        "Certificate expires at {}, renewing now",
                        metadata.expires_at
                    );
                    let metadata = self.config.provision_certificate().await?;
                    self.reload_acceptor(&metadata).await?;
                    Ok(true)
                } else {
                    info!("Certificate valid until: {}", metadata.expires_at);
                    Ok(false)
                }
            }
            None => {
                info!("No existing certificate found, provisioning new one");
                let metadata = self.config.provision_certificate().await?;
                self.reload_acceptor(&metadata).await?;
                Ok(true)
            }
        }
    }

    async fn reload_acceptor(&self, metadata: &crate::acme::CertificateMetadata) -> Result<()> {
        let tls_conf = TlsConfig::load_from_files(&metadata.cert_path, &metadata.key_path)
            .map_err(|e| anyhow::anyhow!("Failed to load TLS config: {}", e))?;
        let new_acceptor = Arc::new(
            tls_conf
                .create_acceptor()
                .map_err(|e| anyhow::anyhow!("Failed to create acceptor: {}", e))?,
        );

        let mut guard = self.shared_acceptor.write().await;
        *guard = new_acceptor;

        info!(
            "Swapped TLS acceptor to use cert: {}",
            metadata.cert_path.display()
        );
        Ok(())
    }
}
