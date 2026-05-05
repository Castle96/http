use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub domain: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone)]
pub struct LetsEncryptConfig {
    pub domain: String,
    pub email: String,
    pub cert_dir: PathBuf,
    pub use_staging: bool,
}

impl LetsEncryptConfig {
    pub fn new(domain: String, email: String, cert_dir: &str, use_staging: bool) -> Self {
        Self {
            domain,
            email,
            cert_dir: PathBuf::from(cert_dir),
            use_staging,
        }
    }

    fn metadata_path(&self) -> PathBuf {
        self.cert_dir.join("cert_metadata.json")
    }

    /// Load certificate metadata if it exists
    pub fn load_metadata(&self) -> Option<CertificateMetadata> {
        let path = self.metadata_path();
        if !path.exists() {
            return None;
        }

        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(metadata) => Some(metadata),
                Err(e) => {
                    error!("Failed to parse certificate metadata: {}", e);
                    None
                }
            },
            Err(e) => {
                error!("Failed to read certificate metadata: {}", e);
                None
            }
        }
    }

    /// Save certificate metadata
    pub fn save_metadata(&self, metadata: &CertificateMetadata) -> Result<()> {
        fs::create_dir_all(&self.cert_dir)?;
        let json = serde_json::to_string_pretty(metadata)?;
        fs::write(self.metadata_path(), json)?;
        Ok(())
    }

    /// Check if certificate needs renewal (30 days before expiry)
    pub fn needs_renewal(&self, metadata: &CertificateMetadata) -> bool {
        let now = Utc::now();
        let renewal_threshold = metadata.expires_at - chrono::Duration::days(30);
        now > renewal_threshold
    }

    /// Provision a new certificate by invoking an external ACME command.
    ///
    /// The command is templated and can be set via the environment variable
    /// `ACME_CMD_TEMPLATE`. If not set, a reasonable certbot webroot command is used.
    ///
    /// Supported template placeholders:
    /// - {domain}
    /// - {email}
    /// - {cert_dir}
    /// - {staging_flag}
    pub async fn provision_certificate(&self) -> Result<CertificateMetadata> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            info!(
                "Provisioning certificate for domain: {} (attempt {}/{})",
                self.domain, attempt, MAX_RETRIES
            );

            match self.try_provision_certificate().await {
                Ok(metadata) => return Ok(metadata),
                Err(e) => {
                    warn!("Certificate provisioning attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }
        }

        Err(anyhow!(
            "Certificate provisioning failed after {} attempts: {}",
            MAX_RETRIES,
            last_error.unwrap()
        ))
    }

    async fn try_provision_certificate(&self) -> Result<CertificateMetadata> {
        fs::create_dir_all(&self.cert_dir)
            .with_context(|| format!("creating cert_dir {}", self.cert_dir.display()))?;

        let default_template = "certbot certonly --webroot -w {cert_dir} -d {domain} --email {email} --agree-tos --non-interactive {staging_flag}";
        let template =
            env::var("ACME_CMD_TEMPLATE").unwrap_or_else(|_| default_template.to_string());

        let staging_flag = if self.use_staging { "--staging" } else { "" };

        let cmd = template
            .replace("{domain}", &self.domain)
            .replace("{email}", &self.email)
            .replace("{cert_dir}", &self.cert_dir.to_string_lossy())
            .replace("{staging_flag}", staging_flag);

        info!("Running ACME command: {}", cmd);

        let status = timeout(
            std::time::Duration::from_secs(120),
            Command::new("sh").arg("-c").arg(&cmd).status(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ACME command timed out"))?
        .with_context(|| "failed to spawn ACME command")?;

        if !status.success() {
            return Err(anyhow!(
                "ACME command exited with non-zero status: {}",
                status
            ));
        }

        let local_cert = self.cert_dir.join("cert.pem");
        let local_key = self.cert_dir.join("key.pem");

        if local_cert.exists() && local_key.exists() {
            info!("Found cert/key in cert_dir");
            let (expires_at, issued_at) = extract_dates_from_pem(&local_cert).unwrap_or_else(|e| {
                warn!(
                    "Failed to parse cert dates: {} — falling back to 90 days",
                    e
                );
                (Utc::now() + chrono::Duration::days(90), Utc::now())
            });

            let metadata = CertificateMetadata {
                domain: self.domain.clone(),
                issued_at,
                expires_at,
                cert_path: local_cert,
                key_path: local_key,
            };

            self.save_metadata(&metadata)?;
            return Ok(metadata);
        }

        let letsencrypt_cert = PathBuf::from("/etc/letsencrypt/live")
            .join(&self.domain)
            .join("fullchain.pem");
        let letsencrypt_key = PathBuf::from("/etc/letsencrypt/live")
            .join(&self.domain)
            .join("privkey.pem");

        if letsencrypt_cert.exists() && letsencrypt_key.exists() {
            info!("Found certs in /etc/letsencrypt/live, copying into cert_dir");
            fs::copy(&letsencrypt_cert, &local_cert)?;
            fs::copy(&letsencrypt_key, &local_key)?;

            let (expires_at, issued_at) = extract_dates_from_pem(&local_cert).unwrap_or_else(|e| {
                warn!(
                    "Failed to parse cert dates: {} — falling back to 90 days",
                    e
                );
                (Utc::now() + chrono::Duration::days(90), Utc::now())
            });

            let metadata = CertificateMetadata {
                domain: self.domain.clone(),
                issued_at,
                expires_at,
                cert_path: local_cert,
                key_path: local_key,
            };

            self.save_metadata(&metadata)?;
            return Ok(metadata);
        }

        Err(anyhow!(
            "ACME command succeeded but cert files not found in known locations (tried {}, {})",
            local_cert.display(),
            letsencrypt_cert.display()
        ))
    }
}

/// Try to extract NotBefore/NotAfter date using openssl command-line.
/// Returns (expires_at, issued_at)
fn extract_dates_from_pem(cert_path: &Path) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    use std::process::Command as StdCommand;

    let output = StdCommand::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(cert_path)
        .arg("-noout")
        .arg("-dates")
        .output()
        .with_context(|| "failed to run openssl to parse certificate dates")?;

    if !output.status.success() {
        return Err(anyhow!("openssl exited non-zero parsing cert"));
    }

    let out = String::from_utf8_lossy(&output.stdout);
    let mut issued = None;
    let mut expires = None;
    for line in out.lines() {
        if let Some(stripped) = line.strip_prefix("notBefore=") {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(stripped) {
                issued = Some(dt.with_timezone(&Utc));
            } else if let Ok(dt) = chrono::DateTime::parse_from_str(stripped, "%b %e %T %Y %Z") {
                issued = Some(dt.with_timezone(&Utc));
            }
        } else if let Some(stripped) = line.strip_prefix("notAfter=") {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(stripped) {
                expires = Some(dt.with_timezone(&Utc));
            } else if let Ok(dt) = chrono::DateTime::parse_from_str(stripped, "%b %e %T %Y %Z") {
                expires = Some(dt.with_timezone(&Utc));
            }
        }
    }

    let issued_at = issued.unwrap_or_else(Utc::now);
    let expires_at = expires.unwrap_or_else(|| Utc::now() + chrono::Duration::days(90));
    Ok((expires_at, issued_at))
}
