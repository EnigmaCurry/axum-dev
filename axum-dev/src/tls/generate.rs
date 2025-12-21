use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::{
    path::PathBuf,
    sync::Once,
    time::{Duration, SystemTime},
};
use time::OffsetDateTime;
use tracing::info;

use crate::{
    tls::self_signed_cache::{
        delete_cached_pair, inspect_self_signed_cert_pem, read_private_tls_file, read_tls_file,
        validate_self_signed_cert_pem,
    },
    util::write_files::{
        atomic_write_file_0600, create_private_dir_all_0700, validate_private_dir_0700,
    },
};

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();
const CERT_FILE_NAME: &'static str = "self_signed_cert.pem";
const KEY_FILE_NAME: &'static str = "self_signed_key.pem";

pub fn ensure_rustls_crypto_provider() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install rustls crypto provider");
    });
}

#[derive(Debug, Clone)]
pub struct SelfSignedDn {
    pub organization: String,
    pub common_name: String,
}

impl SelfSignedDn {
    pub fn from_bin_name(bin: &str) -> Self {
        Self {
            organization: format!("{bin} self-signed authority"),
            common_name: bin.to_string(),
        }
    }
}

pub fn default_self_signed_dn() -> SelfSignedDn {
    SelfSignedDn::from_bin_name(env!("CARGO_BIN_NAME"))
}

/// Backwards-compatible wrapper
pub fn generate_self_signed_with_validity(
    sans: Vec<String>,
    valid_secs: u32,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    generate_self_signed_with_validity_and_dn(sans, valid_secs, &default_self_signed_dn())
}

/// New API: caller provides the DN.
pub fn generate_self_signed_with_validity_and_dn(
    sans: Vec<String>,
    valid_secs: u32,
    dn: &SelfSignedDn,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    let mut params = CertificateParams::new(sans)?;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::OrganizationName, dn.organization.clone());
    distinguished_name.push(rcgen::DnType::CommonName, dn.common_name.clone());
    params.distinguished_name = distinguished_name;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::from_secs(valid_secs as u64);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}

pub async fn load_or_generate_self_signed(
    cache_dir: Option<std::path::PathBuf>,
    sans: Vec<String>,
    valid_secs: u32,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let expected_dn = default_self_signed_dn();

    if let Some(dir) = cache_dir.as_ref() {
        create_private_dir_all_0700(&dir)
            .await
            .map_err(|e| anyhow::anyhow!("TLS cache dir invalid: {e:#}"))?;

        let cert_path = dir.join(CERT_FILE_NAME);
        let key_path = dir.join(KEY_FILE_NAME);

        let cert_exists = tokio::fs::try_exists(cert_path.clone()).await?;
        let key_exists = tokio::fs::try_exists(key_path.clone()).await?;

        if cert_exists && key_exists {
            let cert_pem = read_tls_file(&cert_path).await?;
            let key_pem = read_private_tls_file(&key_path).await?;

            let details = match inspect_self_signed_cert_pem(&cert_pem) {
                Ok(d) => Some(d),
                Err(err) => {
                    info!(
                        "Cached self-signed cert could not be inspected ({err}); deleting and regenerating"
                    );
                    delete_cached_pair(&cert_path, &key_path).await?;
                    None
                }
            };

            if let Some(details) = details {
                match validate_self_signed_cert_pem(&cert_pem, &expected_dn) {
                    Ok(()) => {
                        info!(
                            "Loading cached self-signed TLS certificate from '{}' (expires {}, remaining {})",
                            cert_path.display(),
                            details.not_after,
                            details.remaining_human,
                        );
                        return Ok((cert_pem, key_pem));
                    }
                    Err(err) => {
                        info!(
                            "Cached self-signed cert invalid (expires {}, remaining {}): {err}; deleting and regenerating",
                            details.not_after, details.remaining_human,
                        );
                        delete_cached_pair(&cert_path, &key_path).await?;
                    }
                }
            }
        } else if cert_exists || key_exists {
            info!(
                "Cached self-signed cert/key incomplete; deleting and regenerating (cert_exists={}, key_exists={})",
                cert_exists, key_exists
            );
            delete_cached_pair(&cert_path, &key_path).await?;
        }

        info!(
            "Generating new cached self-signed TLS certificate (valid_secs={}, sans={:?}) in '{}'",
            valid_secs,
            sans,
            dir.display()
        );

        let (cert_pem, key_pem) = generate_self_signed_with_validity(sans, valid_secs)?;

        let fp = sha256_fingerprint_first_cert_pem(&cert_pem)
            .unwrap_or_else(|e| format!("(fingerprint unavailable: {e})"));

        let details = inspect_self_signed_cert_pem(&cert_pem).ok();

        if let Some(details) = details {
            info!(
                "Generated new self-signed TLS certificate (sha256_fingerprint={}, expires {}, remaining {})",
                fp, details.not_after, details.remaining_human
            );
        } else {
            info!(
                "Generated new self-signed TLS certificate (sha256_fingerprint={})",
                fp
            );
        }

        // Write with secure perms atomically (no chmod race).
        atomic_write_file_0600(&cert_path, &cert_pem).await?;
        atomic_write_file_0600(&key_path, &key_pem).await?;

        return Ok((cert_pem, key_pem));
    }

    info!(
        "Generating ephemeral self-signed TLS certificate (valid_secs={}, sans={:?}); not cached",
        valid_secs, sans
    );

    let (cert_pem, key_pem) = generate_self_signed_with_validity(sans, valid_secs)?;

    let fp = sha256_fingerprint_first_cert_pem(&cert_pem)
        .unwrap_or_else(|e| format!("(fingerprint unavailable: {e})"));

    let details = inspect_self_signed_cert_pem(&cert_pem).ok();

    if let Some(details) = details {
        info!(
            "Generated new self-signed TLS certificate (sha256_fingerprint={}, expires {}, remaining {})",
            fp, details.not_after, details.remaining_human
        );
    } else {
        info!(
            "Generated new self-signed TLS certificate (sha256_fingerprint={})",
            fp
        );
    }

    Ok((cert_pem, key_pem))
}

pub async fn renew_self_signed_loop(
    rustls_config: axum_server::tls_rustls::RustlsConfig,
    cache_dir: Option<std::path::PathBuf>,
    sans: Vec<String>,
    valid_secs: u32,
    renew_margin: Duration,
    mut current_cert_pem: Vec<u8>,
) {
    let validity = Duration::from_secs(valid_secs as u64);
    let min_sleep = Duration::from_secs(1);

    // Renew at ~80% lifetime: margin = 20% validity, capped at 10 minutes.
    // Also ensure margin is strictly less than validity.
    let validity = Duration::from_secs(valid_secs as u64);
    let mut renew_margin = Duration::from_secs((valid_secs as u64) / 5).max(Duration::from_secs(1));
    renew_margin = renew_margin.min(Duration::from_secs(600));
    if renew_margin >= validity {
        renew_margin = validity
            .saturating_sub(Duration::from_secs(1))
            .max(Duration::from_secs(1));
    }
    let renew_every = validity
        .saturating_sub(renew_margin)
        .max(Duration::from_secs(1));
    info!(
        "self-signed TLS: validity={}s; will renew {}s before expiry (~every {}s); cache_dir={:?}; sans={:?}",
        validity.as_secs(),
        renew_margin.as_secs(),
        renew_every.as_secs(),
        cache_dir,
        sans,
    );

    loop {
        // 1) Figure out how long until expiry.
        let sleep_for = match cert_not_after(&current_cert_pem) {
            Ok(not_after) => {
                let now = SystemTime::now();

                // If cert is already expired (clock skew, parsing bug, etc), renew immediately.
                let until_expiry = match not_after.duration_since(now) {
                    Ok(d) => d,
                    Err(_) => Duration::from_secs(0),
                };

                // Sleep until we ENTER the renew window.
                if until_expiry > renew_margin {
                    (until_expiry - renew_margin).max(min_sleep)
                } else {
                    Duration::from_secs(0)
                }
            }
            Err(err) => {
                tracing::warn!(%err, "could not parse cert expiry; will retry soon");
                Duration::from_secs(2)
            }
        };

        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }

        // 2) We are in the renew window → FORCE create a fresh cert (do NOT load-or-generate).
        match generate_and_persist_self_signed(cache_dir.clone(), sans.clone(), valid_secs).await {
            Ok((new_cert_pem, new_key_pem)) => {
                if let Err(err) = rustls_config
                    .reload_from_pem(new_cert_pem.clone(), new_key_pem)
                    .await
                {
                    tracing::error!(%err, "failed to reload rustls config; will retry");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }

                tracing::info!("reloaded self-signed certificate");
                current_cert_pem = new_cert_pem;
            }
            Err(err) => {
                tracing::error!(%err, "failed to generate new self-signed cert; will retry");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

fn cert_not_after(cert_pem: &[u8]) -> anyhow::Result<SystemTime> {
    use std::io::Cursor;

    // rustls-pemfile gives you DER bytes for the first cert in the PEM.
    let mut reader = Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed reading PEM certs")?;

    let first = certs
        .into_iter()
        .next()
        .context("no certificate found in PEM")?;

    let (_, x509) = x509_parser::parse_x509_certificate(&first).context("failed parsing x509")?;

    // x509-parser gives an OffsetDateTime (seconds since Unix epoch).
    let ts = x509.validity().not_after.timestamp();
    let ts_u64: u64 = ts.try_into().context("cert not_after before Unix epoch")?;

    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(ts_u64))
}

async fn generate_and_persist_self_signed(
    cache_dir: Option<std::path::PathBuf>,
    sans: Vec<String>,
    valid_secs: u32,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (cert_pem, key_pem) = generate_self_signed_with_validity(sans, valid_secs)
        .map_err(|e| anyhow::anyhow!("failed to generate self-signed cert: {e}"))?;

    let fp = sha256_fingerprint_first_cert_pem(&cert_pem)
        .unwrap_or_else(|e| format!("(fingerprint unavailable: {e})"));

    let details = inspect_self_signed_cert_pem(&cert_pem).ok();

    if let Some(details) = details {
        info!(
            "Generated replacement self-signed TLS certificate (sha256_fingerprint={}, expires {}, remaining {})",
            fp, details.not_after, details.remaining_human
        );
    } else {
        info!(
            "Generated replacement self-signed TLS certificate (sha256_fingerprint={})",
            fp
        );
    }

    if let Some(dir) = cache_dir {
        // Whatever filenames you already use in load_or_generate_self_signed:
        let cert_path = dir.join(CERT_FILE_NAME);
        let key_path = dir.join(KEY_FILE_NAME);

        create_private_dir_all_0700(&dir).await?;
        validate_private_dir_0700(&dir).await?;

        atomic_write_file_0600(&cert_path, &cert_pem).await?;
        atomic_write_file_0600(&key_path, &key_pem).await?;
    }

    Ok((cert_pem, key_pem))
}

fn sha256_fingerprint_first_cert_pem(pem: &[u8]) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

    let mut reader = Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed reading PEM certs")?;

    let first = certs
        .into_iter()
        .next()
        .context("PEM contained no certificates")?;

    let digest = Sha256::digest(first.as_ref());

    // OpenSSL-ish formatting: AA:BB:CC...
    let mut out = String::new();
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        use std::fmt::Write;
        write!(&mut out, "{:02X}", b).expect("write to String cannot fail");
    }

    Ok(out)
}
