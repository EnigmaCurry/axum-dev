use rcgen::{CertificateParams, KeyPair};
use std::sync::Once;
use time::OffsetDateTime;

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

/// Ensure the global rustls CryptoProvider is installed (ring).
pub fn ensure_rustls_crypto_provider() {
    INSTALL_RUSTLS_PROVIDER.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install rustls crypto provider");
    });
}

/// Generate a self-signed cert + key with a custom validity window.
pub fn generate_self_signed_with_validity(
    sans: Vec<String>,
    valid_days: u32,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    // Start with rcgen defaults for the SANs
    let mut params = CertificateParams::new(sans)?;

    // Custom validity
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(valid_days as i64);

    // Generate a keypair with the default algorithm
    let key_pair = KeyPair::generate()?;

    // Self-sign the certificate with that key
    let cert = params.self_signed(&key_pair)?;

    // PEM-encode cert and key
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}
