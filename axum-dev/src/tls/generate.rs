use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::sync::Once;
use time::OffsetDateTime;

static INSTALL_RUSTLS_PROVIDER: Once = Once::new();

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
    valid_days: u32,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    generate_self_signed_with_validity_and_dn(sans, valid_days, &default_self_signed_dn())
}

/// New API: caller provides the DN.
pub fn generate_self_signed_with_validity_and_dn(
    sans: Vec<String>,
    valid_days: u32,
    dn: &SelfSignedDn,
) -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    let mut params = CertificateParams::new(sans)?;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::OrganizationName, dn.organization.clone());
    distinguished_name.push(rcgen::DnType::CommonName, dn.common_name.clone());
    params.distinguished_name = distinguished_name;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(valid_days as i64);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}
