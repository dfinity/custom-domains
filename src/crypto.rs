use derive_new::new;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {}

/// Trait for encrypting and decrypting certificate data
pub trait CertificateCrypto {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[derive(new)]
pub struct Crypto {}

impl CertificateCrypto for Crypto {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(encrypted_data.to_vec())
    }
}
