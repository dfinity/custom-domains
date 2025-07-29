use derive_new::new;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {}

/// Trait for encrypting and decrypting certificate data
pub trait CiphersCertificates: Send + Sync + Debug {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// TODO: implement a concrete encryption
#[derive(Debug, new)]
pub struct CertificateCipher {}

impl CiphersCertificates for CertificateCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(encrypted_data.to_vec())
    }
}
