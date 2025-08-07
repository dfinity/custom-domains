use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherError {}

/// Trait for encrypting and decrypting certificate data
pub trait CiphersCertificates: Send + Sync + std::fmt::Debug {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError>;
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError>;
}
