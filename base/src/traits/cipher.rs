use thiserror::Error;

/// Errors that can occur during encryption/decryption operations.
#[derive(Debug, Error)]
pub enum CipherError {}

/// Trait for encrypting and decrypting certificate data.
pub trait CiphersCertificates: Send + Sync + std::fmt::Debug {
    /// Encrypts the provided data.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError>;

    /// Decrypts the provided encrypted data.
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError>;
}
