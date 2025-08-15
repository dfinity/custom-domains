use derive_new::new;

use crate::traits::cipher::{CipherError, CiphersCertificates};

// TODO: implement a concrete encryption
#[derive(Debug, new)]
pub struct CertificateCipher {}

impl CiphersCertificates for CertificateCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError> {
        Ok(encrypted_data.to_vec())
    }
}
