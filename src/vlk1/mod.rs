//! VLK-1 (Voxfor Lattice Key Exchange v1)
//! 
//! Production-grade quantum-resistant key exchange based on Module-LWE.
//! 
//! Features:
//! - **NTT-optimized polynomial multiplication**
//! - **Constant-time operations** for side-channel resistance
//! - **Dual-state keys** for enhanced security
//! - **Noise folding** for stronger hardness
//! 
//! Security: ~128-bit post-quantum

pub mod params;
pub mod poly;
pub mod ntt;
pub mod ntt_vectors;
pub mod keygen;
pub mod keygen_ratelimit;
pub mod kem;

use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use thiserror::Error;

pub use params::*;
pub use poly::Polynomial;
pub use keygen::{KeyPair, PublicKey, SecretKey};
pub use kem::{encapsulate, decapsulate, SharedSecret, Ciphertext};

#[derive(Error, Debug)]
pub enum Vlk1Error {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, Vlk1Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public_key().as_bytes().len(), PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key().as_bytes().len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn test_kem() {
        let keypair = KeyPair::generate();
        let (ciphertext, shared_secret1) = encapsulate(keypair.public_key()).unwrap();
        let shared_secret2 = decapsulate(&ciphertext, keypair.secret_key()).unwrap();
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }
}
