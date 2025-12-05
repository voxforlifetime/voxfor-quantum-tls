//! VOX-SIG (Voxfor Post-Quantum Signature) v1
//! 
//! Production-grade hash-based signature scheme with:
//! - Merkle tree authentication
//! - Lamport one-time signatures
//! - Stateless design with deterministic key derivation
//! - Constant-time operations
//! 
//! Security: 128-bit post-quantum

pub mod params;
pub mod merkle;
pub mod lamport;
pub mod keygen;
pub mod sign;
pub mod verify;

/// ✅ PRODUCTION: Safe signer with atomic persistence
///
/// **ALWAYS use SafeSigner instead of SigningKey directly!**
///
/// Prevents catastrophic index reuse by ensuring counter is atomically persisted.
pub mod safe_signer;

// SECURITY FIX: StatelessSigner removed completely (was too dangerous)
// Even with deprecation warnings, having it in the codebase risks accidental use
// Use SigningKey instead - it tracks index automatically and prevents reuse
// ✅ REMOVED: compression module was experimental and unsafe
// CompressedSignature::decompress created invalid signatures (zero PKs)
// PolynomialCommitment::verify_point() was unimplemented (panic!)
// pub mod compression;

use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use thiserror::Error;

pub use params::*;
pub use keygen::{SigningKey, VerifyingKey, Keypair};
pub use sign::{sign, Signature};
pub use verify::verify;

#[derive(Error, Debug)]
pub enum VoxSigError {
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Key exhausted: maximum signatures reached")]
    KeyExhausted,
    #[error("Invalid signing key")]
    InvalidSigningKey,
    
    #[error("IO error: {0}")]
    Io(String),
    
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Merkle tree verification failed")]
    MerkleVerificationFailed,
}

pub type Result<T> = std::result::Result<T, VoxSigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let mut keypair = Keypair::generate();
        let message = b"Test message";
        
        let signature = sign(&mut keypair.signing_key, message).unwrap();
        let result = verify(&keypair.verifying_key, message, &signature);
        if let Err(e) = &result {
            eprintln!("[TEST] Verification failed: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_tampered_message() {
        let mut keypair = Keypair::generate();
        let message = b"Original message";
        
        let signature = sign(&mut keypair.signing_key, message).unwrap();
        
        let tampered = b"Tampered message";
        assert!(verify(&keypair.verifying_key, tampered, &signature).is_err());
    }
}
