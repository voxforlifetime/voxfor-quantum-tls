//! QX509 - Quantum X.509 Certificate Format

pub mod certificate;
pub mod certificate_full;
pub mod extensions;
pub mod extensions_full;
pub mod distinguished_name;
pub mod validity;
pub mod pem_der;
pub mod chain_validator;

pub use certificate::{Certificate, CertificateBuilder};
pub use certificate_full::{CertificateFull, SignatureAlgorithm, PublicKeyAlgorithm, SubjectPublicKeyInfo};
pub use extensions::{Extension, KeyUsage, BasicConstraints};
pub use extensions_full::*;
pub use distinguished_name::DistinguishedName;
pub use validity::Validity;
pub use pem_der::{encode_pem, decode_pem, PemType, der};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum QX509Error {
    #[error("Invalid certificate format")]
    InvalidFormat,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Certificate expired")]
    Expired,
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Certificate already revoked")]
    AlreadyRevoked,
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("IO error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, QX509Error>;
