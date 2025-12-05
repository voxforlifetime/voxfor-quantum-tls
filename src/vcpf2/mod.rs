//! VCPF-2 Record Layer Protocol

pub mod record;
pub mod aead;
pub mod keys;
pub mod protection;

pub use record::{Record, ContentType, RecordError, RecordReassembler};
pub use aead::AeadCipher;
pub use keys::derive_keys;
pub use protection::RecordProtection;
