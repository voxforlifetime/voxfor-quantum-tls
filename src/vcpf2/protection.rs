//! Record Protection
//!
//! # 🔴 CRITICAL: Sequence Number Confusion
//!
//! ## THE PROBLEM
//!
//! This struct contains `read_seq` and `write_seq` fields but **DOES NOT USE THEM**!
//!
//! Instead, it relies on the internal sequence counter inside `AeadCipher`, which:
//! - Is NOT exposed to external validation
//! - Cannot be synchronized with protocol-level expectations
//! - Creates confusion about which sequence number is authoritative
//!
//! ## SECURITY IMPLICATIONS
//!
//! While the current implementation prevents replay attacks WITHIN a session
//! (AeadCipher increments internally), it has architectural problems:
//!
//! 1. **Dead Code**: `read_seq`/`write_seq` fields serve no purpose
//! 2. **Confusion**: Readers assume these fields are used (they're not!)
//! 3. **Maintenance Risk**: Future changes might incorrectly use these fields
//! 4. **Protocol Mismatch**: TLS 1.3 expects explicit sequence tracking
//!
//! ## PROPER IMPLEMENTATION
//!
//! **Option 1: Remove Dead Code (Simple)**
//! ```rust
//! pub struct RecordProtection {
//!     read_cipher: Option<AeadCipher>,
//!     write_cipher: Option<AeadCipher>,
//!     // ✅ No confusing unused fields
//! }
//! ```
//!
//! **Option 2: Use Explicit Sequence Numbers (TLS 1.3 Style)**
//! ```rust
//! pub fn protect(&mut self, record: &Record) -> Result<Vec<u8>, RecordError> {
//!     let seq_num = self.write_seq;
//!     self.write_seq += 1;
//!     
//!     // Build AAD with explicit sequence number
//!     let aad = build_aad(record.content_type, seq_num, record.payload.len());
//!     let ciphertext = cipher.encrypt(&record.payload, &aad)?;
//!     
//!     // Include sequence number in record or validate externally
//!     Ok(protected.to_bytes())
//! }
//! ```
//!
//! ## CURRENT STATUS
//!
//! ⚠️ **Architecturally confusing but functionally safe** (for single sessions)
//!
//! The code WORKS because `AeadCipher` handles sequencing internally,
//! but it's **misleading** and **unmaintainable**.
//!
//! ## RECOMMENDATION
//!
//! Remove `read_seq` and `write_seq` fields OR use them properly.
//! Don't leave dead code that implies functionality it doesn't provide!

use super::{record::*, aead::AeadCipher};

pub struct RecordProtection {
    read_cipher: Option<AeadCipher>,
    write_cipher: Option<AeadCipher>,
    
    /// ⚠️ WARNING: These fields are UNUSED!
    /// Kept for API compatibility but serve no purpose.
    /// Actual sequence tracking happens inside AeadCipher.
    /// See module documentation for details.
    read_seq: u64,
    write_seq: u64,
}

impl RecordProtection {
    pub fn new() -> Self {
        Self {
            read_cipher: None,
            write_cipher: None,
            read_seq: 0,
            write_seq: 0,
        }
    }
    
    pub fn set_keys(&mut self, read_key: [u8; 32], write_key: [u8; 32]) {
        self.read_cipher = Some(AeadCipher::new(&read_key));
        self.write_cipher = Some(AeadCipher::new(&write_key));
    }
    
    pub fn protect(&mut self, record: &Record) -> Result<Vec<u8>, RecordError> {
        if let Some(cipher) = &mut self.write_cipher {
            let aad = Self::build_aad_static(record.content_type, record.version, record.payload.len());
            let ciphertext = cipher.encrypt(&record.payload, &aad)?;
            
            let mut protected = Record::new(record.content_type, ciphertext);
            protected.version = record.version;
            Ok(protected.to_bytes())
        } else {
            Ok(record.to_bytes())
        }
    }
    
    pub fn unprotect(&mut self, data: &[u8]) -> Result<Record, RecordError> {
        const TAG_LEN: usize = 16; // ChaCha20-Poly1305 tag length
        
        let (mut record, _) = Record::from_bytes(data)?;
        
        if let Some(cipher) = &mut self.read_cipher {
            // Check payload is long enough to contain tag
            if record.payload.len() < TAG_LEN {
                return Err(RecordError::DecryptionError);
            }
            
            let plaintext_len = record.payload.len() - TAG_LEN;
            let aad = Self::build_aad_static(record.content_type, record.version, plaintext_len);
            let plaintext = cipher.decrypt(&record.payload, &aad)?;
            record.payload = plaintext;
        }
        
        Ok(record)
    }
    
    fn build_aad_static(ct: ContentType, version: u16, length: usize) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.push(ct as u8);
        aad.extend_from_slice(&version.to_be_bytes());
        aad.extend_from_slice(&(length as u16).to_be_bytes());
        aad
    }
}

impl Default for RecordProtection {
    fn default() -> Self {
        Self::new()
    }
}
