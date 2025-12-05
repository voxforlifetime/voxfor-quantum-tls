//! AEAD Encryption (ChaCha20-Poly1305)

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use super::record::RecordError;

/// AEAD cipher for record protection with rekeying threshold
/// 
/// # Security: Rekeying Threshold
/// 
/// **Problem**: ChaCha20-Poly1305 has cryptographic limits on number of messages
/// per key. Exceeding these limits degrades security.
/// 
/// **NIST SP 800-38D** and **RFC 7539** recommend:
/// - Max messages per key: 2^64 (theoretical, but impractical)
/// - **Safe limit**: 2^32 messages (~4 billion) to maintain security margin
/// - **Conservative limit**: 2^24 messages (~16 million) for high-security apps
/// 
/// **Why Rekey?**
/// - Prevents nonce reuse (nonce space = 96 bits, but sequence = 64 bits)
/// - Limits cryptanalysis material (less ciphertext per key)
/// - Reduces impact of key compromise
/// 
/// **Implementation**: We use 2^32 as threshold (practical + secure).
pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
    sequence_number: u64,
}

impl AeadCipher {
    /// Maximum messages before rekeying required (2^32)
    /// 
    /// This is the **safe cryptographic limit** for ChaCha20-Poly1305.
    /// Exceeding this requires rekeying to maintain security guarantees.
    /// 
    /// Rationale:
    /// - ChaCha20 nonce: 96 bits (we use 64 bits for sequence)
    /// - Poly1305 tag collision probability increases with message count
    /// - 2^32 provides safety margin (well below theoretical 2^64 limit)
    pub const REKEY_THRESHOLD: u64 = 1u64 << 32; // 4,294,967,296 messages
    
    /// Create new AEAD cipher
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            cipher,
            sequence_number: 0,
        }
    }
    
    /// Check if rekeying is needed
    /// 
    /// # Returns
    /// - `true` if sequence number approaching threshold (needs rekey)
    /// - `false` if still safe to continue
    /// 
    /// # Availability Note: No Automatic KeyUpdate
    /// 
    /// ⚠️ **LIMITATION**: Current implementation does NOT support TLS 1.3 KeyUpdate.
    /// 
    /// **What happens when threshold reached**:
    /// - `encrypt()` returns error (connection cannot send more)
    /// - Client must establish NEW TLS handshake
    /// - No seamless key rotation
    /// 
    /// **Impact on Availability**:
    /// - Long-lived connections (>4B messages) will disconnect
    /// - For most applications: Not an issue (4B messages = years of traffic)
    /// - For high-throughput servers: May need session resumption or connection pooling
    /// 
    /// **Future Enhancement** (TLS 1.3 KeyUpdate):
    /// ```ignore
    /// // Pseudocode for future implementation
    /// if self.needs_rekey() {
    ///     let new_key = hkdf_expand(current_key, "tls13 key update");
    ///     self.cipher = ChaCha20Poly1305::new(&new_key);
    ///     self.sequence_number = 0;
    /// }
    /// ```
    /// 
    /// **Workaround for now**: Reconnect before threshold (monitor sequence number)
    pub fn needs_rekey(&self) -> bool {
        self.sequence_number >= Self::REKEY_THRESHOLD
    }
    
    /// Get current sequence number (for monitoring)
    pub fn get_sequence_number(&self) -> u64 {
        self.sequence_number
    }
    
    /// TLS 1.3 KeyUpdate: Replace encryption key and reset sequence number
    /// 
    /// # Security Model
    /// 
    /// **When to call**: Before reaching REKEY_THRESHOLD (2^32 messages)
    /// 
    /// **What it does**:
    /// 1. Replaces ChaCha20-Poly1305 key with new key
    /// 2. Resets sequence_number to 0
    /// 3. Allows connection to continue without reconnecting
    /// 
    /// **Key Derivation**: Caller must use `KeySchedule::update_application_key()`
    /// to derive the new key using TLS 1.3 HKDF-Expand-Label.
    /// 
    /// # Example
    /// 
    /// ```ignore
    /// // Check if rekeying needed
    /// if aead.needs_rekey() {
    ///     // Derive new key using TLS 1.3 key update
    ///     let new_key = KeySchedule::update_application_key(&current_key);
    ///     
    ///     // Update cipher
    ///     aead.update_key(&new_key);
    ///     
    ///     // Optionally: send KeyUpdate message to peer
    ///     send_key_update(KeyUpdateRequest::UpdateRequested)?;
    /// }
    /// ```
    /// 
    /// # Forward Secrecy
    /// 
    /// After key update, old messages cannot be decrypted even if new key leaks,
    /// because HKDF derivation is one-way (cannot reverse to get old key).
    pub fn update_key(&mut self, new_key: &[u8; 32]) {
        // Replace cipher with new key
        self.cipher = ChaCha20Poly1305::new(new_key.into());
        
        // Reset sequence number
        self.sequence_number = 0;
    }
    
    /// Encrypt record payload
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        // SECURITY FIX: Check rekeying threshold BEFORE allowing encryption
        // 
        // Previous: Only checked u64::MAX (unrealistic, would take centuries)
        // Now: Check cryptographic safe limit (2^32 messages)
        if self.sequence_number >= Self::REKEY_THRESHOLD {
            return Err(RecordError::RekeyRequired {
                sequence_number: self.sequence_number,
                threshold: Self::REKEY_THRESHOLD,
            });
        }
        
        let nonce = self.generate_nonce();
        
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };
        
        let ciphertext = self.cipher.encrypt(&nonce, payload)
            .map_err(|_| RecordError::EncryptionError)?;
        
        self.sequence_number += 1;
        
        Ok(ciphertext)
    }
    
    /// Decrypt record payload
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        // SECURITY FIX: Check rekeying threshold (same as encrypt)
        if self.sequence_number >= Self::REKEY_THRESHOLD {
            return Err(RecordError::RekeyRequired {
                sequence_number: self.sequence_number,
                threshold: Self::REKEY_THRESHOLD,
            });
        }
        
        let nonce = self.generate_nonce();
        
        let payload = Payload {
            msg: ciphertext,
            aad: additional_data,
        };
        
        let plaintext = self.cipher.decrypt(&nonce, payload)
            .map_err(|_| RecordError::DecryptionError)?;
        
        self.sequence_number += 1;
        
        Ok(plaintext)
    }
    
    /// Generate nonce from sequence number
    fn generate_nonce(&self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.sequence_number.to_be_bytes());
        Nonce::from(nonce_bytes)
    }
    
    /// Get current sequence number
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }
    
    /// Reset sequence number (for new connection)
    pub fn reset(&mut self) {
        self.sequence_number = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let mut cipher = AeadCipher::new(&key);
        
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..], plaintext);
        
        // Reset for decryption
        let mut decipher = AeadCipher::new(&key);
        let recovered = decipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }
    
    #[test]
    fn test_sequence_numbers() {
        let key = [1u8; 32];
        let mut cipher = AeadCipher::new(&key);
        
        assert_eq!(cipher.sequence_number(), 0);
        
        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.sequence_number(), 1);
        
        cipher.encrypt(b"test2", b"").unwrap();
        assert_eq!(cipher.sequence_number(), 2);
    }
}
