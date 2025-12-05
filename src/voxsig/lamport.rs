//! Lamport One-Time Signatures

use crate::voxsig::params::*;
use sha3::{Sha3_256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LamportPrivateKey {
    pub pairs: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])>,
}

/// Lamport Public Key
/// 
/// # Security Fix: Store Individual Key Hashes
/// 
/// **Previous**: Only stored combined hash H(H(key0) || H(key1))
/// **Problem**: Cannot verify preimages during signature verification!
/// 
/// **Fixed**: Now stores BOTH H(key0) and H(key1) for each bit position.
/// This allows verification to check: Hash(revealed_key) == expected_hash[bit]
#[derive(Clone)]
pub struct LamportPublicKey {
    /// Combined hashes (for backward compat with Merkle tree)
    pub hashes: Vec<[u8; HASH_SIZE]>,
    
    /// ✅ SECURITY FIX: Individual key pair hashes for preimage verification
    /// pairs[i] = (H(key0_i), H(key1_i))
    /// This is ESSENTIAL for verifying Lamport OTS correctly!
    pub pairs: Vec<([u8; HASH_SIZE], [u8; HASH_SIZE])>,
}

#[derive(Clone)]
pub struct LamportSignature {
    pub revealed: Vec<[u8; HASH_SIZE]>,
}

impl LamportPrivateKey {
    /// Generate Lamport keypair from seed and index
    /// 
    /// **NOTE**: This is the base derivation WITHOUT message binding.
    /// For stateless signing, use `generate_message_bound()` instead to prevent
    /// index reuse attacks.
    pub fn generate(seed: &[u8; 32], index: u32) -> (Self, LamportPublicKey) {
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(b"lamport");
        hasher.update(&index.to_le_bytes());
        let index_seed = hasher.finalize();
        
        let mut pairs = Vec::with_capacity(LAMPORT_N);
        let mut public_hashes = Vec::with_capacity(LAMPORT_N);
        let mut public_pairs = Vec::with_capacity(LAMPORT_N);  // ✅ NEW
        
        for i in 0..LAMPORT_N {
            let key0 = Self::derive_key(&index_seed, i * 2);
            let key1 = Self::derive_key(&index_seed, i * 2 + 1);
            
            // ✅ SECURITY FIX: Hash individual keys for preimage verification
            let mut h0 = Sha3_256::new();
            h0.update(&key0);
            let pk0: [u8; HASH_SIZE] = h0.finalize().into();
            
            let mut h1 = Sha3_256::new();
            h1.update(&key1);
            let pk1: [u8; HASH_SIZE] = h1.finalize().into();
            
            // Combine into single hash for Merkle tree (backward compat)
            let mut h = Sha3_256::new();
            h.update(&pk0);
            h.update(&pk1);
            let pub_hash: [u8; HASH_SIZE] = h.finalize().into();
            
            pairs.push((key0, key1));
            public_hashes.push(pub_hash);
            public_pairs.push((pk0, pk1));  // ✅ Store individual hashes!
        }
        
        let private_key = Self { pairs };
        let public_key = LamportPublicKey { 
            hashes: public_hashes,
            pairs: public_pairs,  // ✅ Include individual hash pairs!
        };
        
        (private_key, public_key)
    }
    
    /// Generate message-bound Lamport keypair
    /// 
    /// # Security Enhancement
    /// 
    /// This binds the Lamport keys to BOTH index AND message hash.
    /// 
    /// **Key Derivation:**
    /// ```text
    /// index_seed = H(seed || "lamport_msg_bound" || index || message_hash)
    /// key_i = H(index_seed || i)
    /// ```
    /// 
    /// **Security Properties:**
    /// - ✅ Different messages → different Lamport keys (even with same index)
    /// - ✅ Index reuse with different messages → different key reveals → no forgery
    /// - ✅ Attacker cannot combine keys from different messages
    /// 
    /// **Tradeoff:**
    /// - ❌ Cannot pre-compute public keys (need message first)
    /// - ✅ But prevents catastrophic index reuse vulnerability
    /// 
    /// Use this for stateless signing where index tracking is unreliable.
    pub fn generate_message_bound(
        seed: &[u8; 32], 
        index: u32, 
        message_hash: &[u8; 32]
    ) -> (Self, LamportPublicKey) {
        // Bind key derivation to message
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(b"lamport_msg_bound");
        hasher.update(&index.to_le_bytes());
        hasher.update(message_hash); // ✅ MESSAGE BINDING
        let index_seed = hasher.finalize();
        
        let mut pairs = Vec::with_capacity(LAMPORT_N);
        let mut public_hashes = Vec::with_capacity(LAMPORT_N);
        let mut public_pairs = Vec::with_capacity(LAMPORT_N);  // ✅ NEW
        
        for i in 0..LAMPORT_N {
            let key0 = Self::derive_key(&index_seed, i * 2);
            let key1 = Self::derive_key(&index_seed, i * 2 + 1);
            
            let mut h0 = Sha3_256::new();
            h0.update(&key0);
            let pk0: [u8; HASH_SIZE] = h0.finalize().into();
            
            let mut h1 = Sha3_256::new();
            h1.update(&key1);
            let pk1: [u8; HASH_SIZE] = h1.finalize().into();
            
            let mut h = Sha3_256::new();
            h.update(&pk0);
            h.update(&pk1);
            let pub_hash: [u8; HASH_SIZE] = h.finalize().into();
            
            pairs.push((key0, key1));
            public_hashes.push(pub_hash);
            public_pairs.push((pk0, pk1));  // ✅ Store individual hashes!
        }
        
        let private_key = Self { pairs };
        let public_key = LamportPublicKey { 
            hashes: public_hashes,
            pairs: public_pairs,  // ✅ Include individual hash pairs!
        };
        
        (private_key, public_key)
    }
    
    fn derive_key(seed: &[u8], nonce: usize) -> [u8; HASH_SIZE] {
        let mut hasher = Sha3_256::new();
        hasher.update(seed);
        hasher.update(&(nonce as u32).to_le_bytes());
        hasher.finalize().into()
    }
    
    pub fn sign(&self, message_hash: &[u8; 32]) -> LamportSignature {
        let mut revealed = Vec::with_capacity(LAMPORT_N);
        let bits = Self::hash_to_bits(message_hash);
        
        for (_i, &bit) in bits.iter().enumerate() {
            let key = if bit == 0 {
                self.pairs[_i].0
            } else {
                self.pairs[_i].1
            };
            revealed.push(key);
        }
        
        LamportSignature { revealed }
    }
    
    pub fn hash_to_bits(hash: &[u8; 32]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(256);
        for &byte in hash.iter() {
            for j in 0..8 {
                let bit = (byte >> (7 - j)) & 1;
                bits.push(bit);
            }
        }
        bits
    }
}

impl LamportPublicKey {
    // REMOVED: from_signature() method due to security vulnerability
    // 
    // The previous implementation used placeholders (zeros) for unrevealed keys,
    // which could allow signature forgery attacks. 
    //
    // Proper Lamport verification requires:
    // 1. Store the full compressed public key in Merkle tree
    // 2. Verify revealed preimages hash to stored values
    // 3. Never reconstruct from partial information
    
    pub fn compress(&self) -> [u8; HASH_SIZE] {
        let mut accumulated = [0u8; HASH_SIZE];
        
        for (i, hash) in self.hashes.iter().enumerate() {
            let mut h = Sha3_256::new();
            h.update(hash);
            h.update(&(i as u16).to_le_bytes());
            let mixed: [u8; HASH_SIZE] = h.finalize().into();
            
            for j in 0..HASH_SIZE {
                accumulated[j] ^= mixed[j];
            }
        }
        
        let mut h = Sha3_256::new();
        h.update(&accumulated);
        h.update(b"lamport_commit");
        h.finalize().into()
    }
    
    pub fn bind_to_seed(&self, pub_seed: &[u8; 32], index: u32) -> [u8; HASH_SIZE] {
        let compressed = self.compress();
        
        let mut h = Sha3_256::new();
        h.update(&compressed);
        h.update(pub_seed);
        h.update(&index.to_le_bytes());
        h.finalize().into()
    }
}

impl LamportSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(LAMPORT_N * HASH_SIZE);
        for key in &self.revealed {
            bytes.extend_from_slice(key);
        }
        bytes
    }
    
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != LAMPORT_N * HASH_SIZE {
            return None;
        }
        
        let mut revealed = Vec::with_capacity(LAMPORT_N);
        for i in 0..LAMPORT_N {
            let mut key = [0u8; HASH_SIZE];
            key.copy_from_slice(&data[i * HASH_SIZE..(i + 1) * HASH_SIZE]);
            revealed.push(key);
        }
        
        Some(Self { revealed })
    }
}
